package localmachine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

const maximumCredentialFile = 16 * 1024

type stagedCredentials struct {
	administrator []byte
	services      map[iamv1.ServicePurpose][]byte
}

func (effects *Effects) ReadSecurityMailConfiguration(
	ctx context.Context,
	path string,
) (platformcommand.SecurityMailInput, error) {
	if effects == nil || ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") ||
		validateManagedRoot(filepath.Dir(path)) != nil {
		return platformcommand.SecurityMailInput{}, platformcommand.ErrEffectVerification
	}
	encoded, err := readManagedFile(filepath.Dir(path), filepath.Base(path), installationv1.MaximumSecurityMailConfigurationBytes)
	defer clear(encoded)
	if err != nil {
		return platformcommand.SecurityMailInput{}, platformcommand.ErrEffectVerification
	}
	configuration, err := installationv1.DecodeSecurityMailConfiguration(bytes.NewReader(encoded))
	if err != nil {
		return platformcommand.SecurityMailInput{}, platformcommand.ErrEffectVerification
	}
	digest, err := installationv1.SecurityMailConfigurationDigest(configuration)
	if err != nil {
		configuration.Clear()
		return platformcommand.SecurityMailInput{}, platformcommand.ErrEffectVerification
	}
	return platformcommand.SecurityMailInput{Digest: digest, Configuration: configuration}, nil
}

func stageInstallation(plan platformcommand.InstallPlan, entropy io.Reader) error {
	if entropy == nil {
		return errors.New("installation entropy is unavailable")
	}
	for _, directory := range []string{
		"releases", "config", "data", "runtime", layout.ExecutorRoot,
		"secrets", "secrets/database", "secrets/authority",
		"secrets/operator", layout.WorkloadSecretRoot, "backups", "support",
	} {
		if _, err := ensureManagedDirectory(plan.Root, filepath.FromSlash(directory)); err != nil {
			return err
		}
	}
	if _, err := ensurePostgresDataRoot(plan.Root); err != nil {
		return err
	}
	destination, err := managedPath(
		plan.Root,
		filepath.FromSlash(layout.ReleaseDirectory(plan.Bundle.Manifest.Release.ID)),
	)
	if err != nil {
		return err
	}
	if _, err := release.StageDirectory(plan.Bundle, plan.TrustBytes, destination); err != nil {
		if errors.Is(err, release.ErrStageConflict) {
			return errors.Join(platformcommand.ErrEffectConflict, err)
		}
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	if err := writeManagedOnce(
		plan.Root, filepath.FromSlash(layout.ReleaseTrust), plan.TrustBytes,
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}

	credentials, err := ensureIAMBootstrap(plan.Root, plan.InstallationID, entropy)
	if err != nil {
		return err
	}
	defer credentials.clear()
	if err := ensureAccessKeyWrappingKeyring(plan.Root, plan.InstallationID, entropy); err != nil {
		return err
	}
	if err := ensureTOTPKeyring(plan.Root, plan.InstallationID, entropy); err != nil {
		return err
	}
	if err := ensureSecurityMail(plan.Root, plan.InstallationID, entropy, plan.SecurityMail); err != nil {
		return err
	}
	serviceFiles := map[iamv1.ServicePurpose][]string{
		iamv1.ServiceIAM:                  {layout.IAMAuditCredential},
		iamv1.ServicePaaS:                 {layout.PaaSIAMCredential, layout.PaaSAuditCredential},
		iamv1.ServiceAudit:                {layout.AuditIAMCredential},
		iamv1.ServiceInstallationVerifier: {layout.InstallationVerifierCredential},
	}
	for purpose, paths := range serviceFiles {
		credential, found := credentials.services[purpose]
		if !found {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("IAM bootstrap service credential is absent"),
			)
		}
		for _, path := range paths {
			if err := writeManagedOnce(plan.Root, filepath.FromSlash(path), credential); err != nil {
				return errors.Join(platformcommand.ErrEffectConflict, err)
			}
		}
	}
	if err := writeManagedOnce(
		plan.Root, filepath.FromSlash(layout.InitialAdministratorPassword), credentials.administrator,
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	cursorKey, err := ensureRandomHex(plan.Root, layout.IAMCursorKey, entropy)
	if err != nil {
		return err
	}
	clear(cursorKey)
	cursorKey, err = ensureRandomHex(plan.Root, layout.AuditCursorKey, entropy)
	if err != nil {
		return err
	}
	clear(cursorKey)
	backupKey, err := ensureRandomHex(plan.Root, layout.BackupSealKey, entropy)
	if err != nil {
		return err
	}
	clear(backupKey)
	postgresPassword, err := ensureGeneratedCredential(
		plan.Root, layout.PostgresPassword, entropy, "mxp1.", false,
	)
	if err != nil {
		return err
	}
	defer clear(postgresPassword)
	if err := ensureExactDSN(
		plan.Root, layout.PostgresMigration, "matrix", postgresPassword,
	); err != nil {
		return err
	}
	for _, login := range []struct {
		path string
		role string
	}{
		{path: layout.IAMAPI, role: "matrix_iam_api_login"},
		{path: layout.IAMWorker, role: "matrix_iam_worker_login"},
		{path: layout.IAMCredentialRecovery, role: "matrix_iam_credential_recovery_login"},
		{path: layout.IAMAuthenticationRecovery, role: "matrix_iam_authentication_recovery_login"},
		{path: layout.IAMBackupCustody, role: "matrix_iam_backup_custody_login"},
		{path: layout.IAMNotificationWorker, role: "matrix_iam_notification_worker_login"},
		{path: layout.IAMAccessAnalysisWorker, role: "matrix_iam_access_analysis_worker_login"},
		{path: layout.AuditRuntime, role: "matrix_audit_runtime_login"},
		{path: layout.PaaSAPI, role: "matrix_paas_api_login"},
		{path: layout.PaaSWorker, role: "matrix_paas_worker_login"},
	} {
		if err := ensureRuntimeDSN(plan.Root, login.path, login.role, entropy); err != nil {
			return err
		}
	}
	return nil
}

func ensureIAMBootstrap(root, installationID string, entropy io.Reader) (stagedCredentials, error) {
	relative := filepath.FromSlash(layout.IAMBootstrap)
	exists, err := managedFileExists(root, relative)
	if err != nil {
		return stagedCredentials{}, errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if exists {
		content, err := readManagedFile(root, relative, maximumCredentialFile)
		if err != nil {
			return stagedCredentials{}, errors.Join(platformcommand.ErrEffectVerification, err)
		}
		document, err := iamv1.DecodeBootstrapDocument(bytes.NewReader(content))
		clear(content)
		if err != nil || document.InstallationID != installationID {
			return stagedCredentials{}, errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("stored IAM bootstrap is invalid"),
			)
		}
		return credentialsFromBootstrap(document), nil
	}

	administratorText, err := randomCredential(entropy, "mxp1.", true)
	if err != nil {
		return stagedCredentials{}, errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	administrator, err := iamv1.NewSecret(administratorText)
	if err != nil {
		return stagedCredentials{}, errors.Join(platformcommand.ErrEffectVerification, err)
	}
	services := make([]iamv1.BootstrapServiceCredential, 0, len(iamv1.AllServicePurposes()))
	for _, purpose := range iamv1.AllServicePurposes() {
		credentialText, err := randomCredential(entropy, "mx1.", false)
		if err != nil {
			return stagedCredentials{}, errors.Join(platformcommand.ErrEffectUnavailable, err)
		}
		credential, err := iamv1.NewSecret(credentialText)
		if err != nil {
			return stagedCredentials{}, errors.Join(platformcommand.ErrEffectVerification, err)
		}
		services = append(services, iamv1.BootstrapServiceCredential{
			Purpose: purpose, PrincipalID: servicePrincipalID(purpose), Credential: credential,
		})
	}
	document := iamv1.BootstrapDocument{
		APIVersion: iamv1.APIVersion, Kind: "IAMBootstrap", InstallationID: installationID,
		Organization: iamv1.InitialOrganization{
			ID: "organization-default", DisplayName: "Matrix Organization",
		},
		Administrator: iamv1.InitialAdministrator{
			ID: "principal-admin", LoginName: "admin", DisplayName: "Matrix Administrator",
			Password: administrator,
		},
		Services: services,
	}
	content, err := iamv1.EncodeBootstrapDocument(document)
	if err != nil {
		return stagedCredentials{}, errors.Join(platformcommand.ErrEffectVerification, err)
	}
	if err := writeManagedOnce(root, relative, content); err != nil {
		clear(content)
		return stagedCredentials{}, errors.Join(platformcommand.ErrEffectConflict, err)
	}
	clear(content)
	return credentialsFromBootstrap(document), nil
}

func credentialsFromBootstrap(document iamv1.BootstrapDocument) stagedCredentials {
	result := stagedCredentials{
		administrator: document.Administrator.Password.CopyBytes(),
		services:      make(map[iamv1.ServicePurpose][]byte, len(document.Services)),
	}
	for _, service := range document.Services {
		result.services[service.Purpose] = service.Credential.CopyBytes()
	}
	return result
}

// IAM wrapping material is installation-owned and bound to the sealed
// bootstrap. Staging replay validates the existing material and never
// regenerates it.
func ensureAccessKeyWrappingKeyring(root, installationID string, entropy io.Reader) error {
	relative := filepath.FromSlash(layout.IAMAccessKeyWrappingKeyring)
	exists, err := managedFileExists(root, relative)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if exists {
		_, err := readAccessKeyWrappingKeyring(root, installationID)
		return err
	}
	scope, err := accessKeyWrappingScope(root, installationID)
	if err != nil {
		return err
	}
	random := make([]byte, 32)
	if _, err := io.ReadFull(entropy, random); err != nil {
		clear(random)
		return errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	materialText := base64.RawURLEncoding.EncodeToString(random)
	clear(random)
	material, err := iamv1.NewSecret(materialText)
	materialText = ""
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	const keyID = "access-key-wrapping-v1"
	keyring := iamv1.AccessKeyWrappingKeyring{
		APIVersion: iamv1.APIVersion, Kind: "AccessKeyWrappingKeyring",
		Purpose: iamv1.AccessKeyWrappingPurpose, Scope: scope,
		ActiveWrappingKeyID: keyID,
		Keys: []iamv1.AccessKeyWrappingKey{{
			WrappingKeyID: keyID, FormatVersion: 1, KeyMaterial: material,
		}},
	}
	encoded, err := iamv1.EncodeAccessKeyWrappingKeyring(keyring)
	keyring = iamv1.AccessKeyWrappingKeyring{}
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(encoded)
	if err := writeManagedOnce(root, relative, encoded); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return nil
}

func readAccessKeyWrappingKeyring(root, installationID string) (iamv1.AccessKeyWrappingKeyring, error) {
	expected, err := accessKeyWrappingScope(root, installationID)
	if err != nil {
		return iamv1.AccessKeyWrappingKeyring{}, err
	}
	encoded, err := readManagedFile(root, filepath.FromSlash(layout.IAMAccessKeyWrappingKeyring), iamv1.MaxAccessKeyWrappingKeyringBytes)
	if err != nil {
		return iamv1.AccessKeyWrappingKeyring{}, platformcommand.ErrEffectVerification
	}
	defer clear(encoded)
	keyring, err := iamv1.DecodeAccessKeyWrappingKeyring(bytes.NewReader(encoded))
	if err != nil || keyring.Scope != expected {
		return iamv1.AccessKeyWrappingKeyring{}, platformcommand.ErrEffectVerification
	}
	return keyring, nil
}

func accessKeyWrappingScope(root, installationID string) (iamv1.AccessKeyWrappingScope, error) {
	sealedInstallationID, bootstrapDigest, err := sealedIAMBootstrapScope(root, installationID)
	if err != nil {
		return iamv1.AccessKeyWrappingScope{}, err
	}
	return iamv1.AccessKeyWrappingScope{InstallationID: sealedInstallationID, BootstrapDigest: bootstrapDigest}, nil
}

func ensureTOTPKeyring(root, installationID string, entropy io.Reader) error {
	relative := filepath.FromSlash(layout.IAMTOTPKeyring)
	exists, err := managedFileExists(root, relative)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if exists {
		_, err := readTOTPKeyring(root, installationID)
		return err
	}
	scope, err := totpWrappingScope(root, installationID)
	if err != nil {
		return err
	}
	random := make([]byte, 32)
	if _, err := io.ReadFull(entropy, random); err != nil {
		clear(random)
		return errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	materialText := base64.RawURLEncoding.EncodeToString(random)
	clear(random)
	material, err := iamv1.NewSecret(materialText)
	materialText = ""
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	const keyID = "totp-wrapping-v1"
	keyring := iamv1.TOTPKeyring{
		APIVersion: iamv1.APIVersion, Kind: "TOTPKeyring",
		Purpose: iamv1.TOTPWrappingPurpose, Scope: scope,
		KeysetRevision: 1, ActiveKeyID: keyID,
		Keys: []iamv1.TOTPWrappingKey{{KeyID: keyID, FormatVersion: 1, KeyMaterial: material}},
	}
	encoded, err := iamv1.EncodeTOTPKeyring(keyring)
	keyring = iamv1.TOTPKeyring{}
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(encoded)
	if err := writeManagedOnce(root, relative, encoded); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return nil
}

func readTOTPKeyring(root, installationID string) (iamv1.TOTPKeyring, error) {
	expected, err := totpWrappingScope(root, installationID)
	if err != nil {
		return iamv1.TOTPKeyring{}, err
	}
	encoded, err := readManagedFile(root, filepath.FromSlash(layout.IAMTOTPKeyring), iamv1.MaxTOTPKeyringBytes)
	if err != nil {
		return iamv1.TOTPKeyring{}, platformcommand.ErrEffectVerification
	}
	defer clear(encoded)
	keyring, err := iamv1.DecodeTOTPKeyring(bytes.NewReader(encoded))
	if err != nil || keyring.Scope != expected {
		return iamv1.TOTPKeyring{}, platformcommand.ErrEffectVerification
	}
	return keyring, nil
}

func totpWrappingScope(root, installationID string) (iamv1.TOTPWrappingScope, error) {
	sealedInstallationID, bootstrapDigest, err := sealedIAMBootstrapScope(root, installationID)
	if err != nil {
		return iamv1.TOTPWrappingScope{}, err
	}
	return iamv1.TOTPWrappingScope{InstallationID: sealedInstallationID, BootstrapDigest: bootstrapDigest}, nil
}

func sealedIAMBootstrapScope(root, installationID string) (string, string, error) {
	encoded, err := readManagedFile(root, filepath.FromSlash(layout.IAMBootstrap), maximumCredentialFile)
	if err != nil {
		return "", "", platformcommand.ErrEffectVerification
	}
	defer clear(encoded)
	document, err := iamv1.DecodeBootstrapDocument(bytes.NewReader(encoded))
	if err != nil || document.InstallationID != installationID {
		return "", "", platformcommand.ErrEffectVerification
	}
	digest, err := iamv1.BootstrapDigest(document)
	if err != nil {
		return "", "", platformcommand.ErrEffectVerification
	}
	return document.InstallationID, digest, nil
}

func ensureSecurityMail(
	root string,
	installationID string,
	entropy io.Reader,
	input platformcommand.SecurityMailInput,
) error {
	if installationv1.ValidateSecurityMailConfiguration(input.Configuration) != nil {
		return platformcommand.ErrEffectVerification
	}
	digest, err := installationv1.SecurityMailConfigurationDigest(input.Configuration)
	if err != nil || digest != input.Digest {
		return platformcommand.ErrEffectVerification
	}
	keyPath := filepath.FromSlash(layout.IAMEmailVerificationKeyring)
	channelPath := filepath.FromSlash(layout.IAMSecurityMailSMTPChannel)
	keyExists, err := managedFileExists(root, keyPath)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	channelExists, err := managedFileExists(root, channelPath)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if channelExists && !keyExists {
		return platformcommand.ErrEffectVerification
	}
	scope, err := securityMailScope(root, installationID)
	if err != nil {
		return err
	}
	if keyExists {
		if _, err := readEmailVerificationKeyring(root, installationID); err != nil {
			return err
		}
	} else {
		materialBytes := make([]byte, 32)
		if _, err := io.ReadFull(entropy, materialBytes); err != nil {
			clear(materialBytes)
			return errors.Join(platformcommand.ErrEffectUnavailable, err)
		}
		materialText := base64.RawURLEncoding.EncodeToString(materialBytes)
		clear(materialBytes)
		material, err := iamv1.NewSecret(materialText)
		materialText = ""
		if err != nil {
			return platformcommand.ErrEffectVerification
		}
		const keyID = "email-verification-v1"
		keyring := iamv1.EmailVerificationKeyring{
			APIVersion: iamv1.APIVersion, Kind: "EmailVerificationKeyring",
			Purpose: iamv1.EmailVerificationWrappingPurpose, Scope: scope,
			KeysetRevision: 1, ActiveKeyID: keyID,
			Keys: []iamv1.EmailVerificationWrappingKey{{KeyID: keyID, FormatVersion: 1, KeyMaterial: material}},
		}
		encoded, err := iamv1.EncodeEmailVerificationKeyring(keyring)
		keyring = iamv1.EmailVerificationKeyring{}
		if err != nil {
			return platformcommand.ErrEffectVerification
		}
		defer clear(encoded)
		if err := writeManagedOnce(root, keyPath, encoded); err != nil {
			return errors.Join(platformcommand.ErrEffectConflict, err)
		}
	}
	channel := iamv1.SecurityMailSMTPChannel{
		APIVersion: iamv1.APIVersion, Kind: "SecurityMailSMTPChannel",
		Purpose: iamv1.SecurityMailSubmissionPurpose, Scope: scope,
		Host: input.Configuration.Host, Port: input.Configuration.Port,
		TLSMode: input.Configuration.TLSMode, Username: input.Configuration.Username,
		Password: input.Configuration.Password, From: input.Configuration.From,
		TrustedCAPEM: input.Configuration.TrustedCAPEM,
	}
	if channelExists {
		actual, err := readSecurityMailSMTPChannel(root, installationID)
		if err != nil || !equalSecurityMailSMTPChannels(actual, channel) {
			return platformcommand.ErrEffectVerification
		}
		return nil
	}
	encoded, err := iamv1.EncodeSecurityMailSMTPChannel(channel)
	channel = iamv1.SecurityMailSMTPChannel{}
	if err != nil {
		return platformcommand.ErrEffectVerification
	}
	defer clear(encoded)
	if err := writeManagedOnce(root, channelPath, encoded); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return nil
}

func equalSecurityMailSMTPChannels(left, right iamv1.SecurityMailSMTPChannel) bool {
	leftEncoded, leftErr := iamv1.EncodeSecurityMailSMTPChannel(left)
	defer clear(leftEncoded)
	rightEncoded, rightErr := iamv1.EncodeSecurityMailSMTPChannel(right)
	defer clear(rightEncoded)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftEncoded, rightEncoded)
}

func securityMailScope(root, installationID string) (iamv1.SecurityMailInstallationScope, error) {
	sealedInstallationID, bootstrapDigest, err := sealedIAMBootstrapScope(root, installationID)
	if err != nil {
		return iamv1.SecurityMailInstallationScope{}, err
	}
	return iamv1.SecurityMailInstallationScope{InstallationID: sealedInstallationID, BootstrapDigest: bootstrapDigest}, nil
}

func readEmailVerificationKeyring(root, installationID string) (iamv1.EmailVerificationKeyring, error) {
	expected, err := securityMailScope(root, installationID)
	if err != nil {
		return iamv1.EmailVerificationKeyring{}, err
	}
	encoded, err := readManagedFile(root, filepath.FromSlash(layout.IAMEmailVerificationKeyring), iamv1.MaxEmailVerificationKeyringBytes)
	if err != nil {
		return iamv1.EmailVerificationKeyring{}, platformcommand.ErrEffectVerification
	}
	defer clear(encoded)
	keyring, err := iamv1.DecodeEmailVerificationKeyring(bytes.NewReader(encoded))
	if err != nil || keyring.Scope != expected {
		return iamv1.EmailVerificationKeyring{}, platformcommand.ErrEffectVerification
	}
	return keyring, nil
}

func readSecurityMailSMTPChannel(root, installationID string) (iamv1.SecurityMailSMTPChannel, error) {
	expected, err := securityMailScope(root, installationID)
	if err != nil {
		return iamv1.SecurityMailSMTPChannel{}, err
	}
	encoded, err := readManagedFile(root, filepath.FromSlash(layout.IAMSecurityMailSMTPChannel), iamv1.MaxSecurityMailSMTPChannelBytes)
	if err != nil {
		return iamv1.SecurityMailSMTPChannel{}, platformcommand.ErrEffectVerification
	}
	defer clear(encoded)
	channel, err := iamv1.DecodeSecurityMailSMTPChannel(bytes.NewReader(encoded))
	if err != nil || channel.Scope != expected {
		return iamv1.SecurityMailSMTPChannel{}, platformcommand.ErrEffectVerification
	}
	return channel, nil
}

func (credentials *stagedCredentials) clear() {
	if credentials == nil {
		return
	}
	clear(credentials.administrator)
	for purpose, credential := range credentials.services {
		clear(credential)
		delete(credentials.services, purpose)
	}
}

func servicePrincipalID(purpose iamv1.ServicePurpose) iamv1.PrincipalID {
	switch purpose {
	case iamv1.ServiceIAM:
		return "service-iam"
	case iamv1.ServicePaaS:
		return "service-paas"
	case iamv1.ServiceAudit:
		return "service-audit"
	case iamv1.ServiceInstallationVerifier:
		return "service-installation-verifier"
	default:
		panic("closed IAM service purpose is unsupported")
	}
}

func ensureRandomHex(root, relative string, entropy io.Reader) ([]byte, error) {
	path := filepath.FromSlash(relative)
	exists, err := managedFileExists(root, path)
	if err != nil {
		return nil, errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if exists {
		content, err := readManagedFile(root, path, 64)
		decoded, decodeErr := hex.DecodeString(string(content))
		clear(decoded)
		if err != nil || decodeErr != nil || len(content) != 64 {
			clear(content)
			return nil, errors.Join(platformcommand.ErrEffectVerification, errors.New("stored key is invalid"))
		}
		return content, nil
	}
	random := make([]byte, 32)
	if _, err := io.ReadFull(entropy, random); err != nil {
		clear(random)
		return nil, errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	content := []byte(hex.EncodeToString(random))
	clear(random)
	if err := writeManagedOnce(root, path, content); err != nil {
		clear(content)
		return nil, errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return content, nil
}

func ensureGeneratedCredential(
	root, relative string,
	entropy io.Reader,
	prefix string,
	password bool,
) ([]byte, error) {
	path := filepath.FromSlash(relative)
	exists, err := managedFileExists(root, path)
	if err != nil {
		return nil, errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if exists {
		content, err := readManagedFile(root, path, maximumCredentialFile)
		if err != nil || !validGeneratedCredential(content, prefix, password) {
			clear(content)
			return nil, errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("stored generated credential is invalid"),
			)
		}
		return content, nil
	}
	text, err := randomCredential(entropy, prefix, password)
	if err != nil {
		return nil, errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	content := []byte(text)
	text = ""
	if err := writeManagedOnce(root, path, content); err != nil {
		clear(content)
		return nil, errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return content, nil
}

func randomCredential(entropy io.Reader, prefix string, password bool) (string, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(entropy, random); err != nil {
		clear(random)
		return "", errors.New("generate installation credential failed")
	}
	result := prefix + base64.RawURLEncoding.EncodeToString(random)
	clear(random)
	if password {
		result += "-Aa1!"
	}
	return result, nil
}

func validGeneratedCredential(content []byte, prefix string, password bool) bool {
	suffix := ""
	if password {
		suffix = "-Aa1!"
	}
	if len(content) != len(prefix)+43+len(suffix) ||
		!bytes.HasPrefix(content, []byte(prefix)) ||
		!bytes.HasSuffix(content, []byte(suffix)) {
		return false
	}
	encoded := content[len(prefix) : len(prefix)+43]
	decoded, err := base64.RawURLEncoding.DecodeString(string(encoded))
	defer clear(decoded)
	return err == nil && len(decoded) == 32 &&
		bytes.Equal(encoded, []byte(base64.RawURLEncoding.EncodeToString(decoded)))
}

func ensureRuntimeDSN(root, relative, role string, entropy io.Reader) error {
	path := filepath.FromSlash(relative)
	exists, err := managedFileExists(root, path)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if exists {
		content, err := readManagedFile(root, path, maximumCredentialFile)
		if err != nil || validateDatabaseDSN(string(content), role) != nil {
			clear(content)
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("stored database credential is invalid"),
			)
		}
		clear(content)
		return nil
	}
	password, err := randomCredential(entropy, "mxp1.", false)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	content := []byte(formatDatabaseDSN(role, []byte(password)))
	password = ""
	defer clear(content)
	if err := writeManagedOnce(root, path, content); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return nil
}

func ensureExactDSN(root, relative, role string, password []byte) error {
	content := []byte(formatDatabaseDSN(role, password))
	defer clear(content)
	if err := writeManagedOnce(root, filepath.FromSlash(relative), content); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return nil
}

func formatDatabaseDSN(role string, password []byte) string {
	value := &url.URL{
		Scheme: "postgresql", User: url.UserPassword(role, string(password)),
		Host: "postgres:5432", Path: "/matrix",
	}
	query := value.Query()
	query.Set("sslmode", "disable")
	value.RawQuery = query.Encode()
	return value.String()
}

func validateDatabaseDSN(content, role string) error {
	value, err := url.Parse(content)
	if err != nil || value.Scheme != "postgresql" || value.Host != "postgres:5432" ||
		value.Path != "/matrix" || value.User == nil || value.User.Username() != role ||
		value.Query().Get("sslmode") != "disable" || len(value.Query()) != 1 ||
		value.Fragment != "" {
		return errors.New("database DSN is invalid")
	}
	password, found := value.User.Password()
	if !found || !validGeneratedCredential([]byte(password), "mxp1.", false) ||
		strings.ContainsAny(content, "\r\n\x00") {
		return errors.New("database DSN credential is invalid")
	}
	return nil
}
