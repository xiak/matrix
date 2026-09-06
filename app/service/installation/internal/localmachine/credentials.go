package localmachine

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

const maximumCredentialFile = 16 * 1024

// Recovery input is an explicitly selected private file, never a directory
// adopted by the installation. Its owned, private parent and exact regular
// file are checked through the existing protected filesystem boundary.
func readCredentialRecoveryInput(path string) (platformcommand.CredentialRecoveryInput, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 ||
		strings.ContainsAny(path, "\x00\r\n") || validateManagedRoot(filepath.Dir(path)) != nil {
		return platformcommand.CredentialRecoveryInput{}, platformcommand.ErrEffectVerification
	}
	content, err := readManagedFile(filepath.Dir(path), filepath.Base(path), platformcommand.MaximumCredentialRecoveryInputBytes)
	if err != nil {
		return platformcommand.CredentialRecoveryInput{}, platformcommand.ErrEffectVerification
	}
	defer clear(content)
	input, err := platformcommand.DecodeCredentialRecoveryInput(content)
	if err != nil {
		return platformcommand.CredentialRecoveryInput{}, platformcommand.ErrEffectVerification
	}
	return input, nil
}

type stagedCredentials struct {
	administrator []byte
	services      map[iamv1.ServicePurpose][]byte
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
	if err := ensureNodeController(plan.Root, plan.InstallationID, plan.Bundle.Manifest.Release.PreviousID == ""); err != nil {
		return err
	}

	credentials, err := ensureIAMBootstrap(plan.Root, plan.InstallationID, entropy)
	if err != nil {
		return err
	}
	defer credentials.clear()
	if err := ensureLocalCredentialRecoveryAuthority(plan.Root, plan.InstallationID, entropy); err != nil {
		return err
	}
	if err := ensureEnrollmentIngress(plan.Root, plan.InstallationID, entropy); err != nil {
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
	cursorKey, err := ensureRandomHex(plan.Root, layout.AuditCursorKey, entropy)
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

func ensureEnrollmentIssuer(root, installationID string, entropy io.Reader) error {
	keyPath := filepath.FromSlash(layout.EnrollmentIssuerPrivateKey)
	certificatePath := filepath.FromSlash(layout.EnrollmentIssuerCertificate)
	keyExists, err := managedFileExists(root, keyPath)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	certificateExists, err := managedFileExists(root, certificatePath)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if !keyExists {
		if certificateExists {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("node enrollment issuer private key is missing"),
			)
		}
		if entropy == nil {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("node enrollment issuer is missing"),
			)
		}
		_, privateKey, err := ed25519.GenerateKey(entropy)
		if err != nil {
			return errors.Join(platformcommand.ErrEffectUnavailable, errors.New("generate node enrollment issuer failed"))
		}
		privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
		clear(privateKey)
		if err != nil {
			return errors.Join(platformcommand.ErrEffectUnavailable, errors.New("encode node enrollment issuer failed"))
		}
		if err := writeManagedOnce(root, keyPath, privateKeyDER); err != nil {
			clear(privateKeyDER)
			return errors.Join(platformcommand.ErrEffectConflict, err)
		}
		clear(privateKeyDER)
	}
	privateKeyDER, err := readManagedFile(root, keyPath, maximumCredentialFile)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("node enrollment issuer private key is invalid"))
	}
	defer clear(privateKeyDER)
	parsedKey, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	privateKey, ok := parsedKey.(ed25519.PrivateKey)
	if err != nil || !ok || len(privateKey) != ed25519.PrivateKeySize {
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("node enrollment issuer private key is invalid"))
	}
	expectedCertificate, err := enrollmentIssuerCertificate(installationID, privateKey)
	clear(privateKey)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	if !certificateExists {
		if err := writeManagedOnce(root, certificatePath, expectedCertificate); err != nil {
			return errors.Join(platformcommand.ErrEffectConflict, err)
		}
		return nil
	}
	certificate, err := readManagedFile(root, certificatePath, maximumCredentialFile)
	if err != nil || !bytes.Equal(certificate, expectedCertificate) {
		clear(certificate)
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("node enrollment issuer certificate is invalid"),
		)
	}
	clear(certificate)
	return nil
}

func enrollmentIssuerCertificate(installationID string, privateKey ed25519.PrivateKey) ([]byte, error) {
	issuerURI, err := paasv1.NodeEnrollmentIssuerURI(installationID)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("node enrollment issuer identity is invalid")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	serialInput := make([]byte, 0, len(installationID)+len(publicKey)+32)
	serialInput = append(serialInput, "matrix-node-enrollment-issuer/v1\x00"...)
	serialInput = append(serialInput, installationID...)
	serialInput = append(serialInput, publicKey...)
	serialDigest := sha256.Sum256(serialInput)
	clear(serialInput)
	serialNumber := new(big.Int).SetBytes(serialDigest[:20])
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Matrix node enrollment issuer"},
		NotBefore:             time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		URIs:                  []*url.URL{issuerURI},
	}
	certificate, err := x509.CreateCertificate(strings.NewReader(""), template, template, publicKey, privateKey)
	if err != nil {
		return nil, errors.New("encode node enrollment issuer certificate failed")
	}
	return certificate, nil
}

func ensureEnrollmentIngress(root, installationID string, entropy io.Reader) error {
	if err := ensureEnrollmentIssuer(root, installationID, entropy); err != nil {
		return err
	}
	keyPath := filepath.FromSlash(layout.EnrollmentIngressPrivateKey)
	certificatePath := filepath.FromSlash(layout.EnrollmentIngressCertificate)
	keyExists, err := managedFileExists(root, keyPath)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	certificateExists, err := managedFileExists(root, certificatePath)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if !keyExists {
		if certificateExists {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("node enrollment ingress private key is missing"),
			)
		}
		if entropy == nil {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("node enrollment ingress identity is missing"),
			)
		}
		_, privateKey, err := ed25519.GenerateKey(entropy)
		if err != nil {
			return errors.Join(platformcommand.ErrEffectUnavailable, errors.New("generate node enrollment ingress failed"))
		}
		privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
		clear(privateKey)
		if err != nil {
			return errors.Join(platformcommand.ErrEffectUnavailable, errors.New("encode node enrollment ingress failed"))
		}
		encodedKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
		clear(privateKeyDER)
		if len(encodedKey) == 0 {
			return errors.Join(platformcommand.ErrEffectUnavailable, errors.New("encode node enrollment ingress failed"))
		}
		if err := writeManagedOnce(root, keyPath, encodedKey); err != nil {
			clear(encodedKey)
			return errors.Join(platformcommand.ErrEffectConflict, err)
		}
		clear(encodedKey)
	}

	ingressKeyPEM, err := readManagedFile(root, keyPath, maximumCredentialFile)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("node enrollment ingress private key is invalid"))
	}
	defer clear(ingressKeyPEM)
	keyBlock, remaining := pem.Decode(ingressKeyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(remaining) != 0 {
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("node enrollment ingress private key is invalid"))
	}
	defer clear(keyBlock.Bytes)
	parsedIngressKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	ingressPrivateKey, ok := parsedIngressKey.(ed25519.PrivateKey)
	if err != nil || !ok || len(ingressPrivateKey) != ed25519.PrivateKeySize {
		clear(ingressPrivateKey)
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("node enrollment ingress private key is invalid"))
	}
	defer clear(ingressPrivateKey)
	canonicalKeyDER, err := x509.MarshalPKCS8PrivateKey(ingressPrivateKey)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("node enrollment ingress private key is invalid"))
	}
	canonicalKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: canonicalKeyDER})
	clear(canonicalKeyDER)
	if !bytes.Equal(canonicalKeyPEM, ingressKeyPEM) {
		clear(canonicalKeyPEM)
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("node enrollment ingress private key is invalid"))
	}
	clear(canonicalKeyPEM)

	issuerCertificateDER, err := readManagedFile(
		root, filepath.FromSlash(layout.EnrollmentIssuerCertificate), maximumCredentialFile,
	)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("node enrollment issuer certificate is invalid"))
	}
	defer clear(issuerCertificateDER)
	issuerCertificate, err := x509.ParseCertificate(issuerCertificateDER)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("node enrollment issuer certificate is invalid"))
	}
	issuerKeyDER, err := readManagedFile(
		root, filepath.FromSlash(layout.EnrollmentIssuerPrivateKey), maximumCredentialFile,
	)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("node enrollment issuer private key is invalid"))
	}
	defer clear(issuerKeyDER)
	parsedIssuerKey, err := x509.ParsePKCS8PrivateKey(issuerKeyDER)
	issuerPrivateKey, ok := parsedIssuerKey.(ed25519.PrivateKey)
	if err != nil || !ok || len(issuerPrivateKey) != ed25519.PrivateKeySize {
		clear(issuerPrivateKey)
		return errors.Join(platformcommand.ErrEffectVerification, errors.New("node enrollment issuer private key is invalid"))
	}
	defer clear(issuerPrivateKey)
	expectedCertificate, err := enrollmentIngressCertificate(
		installationID, ingressPrivateKey, issuerPrivateKey, issuerCertificate,
	)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(expectedCertificate)
	if !certificateExists {
		if err := writeManagedOnce(root, certificatePath, expectedCertificate); err != nil {
			return errors.Join(platformcommand.ErrEffectConflict, err)
		}
		return nil
	}
	certificate, err := readManagedFile(root, certificatePath, maximumCredentialFile)
	if err != nil || !bytes.Equal(certificate, expectedCertificate) {
		clear(certificate)
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("node enrollment ingress certificate is invalid"),
		)
	}
	clear(certificate)
	return nil
}

func enrollmentIngressCertificate(
	installationID string,
	privateKey ed25519.PrivateKey,
	issuerPrivateKey ed25519.PrivateKey,
	issuerCertificate *x509.Certificate,
) ([]byte, error) {
	serverName, err := paasv1.NodeEnrollmentIngressServerName(installationID)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize ||
		len(issuerPrivateKey) != ed25519.PrivateKeySize || issuerCertificate == nil {
		return nil, errors.New("node enrollment ingress identity is invalid")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	issuerPublicKey, ok := issuerCertificate.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(issuerPrivateKey.Public().(ed25519.PublicKey), issuerPublicKey) ||
		issuerCertificate.CheckSignatureFrom(issuerCertificate) != nil {
		return nil, errors.New("node enrollment ingress issuer is invalid")
	}
	serialInput := make([]byte, 0, len(installationID)+len(publicKey)+32)
	serialInput = append(serialInput, "matrix-node-enrollment-ingress-certificate/v1\x00"...)
	serialInput = append(serialInput, installationID...)
	serialInput = append(serialInput, publicKey...)
	serialDigest := sha256.Sum256(serialInput)
	clear(serialInput)
	serialNumber := new(big.Int).SetBytes(serialDigest[:20])
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Matrix node enrollment ingress"},
		NotBefore:             issuerCertificate.NotBefore,
		NotAfter:              issuerCertificate.NotAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{serverName},
	}
	certificateDER, err := x509.CreateCertificate(
		strings.NewReader(""), template, issuerCertificate, publicKey, issuerPrivateKey,
	)
	if err != nil {
		return nil, errors.New("encode node enrollment ingress certificate failed")
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	clear(certificateDER)
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerCertificate.Raw})
	if len(certificatePEM) == 0 || len(issuerPEM) == 0 {
		clear(certificatePEM)
		clear(issuerPEM)
		return nil, errors.New("encode node enrollment ingress certificate failed")
	}
	certificatePEM = append(certificatePEM, issuerPEM...)
	clear(issuerPEM)
	return certificatePEM, nil
}

func ensureNodeController(root, installationID string, allowCreate bool) error {
	exists, err := managedFileExists(root, filepath.FromSlash(layout.NodeControllerConfiguration))
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if exists {
		configuration, encoded, err := readNodeController(root, installationID)
		configuration.Clear()
		clear(encoded)
		return err
	}
	if !allowCreate {
		return platformcommand.ErrEffectVerification
	}
	encoded, err := nodeconfig.EncodeController(nodeconfig.EmptyController(installationID))
	if err != nil {
		return platformcommand.ErrEffectVerification
	}
	return writeManagedOnce(root, filepath.FromSlash(layout.NodeControllerConfiguration), encoded)
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

// The local issuing key is installation-owned, not a service credential or
// caller-selected recovery target. Replay preserves it and the bootstrap bytes.
func ensureLocalCredentialRecoveryAuthority(root, installationID string, entropy io.Reader) error {
	scope, err := localCredentialRecoveryScope(root, installationID)
	if err != nil {
		return err
	}
	exists, err := managedFileExists(root, filepath.FromSlash(layout.IAMLocalRecoveryAuthority))
	if err != nil {
		return platformcommand.ErrEffectVerification
	}
	if exists {
		_, err := readLocalCredentialRecoveryAuthority(root, installationID)
		return err
	}
	key, err := randomCredential(entropy, "", false)
	if err != nil {
		return platformcommand.ErrEffectUnavailable
	}
	secret, err := iamv1.NewSecret(key)
	key = ""
	if err != nil {
		return platformcommand.ErrEffectVerification
	}
	authority := iamv1.LocalCredentialRecoveryAuthority{
		APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryAuthority",
		Purpose: iamv1.LocalCredentialRecoveryPurpose, Scope: scope, CapabilityKey: secret,
	}
	encoded, err := iamv1.EncodeLocalCredentialRecoveryAuthority(authority)
	if err != nil {
		return platformcommand.ErrEffectVerification
	}
	defer clear(encoded)
	if writeManagedOnce(root, filepath.FromSlash(layout.IAMLocalRecoveryAuthority), encoded) != nil {
		return platformcommand.ErrEffectConflict
	}
	return nil
}

func readLocalCredentialRecoveryAuthority(root, installationID string) (iamv1.LocalCredentialRecoveryAuthority, error) {
	scope, err := localCredentialRecoveryScope(root, installationID)
	if err != nil {
		return iamv1.LocalCredentialRecoveryAuthority{}, err
	}
	encoded, err := readManagedFile(root, filepath.FromSlash(layout.IAMLocalRecoveryAuthority), iamv1.MaxLocalCredentialRecoveryBytes)
	if err != nil {
		return iamv1.LocalCredentialRecoveryAuthority{}, platformcommand.ErrEffectVerification
	}
	defer clear(encoded)
	authority, err := iamv1.DecodeLocalCredentialRecoveryAuthority(bytes.NewReader(encoded))
	if err != nil || authority.Scope != scope {
		return iamv1.LocalCredentialRecoveryAuthority{}, platformcommand.ErrEffectVerification
	}
	return authority, nil
}

func localCredentialRecoveryScope(root, installationID string) (iamv1.LocalCredentialRecoveryScope, error) {
	encoded, err := readManagedFile(root, filepath.FromSlash(layout.IAMBootstrap), maximumCredentialFile)
	if err != nil {
		return iamv1.LocalCredentialRecoveryScope{}, platformcommand.ErrEffectVerification
	}
	defer clear(encoded)
	document, err := iamv1.DecodeBootstrapDocument(bytes.NewReader(encoded))
	if err != nil || document.InstallationID != installationID {
		return iamv1.LocalCredentialRecoveryScope{}, platformcommand.ErrEffectVerification
	}
	digest, err := iamv1.BootstrapDigest(document)
	if err != nil {
		return iamv1.LocalCredentialRecoveryScope{}, platformcommand.ErrEffectVerification
	}
	return iamv1.LocalCredentialRecoveryScope{
		InstallationID: document.InstallationID, BootstrapDigest: digest,
		OrganizationID: document.Organization.ID, PrincipalID: document.Administrator.ID,
	}, nil
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
