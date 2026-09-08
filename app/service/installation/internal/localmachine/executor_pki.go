package localmachine

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"path/filepath"
	"time"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/topology"
)

const (
	executorPKIAPIVersion = "installation.matrix.xiak.com/v1"
	executorPKIKind       = "DevOpsExecutorPKI"
	executorPKILifetime   = 5
	executorPKISkew       = 5 * time.Minute
	maximumExecutorPKI    = 256 * 1024
)

type executorKeyPair struct {
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"privateKey"`
}

type executorPKIBundle struct {
	APIVersion      string          `json:"apiVersion"`
	Kind            string          `json:"kind"`
	InstallationID  string          `json:"installationId"`
	IssuedAt        time.Time       `json:"issuedAt"`
	NotBefore       time.Time       `json:"notBefore"`
	NotAfter        time.Time       `json:"notAfter"`
	ServerAuthority executorKeyPair `json:"serverAuthority"`
	GatewayServer   executorKeyPair `json:"gatewayServer"`
	AdminAuthority  executorKeyPair `json:"adminAuthority"`
	BuildWorker     executorKeyPair `json:"buildWorker"`
	RunnerAuthority executorKeyPair `json:"runnerAuthority"`
}

type executorPKIFile struct {
	path    string
	content []byte
}

func ensureDevOpsExecutorPKI(
	plan platformcommand.InstallPlan,
	entropy io.Reader,
) error {
	if entropy == nil {
		return errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("DevOps executor PKI entropy is unavailable"),
		)
	}
	bundlePath := filepath.FromSlash(layout.DevOpsExecutorPKIBundle)
	exists, err := managedFileExists(plan.Root, bundlePath)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	var bundle executorPKIBundle
	if exists {
		content, readErr := readManagedFile(plan.Root, bundlePath, maximumExecutorPKI)
		if readErr != nil {
			return errors.Join(platformcommand.ErrEffectVerification, readErr)
		}
		bundle, err = decodeExecutorPKIBundle(content, plan.InstallationID)
		clear(content)
		if err != nil {
			return errors.Join(platformcommand.ErrEffectVerification, err)
		}
	} else {
		bundle, err = generateExecutorPKIBundle(
			plan.InstallationID,
			plan.CommandStartedAt,
			entropy,
		)
		if err != nil {
			return err
		}
		encoded, encodeErr := encodeExecutorPKIBundle(bundle)
		if encodeErr != nil {
			bundle.clear()
			return errors.Join(platformcommand.ErrEffectVerification, encodeErr)
		}
		if writeErr := writeManagedOnce(plan.Root, bundlePath, encoded); writeErr != nil {
			clear(encoded)
			bundle.clear()
			return errors.Join(platformcommand.ErrEffectConflict, writeErr)
		}
		clear(encoded)
	}
	defer bundle.clear()
	for _, file := range bundle.runtimeFiles() {
		if err := writeManagedOnce(
			plan.Root,
			filepath.FromSlash(file.path),
			file.content,
		); err != nil {
			return errors.Join(platformcommand.ErrEffectConflict, err)
		}
	}
	return nil
}

func generateExecutorPKIBundle(
	installationID string,
	commandStartedAt time.Time,
	entropy io.Reader,
) (executorPKIBundle, error) {
	issuedAt := commandStartedAt.UTC().Truncate(time.Second)
	if entropy == nil || lifecycle.ValidateInstallationID(installationID) != nil ||
		commandStartedAt.IsZero() || commandStartedAt.Location() != time.UTC ||
		commandStartedAt != commandStartedAt.Truncate(time.Microsecond) ||
		issuedAt.IsZero() {
		return executorPKIBundle{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("DevOps executor PKI issuance plan is invalid"),
		)
	}
	bundle := executorPKIBundle{
		APIVersion:     executorPKIAPIVersion,
		Kind:           executorPKIKind,
		InstallationID: installationID,
		IssuedAt:       issuedAt,
		NotBefore:      issuedAt.Add(-executorPKISkew),
		NotAfter:       issuedAt.AddDate(executorPKILifetime, 0, 0),
	}
	var serverCA, adminCA *x509.Certificate
	var serverKey, adminKey *ecdsa.PrivateKey
	var err error
	bundle.ServerAuthority, serverCA, serverKey, err = generateExecutorAuthority(
		installationID, "server", bundle, entropy,
	)
	if err == nil {
		bundle.AdminAuthority, adminCA, adminKey, err = generateExecutorAuthority(
			installationID, "admin", bundle, entropy,
		)
	}
	if err == nil {
		bundle.RunnerAuthority, _, _, err = generateExecutorAuthority(
			installationID, "runner", bundle, entropy,
		)
	}
	if err == nil {
		bundle.GatewayServer, err = generateExecutorLeaf(
			installationID,
			"gateway-server",
			bundle,
			serverCA,
			serverKey,
			x509.ExtKeyUsageServerAuth,
			topology.DevOpsExecutorGatewayServerName,
			"",
			entropy,
		)
	}
	if err == nil {
		bundle.BuildWorker, err = generateExecutorLeaf(
			installationID,
			"build-worker",
			bundle,
			adminCA,
			adminKey,
			x509.ExtKeyUsageClientAuth,
			"",
			topology.DevOpsBuildWorkerIdentity(installationID),
			entropy,
		)
	}
	if err != nil {
		bundle.clear()
		return executorPKIBundle{}, errors.Join(
			platformcommand.ErrEffectUnavailable,
			errors.New("DevOps executor PKI cannot be generated"),
		)
	}
	if err := validateExecutorPKIBundle(bundle, installationID); err != nil {
		bundle.clear()
		return executorPKIBundle{}, errors.Join(platformcommand.ErrEffectVerification, err)
	}
	return bundle, nil
}

func generateExecutorAuthority(
	installationID string,
	role string,
	bundle executorPKIBundle,
	entropy io.Reader,
) (executorKeyPair, *x509.Certificate, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), entropy)
	if err != nil {
		return executorKeyPair{}, nil, nil, err
	}
	keyID, err := executorKeyID(&privateKey.PublicKey)
	if err != nil {
		return executorKeyPair{}, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          executorCertificateSerial(installationID, role, bundle.IssuedAt),
		Subject:               executorCertificateSubject(installationID, role),
		NotBefore:             bundle.NotBefore,
		NotAfter:              bundle.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          keyID,
		AuthorityKeyId:        append([]byte(nil), keyID...),
	}
	encoded, err := x509.CreateCertificate(
		entropy, template, template, &privateKey.PublicKey, privateKey,
	)
	if err != nil {
		return executorKeyPair{}, nil, nil, err
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		return executorKeyPair{}, nil, nil, err
	}
	pair, err := encodeExecutorKeyPair(encoded, nil, privateKey)
	if err != nil {
		return executorKeyPair{}, nil, nil, err
	}
	return pair, certificate, privateKey, nil
}

func generateExecutorLeaf(
	installationID string,
	role string,
	bundle executorPKIBundle,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	usage x509.ExtKeyUsage,
	dnsName string,
	uriIdentity string,
	entropy io.Reader,
) (executorKeyPair, error) {
	if issuer == nil || issuerKey == nil {
		return executorKeyPair{}, errors.New("executor leaf issuer is unavailable")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), entropy)
	if err != nil {
		return executorKeyPair{}, err
	}
	keyID, err := executorKeyID(&privateKey.PublicKey)
	if err != nil {
		return executorKeyPair{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          executorCertificateSerial(installationID, role, bundle.IssuedAt),
		Subject:               executorCertificateSubject(installationID, role),
		NotBefore:             bundle.NotBefore,
		NotAfter:              bundle.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
		SubjectKeyId:          keyID,
		AuthorityKeyId:        append([]byte(nil), issuer.SubjectKeyId...),
	}
	if dnsName != "" {
		template.DNSNames = []string{dnsName}
	}
	if uriIdentity != "" {
		identity, parseErr := url.Parse(uriIdentity)
		if parseErr != nil || identity.String() != uriIdentity {
			return executorKeyPair{}, errors.New("executor leaf identity is invalid")
		}
		template.URIs = []*url.URL{identity}
	}
	encoded, err := x509.CreateCertificate(
		entropy, template, issuer, &privateKey.PublicKey, issuerKey,
	)
	if err != nil {
		return executorKeyPair{}, err
	}
	return encodeExecutorKeyPair(encoded, issuer.Raw, privateKey)
}

func encodeExecutorKeyPair(
	leaf []byte,
	issuer []byte,
	privateKey *ecdsa.PrivateKey,
) (executorKeyPair, error) {
	encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return executorKeyPair{}, err
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	if len(issuer) > 0 {
		certificate = append(
			certificate,
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer})...,
		)
	}
	return executorKeyPair{
		Certificate: certificate,
		PrivateKey: pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: encodedKey,
		}),
	}, nil
}

func executorKeyID(publicKey *ecdsa.PublicKey) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return append([]byte(nil), digest[:20]...), nil
}

func executorCertificateSerial(
	installationID string,
	role string,
	issuedAt time.Time,
) *big.Int {
	digest := sha256.Sum256([]byte(
		executorPKIAPIVersion + "\x00" + installationID + "\x00" + role + "\x00" +
			issuedAt.Format(time.RFC3339),
	))
	serial := append([]byte(nil), digest[:20]...)
	serial[0] &= 0x7f
	value := new(big.Int).SetBytes(serial)
	if value.Sign() == 0 {
		value.SetInt64(1)
	}
	return value
}

func executorCertificateSubject(installationID string, role string) pkix.Name {
	return pkix.Name{
		Organization: []string{"Matrix"},
		CommonName:   "Matrix DevOps " + role + " " + installationID,
	}
}

func encodeExecutorPKIBundle(bundle executorPKIBundle) ([]byte, error) {
	if err := validateExecutorPKIBundle(bundle, bundle.InstallationID); err != nil {
		return nil, err
	}
	return json.Marshal(bundle)
}

func decodeExecutorPKIBundle(
	content []byte,
	installationID string,
) (executorPKIBundle, error) {
	if len(content) == 0 || len(content) > maximumExecutorPKI {
		return executorPKIBundle{}, errors.New("stored DevOps executor PKI is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var bundle executorPKIBundle
	if err := decoder.Decode(&bundle); err != nil {
		return executorPKIBundle{}, errors.New("stored DevOps executor PKI is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		bundle.clear()
		return executorPKIBundle{}, errors.New("stored DevOps executor PKI is invalid")
	}
	canonical, err := json.Marshal(bundle)
	if err != nil || !bytes.Equal(canonical, content) {
		clear(canonical)
		bundle.clear()
		return executorPKIBundle{}, errors.New("stored DevOps executor PKI is not canonical")
	}
	clear(canonical)
	if err := validateExecutorPKIBundle(bundle, installationID); err != nil {
		bundle.clear()
		return executorPKIBundle{}, err
	}
	return bundle, nil
}

func validateExecutorPKIBundle(bundle executorPKIBundle, installationID string) error {
	if bundle.APIVersion != executorPKIAPIVersion || bundle.Kind != executorPKIKind ||
		bundle.InstallationID != installationID ||
		lifecycle.ValidateInstallationID(installationID) != nil ||
		!canonicalExecutorPKITime(bundle.IssuedAt) ||
		!canonicalExecutorPKITime(bundle.NotBefore) ||
		!canonicalExecutorPKITime(bundle.NotAfter) ||
		bundle.NotBefore != bundle.IssuedAt.Add(-executorPKISkew) ||
		bundle.NotAfter != bundle.IssuedAt.AddDate(executorPKILifetime, 0, 0) {
		return errors.New("DevOps executor PKI identity or lifetime is invalid")
	}
	serverCA, serverFingerprint, err := validateExecutorAuthority(
		bundle.ServerAuthority, bundle, installationID, "server",
	)
	if err != nil {
		return err
	}
	adminCA, adminFingerprint, err := validateExecutorAuthority(
		bundle.AdminAuthority, bundle, installationID, "admin",
	)
	if err != nil {
		return err
	}
	_, runnerFingerprint, err := validateExecutorAuthority(
		bundle.RunnerAuthority, bundle, installationID, "runner",
	)
	if err != nil {
		return err
	}
	if serverFingerprint == adminFingerprint || serverFingerprint == runnerFingerprint ||
		adminFingerprint == runnerFingerprint {
		return errors.New("DevOps executor PKI role authorities overlap")
	}
	if err := validateExecutorLeaf(
		bundle.GatewayServer,
		bundle,
		installationID,
		"gateway-server",
		serverCA,
		x509.ExtKeyUsageServerAuth,
		topology.DevOpsExecutorGatewayServerName,
		"",
	); err != nil {
		return err
	}
	return validateExecutorLeaf(
		bundle.BuildWorker,
		bundle,
		installationID,
		"build-worker",
		adminCA,
		x509.ExtKeyUsageClientAuth,
		"",
		topology.DevOpsBuildWorkerIdentity(installationID),
	)
}

func validateExecutorAuthority(
	pair executorKeyPair,
	bundle executorPKIBundle,
	installationID string,
	role string,
) (*x509.Certificate, [sha256.Size]byte, error) {
	blocks, err := canonicalExecutorCertificateBlocks(pair.Certificate)
	if err != nil || len(blocks) != 1 || !canonicalExecutorPrivateKey(pair.PrivateKey) {
		return nil, [sha256.Size]byte{}, errors.New("DevOps executor authority is invalid")
	}
	certificate, err := x509.ParseCertificate(blocks[0].Bytes)
	keyPair, pairErr := tls.X509KeyPair(pair.Certificate, pair.PrivateKey)
	privateKey, keyOK := keyPair.PrivateKey.(*ecdsa.PrivateKey)
	if err != nil || pairErr != nil || !keyOK || privateKey.Curve != elliptic.P256() ||
		certificate.Subject.String() != executorCertificateSubject(installationID, role).String() ||
		certificate.SerialNumber.Cmp(
			executorCertificateSerial(installationID, role, bundle.IssuedAt),
		) != 0 ||
		!certificate.IsCA || !certificate.BasicConstraintsValid ||
		!certificate.MaxPathLenZero || certificate.MaxPathLen != 0 ||
		certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign ||
		len(certificate.ExtKeyUsage) != 0 || certificate.NotBefore != bundle.NotBefore ||
		certificate.NotAfter != bundle.NotAfter || certificate.CheckSignatureFrom(certificate) != nil ||
		len(certificate.DNSNames) != 0 || len(certificate.URIs) != 0 ||
		len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 ||
		len(certificate.UnhandledCriticalExtensions) != 0 {
		return nil, [sha256.Size]byte{}, errors.New("DevOps executor authority is invalid")
	}
	return certificate, sha256.Sum256(certificate.RawSubjectPublicKeyInfo), nil
}

func validateExecutorLeaf(
	pair executorKeyPair,
	bundle executorPKIBundle,
	installationID string,
	role string,
	issuer *x509.Certificate,
	usage x509.ExtKeyUsage,
	dnsName string,
	uriIdentity string,
) error {
	blocks, err := canonicalExecutorCertificateBlocks(pair.Certificate)
	if err != nil || len(blocks) != 2 || issuer == nil ||
		!bytes.Equal(blocks[1].Bytes, issuer.Raw) ||
		!canonicalExecutorPrivateKey(pair.PrivateKey) {
		return errors.New("DevOps executor leaf identity is invalid")
	}
	certificate, err := x509.ParseCertificate(blocks[0].Bytes)
	keyPair, pairErr := tls.X509KeyPair(pair.Certificate, pair.PrivateKey)
	privateKey, keyOK := keyPair.PrivateKey.(*ecdsa.PrivateKey)
	if err != nil || pairErr != nil || !keyOK || privateKey.Curve != elliptic.P256() ||
		certificate.Subject.String() != executorCertificateSubject(installationID, role).String() ||
		certificate.SerialNumber.Cmp(
			executorCertificateSerial(installationID, role, bundle.IssuedAt),
		) != 0 || certificate.IsCA || !certificate.BasicConstraintsValid ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != usage ||
		certificate.NotBefore != bundle.NotBefore || certificate.NotAfter != bundle.NotAfter ||
		certificate.CheckSignatureFrom(issuer) != nil ||
		len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 ||
		len(certificate.UnhandledCriticalExtensions) != 0 {
		return errors.New("DevOps executor leaf identity is invalid")
	}
	if dnsName != "" {
		if len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != dnsName ||
			len(certificate.URIs) != 0 || certificate.VerifyHostname(dnsName) != nil {
			return errors.New("DevOps executor server identity is invalid")
		}
	} else if len(certificate.DNSNames) != 0 || len(certificate.URIs) != 1 ||
		certificate.URIs[0].String() != uriIdentity {
		return errors.New("DevOps executor client identity is invalid")
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	_, err = certificate.Verify(x509.VerifyOptions{
		DNSName:     dnsName,
		Roots:       roots,
		CurrentTime: bundle.IssuedAt,
		KeyUsages:   []x509.ExtKeyUsage{usage},
	})
	if err != nil {
		return errors.New("DevOps executor certificate chain is invalid")
	}
	return nil
}

func canonicalExecutorCertificateBlocks(content []byte) ([]*pem.Block, error) {
	if len(content) == 0 {
		return nil, errors.New("executor certificate is empty")
	}
	remaining := content
	blocks := make([]*pem.Block, 0, 2)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
			!bytes.HasPrefix(remaining, pem.EncodeToMemory(block)) {
			return nil, errors.New("executor certificate is not canonical")
		}
		blocks = append(blocks, block)
		remaining = rest
	}
	return blocks, nil
}

func canonicalExecutorPrivateKey(content []byte) bool {
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 ||
		len(rest) != 0 || !bytes.Equal(content, pem.EncodeToMemory(block)) {
		return false
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	privateKey, ok := key.(*ecdsa.PrivateKey)
	return err == nil && ok && privateKey.Curve == elliptic.P256()
}

func canonicalExecutorPKITime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value == value.Truncate(time.Second)
}

func (bundle executorPKIBundle) runtimeFiles() []executorPKIFile {
	return []executorPKIFile{
		{path: layout.DevOpsExecutorServerCA, content: bundle.ServerAuthority.Certificate},
		{path: layout.DevOpsExecutorServerCert, content: bundle.GatewayServer.Certificate},
		{path: layout.DevOpsExecutorServerKey, content: bundle.GatewayServer.PrivateKey},
		{path: layout.DevOpsExecutorAdminCA, content: bundle.AdminAuthority.Certificate},
		{path: layout.DevOpsExecutorRunnerCA, content: bundle.RunnerAuthority.Certificate},
		{path: layout.DevOpsBuildWorkerClientCert, content: bundle.BuildWorker.Certificate},
		{path: layout.DevOpsBuildWorkerClientKey, content: bundle.BuildWorker.PrivateKey},
	}
}

func (pair *executorKeyPair) clear() {
	if pair == nil {
		return
	}
	clear(pair.Certificate)
	clear(pair.PrivateKey)
	pair.Certificate = nil
	pair.PrivateKey = nil
}

func (bundle *executorPKIBundle) clear() {
	if bundle == nil {
		return
	}
	bundle.ServerAuthority.clear()
	bundle.GatewayServer.clear()
	bundle.AdminAuthority.clear()
	bundle.BuildWorker.clear()
	bundle.RunnerAuthority.clear()
}
