// Package processmtls loads strict, file-backed mTLS client material for
// independently composed Matrix processes.
package processmtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/xiak/matrix/app/service/internal/processconfig"
)

const (
	maximumCertificateBytes = 1024 * 1024
	maximumPrivateKeyBytes  = 256 * 1024
	maximumCertificateChain = 8
	maximumServerRoots      = 8
)

var ErrInvalidClientMaterial = errors.New("process mTLS client material is invalid")

type ClientCredentials struct {
	Certificate tls.Certificate
	ServerRoots *x509.CertPool
}

func LoadClientCredentials(
	certificatePath string,
	privateKeyPath string,
	serverRootsPath string,
	expectedSPIFFEIdentity string,
	now time.Time,
) (ClientCredentials, error) {
	return loadClientCredentials(
		func(path string, maximum int64, secret bool) ([]byte, error) {
			return processconfig.ReadFile(path, maximum, secret)
		},
		certificatePath, privateKeyPath, serverRootsPath, expectedSPIFFEIdentity, now,
	)
}

func LoadSystemdClientCredentials(
	credentialDirectory string,
	certificateName string,
	privateKeyName string,
	serverRootsName string,
	expectedSPIFFEIdentity string,
	now time.Time,
) (ClientCredentials, error) {
	return loadClientCredentials(
		func(name string, maximum int64, secret bool) ([]byte, error) {
			return processconfig.ReadSystemdCredential(
				credentialDirectory, name, maximum, secret,
			)
		},
		certificateName, privateKeyName, serverRootsName, expectedSPIFFEIdentity, now,
	)
}

func loadClientCredentials(
	read func(string, int64, bool) ([]byte, error),
	certificateSource string,
	privateKeySource string,
	serverRootsSource string,
	expectedSPIFFEIdentity string,
	now time.Time,
) (ClientCredentials, error) {
	if read == nil || now.IsZero() || strictSPIFFEIdentity(expectedSPIFFEIdentity) == nil {
		return ClientCredentials{}, ErrInvalidClientMaterial
	}
	certificatePEM, err := read(
		certificateSource, maximumCertificateBytes, false,
	)
	if err != nil {
		return ClientCredentials{}, ErrInvalidClientMaterial
	}
	privateKeyPEM, err := read(
		privateKeySource, maximumPrivateKeyBytes, true,
	)
	if err != nil {
		return ClientCredentials{}, ErrInvalidClientMaterial
	}
	defer clear(privateKeyPEM)
	serverRootsPEM, err := read(
		serverRootsSource, maximumCertificateBytes, false,
	)
	if err != nil {
		return ClientCredentials{}, ErrInvalidClientMaterial
	}

	certificateBlocks, err := decodeCanonicalPEM(certificatePEM, "CERTIFICATE")
	if err != nil || len(certificateBlocks) == 0 ||
		len(certificateBlocks) > maximumCertificateChain {
		return ClientCredentials{}, ErrInvalidClientMaterial
	}
	keyBlocks, err := decodeCanonicalPrivateKeyPEM(privateKeyPEM)
	if err != nil || len(keyBlocks) != 1 {
		return ClientCredentials{}, ErrInvalidClientMaterial
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) != len(certificateBlocks) {
		return ClientCredentials{}, ErrInvalidClientMaterial
	}
	chain, err := validateClientChain(
		certificate.Certificate, expectedSPIFFEIdentity, now,
	)
	if err != nil {
		return ClientCredentials{}, ErrInvalidClientMaterial
	}
	certificate.Leaf = chain[0]
	serverRoots, err := decodeServerRoots(serverRootsPEM, now)
	if err != nil {
		return ClientCredentials{}, ErrInvalidClientMaterial
	}
	return ClientCredentials{Certificate: certificate, ServerRoots: serverRoots}, nil
}

func validateClientChain(
	encodedChain [][]byte,
	expectedIdentity string,
	now time.Time,
) ([]*x509.Certificate, error) {
	if len(encodedChain) == 0 || len(encodedChain) > maximumCertificateChain {
		return nil, ErrInvalidClientMaterial
	}
	chain := make([]*x509.Certificate, len(encodedChain))
	seen := make(map[[sha256.Size]byte]struct{}, len(encodedChain))
	for index, encoded := range encodedChain {
		certificate, err := x509.ParseCertificate(encoded)
		fingerprint := sha256.Sum256(encoded)
		_, duplicate := seen[fingerprint]
		if err != nil || duplicate || len(certificate.UnhandledCriticalExtensions) != 0 {
			return nil, ErrInvalidClientMaterial
		}
		chain[index] = certificate
		seen[fingerprint] = struct{}{}
	}
	leaf := chain[0]
	if leaf.IsCA || !now.After(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() != expectedIdentity ||
		len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 ||
		len(leaf.IPAddresses) != 0 {
		return nil, ErrInvalidClientMaterial
	}
	for index := 0; index+1 < len(chain); index++ {
		issuer := chain[index+1]
		if !issuer.IsCA || !issuer.BasicConstraintsValid ||
			issuer.KeyUsage&x509.KeyUsageCertSign == 0 ||
			!now.After(issuer.NotBefore) || !now.Before(issuer.NotAfter) ||
			chain[index].CheckSignatureFrom(issuer) != nil {
			return nil, ErrInvalidClientMaterial
		}
	}
	return chain, nil
}

func decodeServerRoots(content []byte, now time.Time) (*x509.CertPool, error) {
	blocks, err := decodeCanonicalPEM(content, "CERTIFICATE")
	if err != nil || len(blocks) == 0 || len(blocks) > maximumServerRoots {
		return nil, ErrInvalidClientMaterial
	}
	pool := x509.NewCertPool()
	seen := make(map[[sha256.Size]byte]struct{}, len(blocks))
	for _, block := range blocks {
		certificate, err := x509.ParseCertificate(block.Bytes)
		var fingerprint [sha256.Size]byte
		if err == nil {
			fingerprint = sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
		}
		_, duplicate := seen[fingerprint]
		if err != nil || duplicate || !certificate.IsCA ||
			!certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			!now.After(certificate.NotBefore) || !now.Before(certificate.NotAfter) ||
			certificate.CheckSignatureFrom(certificate) != nil ||
			len(certificate.UnhandledCriticalExtensions) != 0 {
			return nil, ErrInvalidClientMaterial
		}
		seen[fingerprint] = struct{}{}
		pool.AddCert(certificate)
	}
	if len(pool.Subjects()) != len(blocks) {
		return nil, ErrInvalidClientMaterial
	}
	return pool, nil
}

func strictSPIFFEIdentity(value string) *url.URL {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "spiffe" || parsed.Host == "" ||
		parsed.Host != strings.ToLower(parsed.Host) || parsed.Port() != "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Path == "" || parsed.Path == "/" || path.Clean(parsed.Path) != parsed.Path ||
		parsed.String() != value {
		return nil
	}
	return parsed
}

func decodeCanonicalPEM(content []byte, blockType string) ([]*pem.Block, error) {
	if len(content) == 0 || blockType == "" {
		return nil, ErrInvalidClientMaterial
	}
	remaining := content
	blocks := make([]*pem.Block, 0, 2)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != blockType || len(block.Headers) != 0 ||
			!bytes.HasPrefix(remaining, pem.EncodeToMemory(block)) {
			return nil, ErrInvalidClientMaterial
		}
		blocks = append(blocks, block)
		remaining = rest
	}
	return blocks, nil
}

func decodeCanonicalPrivateKeyPEM(content []byte) ([]*pem.Block, error) {
	for _, blockType := range []string{"PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"} {
		blocks, err := decodeCanonicalPEM(content, blockType)
		if err == nil {
			return blocks, nil
		}
	}
	return nil, ErrInvalidClientMaterial
}
