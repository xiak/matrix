// Package sourcetrust owns the portable, endpoint-bound CA bundle contract
// shared by the installer and the DevOps source runtimes.
package sourcetrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"sort"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	BundleFilename      = "roots.pem"
	MaximumBundleBytes  = 256 * 1024
	MaximumCertificates = 16
)

// Canonicalize validates a bounded bundle and returns its deterministic PEM
// representation. A non-zero observedAt additionally requires every root to
// be valid at that instant.
func Canonicalize(content []byte, observedAt time.Time) ([]byte, error) {
	certificates, err := parse(content, observedAt)
	if err != nil {
		return nil, err
	}
	sort.Slice(certificates, func(left, right int) bool {
		return bytes.Compare(certificates[left].Raw, certificates[right].Raw) < 0
	})
	canonical := make([]byte, 0, len(content))
	for _, certificate := range certificates {
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: certificate.Raw,
		})...)
	}
	if len(canonical) == 0 || len(canonical) > MaximumBundleBytes {
		clear(canonical)
		return nil, errors.New("source trust bundle exceeds its bound")
	}
	return canonical, nil
}

// CertPool accepts only the canonical representation and returns a pool that
// contains no ambient system roots.
func CertPool(content []byte, observedAt time.Time) (*x509.CertPool, error) {
	canonical, err := Canonicalize(content, observedAt)
	if err != nil {
		return nil, err
	}
	defer clear(canonical)
	if !bytes.Equal(content, canonical) {
		return nil, errors.New("source trust bundle is not canonical")
	}
	certificates, err := parse(canonical, observedAt)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool, nil
}

// DirectoryName binds one custom trust pool to one tenant and exact canonical
// endpoint origin. The digest is configuration metadata, not a secret.
func DirectoryName(scope devopsv1.ResourceScope, endpointOrigin string) (string, error) {
	if err := errors.Join(
		devopsv1.ValidateResourceScope(scope),
		devopsv1.ValidateEndpointOrigin(endpointOrigin),
	); err != nil {
		return "", errors.New("source trust identity is invalid")
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("matrix-devops-source-trust-directory-v1"))
	writeFramed(digest, string(scope.TenantID))
	writeFramed(digest, endpointOrigin)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func parse(content []byte, observedAt time.Time) ([]*x509.Certificate, error) {
	if len(content) == 0 || len(content) > MaximumBundleBytes ||
		!observedAt.IsZero() && observedAt.Location() != time.UTC {
		return nil, errors.New("source trust bundle is invalid")
	}
	remaining := content
	certificates := make([]*x509.Certificate, 0, 1)
	seen := make(map[[sha256.Size]byte]struct{})
	for len(remaining) != 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("source trust bundle has non-certificate content")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
			len(certificates) == MaximumCertificates {
			return nil, errors.New("source trust bundle is invalid")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			!bytes.Equal(certificate.RawIssuer, certificate.RawSubject) ||
			len(certificate.UnhandledCriticalExtensions) != 0 ||
			certificate.CheckSignatureFrom(certificate) != nil ||
			!observedAt.IsZero() &&
				(observedAt.Before(certificate.NotBefore) || !observedAt.Before(certificate.NotAfter)) {
			return nil, errors.New("source trust certificate is invalid")
		}
		fingerprint := sha256.Sum256(certificate.Raw)
		if _, duplicate := seen[fingerprint]; duplicate {
			return nil, errors.New("source trust certificate is duplicated")
		}
		seen[fingerprint] = struct{}{}
		certificates = append(certificates, certificate)
		remaining = rest
	}
	if len(certificates) == 0 {
		return nil, errors.New("source trust bundle is empty")
	}
	return certificates, nil
}

func writeFramed(digest interface{ Write([]byte) (int, error) }, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = digest.Write(size[:])
	_, _ = digest.Write([]byte(value))
}
