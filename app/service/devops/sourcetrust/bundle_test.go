package sourcetrust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestCanonicalBundleAndCustomOnlyPool(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	first := newTestRoot(t, 1, now.Add(-time.Hour), now.Add(time.Hour))
	second := newTestRoot(t, 2, now.Add(-time.Hour), now.Add(time.Hour))
	input := append(append([]byte(nil), second...), first...)

	canonical, err := Canonicalize(input, now)
	if err != nil {
		t.Fatalf("Canonicalize() error = %v", err)
	}
	firstDER := testDER(t, first)
	secondDER := testDER(t, second)
	expectedFirst := firstDER
	if bytes.Compare(secondDER, firstDER) < 0 {
		expectedFirst = secondDER
	}
	firstBlock, _ := pem.Decode(canonical)
	if firstBlock == nil || !bytes.Equal(firstBlock.Bytes, expectedFirst) {
		t.Fatal("Canonicalize() did not sort certificates by DER")
	}
	pool, err := CertPool(canonical, now)
	if err != nil {
		t.Fatalf("CertPool() error = %v", err)
	}
	if len(pool.Subjects()) != 2 {
		t.Fatalf("CertPool() subjects = %d", len(pool.Subjects()))
	}
	if !bytes.Equal(input, canonical) {
		if _, err := CertPool(input, now); err == nil {
			t.Fatal("CertPool() accepted a noncanonical order")
		}
	}
}

func TestBundleRejectsUnsafeCertificateShapes(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	valid := newTestRoot(t, 1, now.Add(-time.Hour), now.Add(time.Hour))
	for name, content := range map[string][]byte{
		"duplicate": append(append([]byte(nil), valid...), valid...),
		"trailing":  append(append([]byte(nil), valid...), '\n'),
		"prefix":    append([]byte("unsafe"), valid...),
		"private-key": pem.EncodeToMemory(&pem.Block{
			Type: "EC PRIVATE KEY", Bytes: []byte("not-a-key"),
		}),
		"expired": newTestRoot(t, 2, now.Add(-2*time.Hour), now.Add(-time.Hour)),
		"future":  newTestRoot(t, 3, now.Add(time.Hour), now.Add(2*time.Hour)),
		"self-key-different-issuer": newTestRootWithDifferentIssuer(
			t, 4, now.Add(-time.Hour), now.Add(time.Hour),
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Canonicalize(content, now); err == nil {
				t.Fatal("Canonicalize() accepted unsafe material")
			}
		})
	}

	expired := newTestRoot(t, 4, now.Add(-2*time.Hour), now.Add(-time.Hour))
	canonical, err := Canonicalize(expired, time.Time{})
	if err != nil {
		t.Fatalf("structural Canonicalize() error = %v", err)
	}
	if _, err := CertPool(canonical, now); err == nil {
		t.Fatal("CertPool() accepted an expired root")
	}
}

func TestDirectoryNameBindsTenantAndCanonicalOrigin(t *testing.T) {
	first, err := DirectoryName(
		devopsv1.ResourceScope{TenantID: "tenant-one"}, "https://git.internal.example:3443",
	)
	if err != nil {
		t.Fatalf("DirectoryName() error = %v", err)
	}
	second, err := DirectoryName(
		devopsv1.ResourceScope{TenantID: "tenant-two"}, "https://git.internal.example:3443",
	)
	if err != nil || first == second || len(first) != 64 {
		t.Fatalf("DirectoryName() tenant binding = %q / %q / %v", first, second, err)
	}
	third, err := DirectoryName(
		devopsv1.ResourceScope{TenantID: "tenant-one"}, "https://git.internal.example:3444",
	)
	if err != nil || first == third {
		t.Fatalf("DirectoryName() origin binding = %q / %q / %v", first, third, err)
	}
	for _, invalid := range []string{
		"http://git.internal.example", "https://git.internal.example/path", "https://localhost",
	} {
		if _, err := DirectoryName(
			devopsv1.ResourceScope{TenantID: "tenant-one"}, invalid,
		); err == nil {
			t.Fatalf("DirectoryName() accepted %q", invalid)
		}
	}
}

func TestBundleEnforcesSizeAndCertificateCount(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	bundle := make([]byte, 0, MaximumCertificates*600)
	for serial := int64(1); serial <= MaximumCertificates; serial++ {
		bundle = append(bundle, newTestRoot(
			t, serial, now.Add(-time.Hour), now.Add(time.Hour),
		)...)
	}
	if _, err := Canonicalize(bundle, now); err != nil {
		t.Fatalf("Canonicalize(maximum certificate count) error = %v", err)
	}
	bundle = append(bundle, newTestRoot(
		t, MaximumCertificates+1, now.Add(-time.Hour), now.Add(time.Hour),
	)...)
	if _, err := Canonicalize(bundle, now); err == nil {
		t.Fatal("Canonicalize() accepted too many certificates")
	}
	if _, err := Canonicalize(make([]byte, MaximumBundleBytes+1), now); err == nil {
		t.Fatal("Canonicalize() accepted an oversized bundle")
	}
}

func newTestRootWithDifferentIssuer(
	t *testing.T,
	serial int64,
	notBefore time.Time,
	notAfter time.Time,
) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Matrix test root"},
		NotBefore: notBefore, NotAfter: notAfter,
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	issuer := *certificate
	issuer.Subject = pkix.Name{CommonName: "different issuer"}
	der, err := x509.CreateCertificate(rand.Reader, certificate, &issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestRoot(t *testing.T, serial int64, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Matrix test root"},
		NotBefore: notBefore, NotAfter: notAfter,
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testDER(t *testing.T, content []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatal("test certificate is invalid")
	}
	return block.Bytes
}
