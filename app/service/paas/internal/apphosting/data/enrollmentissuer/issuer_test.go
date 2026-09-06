package enrollmentissuer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/nodeenrollment"
)

func TestIssueWrapsFreshCredentialAndStoresOnlySaltedVerifier(t *testing.T) {
	issuer := testIssuer(t)
	wrappingKey, wrappingPublic := testWrappingKey(t, 3072)
	request := nodeenrollment.JoinIssueRequest{
		EnrollmentID:      "node-enrollment-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExecutionTargetID: "target-a", ExpiresAt: testTime().Add(15 * time.Minute),
		WrappingPublicKey: wrappingPublic,
	}
	issued, err := issuer.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer issued.Clear()
	if err := nodeenrollment.ValidateIssuedJoin(issued, request); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(issued.WrappedCredential.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	label := []byte("matrix-node-enrollment-v1\x00installation-a\x00" + string(request.EnrollmentID))
	credential, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, wrappingKey, ciphertext, label)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credential)
	if len(credential) != 32 {
		t.Fatalf("credential size = %d", len(credential))
	}
	publicDigest := sha256.Sum256(credential)
	if issued.Join.CredentialDigest != "sha256:"+hex.EncodeToString(publicDigest[:]) {
		t.Fatal("join metadata does not commit to the wrapped credential")
	}
	verifierInput := append(bytes.Clone(issued.CredentialSalt), credential...)
	verifier := sha256.Sum256(verifierInput)
	clear(verifierInput)
	if issued.CredentialVerifier != "sha256:"+hex.EncodeToString(verifier[:]) {
		t.Fatal("stored verifier is not salted")
	}
	if bytes.Contains(ciphertext, credential) || bytes.Contains(issued.CredentialSalt, credential) {
		t.Fatal("raw credential escaped its RSA envelope")
	}

	second, err := issuer.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Clear()
	if second.Join.CredentialDigest == issued.Join.CredentialDigest ||
		second.WrappedCredential.Ciphertext == issued.WrappedCredential.Ciphertext ||
		second.CredentialVerifier == issued.CredentialVerifier {
		t.Fatal("credential issuance reused secret material")
	}
}

func TestIssuerRejectsWeakWrappingKeysAndUntrustedConfiguration(t *testing.T) {
	issuer := testIssuer(t)
	_, weakPublic := testWrappingKey(t, 2048)
	request := nodeenrollment.JoinIssueRequest{
		EnrollmentID:      "node-enrollment-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExecutionTargetID: "target-a", ExpiresAt: testTime().Add(15 * time.Minute),
		WrappingPublicKey: weakPublic,
	}
	if _, err := issuer.Issue(context.Background(), request); !errors.Is(err, nodeenrollment.ErrInvalidArgument) {
		t.Fatalf("weak wrapping key error = %v", err)
	}

	certificate, privateKey := testIssuerMaterial(t)
	for name, baseURL := range map[string]string{
		"http":       "http://matrix.internal/api/paas/v1",
		"credential": "https://user:password@matrix.internal/api/paas/v1",
		"query":      "https://matrix.internal/api/paas/v1?token=forbidden",
		"wrong path": "https://matrix.internal/v1",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New("installation-a", baseURL, certificate, privateKey); err == nil {
				t.Fatal("unsafe public URL was accepted")
			}
		})
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(otherPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New("installation-a", "https://matrix.internal/api/paas/v1", certificate, otherDER); err == nil {
		t.Fatal("issuer accepted a mismatched private key")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, validPublic := testWrappingKey(t, 3072)
	request.WrappingPublicKey = validPublic
	if _, err := issuer.Issue(canceled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled issue error = %v", err)
	}
}

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	certificate, privateKey := testIssuerMaterial(t)
	issuer, err := New(
		"installation-a", "https://matrix.internal/api/paas/v1", certificate, privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func testIssuerMaterial(t *testing.T) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := testTime()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "matrix-enrollment-issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, privateDER
}

func testWrappingKey(t *testing.T, bits int) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, base64.RawURLEncoding.EncodeToString(encoded)
}

func testTime() time.Time {
	return time.Date(2026, 9, 6, 8, 0, 0, 0, time.UTC)
}
