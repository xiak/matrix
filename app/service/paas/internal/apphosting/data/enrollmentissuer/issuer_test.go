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
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/nodeenrollment"
)

func TestIssueWrapsFreshCredentialAndStoresOnlySaltedVerifier(t *testing.T) {
	issuer := testIssuer(t)
	wrappingKey, wrappingPublic := testWrappingKey(t, 3072)
	request := nodeenrollment.JoinIssueRequest{
		EnrollmentID:      "node-enrollment-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExecutionTargetID: "target-a", ExpiresAt: testTime().Add(15 * time.Minute),
		WrappingPublicKey: wrappingPublic, ControlPlaneBaseURL: "https://matrix.internal/api/paas/v1",
	}
	issued, err := issuer.IssueJoin(context.Background(), request)
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

	second, err := issuer.IssueJoin(context.Background(), request)
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
		WrappingPublicKey: weakPublic, ControlPlaneBaseURL: "https://matrix.internal/api/paas/v1",
	}
	if _, err := issuer.IssueJoin(context.Background(), request); !errors.Is(err, nodeenrollment.ErrInvalidArgument) {
		t.Fatalf("weak wrapping key error = %v", err)
	}

	certificate, privateKey := testIssuerMaterial(t)
	_, validPublic := testWrappingKey(t, 3072)
	request.WrappingPublicKey = validPublic
	for name, baseURL := range map[string]string{
		"http":       "http://matrix.internal/api/paas/v1",
		"credential": "https://user:password@matrix.internal/api/paas/v1",
		"query":      "https://matrix.internal/api/paas/v1?token=forbidden",
		"wrong path": "https://matrix.internal/v1",
	} {
		t.Run(name, func(t *testing.T) {
			unsafe := request
			unsafe.ControlPlaneBaseURL = baseURL
			if _, err := issuer.IssueJoin(context.Background(), unsafe); !errors.Is(err, nodeenrollment.ErrInvalidArgument) {
				t.Fatal("unsafe public URL was accepted")
			}
		})
	}
	if _, err := New("installation-other", certificate, privateKey); err == nil {
		t.Fatal("issuer accepted a certificate for another installation")
	}
	corruptedCertificate := bytes.Clone(certificate)
	corruptedCertificate[len(corruptedCertificate)-1] ^= 0x01
	if _, err := New("installation-a", corruptedCertificate, privateKey); err == nil {
		t.Fatal("issuer accepted a certificate with an invalid self-signature")
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(otherPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New("installation-a", certificate, otherDER); err == nil {
		t.Fatal("issuer accepted a mismatched private key")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	request.WrappingPublicKey = validPublic
	if _, err := issuer.IssueJoin(canceled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled issue error = %v", err)
	}
}

func TestIssueExchangeSignsDistinctRolesAndSealsRecoverableResult(t *testing.T) {
	certificate, privateKey := testIssuerMaterial(t)
	issuer, err := New("installation-a", certificate, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	nodePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	collectorPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodeSPKI, err := x509.MarshalPKIXPublicKey(nodePublic)
	if err != nil {
		t.Fatal(err)
	}
	collectorSPKI, err := x509.MarshalPKIXPublicKey(collectorPublic)
	if err != nil {
		t.Fatal(err)
	}
	request := nodeenrollment.ExchangeIssueRequest{
		EnrollmentID: "node-enrollment-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", InstallationID: "installation-a",
		ExecutionTargetID:  "execution-target-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExchangeID:         "node-exchange-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		MachineFingerprint: "sha256:" + strings.Repeat("a", 64), RuntimeContractDigest: "sha256:" + strings.Repeat("b", 64),
		Listener:      paasv1.NodeEnrollmentListenerClaim{ManagementPort: 16443, CollectorPort: 19100},
		NodePublicKey: nodeSPKI, CollectorPublicKey: collectorSPKI, ObservedPeerAddress: "192.168.50.10",
		BindingRef: "node-binding-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ControllerID: "paas-controller-v1",
		CertificateNotBefore: testTime(), CertificateNotAfter: testTime().Add(30 * 24 * time.Hour),
	}
	issued, err := issuer.IssueExchange(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if paasv1.ValidateNodeEnrollmentExchangeResponse(issued.Response) != nil ||
		nodeenrollment.ValidateSealedExchangeResult(issued.Sealed) != nil ||
		issued.Response.NodeListenAddress != "192.168.50.10:16443" ||
		issued.Response.CollectorEndpoint != "https://127.0.0.1:19100" {
		t.Fatal("issued exchange does not preserve the exact role and listener contract")
	}

	encodedResponse, err := json.Marshal(issued.Response)
	if err != nil {
		t.Fatal(err)
	}
	exchange := nodeenrollment.StoredExchange{
		APIVersion: nodeenrollment.StoredExchangeAPIVersion, Kind: nodeenrollment.StoredExchangeKind,
		EnrollmentID: request.EnrollmentID, InstallationID: request.InstallationID,
		ExecutionTargetID: request.ExecutionTargetID, ExchangeID: request.ExchangeID,
		MachineFingerprint: request.MachineFingerprint, RuntimeContractDigest: request.RuntimeContractDigest,
		ControllerID: request.ControllerID, BindingRef: request.BindingRef,
		NodeListenAddress: issued.Response.NodeListenAddress, CollectorEndpoint: issued.Response.CollectorEndpoint,
		NodePublicKey: base64.RawURLEncoding.EncodeToString(nodeSPKI), NodePublicKeyFingerprint: testDigest(nodeSPKI),
		CollectorPublicKey: base64.RawURLEncoding.EncodeToString(collectorSPKI), CollectorPublicKeyFingerprint: testDigest(collectorSPKI),
		ResultDigest: testDigest(encodedResponse), ConsumedAt: testTime(),
	}
	clear(encodedResponse)
	if err := nodeenrollment.ValidateStoredExchange(exchange); err != nil {
		t.Fatalf("invalid stored exchange fixture: %v", err)
	}

	// A process restart derives the same encryption subkey from the protected
	// issuer key; no independent key file or topology compatibility path exists.
	restarted, err := New("installation-a", certificate, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := restarted.OpenExchangeResult(context.Background(), exchange, issued.Sealed)
	if err != nil || opened != issued.Response {
		t.Fatalf("open sealed exchange after restart: %#v / %v", opened, err)
	}

	tamperedCiphertext, err := base64.RawURLEncoding.Strict().DecodeString(issued.Sealed.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 1
	tampered := issued.Sealed
	tampered.Ciphertext = base64.RawURLEncoding.EncodeToString(tamperedCiphertext)
	clear(tamperedCiphertext)
	if _, err := restarted.OpenExchangeResult(context.Background(), exchange, tampered); !errors.Is(err, nodeenrollment.ErrInvalidArgument) {
		t.Fatalf("tampered ciphertext error = %v", err)
	}
	rebound := exchange
	rebound.ExchangeID = "node-exchange-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := restarted.OpenExchangeResult(context.Background(), rebound, issued.Sealed); !errors.Is(err, nodeenrollment.ErrInvalidArgument) {
		t.Fatalf("rebound exchange error = %v", err)
	}
	other := testIssuer(t)
	if _, err := other.OpenExchangeResult(context.Background(), exchange, issued.Sealed); !errors.Is(err, nodeenrollment.ErrInvalidArgument) {
		t.Fatalf("different installation key error = %v", err)
	}
}

func TestIssueExchangeRejectsCallerSelectedAuthority(t *testing.T) {
	issuer := testIssuer(t)
	nodePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	collectorPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodeSPKI, _ := x509.MarshalPKIXPublicKey(nodePublic)
	collectorSPKI, _ := x509.MarshalPKIXPublicKey(collectorPublic)
	valid := nodeenrollment.ExchangeIssueRequest{
		EnrollmentID: "node-enrollment-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", InstallationID: "installation-a",
		ExecutionTargetID: "execution-target-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExchangeID:        "node-exchange-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", MachineFingerprint: "sha256:" + strings.Repeat("a", 64),
		RuntimeContractDigest: "sha256:" + strings.Repeat("b", 64), Listener: paasv1.NodeEnrollmentListenerClaim{ManagementPort: 16443, CollectorPort: 19100},
		NodePublicKey: nodeSPKI, CollectorPublicKey: collectorSPKI, ObservedPeerAddress: "192.168.50.10",
		BindingRef: "node-binding-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ControllerID: "paas-controller-v1",
		CertificateNotBefore: testTime(), CertificateNotAfter: testTime().Add(30 * 24 * time.Hour),
	}
	for name, mutate := range map[string]func(*nodeenrollment.ExchangeIssueRequest){
		"wrong installation": func(value *nodeenrollment.ExchangeIssueRequest) { value.InstallationID = "installation-b" },
		"public peer":        func(value *nodeenrollment.ExchangeIssueRequest) { value.ObservedPeerAddress = "8.8.8.8" },
		"shared role key": func(value *nodeenrollment.ExchangeIssueRequest) {
			value.CollectorPublicKey = value.NodePublicKey
		},
		"caller binding": func(value *nodeenrollment.ExchangeIssueRequest) { value.BindingRef = "binding-caller" },
		"overlong certificate": func(value *nodeenrollment.ExchangeIssueRequest) {
			value.CertificateNotAfter = value.CertificateNotBefore.Add(paasv1.MaximumNodeEnrollmentCertificateLifetime + time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := valid
			mutate(&changed)
			if _, err := issuer.IssueExchange(context.Background(), changed); !errors.Is(err, nodeenrollment.ErrInvalidArgument) {
				t.Fatalf("unsafe exchange issue error = %v", err)
			}
		})
	}
}

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	certificate, privateKey := testIssuerMaterial(t)
	issuer, err := New("installation-a", certificate, privateKey)
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
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	issuerURI, err := paasv1.NodeEnrollmentIssuerURI("installation-a")
	if err != nil {
		t.Fatal(err)
	}
	template.URIs = append(template.URIs, issuerURI)
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

func testDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
