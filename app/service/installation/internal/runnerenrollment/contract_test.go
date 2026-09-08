package runnerenrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/installation/topology"
)

const (
	testInstallationID = "mxi-11111111111111111111111111111111"
	testReleaseID      = "matrix-v0.1.0-aaaaaaaaaaaa"
	testNodeID         = "runner-one"
	testGatewayOrigin  = "https://192.0.2.10:8444"
)

func TestEnrollmentCSRJourneyKeepsFourSlotsDistinctAndBound(t *testing.T) {
	slots := make([]SlotRequest, 4)
	keys := make([]*ecdsa.PrivateKey, 4)
	for index := range slots {
		slot := uint8(index + 1)
		identity := SlotIdentity(testInstallationID, testNodeID, slot)
		key, csr := testCSR(t, testNodeID, slot, identity)
		keys[index] = key
		slots[index] = SlotRequest{Index: slot, Identity: identity, CSR: csr}
	}
	runnerCA, runnerKey := testAuthority(t, "runner")
	serverCA, _ := testAuthority(t, "server")
	pins, err := NewAuthorityPins(serverCA, runnerCA)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRequest(
		testReleaseID, testInstallationID, testNodeID, testGatewayOrigin, pins, slots,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRequest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := RequestDigest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	document := EnrollmentDocument{
		APIVersion: APIVersion, Kind: SignedEnrollmentKind,
		RequestDigest: requestDigest, ReleaseID: request.ReleaseID,
		InstallationID: request.InstallationID, NodeID: request.NodeID,
		GatewayOrigin:     request.GatewayOrigin,
		GatewayServerName: topology.DevOpsExecutorGatewayServerName,
		RunnerNamespace:   request.RunnerNamespace,
		ServerCA:          serverCA, RunnerCA: runnerCA,
		Slots: make([]IssuedSlot, len(request.Slots)),
	}
	for index, slot := range request.Slots {
		document.Slots[index] = IssuedSlot{
			Index: slot.Index, Identity: slot.Identity,
			Certificate: testIssuedCertificate(
				t, runnerCA, runnerKey, keys[index].Public(), testNodeID,
				slot.Index, slot.Identity,
			),
		}
	}
	signed, err := NewSignedEnrollment(document, runnerKey, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentBytes, err := EncodeSignedEnrollment(signed)
	if err != nil {
		t.Fatal(err)
	}
	decodedEnrollment, err := DecodeSignedEnrollment(enrollmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEnrollmentAgainstRequest(decodedEnrollment, decoded); err != nil {
		t.Fatal(err)
	}
	untrustedServerCA, _ := testAuthority(t, "untrusted-server")
	untrustedDocument := document
	untrustedDocument.ServerCA = untrustedServerCA
	untrusted, err := NewSignedEnrollment(untrustedDocument, runnerKey, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if ValidateEnrollmentAgainstRequest(untrusted, decoded) == nil {
		t.Fatal("self-consistent enrollment with an unpinned server authority was accepted")
	}
	for index := range document.Slots {
		for other := index + 1; other < len(document.Slots); other++ {
			if document.Slots[index].Identity == document.Slots[other].Identity ||
				keys[index].D.Cmp(keys[other].D) == 0 {
				t.Fatal("runner slots share identity or private key")
			}
		}
	}

	changed := decodedEnrollment
	changed.Document.NodeID = "runner-two"
	if ValidateSignedEnrollment(changed) == nil {
		t.Fatal("changed signed enrollment was accepted")
	}
	wrongRequest := decoded
	wrongRequest.NodeID = "runner-two"
	if ValidateEnrollmentAgainstRequest(decodedEnrollment, wrongRequest) == nil {
		t.Fatal("enrollment was accepted for another request")
	}
}

func TestEnrollmentRequestRejectsExpandedOrUnsafeNodeAuthority(t *testing.T) {
	identity := SlotIdentity(testInstallationID, testNodeID, 1)
	_, csr := testCSR(t, testNodeID, 1, identity)
	base := []SlotRequest{{Index: 1, Identity: identity, CSR: csr}}
	pins := testAuthorityPins()
	tests := map[string]func() (Request, error){
		"non canonical gateway": func() (Request, error) {
			return NewRequest(testReleaseID, testInstallationID, testNodeID, "https://EXAMPLE.com:8444", pins, base)
		},
		"wrong port": func() (Request, error) {
			return NewRequest(testReleaseID, testInstallationID, testNodeID, "https://192.0.2.10:443", pins, base)
		},
		"unsafe node": func() (Request, error) {
			return NewRequest(testReleaseID, testInstallationID, "../node", testGatewayOrigin, pins, base)
		},
		"five slots": func() (Request, error) {
			slots := make([]SlotRequest, 5)
			for index := range slots {
				slot := uint8(index + 1)
				id := SlotIdentity(testInstallationID, testNodeID, slot)
				_, request := testCSR(t, testNodeID, slot, id)
				slots[index] = SlotRequest{Index: slot, Identity: id, CSR: request}
			}
			return NewRequest(testReleaseID, testInstallationID, testNodeID, testGatewayOrigin, pins, slots)
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); err == nil {
				t.Fatal("invalid runner request was accepted")
			}
		})
	}

	request, err := NewRequest(testReleaseID, testInstallationID, testNodeID, testGatewayOrigin, pins, base)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = true
	withUnknown, _ := json.Marshal(object)
	if _, err := DecodeRequest(withUnknown); err == nil {
		t.Fatal("unknown request field was accepted")
	}
}

func testAuthorityPins() AuthorityPins {
	return AuthorityPins{
		ServerCAFingerprint: "sha256:" + strings.Repeat("a", 64),
		RunnerCAFingerprint: "sha256:" + strings.Repeat("b", 64),
	}
}

func testCSR(
	t *testing.T,
	nodeID string,
	slot uint8,
	identity string,
) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	content, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: SlotCertificateSubject(nodeID, slot), URIs: []*url.URL{uri},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, content
}

func testAuthority(t *testing.T, role string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(len(role) + 1)),
		Subject:               pkix.Name{Organization: []string{"Matrix"}, CommonName: "test " + role},
		NotBefore:             time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2031, 9, 9, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), key
}

func testIssuedCertificate(
	t *testing.T,
	authorityPEM []byte,
	authorityKey *ecdsa.PrivateKey,
	publicKey any,
	nodeID string,
	slot uint8,
	identity string,
) []byte {
	t.Helper()
	block, _ := pem.Decode(authorityPEM)
	authority, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100 + int64(slot)),
		Subject:      SlotCertificateSubject(nodeID, slot),
		NotBefore:    authority.NotBefore, NotAfter: authority.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, URIs: []*url.URL{uri},
	}
	encoded, err := x509.CreateCertificate(
		rand.Reader, template, authority, publicKey, authorityKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}),
		authorityPEM,
	}, nil)
}

func TestReleaseIdentityFixtureMatchesClosedGrammar(t *testing.T) {
	if !releasePattern.MatchString(testReleaseID) || strings.Contains(testReleaseID, "latest") {
		t.Fatal("test release identity is outside the closed grammar")
	}
}
