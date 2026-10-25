package localmachine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
)

func TestNodeEnrollmentStorePersistsProtectedStateAndFinalizesExactly(t *testing.T) {
	store, plan, intent, response, credential := storedNodeEnrollment(t)
	defer plan.Clear()
	defer intent.Clear()
	intentPath := filepath.Join(plan.Root, filepath.FromSlash(layout.NodeEnrollmentIntent))
	source, err := os.ReadFile(intentPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(source, credential) || bytes.Contains(source, []byte(base64.RawURLEncoding.EncodeToString(credential))) {
		t.Fatal("protected enrollment intent retained the raw one-time credential")
	}
	attempted, err := store.EnrollmentExchangeAttempted(plan.Root, intent)
	if err != nil || !attempted {
		t.Fatalf("sealed exchange attempt = %t / %v", attempted, err)
	}

	attemptPath := filepath.Join(plan.Root, filepath.FromSlash(layout.NodeEnrollmentAttempt))
	if err := os.WriteFile(attemptPath, []byte("foreign-attempt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.FinalizeEnrollment(plan.Root, intent, response); !errors.Is(err, nodecommand.ErrConflict) {
		t.Fatalf("substituted enrollment state = %v", err)
	}
	if _, err := os.Stat(intentPath); err != nil {
		t.Fatal("preflight conflict removed enrollment secrets")
	}
	if err := os.WriteFile(attemptPath, enrollmentAttemptBytes(intent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.FinalizeEnrollment(plan.Root, intent, response); err != nil {
		t.Fatal(err)
	}
	assertEnrollmentFilesAbsent(t, plan.Root)
	if err := store.FinalizeEnrollment(plan.Root, intent, response); err != nil {
		t.Fatalf("idempotent enrollment finalization: %v", err)
	}
}

func TestNodeEnrollmentStoreDiscardsRejectedPreResponseIntent(t *testing.T) {
	store, plan, intent, _, _ := storedNodeEnrollment(t)
	defer plan.Clear()
	defer intent.Clear()
	responsePath := filepath.Join(plan.Root, filepath.FromSlash(layout.NodeEnrollmentResponse))
	if err := os.Remove(responsePath); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardEnrollmentIntent(plan.Root, intent); err != nil {
		t.Fatal(err)
	}
	assertEnrollmentFilesAbsent(t, plan.Root)
	if err := store.DiscardEnrollmentIntent(plan.Root, intent); err != nil {
		t.Fatalf("idempotent rejected intent cleanup: %v", err)
	}
}

func TestNodeEnrollmentCleanupMarkerResumesAfterSecretDeletion(t *testing.T) {
	store, plan, intent, response, _ := storedNodeEnrollment(t)
	defer plan.Clear()
	defer intent.Clear()
	intentBytes, err := nodecommand.EncodeEnrollmentIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(intentBytes)
	responseBytes, err := encodeEnrollmentResponse(intent, response)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(responseBytes)
	attemptBytes := enrollmentAttemptBytes(intent)
	marker := enrollmentCleanupMarker{
		APIVersion:     nodeconfig.APIVersion,
		Kind:           enrollmentCleanupKind,
		Mode:           enrollmentCleanupFinalize,
		IntentDigest:   enrollmentFileDigest(intentBytes),
		AttemptDigest:  enrollmentFileDigest(attemptBytes),
		ResponseDigest: enrollmentFileDigest(responseBytes),
	}
	markerBytes, err := encodeEnrollmentCleanupMarker(marker)
	if err != nil || writeManagedOnce(plan.Root, filepath.FromSlash(layout.NodeEnrollmentCleanup), markerBytes) != nil {
		t.Fatal("write enrollment cleanup marker")
	}
	defer clear(markerBytes)
	if err := removeEnrollmentDigestFile(plan.Root, enrollmentDigestFile{
		filepath.FromSlash(layout.NodeEnrollmentIntent), maximumStoredEnrollmentIntentBytes, marker.IntentDigest,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(plan.Root, filepath.FromSlash(layout.NodeEnrollmentIntent))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("simulated cleanup crash retained the private-key intent")
	}
	responsePath := filepath.Join(plan.Root, filepath.FromSlash(layout.NodeEnrollmentResponse))
	if err := os.WriteFile(responsePath, []byte("foreign-response"), 0o600); err != nil {
		t.Fatal(err)
	}
	if resumed, err := store.ResumeEnrollmentCleanup(plan.Root); resumed || !errors.Is(err, nodecommand.ErrConflict) {
		t.Fatalf("substituted cleanup residue = %t / %v", resumed, err)
	}
	for _, relative := range []string{layout.NodeEnrollmentAttempt, layout.NodeEnrollmentCleanup} {
		if _, err := os.Stat(filepath.Join(plan.Root, filepath.FromSlash(relative))); err != nil {
			t.Fatal("cleanup conflict removed authenticated residue")
		}
	}
	if err := os.WriteFile(responsePath, responseBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	resumed, err := store.ResumeEnrollmentCleanup(plan.Root)
	if err != nil || !resumed {
		t.Fatalf("resume enrollment cleanup = %t / %v", resumed, err)
	}
	assertEnrollmentFilesAbsent(t, plan.Root)
	if resumed, err := store.ResumeEnrollmentCleanup(plan.Root); err != nil || resumed {
		t.Fatalf("completed cleanup replay = %t / %v", resumed, err)
	}
}

func TestNodeEnrollmentStoreRejectsSubstitutionThenCleansOnlyIssuedFiles(t *testing.T) {
	store, plan, intent, response, _ := storedNodeEnrollment(t)
	defer plan.Clear()
	defer intent.Clear()
	startup := nativeNodeStartup(plan)
	startupRelative, err := filepath.Rel(plan.Root, startup.unitFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeManagedOnce(plan.Root, startupRelative, nativeStartupUnit(startup)); err != nil {
		t.Fatal(err)
	}
	for _, file := range nodeCredentialFiles(plan) {
		if err := writeManagedOnce(plan.Root, filepath.FromSlash(file.name), file.content); err != nil {
			t.Fatal(err)
		}
	}
	keptRelative := filepath.FromSlash("state/operator-owned-evidence.json")
	if err := writeManagedOnce(plan.Root, keptRelative, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	otherPlan := plan
	otherPlan.Credentials = cloneEnrollmentCredentials(plan.Credentials)
	otherPlan.Credentials.Certificate = []byte("another structurally valid certificate value")
	otherPlan.Binding, err = nodecommand.Binding(otherPlan.Configuration, otherPlan.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupRejectedEnrollment(context.Background(), otherPlan, intent, response); !errors.Is(err, nodecommand.ErrVerification) {
		otherPlan.Clear()
		t.Fatalf("cleanup admitted a different valid node plan: %v", err)
	}
	otherPlan.Clear()

	credential := nodeCredentialFiles(plan)[0]
	credentialPath := filepath.Join(plan.Root, filepath.FromSlash(credential.name))
	if err := os.WriteFile(credentialPath, []byte("foreign-certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupRejectedEnrollment(context.Background(), plan, intent, response); !errors.Is(err, nodecommand.ErrConflict) {
		t.Fatalf("substituted issued credential = %v", err)
	}
	if _, err := os.Stat(startup.unitFile); err != nil {
		t.Fatal("cleanup preflight changed startup state")
	}
	if err := os.WriteFile(credentialPath, credential.content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupRejectedEnrollment(context.Background(), plan, intent, response); err != nil {
		t.Fatal(err)
	}
	for _, path := range append([]string{startup.unitFile}, enrollmentCredentialPaths(plan)...) {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("issued file still exists after rejection cleanup: %s / %v", path, err)
		}
	}
	assertEnrollmentFilesAbsent(t, plan.Root)
	if _, err := os.Stat(filepath.Join(plan.Root, keptRelative)); err != nil {
		t.Fatal("rejection cleanup removed an unrelated owned file")
	}
	if err := store.CleanupRejectedEnrollment(context.Background(), plan, intent, response); err != nil {
		t.Fatalf("idempotent rejection cleanup: %v", err)
	}
}

func storedNodeEnrollment(
	t *testing.T,
) (*NodeEffects, nodecommand.Plan, nodecommand.EnrollmentIntent, paasv1.NodeEnrollmentExchangeResponse, []byte) {
	t.Helper()
	fixture, err := releasetest.WriteNode(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	installationID := "mxi-" + strings.Repeat("a", 32)
	issuerDER, issuerPrivate := localEnrollmentIssuer(t, installationID)
	credential := []byte("0123456789abcdef0123456789abcdef")
	join := localEnrollmentJoin(t, installationID, issuerDER, issuerPrivate, credential)
	base := t.TempDir()
	joinPath := filepath.Join(base, "join.json")
	joinSource, err := json.Marshal(nodeconfig.JoinFile{
		APIVersion: nodeconfig.APIVersion,
		Kind:       nodeconfig.JoinFileKind,
		Join:       join,
		Credential: base64.RawURLEncoding.EncodeToString(credential),
	})
	if err != nil || os.WriteFile(joinPath, joinSource, 0o600) != nil {
		t.Fatal("write signed join fixture")
	}
	root := filepath.Join(base, "node")
	effects := &captureEnrollmentPlan{}
	store := NewNodeEffects(nodeVerifierFixture{})
	backend, err := nodecommand.NewBackend(
		effects,
		store,
		localEnrollmentHost{},
		&localEnrollmentClient{issuerDER: issuerDER, issuerPrivate: issuerPrivate},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, runErr := backend.Run(context.Background(), cli.Request{
		Subject:  cli.SubjectNode,
		Action:   lifecycle.ActionInstall,
		Root:     root,
		Bundle:   fixture.Root,
		TrustKey: fixture.TrustPath,
		Join:     joinPath,
	})
	if runErr == nil || effects.plan.Root == "" {
		t.Fatalf("fixture did not stop after enrollment plan capture: %v", runErr)
	}
	intent, exists, err := store.ReadEnrollmentIntent(root)
	if err != nil || !exists {
		t.Fatalf("read enrollment intent = %t / %v", exists, err)
	}
	response, exists, err := store.ReadEnrollmentResponse(root, intent)
	if err != nil || !exists {
		intent.Clear()
		t.Fatalf("read enrollment response = %t / %v", exists, err)
	}
	return store, effects.plan, intent, response, bytes.Clone(credential)
}

func localEnrollmentIssuer(t *testing.T, installationID string) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("matrix local enrollment store test issuer"))
	private := ed25519.NewKeyFromSeed(seed[:])
	issuerURI, err := paasv1.NodeEnrollmentIssuerURI(installationID)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Matrix local enrollment store test issuer"},
		NotBefore:             time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		URIs:                  []*url.URL{issuerURI},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, private
}

func localEnrollmentJoin(
	t *testing.T,
	installationID string,
	issuerDER []byte,
	issuerPrivate ed25519.PrivateKey,
	credential []byte,
) paasv1.NodeEnrollmentJoin {
	t.Helper()
	credentialDigest := sha256.Sum256(credential)
	enrollmentID := paasv1.ResourceID("node-enrollment-" + strings.Repeat("a", 32))
	join := paasv1.NodeEnrollmentJoin{
		APIVersion:         paasv1.NodeEnrollmentJoinAPIVersion,
		Kind:               paasv1.NodeEnrollmentJoinKind,
		EnrollmentID:       enrollmentID,
		InstallationID:     installationID,
		ExecutionTargetID:  "target-a",
		ControlPlaneURL:    "https://matrix.internal/api/paas/v1/node-enrollments/" + string(enrollmentID) + "/exchange",
		CredentialDigest:   "sha256:" + hex.EncodeToString(credentialDigest[:]),
		ExpiresAt:          time.Now().UTC().Add(15 * time.Minute).Truncate(time.Microsecond),
		IssuerCertificate:  base64.RawURLEncoding.EncodeToString(issuerDER),
		SignatureAlgorithm: paasv1.NodeJoinSignatureEd25519,
	}
	commitment, err := paasv1.NodeEnrollmentJoinSigningBytes(join)
	if err != nil {
		t.Fatal(err)
	}
	join.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerPrivate, commitment))
	if err := paasv1.ValidateNodeEnrollmentJoin(join); err != nil {
		t.Fatal(err)
	}
	return join
}

type localEnrollmentClient struct {
	issuerDER     []byte
	issuerPrivate ed25519.PrivateKey
}

func (client *localEnrollmentClient) Exchange(
	_ context.Context,
	join paasv1.NodeEnrollmentJoin,
	request paasv1.ExchangeNodeEnrollmentRequest,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	if paasv1.ValidateExchangeNodeEnrollmentRequest(request) != nil ||
		request.EnrollmentID != join.EnrollmentID || request.InstallationID != join.InstallationID ||
		request.ExecutionTargetID != join.ExecutionTargetID {
		return paasv1.NodeEnrollmentExchangeResponse{}, nodecommand.ErrEnrollmentRejected
	}
	issuer, err := x509.ParseCertificate(client.issuerDER)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	nodePKIX, collectorPKIX, err := paasv1.NodeEnrollmentExchangePublicKeys(request)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	nodePublic, err := x509.ParsePKIXPublicKey(nodePKIX)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	collectorPublic, err := x509.ParsePKIXPublicKey(collectorPKIX)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	notBefore := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second)
	notAfter := notBefore.Add(24 * time.Hour)
	issue := func(role string, public any, address net.IP, usages []x509.ExtKeyUsage, serial int64) (string, error) {
		identity := &url.URL{Scheme: "spiffe", Host: "matrix.xiak.com",
			Path: "/installations/" + request.InstallationID + "/" + role + "/" + string(request.ExecutionTargetID)}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: notBefore, NotAfter: notAfter,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: usages, URIs: []*url.URL{identity}, IPAddresses: []net.IP{address},
		}
		certificate, err := x509.CreateCertificate(rand.Reader, template, issuer, public, client.issuerPrivate)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(certificate), nil
	}
	nodeCertificate, err := issue("nodes", nodePublic, net.ParseIP("192.168.50.10"),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, 2)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	collectorCertificate, err := issue("collectors", collectorPublic, net.ParseIP("127.0.0.1"),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 3)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	return paasv1.NodeEnrollmentExchangeResponse{
		APIVersion:            paasv1.NodeEnrollmentExchangeAPIVersion,
		Kind:                  paasv1.NodeEnrollmentExchangeResponseKind,
		EnrollmentID:          request.EnrollmentID,
		InstallationID:        request.InstallationID,
		ExecutionTargetID:     request.ExecutionTargetID,
		ExchangeID:            request.ExchangeID,
		MachineFingerprint:    request.MachineFingerprint,
		RuntimeContractDigest: request.RuntimeContractDigest,
		ControllerID:          "controller-a",
		BindingRef:            "node-binding-" + strings.Repeat("a", 32),
		NodeListenAddress:     "192.168.50.10:16443",
		CollectorEndpoint:     "https://127.0.0.1:19100",
		NodeCertificate:       nodeCertificate,
		CollectorCertificate:  collectorCertificate,
		IssuerCertificate:     join.IssuerCertificate,
		CertificateNotBefore:  notBefore,
		CertificateNotAfter:   notAfter,
	}, nil
}

func (*localEnrollmentClient) CreateRecoveryChallenge(
	context.Context,
	paasv1.NodeEnrollmentJoin,
	paasv1.CreateNodeEnrollmentRecoveryChallengeRequest,
) (paasv1.NodeEnrollmentRecoveryChallenge, error) {
	return paasv1.NodeEnrollmentRecoveryChallenge{}, nodecommand.ErrEnrollmentUnavailable
}

func (*localEnrollmentClient) RecoverExchange(
	context.Context,
	paasv1.NodeEnrollmentJoin,
	paasv1.RecoverNodeEnrollmentExchangeRequest,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	return paasv1.NodeEnrollmentExchangeResponse{}, nodecommand.ErrEnrollmentUnavailable
}

func (*localEnrollmentClient) Complete(
	context.Context,
	paasv1.NodeEnrollmentJoin,
	paasv1.CompleteNodeEnrollmentRequest,
) error {
	return nodecommand.ErrEnrollmentUnavailable
}

type localEnrollmentHost struct{}

func (localEnrollmentHost) MachineFingerprint(context.Context, string) (string, error) {
	return "sha256:" + strings.Repeat("a", 64), nil
}

type captureEnrollmentPlan struct {
	plan nodecommand.Plan
}

func (effects *captureEnrollmentPlan) ValidateEnrollment(plan nodecommand.Plan) error {
	if nodecommand.ValidatePlan(plan) != nil {
		return nodecommand.ErrVerification
	}
	effects.plan = plan
	effects.plan.TrustBytes = bytes.Clone(plan.TrustBytes)
	effects.plan.Credentials = cloneEnrollmentCredentials(plan.Credentials)
	return nodecommand.ErrVerification
}

func (*captureEnrollmentPlan) ReadInstallation(string) (nodeconfig.Configuration, nodecommand.Credentials, error) {
	return nodeconfig.Configuration{}, nodecommand.Credentials{}, nodecommand.ErrVerification
}

func (*captureEnrollmentPlan) ReadRotation(string, string) (nodeconfig.Configuration, nodecommand.Credentials, error) {
	return nodeconfig.Configuration{}, nodecommand.Credentials{}, nodecommand.ErrVerification
}

func (*captureEnrollmentPlan) FinalizeRotation(context.Context, nodecommand.Plan, lifecycle.Command) error {
	return nodecommand.ErrVerification
}

func (*captureEnrollmentPlan) StageRelease(context.Context, nodecommand.Plan) error {
	return nodecommand.ErrVerification
}

func (*captureEnrollmentPlan) ApplyPhase(context.Context, nodecommand.Plan, lifecycle.Phase) error {
	return nodecommand.ErrVerification
}

func (*captureEnrollmentPlan) Rollback(context.Context, nodecommand.Plan) error {
	return nodecommand.ErrVerification
}

func (*captureEnrollmentPlan) Observe(context.Context, nodecommand.Plan) (bool, error) {
	return false, nodecommand.ErrVerification
}

func (*captureEnrollmentPlan) WriteSupportEvidence(context.Context, nodecommand.SupportPlan) (bool, error) {
	return false, nodecommand.ErrVerification
}

func cloneEnrollmentCredentials(value nodecommand.Credentials) nodecommand.Credentials {
	return nodecommand.Credentials{
		Certificate:          bytes.Clone(value.Certificate),
		PrivateKey:           bytes.Clone(value.PrivateKey),
		Trust:                bytes.Clone(value.Trust),
		CollectorCertificate: bytes.Clone(value.CollectorCertificate),
		CollectorPrivateKey:  bytes.Clone(value.CollectorPrivateKey),
	}
}

func enrollmentCredentialPaths(plan nodecommand.Plan) []string {
	result := make([]string, 0, len(nodeCredentialFiles(plan)))
	for _, file := range nodeCredentialFiles(plan) {
		result = append(result, filepath.Join(plan.Root, filepath.FromSlash(file.name)))
	}
	return result
}

func assertEnrollmentFilesAbsent(t *testing.T, root string) {
	t.Helper()
	for _, relative := range []string{
		layout.NodeEnrollmentIntent,
		layout.NodeEnrollmentAttempt,
		layout.NodeEnrollmentResponse,
		layout.NodeEnrollmentCleanup,
	} {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("enrollment state still exists: %s / %v", path, err)
		}
	}
}
