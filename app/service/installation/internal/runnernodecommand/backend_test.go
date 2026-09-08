package runnernodecommand_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/internal/runnerenrollment"
	"github.com/xiak/matrix/app/service/installation/internal/runnernodecommand"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

type fakeEffects struct {
	bundle        release.VerifiedBundle
	request       runnerenrollment.Request
	pins          runnerenrollment.AuthorityPins
	exported      bool
	createCalled  bool
	enrollCalled  bool
	installCalled bool
	installPlan   runnernodecommand.InstallPlan
	enrollment    runnerenrollment.SignedEnrollment
}

func (fake *fakeEffects) AuthenticateRunnerRelease(
	context.Context, string, string,
) (release.VerifiedBundle, error) {
	return fake.bundle, nil
}

func (fake *fakeEffects) CreateRunnerRequest(
	context.Context, runnernodecommand.CreateRequestPlan,
) (runnerenrollment.Request, error) {
	fake.createCalled = true
	return fake.request, nil
}

func (fake *fakeEffects) ExportRunnerRelease(
	context.Context, runnernodecommand.ExportReleasePlan,
) (runnerenrollment.AuthorityPins, error) {
	fake.exported = true
	return fake.pins, nil
}

func (fake *fakeEffects) ReadRunnerRequest(
	context.Context, string,
) (runnerenrollment.Request, error) {
	return fake.request, nil
}

func (fake *fakeEffects) EnrollRunner(
	context.Context, runnernodecommand.EnrollPlan,
) (runnerenrollment.SignedEnrollment, error) {
	fake.enrollCalled = true
	return runnerenrollment.SignedEnrollment{}, nil
}

func (fake *fakeEffects) ReadRunnerEnrollment(
	context.Context, string,
) (runnerenrollment.SignedEnrollment, error) {
	return fake.enrollment, nil
}

func (fake *fakeEffects) InstallRunnerNode(
	_ context.Context, plan runnernodecommand.InstallPlan,
) (runnernodecommand.InstallationEvidence, error) {
	fake.installCalled = true
	fake.installPlan = plan
	digest, _ := runnerenrollment.RequestDigest(plan.Request)
	return runnernodecommand.InstallationEvidence{
		ReleaseID: plan.Request.ReleaseID, InstallationID: plan.Request.InstallationID,
		NodeID: plan.Request.NodeID, Slots: uint8(len(plan.Request.Slots)), RequestDigest: digest,
	}, nil
}

func TestRunnerReleaseExportAuthenticatesIdleSelectedInstallation(t *testing.T) {
	root, _ := installedFixture(t, true, false)
	effects := &fakeEffects{pins: authorityPins()}
	backend, err := runnernodecommand.NewBackend(effects)
	if err != nil {
		t.Fatal(err)
	}
	result, err := backend.RunRunnerNode(context.Background(), cli.RunnerNodeRequest{
		Operation: cli.RunnerNodeExportRelease, Root: root,
		Output: filepath.Join(t.TempDir(), "runner-release"),
	})
	if err != nil || !effects.exported || result.State != "EXPORTED" || result.ReleaseID == "" ||
		result.ServerCAPin != effects.pins.ServerCAFingerprint ||
		result.RunnerCAPin != effects.pins.RunnerCAFingerprint {
		t.Fatalf("export result=%#v called=%t err=%v", result, effects.exported, err)
	}

	paasRoot, _ := installedFixture(t, false, false)
	effects.exported = false
	_, err = backend.RunRunnerNode(context.Background(), cli.RunnerNodeRequest{
		Operation: cli.RunnerNodeExportRelease, Root: paasRoot,
		Output: filepath.Join(t.TempDir(), "runner-release"),
	})
	assertFault(t, err, cli.FaultPrecondition, "DEVOPS_PRODUCT_NOT_INSTALLED")
	if effects.exported {
		t.Fatal("PaaS-only installation exported runner authority")
	}

	activeRoot, _ := installedFixture(t, true, true)
	_, err = backend.RunRunnerNode(context.Background(), cli.RunnerNodeRequest{
		Operation: cli.RunnerNodeExportRelease, Root: activeRoot,
		Output: filepath.Join(t.TempDir(), "runner-release"),
	})
	assertFault(t, err, cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
}

func TestRunnerRequestCreationUsesAuthenticatedReleaseIdentity(t *testing.T) {
	manifest := releasetest.DevOpsManifest()
	request := enrollmentRequest(t, manifest.Release.ID, "mxi-11111111111111111111111111111111")
	effects := &fakeEffects{
		bundle:  release.VerifiedBundle{Manifest: manifest},
		request: request,
	}
	backend, err := runnernodecommand.NewBackend(effects)
	if err != nil {
		t.Fatal(err)
	}
	result, err := backend.RunRunnerNode(context.Background(), cli.RunnerNodeRequest{
		Operation:      cli.RunnerNodeCreateRequest,
		Root:           filepath.Join(t.TempDir(), "runner"),
		Release:        filepath.Join(t.TempDir(), "release"),
		TrustKey:       filepath.Join(t.TempDir(), "trust.json"),
		InstallationID: request.InstallationID, NodeID: request.NodeID,
		Slots: 1, GatewayOrigin: request.GatewayOrigin,
		ServerCAPin: request.AuthorityPins.ServerCAFingerprint,
		RunnerCAPin: request.AuthorityPins.RunnerCAFingerprint,
	})
	if err != nil || !effects.createCalled || result.State != "REQUESTED" ||
		result.NodeID != request.NodeID || result.Slots != 1 || result.RequestDigest == "" {
		t.Fatalf("request result=%#v called=%t err=%v", result, effects.createCalled, err)
	}
}

func TestRunnerEnrollmentRejectsForeignInstallationBeforeSigning(t *testing.T) {
	root, fixture := installedFixture(t, true, false)
	effects := &fakeEffects{
		request: enrollmentRequest(
			t, fixture.Manifest.Release.ID, "mxi-22222222222222222222222222222222",
		),
	}
	backend, err := runnernodecommand.NewBackend(effects)
	if err != nil {
		t.Fatal(err)
	}
	_, err = backend.RunRunnerNode(context.Background(), cli.RunnerNodeRequest{
		Operation: cli.RunnerNodeEnroll, Root: root,
		RequestFile: filepath.Join(t.TempDir(), "request.json"),
		Output:      filepath.Join(t.TempDir(), "enrollment.json"),
	})
	assertFault(t, err, cli.FaultPrecondition, "RUNNER_REQUEST_INSTALLATION_MISMATCH")
	if effects.enrollCalled {
		t.Fatal("foreign runner request reached the certificate signer")
	}
}

func TestRunnerInstallAuthenticatesRealSignedEnrollmentBeforeEffect(t *testing.T) {
	manifest := releasetest.DevOpsManifest()
	serverCA, _ := runnerTestAuthority(t, "server", 11)
	runnerCA, runnerKey := runnerTestAuthority(t, "runner", 12)
	pins, err := runnerenrollment.NewAuthorityPins(serverCA, runnerCA)
	if err != nil {
		t.Fatal(err)
	}
	request := enrollmentRequestWithPins(
		t, manifest.Release.ID, "mxi-11111111111111111111111111111111", pins,
	)
	enrollment := signedEnrollmentForRequest(t, request, serverCA, runnerCA, runnerKey)
	effects := &fakeEffects{
		bundle: release.VerifiedBundle{Manifest: manifest}, request: request, enrollment: enrollment,
	}
	backend, err := runnernodecommand.NewBackend(effects)
	if err != nil {
		t.Fatal(err)
	}
	result, err := backend.RunRunnerNode(context.Background(), cli.RunnerNodeRequest{
		Operation: cli.RunnerNodeInstall, Root: filepath.Join(t.TempDir(), "runner"),
		Release: filepath.Join(t.TempDir(), "release"), TrustKey: filepath.Join(t.TempDir(), "trust.json"),
		EnrollmentFile: filepath.Join(t.TempDir(), "enrollment.json"),
	})
	if err != nil || !effects.installCalled || result.State != "INSTALLED" ||
		result.ReleaseID != request.ReleaseID || result.InstallationID != request.InstallationID ||
		result.NodeID != request.NodeID || result.Slots != 1 || result.RequestDigest == "" ||
		effects.installPlan.Root == "" ||
		runnerenrollment.ValidateEnrollmentAgainstRequest(effects.installPlan.Enrollment, effects.installPlan.Request) != nil {
		t.Fatalf("install result=%#v called=%t err=%v", result, effects.installCalled, err)
	}

	effects.installCalled = false
	effects.enrollment = runnerenrollment.SignedEnrollment{}
	_, err = backend.RunRunnerNode(context.Background(), cli.RunnerNodeRequest{
		Operation: cli.RunnerNodeInstall, Root: filepath.Join(t.TempDir(), "runner"),
		Release: filepath.Join(t.TempDir(), "release"), TrustKey: filepath.Join(t.TempDir(), "trust.json"),
		EnrollmentFile: filepath.Join(t.TempDir(), "enrollment.json"),
	})
	assertFault(t, err, cli.FaultPrecondition, "RUNNER_ENROLLMENT_REQUEST_MISMATCH")
	if effects.installCalled {
		t.Fatal("invalid signed enrollment reached the install effect")
	}
}

func enrollmentRequest(t *testing.T, releaseID, installationID string) runnerenrollment.Request {
	return enrollmentRequestWithPins(t, releaseID, installationID, authorityPins())
}

func enrollmentRequestWithPins(
	t *testing.T,
	releaseID string,
	installationID string,
	pins runnerenrollment.AuthorityPins,
) runnerenrollment.Request {
	t.Helper()
	identity := runnerenrollment.SlotIdentity(installationID, "runner-one", 1)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: runnerenrollment.SlotCertificateSubject("runner-one", 1),
		URIs:    []*url.URL{uri}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	request, err := runnerenrollment.NewRequest(
		releaseID, installationID, "runner-one", "https://192.0.2.10:8444",
		pins,
		[]runnerenrollment.SlotRequest{{Index: 1, Identity: identity, CSR: csr}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func signedEnrollmentForRequest(
	t *testing.T,
	request runnerenrollment.Request,
	serverCA []byte,
	runnerCA []byte,
	runnerKey *ecdsa.PrivateKey,
) runnerenrollment.SignedEnrollment {
	t.Helper()
	requestDigest, err := runnerenrollment.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(runnerCA)
	authority, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(request.Slots[0].CSR)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := url.Parse(request.Slots[0].Identity)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      runnerenrollment.SlotCertificateSubject(request.NodeID, 1),
		NotBefore:    authority.NotBefore, NotAfter: authority.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, URIs: []*url.URL{identity},
	}
	encodedLeaf, err := x509.CreateCertificate(rand.Reader, leaf, authority, csr.PublicKey, runnerKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encodedLeaf}), runnerCA,
	}, nil)
	document := runnerenrollment.EnrollmentDocument{
		APIVersion: runnerenrollment.APIVersion, Kind: runnerenrollment.SignedEnrollmentKind,
		RequestDigest: requestDigest, ReleaseID: request.ReleaseID,
		InstallationID: request.InstallationID, NodeID: request.NodeID,
		GatewayOrigin:     request.GatewayOrigin,
		GatewayServerName: topology.DevOpsExecutorGatewayServerName,
		RunnerNamespace:   request.RunnerNamespace, ServerCA: serverCA, RunnerCA: runnerCA,
		Slots: []runnerenrollment.IssuedSlot{{
			Index: 1, Identity: request.Slots[0].Identity, Certificate: certificate,
		}},
	}
	signed, err := runnerenrollment.NewSignedEnrollment(document, runnerKey, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func runnerTestAuthority(
	t *testing.T,
	role string,
	serial int64,
) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
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

func authorityPins() runnerenrollment.AuthorityPins {
	return runnerenrollment.AuthorityPins{
		ServerCAFingerprint: "sha256:" + strings.Repeat("a", 64),
		RunnerCAFingerprint: "sha256:" + strings.Repeat("b", 64),
	}
}

func installedFixture(
	t *testing.T,
	devops bool,
	active bool,
) (string, releasetest.Fixture) {
	t.Helper()
	base := t.TempDir()
	fixtureRoot := filepath.Join(base, "fixture")
	if err := os.Mkdir(fixtureRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	var fixture releasetest.Fixture
	var err error
	if devops {
		fixture, err = releasetest.WriteDevOps(fixtureRoot)
	} else {
		fixture, err = releasetest.Write(fixtureRoot)
	}
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "installation")
	state, err := lifecycle.New(
		"mxi-11111111111111111111111111111111",
		lifecycle.ReleaseTrust{
			KeyID: fixture.Trust.KeyID, Fingerprint: fixture.Trust.PublicKeyFingerprint,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 9, 6, 0, 0, 0, time.UTC)
	started, err := lifecycle.Start(state, lifecycle.Command{
		ID: "cmd-11111111111111111111111111111111", Action: lifecycle.ActionInstall,
		InputDigest: fixture.ManifestDigest, TargetReleaseID: fixture.Manifest.Release.ID,
		RequestedAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	state = started.Journal
	if !active {
		for state.Active != nil {
			next, ok := lifecycle.NextPhase(state.Active.Command.Action, state.Active.Phase)
			if !ok {
				t.Fatal("fixture lifecycle cannot advance")
			}
			at = at.Add(time.Microsecond)
			state, err = lifecycle.Advance(state, state.Active.Command.ID, next, at)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	session, err := journal.Acquire(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Initialize(state); err != nil {
		_ = session.Close()
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	trustBytes, err := os.ReadFile(fixture.TrustPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(trustBytes)
	verified, err := release.VerifyDirectory(fixture.Root, trustBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "releases"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := release.StageDirectory(
		verified, trustBytes,
		filepath.Join(root, filepath.FromSlash(layout.ReleaseDirectory(fixture.Manifest.Release.ID))),
	); err != nil {
		t.Fatal(err)
	}
	trustTarget := filepath.Join(root, filepath.FromSlash(layout.ReleaseTrust))
	if err := os.MkdirAll(filepath.Dir(trustTarget), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustTarget, trustBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, fixture
}

func assertFault(t *testing.T, err error, class cli.FaultClass, code string) {
	t.Helper()
	var fault *cli.Fault
	if !errors.As(err, &fault) || fault.Class != class || fault.Code != code {
		t.Fatalf("fault=%#v err=%v want=%s/%s", fault, err, class, code)
	}
}
