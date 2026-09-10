package sourcetrustcommand_test

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/sourcetrust"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/localmachine"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/internal/sourcetrustcommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

func TestInstalledDevOpsSourceTrustJourney(t *testing.T) {
	root := installedTrustFixture(t, true, false)
	backend := newTrustBackend(t)
	tenant := "tenant-one"
	origin := "https://git.internal.example:8443"
	first := newRootBundle(t, "first-root")
	second := newRootBundle(t, "second-root")
	input := writeTrustInput(t, first)
	request := cli.SourceTrustRequest{
		Operation: cli.SourceTrustApply, Root: root, TenantID: tenant,
		EndpointOrigin: origin, FromFile: input,
	}

	result, err := backend.RunSourceTrust(context.Background(), request)
	if err != nil || result.State != string(sourcetrustcommand.StateApplied) ||
		result.TenantID != tenant || result.EndpointOrigin != origin {
		t.Fatalf("apply first trust bundle=%#v err=%v", result, err)
	}
	storedPath := sourceTrustPath(t, root, tenant, origin)
	stored, err := os.ReadFile(storedPath)
	if err != nil || !bytes.Equal(stored, first) {
		clear(stored)
		t.Fatalf("stored first trust bundle differs: %v", err)
	}
	clear(stored)

	result, err = backend.RunSourceTrust(context.Background(), request)
	if err != nil || result.State != string(sourcetrustcommand.StateUnchanged) {
		t.Fatalf("reapply equal trust bundle=%#v err=%v", result, err)
	}
	writeExactTrustInput(t, input, second)
	result, err = backend.RunSourceTrust(context.Background(), request)
	if err != nil || result.State != string(sourcetrustcommand.StateApplied) {
		t.Fatalf("rotate trust bundle=%#v err=%v", result, err)
	}
	stored, err = os.ReadFile(storedPath)
	if err != nil || !bytes.Equal(stored, second) {
		clear(stored)
		t.Fatalf("stored rotated trust bundle differs: %v", err)
	}
	clear(stored)
	inputAfter, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(inputAfter, second) {
		clear(inputAfter)
		t.Fatalf("apply modified operator input: %v", err)
	}
	clear(inputAfter)

	request.Operation = cli.SourceTrustRemove
	request.FromFile = ""
	for attempt := 0; attempt < 2; attempt++ {
		result, err = backend.RunSourceTrust(context.Background(), request)
		if err != nil || result.State != string(sourcetrustcommand.StateRemoved) {
			t.Fatalf("remove trust attempt %d=%#v err=%v", attempt, result, err)
		}
	}
	if _, err := os.Lstat(filepath.Dir(storedPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed trust directory remains: %v", err)
	}
}

func TestSourceTrustCommandAuthenticatesIdleSelectedRelease(t *testing.T) {
	input := writeTrustInput(t, newRootBundle(t, "selected-root"))
	request := cli.SourceTrustRequest{
		Operation: cli.SourceTrustApply, TenantID: "tenant-one",
		EndpointOrigin: "https://git.internal.example", FromFile: input,
	}

	paasRoot := installedTrustFixture(t, false, false)
	request.Root = paasRoot
	_, err := newTrustBackend(t).RunSourceTrust(context.Background(), request)
	assertTrustFault(t, err, cli.FaultPrecondition, "DEVOPS_PRODUCT_NOT_INSTALLED")
	if _, statErr := os.Lstat(filepath.Join(paasRoot, filepath.FromSlash(layout.DevOpsSourceTrustRoot))); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unselected DevOps command created trust storage: %v", statErr)
	}

	activeRoot := installedTrustFixture(t, true, true)
	request.Root = activeRoot
	_, err = newTrustBackend(t).RunSourceTrust(context.Background(), request)
	assertTrustFault(t, err, cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")

	tamperedRoot := installedTrustFixture(t, true, false)
	request.Root = tamperedRoot
	trustPath := filepath.Join(tamperedRoot, filepath.FromSlash(layout.ReleaseTrust))
	if err := os.WriteFile(trustPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = newTrustBackend(t).RunSourceTrust(context.Background(), request)
	assertTrustFault(t, err, cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
}

func TestSourceTrustCommandRejectsUnsafeInputAndStoredStateWithoutDisclosure(t *testing.T) {
	root := installedTrustFixture(t, true, false)
	backend := newTrustBackend(t)
	secretMarker := "private-root-material-marker"
	input := writeTrustInput(t, []byte(secretMarker))
	request := cli.SourceTrustRequest{
		Operation: cli.SourceTrustApply, Root: root, TenantID: "tenant-one",
		EndpointOrigin: "https://git.internal.example", FromFile: input,
	}
	_, err := backend.RunSourceTrust(context.Background(), request)
	assertTrustFault(t, err, cli.FaultInvalidArgument, "SOURCE_TRUST_INPUT_INVALID")
	if strings.Contains(err.Error(), secretMarker) || strings.Contains(err.Error(), input) {
		t.Fatal("invalid input fault disclosed trust material or its local path")
	}

	valid := newRootBundle(t, "valid-root")
	writeExactTrustInput(t, input, valid)
	if _, err := backend.RunSourceTrust(context.Background(), request); err != nil {
		t.Fatalf("apply valid fixture: %v", err)
	}
	storedPath := sourceTrustPath(t, root, request.TenantID, request.EndpointOrigin)
	if err := os.WriteFile(storedPath, []byte("not-canonical-trust"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeExactTrustInput(t, input, newRootBundle(t, "replacement-root"))
	_, err = backend.RunSourceTrust(context.Background(), request)
	assertTrustFault(t, err, cli.FaultVerification, "SOURCE_TRUST_STATE_INVALID")
	if strings.Contains(err.Error(), input) || strings.Contains(err.Error(), storedPath) {
		t.Fatal("stored-state fault disclosed a local path")
	}

	otherRoot := installedTrustFixture(t, true, false)
	request.Root = otherRoot
	writeExactTrustInput(t, input, valid)
	if _, err := backend.RunSourceTrust(context.Background(), request); err != nil {
		t.Fatalf("apply ownership fixture: %v", err)
	}
	storedPath = sourceTrustPath(t, otherRoot, request.TenantID, request.EndpointOrigin)
	if err := os.WriteFile(filepath.Join(filepath.Dir(storedPath), "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = backend.RunSourceTrust(context.Background(), request)
	assertTrustFault(t, err, cli.FaultConflict, "SOURCE_TRUST_OWNERSHIP_CONFLICT")
	request.Operation = cli.SourceTrustRemove
	request.FromFile = ""
	_, err = backend.RunSourceTrust(context.Background(), request)
	assertTrustFault(t, err, cli.FaultConflict, "SOURCE_TRUST_OWNERSHIP_CONFLICT")
}

func newTrustBackend(t *testing.T) *sourcetrustcommand.Backend {
	t.Helper()
	backend, err := sourcetrustcommand.NewBackend(localmachine.NewEffects(nil))
	if err != nil {
		t.Fatal(err)
	}
	return backend
}

func installedTrustFixture(t *testing.T, devops bool, active bool) string {
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
		t.Fatalf("write release fixture: %v", err)
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
	at := time.Date(2026, 9, 8, 3, 0, 0, 0, time.UTC)
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
				t.Fatalf("fixture phase %s has no successor", state.Active.Phase)
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
	return root
}

func newRootBundle(t *testing.T, commonName string) []byte {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	canonical, err := sourcetrust.Canonicalize(bundle, now)
	if err != nil {
		t.Fatalf("canonicalize generated root: %v", err)
	}
	return canonical
}

func writeTrustInput(t *testing.T, value []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roots.pem")
	writeExactTrustInput(t, path, value)
	return path
}

func writeExactTrustInput(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
}

func sourceTrustPath(t *testing.T, root string, tenant string, origin string) string {
	t.Helper()
	directory, err := sourcetrust.DirectoryName(
		devopsv1.ResourceScope{TenantID: devopsv1.TenantID(tenant)}, origin,
	)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(
		root, filepath.FromSlash(layout.DevOpsSourceTrustRoot), directory,
		sourcetrust.BundleFilename,
	)
}

func assertTrustFault(t *testing.T, err error, class cli.FaultClass, code string) {
	t.Helper()
	var value *cli.Fault
	if !errors.As(err, &value) || value.Class != class || value.Code != code {
		t.Fatalf("fault=%v (%#v), want %s/%s", err, value, class, code)
	}
}
