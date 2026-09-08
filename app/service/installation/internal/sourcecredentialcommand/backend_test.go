package sourcecredentialcommand_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/localmachine"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/internal/sourcecredentialcommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

func TestInstalledDevOpsSourceCredentialJourney(t *testing.T) {
	root, _ := installedFixture(t, true, false)
	backend := newBackend(t)
	tenant := "tenant:one"
	webhookReference := "webhook:v1"
	firstWebhook := []byte("first-webhook-secret-000000000000001")
	secondWebhook := []byte("second-webhook-secret-00000000000001")
	input := writeInput(t, firstWebhook)

	request := cli.SourceCredentialRequest{
		Operation: cli.SourceCredentialApply, Root: root, TenantID: tenant,
		Purpose: sourcecredential.PurposeWebhook, Reference: webhookReference,
		FromFile: input,
	}
	result, err := backend.RunSourceCredential(context.Background(), request)
	if err != nil || result.State != string(sourcecredentialcommand.StateApplied) {
		t.Fatalf("apply first webhook credential=%#v err=%v", result, err)
	}
	material := readMaterial(
		t, root, sourcecredential.PurposeWebhook, tenant, webhookReference,
	)
	if !bytes.Equal(material.Current, firstWebhook) || len(material.Previous) != 0 {
		material.Clear()
		t.Fatal("initial webhook material is invalid")
	}
	material.Clear()
	result, err = backend.RunSourceCredential(context.Background(), request)
	if err != nil || result.State != string(sourcecredentialcommand.StateUnchanged) {
		t.Fatalf("reapply equal webhook credential=%#v err=%v", result, err)
	}

	writeExactInput(t, input, secondWebhook)
	result, err = backend.RunSourceCredential(context.Background(), request)
	if err != nil || result.State != string(sourcecredentialcommand.StateApplied) {
		t.Fatalf("rotate webhook credential=%#v err=%v", result, err)
	}
	material = readMaterial(
		t, root, sourcecredential.PurposeWebhook, tenant, webhookReference,
	)
	if !bytes.Equal(material.Current, secondWebhook) ||
		!bytes.Equal(material.Previous, firstWebhook) {
		material.Clear()
		t.Fatal("webhook rotation was not committed as one material set")
	}
	material.Clear()
	if actual, err := os.ReadFile(input); err != nil || !bytes.Equal(actual, secondWebhook) {
		clear(actual)
		t.Fatal("apply modified the operator input file")
	} else {
		clear(actual)
	}

	request.Operation = cli.SourceCredentialRetirePrevious
	request.FromFile = ""
	for attempt := 0; attempt < 2; attempt++ {
		result, err = backend.RunSourceCredential(context.Background(), request)
		if err != nil || result.State != string(sourcecredentialcommand.StatePreviousRetired) {
			t.Fatalf("retire previous webhook attempt %d=%#v err=%v", attempt, result, err)
		}
	}
	material = readMaterial(
		t, root, sourcecredential.PurposeWebhook, tenant, webhookReference,
	)
	if !bytes.Equal(material.Current, secondWebhook) || len(material.Previous) != 0 {
		material.Clear()
		t.Fatal("previous webhook credential was not retired")
	}
	material.Clear()

	for _, purpose := range []sourcecredential.Purpose{
		sourcecredential.PurposeFetch, sourcecredential.PurposeReport,
	} {
		value := []byte("provider-token-000000000000000000000001")
		purposeInput := writeInput(t, value)
		purposeRequest := cli.SourceCredentialRequest{
			Operation: cli.SourceCredentialApply, Root: root, TenantID: tenant,
			Purpose: purpose, Reference: string(purpose) + ":v1", FromFile: purposeInput,
		}
		result, err = backend.RunSourceCredential(context.Background(), purposeRequest)
		if err != nil || result.State != string(sourcecredentialcommand.StateApplied) {
			t.Fatalf("apply %s credential=%#v err=%v", purpose, result, err)
		}
		material = readMaterial(t, root, purpose, tenant, purposeRequest.Reference)
		if !bytes.Equal(material.Current, value) || len(material.Previous) != 0 {
			material.Clear()
			t.Fatalf("%s material is invalid", purpose)
		}
		material.Clear()
	}
}

func TestSourceCredentialCommandAuthenticatesIdleSelectedRelease(t *testing.T) {
	input := writeInput(t, []byte("source-credential-00000000000000000001"))
	request := cli.SourceCredentialRequest{
		Operation: cli.SourceCredentialApply, TenantID: "tenant-one",
		Purpose: sourcecredential.PurposeWebhook, Reference: "webhook.v1",
		FromFile: input,
	}

	paasRoot, _ := installedFixture(t, false, false)
	request.Root = paasRoot
	_, err := newBackend(t).RunSourceCredential(context.Background(), request)
	assertFault(t, err, cli.FaultPrecondition, "DEVOPS_PRODUCT_NOT_INSTALLED")
	if _, statErr := os.Lstat(filepath.Join(paasRoot, "secrets", "devops")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unselected DevOps command created credential storage: %v", statErr)
	}

	activeRoot, _ := installedFixture(t, true, true)
	request.Root = activeRoot
	_, err = newBackend(t).RunSourceCredential(context.Background(), request)
	assertFault(t, err, cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")

	tamperedRoot, _ := installedFixture(t, true, false)
	request.Root = tamperedRoot
	trustPath := filepath.Join(tamperedRoot, filepath.FromSlash(layout.ReleaseTrust))
	if err := os.WriteFile(trustPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = newBackend(t).RunSourceCredential(context.Background(), request)
	assertFault(t, err, cli.FaultVerification, "INSTALLATION_RELEASE_INVALID")
}

func TestSourceCredentialCommandRejectsUnsafeInputAndStoredMaterial(t *testing.T) {
	root, _ := installedFixture(t, true, false)
	backend := newBackend(t)
	input := writeInput(t, []byte("short"))
	request := cli.SourceCredentialRequest{
		Operation: cli.SourceCredentialApply, Root: root, TenantID: "tenant-one",
		Purpose: sourcecredential.PurposeWebhook, Reference: "webhook.v1",
		FromFile: input,
	}
	_, err := backend.RunSourceCredential(context.Background(), request)
	assertFault(t, err, cli.FaultInvalidArgument, "SOURCE_CREDENTIAL_INPUT_INVALID")

	writeExactInput(t, input, []byte("valid-webhook-secret-0000000000000001"))
	if _, err := backend.RunSourceCredential(context.Background(), request); err != nil {
		t.Fatalf("apply valid fixture: %v", err)
	}
	materialPath := credentialMaterialPath(
		t, root, sourcecredential.PurposeWebhook, request.TenantID, request.Reference,
	)
	if err := os.WriteFile(materialPath, []byte("not-canonical-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeExactInput(t, input, []byte("next-webhook-secret-00000000000000001"))
	_, err = backend.RunSourceCredential(context.Background(), request)
	assertFault(t, err, cli.FaultVerification, "SOURCE_CREDENTIAL_STATE_INVALID")

	if runtime.GOOS != "windows" {
		otherRoot, _ := installedFixture(t, true, false)
		request.Root = otherRoot
		broad := writeInput(t, []byte("valid-webhook-secret-0000000000000001"))
		if err := os.Chmod(broad, 0o644); err != nil {
			t.Fatal(err)
		}
		request.FromFile = broad
		_, err = backend.RunSourceCredential(context.Background(), request)
		assertFault(t, err, cli.FaultInvalidArgument, "SOURCE_CREDENTIAL_INPUT_INVALID")
	}
}

func newBackend(t *testing.T) *sourcecredentialcommand.Backend {
	t.Helper()
	backend, err := sourcecredentialcommand.NewBackend(localmachine.NewEffects(nil))
	if err != nil {
		t.Fatal(err)
	}
	return backend
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
	return root, fixture
}

func writeInput(t *testing.T, value []byte) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "credential")
	writeExactInput(t, path, value)
	return path
}

func writeExactInput(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func readMaterial(
	t *testing.T,
	root string,
	purpose sourcecredential.Purpose,
	tenant string,
	reference string,
) sourcecredential.Material {
	t.Helper()
	content, err := os.ReadFile(credentialMaterialPath(t, root, purpose, tenant, reference))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(content)
	material, err := sourcecredential.Decode(purpose, content)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func credentialMaterialPath(
	t *testing.T,
	root string,
	purpose sourcecredential.Purpose,
	tenant string,
	reference string,
) string {
	t.Helper()
	directory, err := sourcecredential.DirectoryName(
		purpose,
		devopsv1.ResourceScope{TenantID: devopsv1.TenantID(tenant)},
		devopsv1.ResourceID(reference),
	)
	if err != nil {
		t.Fatal(err)
	}
	relativeRoot := map[sourcecredential.Purpose]string{
		sourcecredential.PurposeWebhook: layout.DevOpsWebhookCredentialRoot,
		sourcecredential.PurposeFetch:   layout.DevOpsFetchCredentialRoot,
		sourcecredential.PurposeReport:  layout.DevOpsReportCredentialRoot,
	}[purpose]
	return filepath.Join(
		root, filepath.FromSlash(relativeRoot), directory, sourcecredential.MaterialFilename,
	)
}

func assertFault(
	t *testing.T,
	err error,
	class cli.FaultClass,
	code string,
) {
	t.Helper()
	var value *cli.Fault
	if !errors.As(err, &value) || value.Class != class || value.Code != code {
		t.Fatalf("fault=%v (%#v), want %s/%s", err, value, class, code)
	}
}
