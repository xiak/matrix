package localmachine

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/xiak/matrix/app/service/installation/internal/runnerenrollment"
	"github.com/xiak/matrix/app/service/installation/internal/runnernodecommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

type recordingRunnerNodeSystem struct {
	err             error
	preflightCalled bool
	convergeCalled  bool
	plan            runnerSystemPlan
}

func (system *recordingRunnerNodeSystem) Preflight(
	_ context.Context,
	plan runnerSystemPlan,
) error {
	system.preflightCalled = true
	system.plan = plan
	if system.err != nil {
		return system.err
	}
	return validateRunnerSystemPlan(plan)
}

func (system *recordingRunnerNodeSystem) Converge(
	_ context.Context,
	plan runnerSystemPlan,
) error {
	system.convergeCalled = true
	system.plan = plan
	return validateRunnerSystemPlan(plan)
}

func TestGVisorArchiveExtractionRejectsDriftAndUnexpectedEntries(t *testing.T) {
	entries := []fixedGVisorEntry{
		{path: "runsc", size: 5},
		{path: "gvisor-bin", directory: true},
		{path: "gvisor-bin/sidecar", size: 7},
	}
	archive := filepath.Join(t.TempDir(), "gvisor.tar.zstd")
	writeGVisorTestArchive(t, archive, entries, "")
	target := filepath.Join(t.TempDir(), "gvisor")
	if err := extractGVisorArchive(archive, target, entries); err != nil {
		t.Fatal(err)
	}
	if err := verifyGVisorExtraction(archive, target, entries); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "runsc"), []byte("drift"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := verifyGVisorExtraction(archive, target, entries); err == nil {
		t.Fatal("changed installed gVisor executable was accepted")
	}

	unexpected := filepath.Join(t.TempDir(), "gvisor.tar.zstd")
	writeGVisorTestArchive(t, unexpected, entries, "unexpected")
	if err := extractGVisorArchive(unexpected, filepath.Join(t.TempDir(), "output"), entries); err == nil {
		t.Fatal("unexpected gVisor archive entry was extracted")
	}
}

func TestFixedGVisorArchiveExtractsAndReverifiesIntegration(t *testing.T) {
	archive := os.Getenv("MATRIX_TEST_GVISOR_ARCHIVE")
	if archive == "" {
		t.Skip("MATRIX_TEST_GVISOR_ARCHIVE is not set")
	}
	abs, err := filepath.Abs(archive)
	if err != nil || filepath.Clean(abs) != archive {
		t.Fatal("gVisor fixture path must be canonical and absolute")
	}
	target := filepath.Join(t.TempDir(), "gvisor")
	if err := extractFixedGVisorArchive(archive, target); err != nil {
		t.Fatal(err)
	}
	if err := verifyFixedGVisorExtraction(archive, target); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerInstallationPreflightsHostBeforePublishingMaterials(t *testing.T) {
	platform := newDevOpsInstallPlan(t)
	if err := stageInstallation(platform, rand.Reader); err != nil {
		t.Fatal(err)
	}
	effects := NewEffects(nil)
	pins, err := readRunnerAuthorityPins(platform.Root, platform.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	nodeRoot := filepath.Join(t.TempDir(), "runner-node")
	request, err := effects.CreateRunnerRequest(context.Background(), runnernodecommand.CreateRequestPlan{
		Root: nodeRoot, Bundle: platform.Bundle, InstallationID: platform.InstallationID,
		NodeID: "runner-one", Slots: 1, GatewayOrigin: "https://192.0.2.10:8444",
		AuthorityPins: pins,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := effects.EnrollRunner(context.Background(), runnernodecommand.EnrollPlan{
		Root: platform.Root, InstallationID: platform.InstallationID, Bundle: platform.Bundle,
		Request: request, Output: filepath.Join(t.TempDir(), "enrollment.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	preflightFailure := errors.New("runner host preflight blocked")
	system := &recordingRunnerNodeSystem{err: preflightFailure}
	effects.runnerSystem = system
	_, err = effects.InstallRunnerNode(context.Background(), runnernodecommand.InstallPlan{
		Root: nodeRoot, Bundle: platform.Bundle, Request: request, Enrollment: enrollment,
	})
	if !errors.Is(err, preflightFailure) || !system.preflightCalled || system.convergeCalled {
		t.Fatalf("preflight result=%v system=%#v", err, system)
	}
	if _, statErr := os.Lstat(filepath.Join(nodeRoot, runnerInstalledDirectory)); !errors.Is(
		statErr, os.ErrNotExist,
	) {
		t.Fatalf("failed preflight published runner materials: %v", statErr)
	}
}

func TestRunnerInstallationPublishesAuthenticOfflineMaterialsIntegration(t *testing.T) {
	external := map[string]string{
		release.RunnerBinaryPath:           os.Getenv("MATRIX_TEST_RUNNER_BINARY"),
		release.RunnerToolchainArchivePath: os.Getenv("MATRIX_TEST_RUNNER_TOOLCHAIN_ARCHIVE"),
		release.RunnerGVisorArchivePath:    os.Getenv("MATRIX_TEST_GVISOR_ARCHIVE"),
	}
	for _, source := range external {
		if source == "" {
			t.Skip("authentic runner installation fixtures are not set")
		}
		absolute, err := filepath.Abs(source)
		info, statErr := os.Lstat(source)
		if err != nil || filepath.Clean(absolute) != source || statErr != nil ||
			info == nil || !info.Mode().IsRegular() || managedPathIsLink(source, info) || info.Size() <= 0 {
			t.Fatal("authentic runner installation fixture is unsafe")
		}
	}
	_, gvisorDigest := runnerIntegrationFileIdentity(t, external[release.RunnerGVisorArchivePath])
	if gvisorDigest != release.RunnerGVisorArchiveSHA256 {
		t.Fatalf("gVisor fixture digest=%s, want %s", gvisorDigest, release.RunnerGVisorArchiveSHA256)
	}

	platform := newDevOpsInstallPlan(t)
	if err := stageInstallation(platform, rand.Reader); err != nil {
		t.Fatal(err)
	}
	effects := NewEffects(nil)
	pins, err := readRunnerAuthorityPins(platform.Root, platform.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	nodeRoot := filepath.Join(t.TempDir(), "runner-node")
	request, err := effects.CreateRunnerRequest(context.Background(), runnernodecommand.CreateRequestPlan{
		Root: nodeRoot, Bundle: platform.Bundle, InstallationID: platform.InstallationID,
		NodeID: "runner-one", Slots: 2, GatewayOrigin: "https://192.0.2.10:8444",
		AuthorityPins: pins,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := effects.EnrollRunner(context.Background(), runnernodecommand.EnrollPlan{
		Root: platform.Root, InstallationID: platform.InstallationID, Bundle: platform.Bundle,
		Request: request, Output: filepath.Join(t.TempDir(), "enrollment.json"),
	})
	if err != nil {
		t.Fatal(err)
	}

	bundleRoot := t.TempDir()
	for relative, source := range external {
		runnerIntegrationCopy(t, source, filepath.Join(bundleRoot, filepath.FromSlash(relative)), relative == release.RunnerBinaryPath)
	}
	checksumTarget := filepath.Join(bundleRoot, filepath.FromSlash(release.RunnerGVisorChecksumPath))
	if err := os.MkdirAll(filepath.Dir(checksumTarget), 0o700); err != nil ||
		os.WriteFile(checksumTarget, release.RunnerGVisorChecksumContent(), 0o600) != nil {
		t.Fatal("write runner gVisor checksum fixture failed")
	}
	manifest := platform.Bundle.Manifest
	for _, relative := range release.RunnerPayloadPaths() {
		runnerIntegrationUpdateDeclaration(
			t, &manifest, relative, filepath.Join(bundleRoot, filepath.FromSlash(relative)),
		)
	}
	bundle := release.VerifiedBundle{Root: bundleRoot, Manifest: manifest}
	system := &recordingRunnerNodeSystem{}
	effects.runnerSystem = system
	evidence, err := effects.InstallRunnerNode(context.Background(), runnernodecommand.InstallPlan{
		Root: nodeRoot, Bundle: bundle, Request: request, Enrollment: enrollment,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := runnerenrollment.RequestDigest(request)
	if !system.preflightCalled || !system.convergeCalled || evidence != (runnernodecommand.InstallationEvidence{
		ReleaseID: request.ReleaseID, InstallationID: request.InstallationID,
		NodeID: request.NodeID, Slots: 2, RequestDigest: digest,
	}) {
		t.Fatalf("authentic runner installation evidence=%#v system=%#v", evidence, system)
	}
	installedPath := filepath.Join(nodeRoot, runnerInstalledDirectory)
	installedBefore, err := os.Lstat(installedPath)
	if err != nil {
		t.Fatal(err)
	}
	system.preflightCalled = false
	system.convergeCalled = false
	replayed, err := effects.InstallRunnerNode(context.Background(), runnernodecommand.InstallPlan{
		Root: nodeRoot, Bundle: bundle, Request: request, Enrollment: enrollment,
	})
	installedAfter, statErr := os.Lstat(installedPath)
	if err != nil || statErr != nil || replayed != evidence ||
		!os.SameFile(installedBefore, installedAfter) || !system.preflightCalled || !system.convergeCalled {
		t.Fatalf("authentic runner installation replay=%#v err=%v stat=%v", replayed, err, statErr)
	}
}

func runnerIntegrationCopy(t *testing.T, source, target string, executable bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	input, err := openManagedRegularNoFollow(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	syncErr := output.Sync()
	closeErr := output.Close()
	mode := os.FileMode(0o600)
	if executable {
		mode = 0o700
	}
	if copyErr != nil || syncErr != nil || closeErr != nil || os.Chmod(target, mode) != nil {
		t.Fatal("copy authentic runner installation fixture failed")
	}
}

func runnerIntegrationUpdateDeclaration(
	t *testing.T,
	manifest *release.Manifest,
	relative string,
	target string,
) {
	t.Helper()
	size, digest := runnerIntegrationFileIdentity(t, target)
	for index := range manifest.Files {
		if manifest.Files[index].Path == relative {
			manifest.Files[index].Size = uint64(size)
			manifest.Files[index].SHA256 = digest
			return
		}
	}
	t.Fatalf("runner payload declaration %s is missing", relative)
}

func runnerIntegrationFileIdentity(t *testing.T, target string) (int64, string) {
	t.Helper()
	file, err := openManagedRegularNoFollow(target)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil || size <= 0 {
		t.Fatalf("hash runner integration fixture: %v", err)
	}
	return size, "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func TestRunnerSystemPlanUsesLiteralGatewayAndDisjointSlots(t *testing.T) {
	request := runnerenrollment.Request{
		ReleaseID: "matrix-v0.1.0-aaaaaaaaaaaa", InstallationID: "mxi-11111111111111111111111111111111",
		NodeID: "runner-one", GatewayOrigin: "https://192.0.2.10:8444",
		RunnerNamespace: "spiffe://matrix.local/devops/installations/mxi-11111111111111111111111111111111/runners",
		Slots: []runnerenrollment.SlotRequest{
			{Index: 1, Identity: "slot-one"}, {Index: 2, Identity: "slot-two"},
		},
	}
	root := filepath.Join(t.TempDir(), "runner")
	plan, err := newRunnerSystemPlan(root, request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.GatewayAddress != "192.0.2.10" || len(plan.Slots) != 2 ||
		plan.Slots[0].Listen != "127.0.0.1:18081" || plan.Slots[1].Listen != "127.0.0.1:18082" ||
		plan.Slots[0].StorageRoot == plan.Slots[1].StorageRoot ||
		plan.Slots[0].ClientKey == plan.Slots[1].ClientKey {
		t.Fatalf("runner system plan is not closed: %#v", plan)
	}
	request.GatewayOrigin = "https://runner.example.test:8444"
	if _, err := newRunnerSystemPlan(root, request); err == nil {
		t.Fatal("DNS gateway escaped literal firewall plan")
	}
}

func writeGVisorTestArchive(
	t *testing.T,
	path string,
	entries []fixedGVisorEntry,
	extra string,
) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	encoder, err := zstd.NewWriter(file, zstd.WithEncoderConcurrency(1))
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	writer := tar.NewWriter(encoder)
	for _, entry := range entries {
		typeFlag := byte(tar.TypeReg)
		if entry.directory {
			typeFlag = tar.TypeDir
		}
		if err := writer.WriteHeader(&tar.Header{
			Name: entry.path, Mode: 0o755, Size: entry.size, Typeflag: typeFlag,
		}); err != nil {
			t.Fatal(err)
		}
		if !entry.directory {
			content := bytes.Repeat([]byte{entry.path[0]}, int(entry.size))
			if _, err := writer.Write(content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if extra != "" {
		if err := writer.WriteHeader(&tar.Header{Name: extra, Mode: 0o755, Size: 1, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
