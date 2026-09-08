package releasebuild

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLocalImageBuildEffectIsNetworkAndPullClosed(t *testing.T) {
	contextRoot := filepath.Join(t.TempDir(), "context")
	if err := os.Mkdir(contextRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contextRoot, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var observed localCommand
	effects := &LocalEffects{run: func(_ context.Context, command localCommand) ([]byte, error) {
		observed = command
		return nil, nil
	}}
	tag := "matrix-release-build/iam:0123456789abcdef01234567"
	if err := effects.BuildImage(context.Background(), contextRoot, tag); err != nil {
		t.Fatal(err)
	}
	if observed.program != "docker" || !slices.Contains(observed.args, "--network=none") ||
		!slices.Contains(observed.args, "--pull=false") || slices.Contains(observed.args, "--pull=true") {
		t.Fatalf("Docker build effect is not offline closed: %v", observed.args)
	}
}

func TestLocalGoBuildRejectsUnownedPackage(t *testing.T) {
	called := false
	effects := &LocalEffects{run: func(context.Context, localCommand) ([]byte, error) {
		called = true
		return nil, nil
	}}
	if err := effects.BuildGoBinary(context.Background(), t.TempDir(), "./customer/package", filepath.Join(t.TempDir(), "binary")); err == nil {
		t.Fatal("caller-selected Go package was accepted")
	}
	if called {
		t.Fatal("rejected Go package reached the provider effect")
	}
}

func TestLocalRunnerSandboxRejectsUnpinnedArchive(t *testing.T) {
	source := filepath.Join(t.TempDir(), "gvisor-x86_64.tar.zstd")
	if err := os.WriteFile(source, []byte("not the fixed gVisor archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "gvisor-x86_64.tar.zstd")
	if _, err := NewLocalEffects().StageRunnerSandbox(
		context.Background(), source, output,
	); err == nil {
		t.Fatal("changed gVisor archive was staged")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("rejected gVisor archive created a release payload")
	}
}

func TestLocalRunnerSandboxStagesPinnedOfficialArchive(t *testing.T) {
	source := os.Getenv("MATRIX_TEST_GVISOR_ARCHIVE")
	if source == "" {
		t.Skip("MATRIX_TEST_GVISOR_ARCHIVE is not set")
	}
	abs, err := filepath.Abs(source)
	if err != nil || filepath.Clean(abs) != source {
		t.Fatal("gVisor integration fixture path is not canonical and absolute")
	}
	output := filepath.Join(t.TempDir(), "gvisor-x86_64.tar.zstd")
	metadata, err := NewLocalEffects().StageRunnerSandbox(
		context.Background(), source, output,
	)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(output)
	if err != nil || !info.Mode().IsRegular() || uint64(info.Size()) != metadata.Size ||
		metadata.SHA256 != RunnerGVisorSHA256 {
		t.Fatalf("staged gVisor metadata=%#v info=%#v err=%v", metadata, info, err)
	}
}

func TestLocalRunnerToolchainStagesPinnedOfflineImage(t *testing.T) {
	if os.Getenv("MATRIX_TEST_RUNNER_TOOLCHAIN") != "1" {
		t.Skip("MATRIX_TEST_RUNNER_TOOLCHAIN is not enabled")
	}
	effects := NewLocalEffects()
	image, err := effects.InspectImage(context.Background(), RunnerToolchainReference)
	if err != nil || image.ID != RunnerToolchainSourceID {
		t.Fatalf("pinned toolchain image=%#v err=%v", image, err)
	}
	output := filepath.Join(t.TempDir(), "go-1.26-offline-v1.tar")
	loaded, err := effects.SaveImage(context.Background(), image.ID, output)
	if err != nil || loaded.ID != RunnerToolchainLoadID ||
		loaded.OS != "linux" || loaded.Architecture != "amd64" {
		t.Fatalf("portable toolchain identity=%#v err=%v", loaded, err)
	}
}
