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

func TestLocalImageInspectionAdmitsOnlyFixedBasesAndBuildTags(t *testing.T) {
	called := 0
	configID := testDigest("local-config")
	effects := &LocalEffects{run: func(_ context.Context, command localCommand) ([]byte, error) {
		called++
		if command.program != "docker" || len(command.args) != 3 ||
			command.args[0] != "image" || command.args[1] != "inspect" {
			t.Fatalf("unexpected image inspection command: %#v", command)
		}
		return []byte(`[{"Id":"` + configID + `","RepoDigests":["apache/apisix@` +
			APISIXBaseManifestDigest + `"],"Os":"linux","Architecture":"amd64"}]`), nil
	}}
	references := make([]string, 0, len(baseImageSpecifications)+1)
	for _, specification := range baseImageSpecifications {
		references = append(references, specification.reference)
	}
	references = append(references, "matrix-release-build/iam:0123456789abcdef01234567")
	for _, reference := range references {
		metadata, err := effects.InspectImage(context.Background(), reference)
		if err != nil {
			t.Fatalf("fixed image reference %q rejected: %v", reference, err)
		}
		if metadata.ID != configID || len(metadata.RepositoryDigests) != 1 ||
			metadata.RepositoryDigests[0] != "apache/apisix@"+APISIXBaseManifestDigest {
			t.Fatalf("image identity dimensions were collapsed: %#v", metadata)
		}
	}
	for _, rejected := range []string{APISIXBaseReference, "caller.example/arbitrary:latest"} {
		if _, err := effects.InspectImage(context.Background(), rejected); err == nil {
			t.Fatalf("mutable or caller-selected image reference %q was admitted", rejected)
		}
	}
	if called != len(references) {
		t.Fatalf("provider inspection calls = %d, want %d", called, len(references))
	}
}

func TestLocalFixedBaseImageInspection(t *testing.T) {
	if os.Getenv("MATRIX_RELEASEBUILD_DOCKER_TEST") != "1" {
		t.Skip("set MATRIX_RELEASEBUILD_DOCKER_TEST=1 with the sealed base images in a Docker 27 classic store")
	}
	images, err := verifyBaseImages(context.Background(), NewLocalEffects())
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != len(baseImageSpecifications) {
		t.Fatalf("verified base image count = %d, want %d", len(images), len(baseImageSpecifications))
	}
	for _, specification := range baseImageSpecifications {
		image, found := images[specification.reference]
		if !found || image.ID == specification.manifestDigest ||
			!hasRepositoryDigest(image.RepositoryDigests, specification.repository, specification.manifestDigest) {
			t.Fatalf("base image identities were not independently verified: %#v", image)
		}
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
	if err != nil || loaded.ID != RunnerToolchainArchiveConfigID ||
		loaded.OS != "linux" || loaded.Architecture != "amd64" {
		t.Fatalf("authenticated toolchain archive config=%#v err=%v", loaded, err)
	}
}
