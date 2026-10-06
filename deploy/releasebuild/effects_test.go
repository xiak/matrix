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
	for _, reference := range []string{
		APISIXBasePinnedReference, AlpineBasePinnedReference, DockerBasePinnedReference, PostgresPinnedReference,
		"matrix-release-build/iam:0123456789abcdef01234567",
	} {
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
	if called != 5 {
		t.Fatalf("provider inspection calls = %d, want 5", called)
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
