package releasebuild

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func TestLocalWorkloadShellVerificationIsIsolatedAndNonRoot(t *testing.T) {
	var observed localCommand
	effects := &LocalEffects{run: func(_ context.Context, command localCommand) ([]byte, error) {
		observed = command
		return nil, nil
	}}
	imageID := "sha256:" + strings.Repeat("a", 64)
	if err := effects.VerifyWorkloadShell(context.Background(), imageID); err != nil {
		t.Fatal(err)
	}
	for _, argument := range []string{
		"--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--user", "65534:65534", "--entrypoint", "/bin/sh",
	} {
		if !slices.Contains(observed.args, argument) {
			t.Fatalf("workload shell verification lost %q: %v", argument, observed.args)
		}
	}
	if observed.program != "docker" || slices.Contains(observed.args, "--privileged") ||
		observed.args[len(observed.args)-2] != "-c" || observed.args[len(observed.args)-1] != "test -x /bin/sh" {
		t.Fatalf("workload shell verification escaped its fixed command: %v", observed.args)
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

func TestLocalGoBuildSupportsTheClosedNodePayloads(t *testing.T) {
	root := t.TempDir()
	for _, packagePath := range []string{"./app/service/installation/cmd/mx", "./app/service/nodeagent/cmd/matrix-node-agent"} {
		called := false
		effects := &LocalEffects{run: func(_ context.Context, command localCommand) ([]byte, error) {
			called = true
			if command.program != "go" || command.dir != root ||
				!slices.Contains(command.args, "-mod=readonly") || !slices.Contains(command.args, "-buildvcs=true") ||
				!slices.Contains(command.args, packagePath) || !slices.Contains(command.env, "GOOS=linux") ||
				!slices.Contains(command.env, "GOARCH=amd64") || !slices.Contains(command.env, "CGO_ENABLED=0") {
				t.Fatal("node payload build lost its source or target constraints")
			}
			return nil, nil
		}}
		if err := effects.BuildGoBinary(context.Background(), root, packagePath, filepath.Join(root, "binary")); err != nil || !called {
			t.Fatalf("owned node payload was not built: %v", err)
		}
	}
}
