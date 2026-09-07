package webhooksecretfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
)

func TestResolveCurrentAndPreviousWebhookSecrets(t *testing.T) {
	root := privateTempDir(t)
	scope := devopsv1.ResourceScope{TenantID: "tenant:one"}
	reference := devopsv1.ResourceID("secret:webhook.v1")
	directory, err := DirectoryName(scope, reference)
	if err != nil {
		t.Fatal(err)
	}
	secretDirectory := filepath.Join(root, directory)
	if err := os.Mkdir(secretDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	current := []byte("current-webhook-secret-000000000001")
	previous := []byte("previous-webhook-secret-0000000001")
	writePrivate(t, filepath.Join(secretDirectory, "current"), current)
	writePrivate(t, filepath.Join(secretDirectory, "previous"), previous)
	resolver, err := NewResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	set, err := resolver.ResolveWebhookSecrets(context.Background(), scope, reference)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Clear()
	for name, candidate := range map[string][]byte{"current": current, "previous": previous} {
		if !set.Matches(func(value []byte) bool { return string(value) == string(candidate) }) {
			t.Fatalf("%s rotation value was not resolved", name)
		}
	}
	if directory == string(reference) || filepath.Base(secretDirectory) != directory || len(directory) != 64 {
		t.Fatalf("secret directory identity=%q", directory)
	}
}

func TestWebhookSecretFilesystemFailsClosed(t *testing.T) {
	root := privateTempDir(t)
	resolver, err := NewResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	if _, err := resolver.ResolveWebhookSecrets(context.Background(), scope, "missing"); !errors.Is(err, sourceingress.ErrSecretNotFound) {
		t.Fatalf("missing secret error=%v", err)
	}
	emptyDirectory, err := DirectoryName(scope, "missing-current")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, emptyDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveWebhookSecrets(context.Background(), scope, "missing-current"); !errors.Is(err, sourceingress.ErrSecretNotFound) {
		t.Fatalf("missing current secret error=%v", err)
	}

	directory, err := DirectoryName(scope, "invalid-content")
	if err != nil {
		t.Fatal(err)
	}
	secretDirectory := filepath.Join(root, directory)
	if err := os.Mkdir(secretDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	writePrivate(t, filepath.Join(secretDirectory, "current"), []byte("short"))
	if _, err := resolver.ResolveWebhookSecrets(context.Background(), scope, "invalid-content"); err == nil || errors.Is(err, sourceingress.ErrSecretNotFound) {
		t.Fatalf("invalid secret content error=%v", err)
	}
}

func TestWebhookSecretFilesystemRejectsLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unprivileged Windows symlink creation is not portable")
	}
	root := privateTempDir(t)
	target := privateTempDir(t)
	if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewResolver(filepath.Join(root, "linked")); err == nil {
		t.Fatal("symlinked secret root was accepted")
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func writePrivate(t *testing.T, path string, value []byte) {
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
