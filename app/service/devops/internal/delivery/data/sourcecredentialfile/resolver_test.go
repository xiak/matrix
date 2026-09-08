package sourcecredentialfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
)

func TestResolveAtomicCurrentAndPreviousWebhookMaterial(t *testing.T) {
	root := privateTempDir(t)
	scope := devopsv1.ResourceScope{TenantID: "tenant:one"}
	reference := devopsv1.ResourceID("secret:webhook.v1")
	directory, err := sourcecredential.DirectoryName(
		sourcecredential.PurposeWebhook, scope, reference,
	)
	if err != nil {
		t.Fatal(err)
	}
	credentialDirectory := filepath.Join(root, directory)
	if err := os.Mkdir(credentialDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	current := []byte("current-webhook-secret-000000000001")
	previous := []byte("previous-webhook-secret-0000000001")
	writeMaterial(t, credentialDirectory, current, previous)
	resolver, err := NewResolver(sourcecredential.PurposeWebhook, root)
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
	if directory == string(reference) || filepath.Base(credentialDirectory) != directory || len(directory) != 64 {
		t.Fatalf("credential directory identity=%q", directory)
	}
}

func TestWebhookCredentialFilesystemFailsClosed(t *testing.T) {
	root := privateTempDir(t)
	resolver, err := NewResolver(sourcecredential.PurposeWebhook, root)
	if err != nil {
		t.Fatal(err)
	}
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	if _, err := resolver.ResolveWebhookSecrets(context.Background(), scope, "missing"); !errors.Is(err, sourceingress.ErrSecretNotFound) {
		t.Fatalf("missing credential error=%v", err)
	}
	emptyDirectory, err := sourcecredential.DirectoryName(
		sourcecredential.PurposeWebhook, scope, "missing-material",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, emptyDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveWebhookSecrets(context.Background(), scope, "missing-material"); !errors.Is(err, sourceingress.ErrSecretNotFound) {
		t.Fatalf("missing material error=%v", err)
	}

	directory, err := sourcecredential.DirectoryName(
		sourcecredential.PurposeWebhook, scope, "invalid-content",
	)
	if err != nil {
		t.Fatal(err)
	}
	credentialDirectory := filepath.Join(root, directory)
	if err := os.Mkdir(credentialDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	writePrivate(t, filepath.Join(credentialDirectory, sourcecredential.MaterialFilename), []byte("invalid"))
	if _, err := resolver.ResolveWebhookSecrets(context.Background(), scope, "invalid-content"); err == nil || errors.Is(err, sourceingress.ErrSecretNotFound) {
		t.Fatalf("invalid credential content error=%v", err)
	}
}

func TestResolvePurposeBoundFetchAndReportMaterial(t *testing.T) {
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	for _, purpose := range []sourcecredential.Purpose{
		sourcecredential.PurposeFetch, sourcecredential.PurposeReport,
	} {
		t.Run(string(purpose), func(t *testing.T) {
			root := privateTempDir(t)
			reference := devopsv1.ResourceID("credential-" + string(purpose))
			directory, err := sourcecredential.DirectoryName(purpose, scope, reference)
			if err != nil {
				t.Fatal(err)
			}
			credentialDirectory := filepath.Join(root, directory)
			if err := os.Mkdir(credentialDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			current := []byte("provider-token-0000000000000000000001")
			writePurposeMaterial(t, purpose, credentialDirectory, current, nil)
			resolver, err := NewResolver(purpose, root)
			if err != nil {
				t.Fatal(err)
			}
			material, err := resolver.Resolve(context.Background(), scope, reference)
			if err != nil {
				t.Fatal(err)
			}
			defer material.Clear()
			if string(material.Current) != string(current) || len(material.Previous) != 0 {
				t.Fatal("purpose-bound source credential differed")
			}
		})
	}
}

func TestWebhookCredentialFilesystemRejectsLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unprivileged Windows symlink creation is not portable")
	}
	root := privateTempDir(t)
	target := privateTempDir(t)
	if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewResolver(sourcecredential.PurposeWebhook, filepath.Join(root, "linked")); err == nil {
		t.Fatal("symlinked credential root was accepted")
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

func writeMaterial(t *testing.T, directory string, current, previous []byte) {
	t.Helper()
	writePurposeMaterial(
		t, sourcecredential.PurposeWebhook, directory, current, previous,
	)
}

func writePurposeMaterial(
	t *testing.T,
	purpose sourcecredential.Purpose,
	directory string,
	current, previous []byte,
) {
	t.Helper()
	material, err := sourcecredential.NewMaterial(
		purpose, current, previous,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	content, err := sourcecredential.Encode(purpose, material)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(content)
	writePrivate(t, filepath.Join(directory, sourcecredential.MaterialFilename), content)
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
