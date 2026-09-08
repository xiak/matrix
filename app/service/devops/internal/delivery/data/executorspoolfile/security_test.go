package executorspoolfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
)

func TestSpoolRejectsUnsafeRootAndForeignInventory(t *testing.T) {
	if _, err := New("relative-spool"); err == nil {
		t.Fatal("relative spool root was accepted")
	}
	if runtime.GOOS != "windows" {
		public := spoolRoot(t)
		if err := os.Chmod(public, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := New(public); err == nil {
			t.Fatal("public spool root was accepted")
		}
	}
	root := spoolRoot(t)
	if err := os.WriteFile(filepath.Join(root, "foreign"), []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("foreign spool inventory error=%v", err)
	}

	target := spoolRoot(t)
	linkParent := t.TempDir()
	link := filepath.Join(linkParent, "spool-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := New(link); err == nil {
		t.Fatal("symbolic-link spool root was accepted")
	}
}

func TestSpoolRejectsUnsafePublishedFileShape(t *testing.T) {
	for _, name := range []string{"broad mode", "symbolic archive"} {
		t.Run(name, func(t *testing.T) {
			root := spoolRoot(t)
			spool, err := New(root)
			if err != nil {
				t.Fatal(err)
			}
			request, archive := executionFixture(t, 'a', fixtureStart())
			if _, err := spool.Create(
				context.Background(), submissionFrame(t, request, archive),
			); err != nil {
				t.Fatal(err)
			}
			executionID, _ := devopsbuildv1.ExecutionID(request)
			directory := filepath.Join(root, executionKey(executionID))
			switch name {
			case "broad mode":
				if runtime.GOOS == "windows" {
					t.Skip("Windows ACLs are enforced by installation ownership")
				}
				if err := os.Chmod(filepath.Join(directory, submissionName), 0o644); err != nil {
					t.Fatal(err)
				}
			case "symbolic archive":
				archivePath := filepath.Join(directory, archiveName)
				external := filepath.Join(t.TempDir(), "external.tar.gz")
				if err := os.WriteFile(external, archive, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(archivePath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(external, archivePath); err != nil {
					t.Skipf("symbolic links unavailable: %v", err)
				}
			}
			if _, err := spool.Observe(
				context.Background(), request,
			); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unsafe published shape error=%v", err)
			}
		})
	}
}
