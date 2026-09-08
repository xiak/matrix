package executorspoolfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSpoolOwnershipIsExclusiveAndCrashRecoverable(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("gateway ownership is supported only on accepted runtime platforms")
	}
	root := spoolRoot(t)
	first, err := AcquireOwnership(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := New(root); err != nil {
		t.Fatalf("open owned spool: %v", err)
	}
	if _, err := AcquireOwnership(root); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("duplicate spool ownership error=%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := AcquireOwnership(root)
	if err != nil {
		t.Fatalf("recover released spool ownership: %v", err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatalf("ownership close replay: %v", err)
	}
}

func TestSpoolOwnershipRejectsTamperedLockFile(t *testing.T) {
	root := spoolRoot(t)
	path := filepath.Join(root, ownershipLockName)
	if err := os.WriteFile(path, []byte("forged-owner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireOwnership(root); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("content-bearing ownership file error=%v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err == nil {
		if _, err := AcquireOwnership(root); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("linked ownership file error=%v", err)
		}
	}
}
