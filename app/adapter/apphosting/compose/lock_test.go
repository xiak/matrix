package compose

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

const (
	lockChildMode = "MATRIX_COMPOSE_LOCK_CHILD"
	lockChildRoot = "MATRIX_COMPOSE_LOCK_ROOT"
)

func TestProjectLockExcludesAnotherProcess(t *testing.T) {
	root, err := prepareManagedRoot(t.TempDir())
	if err != nil {
		t.Fatalf("prepare lock root: %v", err)
	}
	project := "matrix-0123456789abcdef01234567"
	lock, err := acquireProjectLock(context.Background(), root, project)
	if err != nil {
		t.Fatalf("acquire parent project lock: %v", err)
	}
	runLockChild(t, root, "blocked")
	if err := lock.Close(); err != nil {
		t.Fatalf("release parent project lock: %v", err)
	}
	runLockChild(t, root, "acquire")
}

func TestProjectLockChild(t *testing.T) {
	mode := os.Getenv(lockChildMode)
	if mode == "" {
		t.Skip("project-lock subprocess helper")
	}
	root, err := prepareManagedRoot(os.Getenv(lockChildRoot))
	if err != nil {
		t.Fatalf("prepare child lock root: %v", err)
	}
	project := "matrix-0123456789abcdef01234567"
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	lock, err := acquireProjectLock(ctx, root, project)
	switch mode {
	case "blocked":
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked child lock error = %v, want deadline", err)
		}
	case "acquire":
		if err != nil {
			t.Fatalf("acquire child lock: %v", err)
		}
		if err := lock.Close(); err != nil {
			t.Fatalf("release child lock: %v", err)
		}
	default:
		t.Fatalf("unknown project-lock child mode %q", mode)
	}
}

func runLockChild(t *testing.T, root, mode string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestProjectLockChild$", "-test.count=1")
	command.Env = append(os.Environ(), lockChildMode+"="+mode, lockChildRoot+"="+root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("project-lock child %s: %v: %s", mode, err, output)
	}
}
