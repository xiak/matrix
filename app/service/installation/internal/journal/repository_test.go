package journal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
)

func TestSessionPersistsSealedMonotonicJournal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "installation")
	session, err := Acquire(context.Background(), root)
	if err != nil {
		t.Fatalf("acquire new installation: %v", err)
	}
	initial := activeInstallJournal(t)
	initialized, err := session.Initialized()
	if err != nil || initialized {
		t.Fatalf("new initialization state = %t / %v", initialized, err)
	}
	if err := session.Initialize(initial); err != nil {
		t.Fatalf("initialize journal: %v", err)
	}
	if err := session.Initialize(initial); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second initialization error = %v", err)
	}
	stored, err := session.Read()
	if err != nil || !reflect.DeepEqual(stored, initial) {
		t.Fatalf("stored initial journal = %#v / %v", stored, err)
	}

	advanced, err := lifecycle.Advance(
		initial,
		initial.Active.Command.ID,
		lifecycle.PhaseStaging,
		initial.Active.UpdatedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatalf("advance journal fixture: %v", err)
	}
	if err := session.Write(advanced); err != nil {
		t.Fatalf("write advanced journal: %v", err)
	}
	if err := session.Write(advanced); err == nil {
		t.Fatal("same or stale journal version must fail")
	}
	stored, err = session.Read()
	if err != nil || !reflect.DeepEqual(stored, advanced) {
		t.Fatalf("stored advanced journal = %#v / %v", stored, err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close installation session: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}

	reopened, err := Acquire(context.Background(), root)
	if err != nil {
		t.Fatalf("reopen installation: %v", err)
	}
	defer reopened.Close()
	stored, err = reopened.Read()
	if err != nil || !reflect.DeepEqual(stored, advanced) {
		t.Fatalf("reopened journal = %#v / %v", stored, err)
	}
	assertProtectedPath(t, root, true)
	assertProtectedPath(t, filepath.Join(root, stateDirectoryName), true)
	assertProtectedPath(t, filepath.Join(root, stateDirectoryName, keyFilename), false)
	assertProtectedPath(t, filepath.Join(root, stateDirectoryName, journalFilename), false)
}

func TestSessionRejectsJournalAndKeyTampering(t *testing.T) {
	t.Run("journal", func(t *testing.T) {
		root := initializedRoot(t)
		journalPath := filepath.Join(root, stateDirectoryName, journalFilename)
		content, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatalf("read sealed journal: %v", err)
		}
		index := strings.Index(string(content), "PREFLIGHT")
		if index < 0 {
			t.Fatal("sealed journal fixture lacks active phase")
		}
		content[index] = 'Q'
		if err := os.WriteFile(journalPath, content, managedFileMode); err != nil {
			t.Fatalf("tamper sealed journal: %v", err)
		}
		session, err := Acquire(context.Background(), root)
		if err != nil {
			t.Fatalf("acquire tampered installation: %v", err)
		}
		defer session.Close()
		if _, err := session.Read(); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("tampered journal read error = %v", err)
		}
	})

	t.Run("key", func(t *testing.T) {
		root := initializedRoot(t)
		keyPath := filepath.Join(root, stateDirectoryName, keyFilename)
		key, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatalf("read seal key: %v", err)
		}
		key[0] ^= 0xff
		if err := os.WriteFile(keyPath, key, managedFileMode); err != nil {
			t.Fatalf("tamper seal key: %v", err)
		}
		session, err := Acquire(context.Background(), root)
		if err != nil {
			t.Fatalf("acquire key-tampered installation: %v", err)
		}
		defer session.Close()
		if _, err := session.Read(); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("tampered key read error = %v", err)
		}
	})
}

func TestSessionRecoversInterruptedKeyCreation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "installation")
	session, err := Acquire(context.Background(), root)
	if err != nil {
		t.Fatalf("acquire new installation: %v", err)
	}
	defer session.Close()
	key, err := readOrCreateKey(
		filepath.Join(session.state, keyFilename),
		session.state,
	)
	if err != nil {
		t.Fatalf("create interrupted seal key: %v", err)
	}
	wipe(key)
	initialized, err := session.Initialized()
	if err != nil || initialized {
		t.Fatalf("key-only initialization state = %t / %v", initialized, err)
	}
	if err := session.Initialize(activeInstallJournal(t)); err != nil {
		t.Fatalf("resume initialization after key creation: %v", err)
	}
	if _, err := session.Read(); err != nil {
		t.Fatalf("read resumed initialization: %v", err)
	}
}

func TestAcquireSerializesProcessesAndHonorsContext(t *testing.T) {
	root := filepath.Join(t.TempDir(), "installation")
	first, err := Acquire(context.Background(), root)
	if err != nil {
		t.Fatalf("acquire first lock: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, err := Acquire(ctx, root); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended lock error = %v, want deadline", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("release first lock: %v", err)
	}
	second, err := Acquire(context.Background(), root)
	if err != nil {
		t.Fatalf("acquire lock after release: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("release second lock: %v", err)
	}
}

func TestAcquireExistingNeverInitializesState(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-installation")
	if _, err := AcquireExisting(context.Background(), missing); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("missing installation error = %v", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only acquisition created the missing root: %v", err)
	}

	root := initializedRoot(t)
	journalPath := filepath.Join(root, stateDirectoryName, journalFilename)
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("read journal before existing acquisition: %v", err)
	}
	session, err := AcquireExisting(context.Background(), root)
	if err != nil {
		t.Fatalf("acquire initialized installation: %v", err)
	}
	if _, err := session.Read(); err != nil {
		_ = session.Close()
		t.Fatalf("read initialized installation: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close existing installation: %v", err)
	}
	after, err := os.ReadFile(journalPath)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("read-only acquisition changed the sealed journal: %v", err)
	}
}

func TestAcquireRejectsOwnershipLinksAndUnsafePermissions(t *testing.T) {
	t.Run("foreign object", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "installation")
		if err := os.Mkdir(root, managedDirectoryMode); err != nil {
			t.Fatalf("create root: %v", err)
		}
		if err := securePermissions(root, true); err != nil {
			t.Fatalf("protect root: %v", err)
		}
		foreign := filepath.Join(root, "foreign")
		if err := os.WriteFile(foreign, []byte("foreign"), managedFileMode); err != nil {
			t.Fatalf("write foreign object: %v", err)
		}
		if err := securePermissions(foreign, false); err != nil {
			t.Fatalf("protect foreign object: %v", err)
		}
		if _, err := Acquire(context.Background(), root); !errors.Is(err, ErrOwnershipConflict) {
			t.Fatalf("foreign root error = %v", err)
		}
	})

	t.Run("link", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target")
		if err := os.Mkdir(target, managedDirectoryMode); err != nil {
			t.Fatalf("create target: %v", err)
		}
		root := filepath.Join(t.TempDir(), "installation")
		if err := os.Symlink(target, root); err != nil {
			t.Skipf("symbolic links are unavailable to this test user: %v", err)
		}
		if _, err := Acquire(context.Background(), root); err == nil {
			t.Fatal("linked installation root must fail")
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("permissions", func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "installation")
			if err := os.Mkdir(root, 0o755); err != nil {
				t.Fatalf("create unsafe root: %v", err)
			}
			if _, err := Acquire(context.Background(), root); err == nil {
				t.Fatal("group-readable installation root must fail")
			}
		})
	}
}

func initializedRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "installation")
	session, err := Acquire(context.Background(), root)
	if err != nil {
		t.Fatalf("acquire installation fixture: %v", err)
	}
	if err := session.Initialize(activeInstallJournal(t)); err != nil {
		_ = session.Close()
		t.Fatalf("initialize fixture: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	return root
}

func activeInstallJournal(t *testing.T) lifecycle.Journal {
	t.Helper()
	value, err := lifecycle.New(
		"mxi-"+strings.Repeat("a", 32),
		lifecycle.ReleaseTrust{
			KeyID: "xiak-release-2026", Fingerprint: "sha256:" + strings.Repeat("f", 64),
		},
	)
	if err != nil {
		t.Fatalf("create lifecycle journal: %v", err)
	}
	started, err := lifecycle.Start(value, lifecycle.Command{
		ID: "cmd-" + strings.Repeat("b", 32), Action: lifecycle.ActionInstall,
		InputDigest:     "sha256:" + strings.Repeat("c", 64),
		TargetReleaseID: "matrix-v0.1.0-aaaaaaaaaaaa",
		RequestedAt:     time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("start lifecycle journal: %v", err)
	}
	return started.Journal
}

func assertProtectedPath(t *testing.T, path string, directory bool) {
	t.Helper()
	if err := verifySecurePermissions(path, directory); err != nil {
		t.Fatalf("path permissions are unsafe: %v", err)
	}
}
