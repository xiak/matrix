package runnerjournalfile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

func TestJournalRejectsEffectOutsideDurableCurrentLease(t *testing.T) {
	root := journalRoot(t)
	runnerID := journalRunnerID('f')
	journal, err := New(root, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := journalExecutionFixture(t, 'f', journalStart())
	assignment := journalAssignment(t, request, devopsbuildv1.AssignmentExecute, 1, 2*time.Minute)
	if _, err := journal.MarkEffectStarted(
		context.Background(), assignment, request.StartedAt.Add(time.Second),
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("effect without durable claim error = %v", err)
	}
	commitJournalAssignment(t, journal, assignment, archive)
	if _, err := journal.MarkEffectStarted(
		context.Background(), assignment, assignment.LeaseExpiresAt,
	); !errors.Is(err, ErrStale) {
		t.Fatalf("effect at expired lease error = %v", err)
	}

	receipt := journalReceipt(
		request, runnerID, devopsbuildv1.ConclusionPassed,
		devopsbuildv1.StepConclusionPassed, devopsbuildv1.StepConclusionPassed,
	)
	if _, err := journal.RecordReceipt(
		context.Background(), assignment, receipt,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("receipt before effect error = %v", err)
	}
	renewal := devopsbuildv1.Renewal{
		APIVersion: devopsbuildv1.APIVersion, Kind: devopsbuildv1.RenewalKind,
		ExecutionID: assignment.ExecutionID, FencingToken: assignment.FencingToken,
		LeaseExpiresAt: assignment.LeaseExpiresAt, CancellationRequested: true,
	}
	cancelled, err := journal.ApplyRenewal(context.Background(), assignment, renewal)
	if err != nil || !cancelled.CancellationRequested {
		t.Fatalf("persist cancellation = %#v / %v", cancelled, err)
	}
	if _, err := journal.MarkEffectStarted(
		context.Background(), cancelled.Assignment, request.StartedAt.Add(time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("effect after cancellation error = %v", err)
	}
}

func TestJournalDetectsPublishedTampering(t *testing.T) {
	t.Run("archive", func(t *testing.T) {
		root, journal, assignment, archive := committedJournalFixture(t, '1')
		path := filepath.Join(
			journalExecutionPath(root, assignment.ExecutionID), archiveName,
		)
		changed := append([]byte(nil), archive...)
		changed[len(changed)/2] ^= 0xff
		if err := os.WriteFile(path, changed, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.Load(
			context.Background(), assignment.ExecutionID,
		); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("changed archive error = %v", err)
		}
	})

	t.Run("request digest", func(t *testing.T) {
		root, _, assignment, _ := committedJournalFixture(t, '2')
		path := filepath.Join(
			journalExecutionPath(root, assignment.ExecutionID), stateFileName(1),
		)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		state, err := decodeState(assignment.Request, content)
		if err != nil {
			t.Fatal(err)
		}
		state.RequestDigest = "sha256:" + strings.Repeat("0", 64)
		sealState(&state)
		content, err = json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(root, journalRunnerID('2')); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("recomputed foreign request digest error = %v", err)
		}
	})

	t.Run("step state chain", func(t *testing.T) {
		root, journal, assignment, _ := committedJournalFixture(t, 'a')
		started, err := journal.MarkEffectStarted(
			context.Background(), assignment,
			assignment.Request.StartedAt.Add(time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := journal.MarkStepStarted(
			context.Background(), started.Assignment,
			assignment.Request.Steps[0],
			assignment.Request.StartedAt.Add(2*time.Second),
		); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(
			journalExecutionPath(root, assignment.ExecutionID), stateFileName(3),
		)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		state, err := decodeState(assignment.Request, content)
		if err != nil {
			t.Fatal(err)
		}
		state.Steps[0].Phase = StepPending
		sealState(&state)
		content, err = json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(root, journalRunnerID('a')); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("recomputed step rollback error = %v", err)
		}
	})

	t.Run("log progress chain", func(t *testing.T) {
		root, journal, assignment, _ := committedJournalFixture(t, 'b')
		started, err := journal.MarkEffectStarted(
			context.Background(), assignment,
			assignment.Request.StartedAt.Add(time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := journal.MarkStepStarted(
			context.Background(), started.Assignment,
			assignment.Request.Steps[0],
			assignment.Request.StartedAt.Add(2*time.Second),
		); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(
			journalExecutionPath(root, assignment.ExecutionID), stateFileName(3),
		)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		state, err := decodeState(assignment.Request, content)
		if err != nil {
			t.Fatal(err)
		}
		state.LogProgress = runnerlog.Progress{
			NativeBytes: 1, NormalizedBytes: 10, LastSequence: 1,
		}
		sealState(&state)
		content, err = json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(root, journalRunnerID('b')); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("recomputed log progress outside conclusion error = %v", err)
		}
	})

	t.Run("assignment canonical form", func(t *testing.T) {
		root, journal, assignment, _ := committedJournalFixture(t, '3')
		path := filepath.Join(
			journalExecutionPath(root, assignment.ExecutionID), assignmentName,
		)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		content = append(content, '\n')
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.Load(
			context.Background(), assignment.ExecutionID,
		); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("noncanonical assignment error = %v", err)
		}
	})

	t.Run("identity", func(t *testing.T) {
		root := journalRoot(t)
		original := journalRunnerID('4')
		if _, err := New(root, original); err != nil {
			t.Fatal(err)
		}
		identity := identityDocument{SchemaVersion: 1, RunnerID: journalRunnerID('5')}
		identity.ContentDigest = digestIdentity(identity)
		content, err := json.Marshal(identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, identityName), content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(root, original); !errors.Is(err, ErrConflict) {
			t.Fatalf("rebound identity error = %v", err)
		}
	})

	t.Run("foreign root entry", func(t *testing.T) {
		root := journalRoot(t)
		runnerID := journalRunnerID('6')
		if _, err := New(root, runnerID); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "foreign"), []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(root, runnerID); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("foreign root entry error = %v", err)
		}
	})

	t.Run("archive symlink", func(t *testing.T) {
		root, journal, assignment, archive := committedJournalFixture(t, '7')
		path := filepath.Join(
			journalExecutionPath(root, assignment.ExecutionID), archiveName,
		)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "outside.tar.gz")
		if err := os.WriteFile(target, archive, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symbolic links are not available: %v", err)
		}
		if _, err := journal.OpenArchive(
			context.Background(), assignment.ExecutionID,
		); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("linked archive error = %v", err)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("state permissions", func(t *testing.T) {
			root, _, assignment, _ := committedJournalFixture(t, '8')
			path := filepath.Join(
				journalExecutionPath(root, assignment.ExecutionID), stateFileName(1),
			)
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := New(root, journalRunnerID('8')); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("public state permissions error = %v", err)
			}
		})
	}
}

func committedJournalFixture(
	t *testing.T,
	identity byte,
) (string, *Journal, devopsbuildv1.Assignment, []byte) {
	t.Helper()
	root := journalRoot(t)
	journal, err := New(root, journalRunnerID(identity))
	if err != nil {
		t.Fatal(err)
	}
	request, archive := journalExecutionFixture(t, identity, journalStart())
	assignment := journalAssignment(
		t, request, devopsbuildv1.AssignmentExecute, 1, 2*time.Minute,
	)
	commitJournalAssignment(t, journal, assignment, archive)
	return root, journal, assignment, archive
}
