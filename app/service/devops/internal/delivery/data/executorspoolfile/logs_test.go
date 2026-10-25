package executorspoolfile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
)

func TestLogBatchesAppendReadAndReplayAcrossRecoveryFence(t *testing.T) {
	root := spoolRoot(t)
	spool, request, assignment, claimedAt := assignedExecution(t, root, 'b')
	first := spoolLogBatch(request, 0, devopsbuildv1.LogProgress{}, []string{
		"[stdout] test ok\n", "[stderr] warning\n",
	})
	if err := spool.AppendLogs(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, first, claimedAt.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}
	if err := spool.AppendLogs(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, first, claimedAt.Add(2*time.Second),
	); err != nil {
		t.Fatalf("equal replay: %v", err)
	}
	changed := cloneSpoolLogBatch(first)
	changed.Chunks[0].Content = "[stdout] changed\n"
	changed.Chunks[0].ContentDigest = devopsbuildv1.DigestLogChunk(
		changed.ExecutionID, changed.Step, changed.Chunks[0],
	)
	changed.ContentDigest = devopsbuildv1.DigestLogBatch(changed)
	if err := spool.AppendLogs(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, changed, claimedAt.Add(3*time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed replay error = %v", err)
	}

	read, found, err := spool.ReadLogs(context.Background(), request, 0)
	if err != nil || !found || !reflect.DeepEqual(read, first) {
		t.Fatalf("first read = %#v / %t / %v", read, found, err)
	}
	if read, found, err := spool.ReadLogs(
		context.Background(), request, first.Next.LastSequence,
	); err != nil || found || !reflect.DeepEqual(read, devopsbuildv1.LogBatch{}) {
		t.Fatalf("end read = %#v / %t / %v", read, found, err)
	}
	if _, _, err := spool.ReadLogs(context.Background(), request, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("mid-batch cursor error = %v", err)
	}

	recoveryAt := assignment.LeaseExpiresAt.Add(time.Microsecond)
	recovery, archive, found, err := spool.Claim(
		context.Background(), "runner-one", recoveryAt,
	)
	if err != nil || !found || archive != nil ||
		recovery.Mode != devopsbuildv1.AssignmentObserve ||
		recovery.FencingToken != assignment.FencingToken+1 {
		t.Fatalf("recovery = %#v / %v / %t / %v", recovery, archive, found, err)
	}
	if err := spool.AppendLogs(
		context.Background(), "runner-one", recovery.ExecutionID,
		recovery.FencingToken, first, recoveryAt.Add(time.Second),
	); err != nil {
		t.Fatalf("later-fence equal replay: %v", err)
	}
	second := spoolLogBatch(request, 1, first.Next, []string{"[stdout] vet ok\n"})
	if err := spool.AppendLogs(
		context.Background(), "runner-one", recovery.ExecutionID,
		recovery.FencingToken, second, recoveryAt.Add(2*time.Second),
	); err != nil {
		t.Fatal(err)
	}

	restarted, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	firstRead, found, err := restarted.ReadLogs(context.Background(), request, 0)
	if err != nil || !found || !reflect.DeepEqual(firstRead, first) {
		t.Fatalf("restart first = %#v / %t / %v", firstRead, found, err)
	}
	secondRead, found, err := restarted.ReadLogs(
		context.Background(), request, first.Next.LastSequence,
	)
	if err != nil || !found || !reflect.DeepEqual(secondRead, second) {
		t.Fatalf("restart second = %#v / %t / %v", secondRead, found, err)
	}
	if _, found, err := restarted.ReadLogs(
		context.Background(), request, second.Next.LastSequence,
	); err != nil || found {
		t.Fatalf("restart end found=%t error=%v", found, err)
	}
}

func TestLogAppendRejectsForeignStaleInvalidAndOutOfOrderAuthority(t *testing.T) {
	spool, request, assignment, claimedAt := assignedExecution(t, spoolRoot(t), 'c')
	first := spoolLogBatch(
		request, 0, devopsbuildv1.LogProgress{}, []string{"[stdout] ok\n"},
	)
	for name, authority := range map[string]struct {
		runner string
		fence  uint64
	}{
		"foreign runner": {runner: "runner-two", fence: assignment.FencingToken},
		"stale fence":    {runner: "runner-one", fence: assignment.FencingToken + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if err := spool.AppendLogs(
				context.Background(), authority.runner, assignment.ExecutionID,
				authority.fence, first, claimedAt.Add(time.Second),
			); !errors.Is(err, ErrStaleAssignment) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	invalid := cloneSpoolLogBatch(first)
	invalid.ContentDigest = "sha256:invalid"
	if err := spool.AppendLogs(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, invalid, claimedAt.Add(time.Second),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid batch error = %v", err)
	}
	second := spoolLogBatch(request, 1, first.Next, []string{"[stdout] vet\n"})
	if err := spool.AppendLogs(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, second, claimedAt.Add(time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("out-of-order batch error = %v", err)
	}
	if err := spool.AppendLogs(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, first, assignment.LeaseExpiresAt,
	); !errors.Is(err, ErrStaleAssignment) {
		t.Fatalf("expired append error = %v", err)
	}
}

func TestTamperedLogBlocksReadRecoveryAndCompletion(t *testing.T) {
	root := spoolRoot(t)
	spool, request, assignment, claimedAt := assignedExecution(t, root, 'd')
	batch := spoolLogBatch(
		request, 0, devopsbuildv1.LogProgress{}, []string{"[stdout] safe\n"},
	)
	if err := spool.AppendLogs(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, batch, claimedAt.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(
		root, executionKey(assignment.ExecutionID),
		logFileName(batch.Next.LastSequence),
	)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content = bytes.Replace(content, []byte("safe"), []byte("evil"), 1)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := spool.ReadLogs(
		context.Background(), request, 0,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("tampered read error = %v", err)
	}
	receipt := receiptFixture(
		request, devopsbuildv1.ConclusionFailed,
		devopsbuildv1.StepConclusionFailed, devopsbuildv1.StepConclusionNotRun,
	)
	if _, err := spool.Complete(
		context.Background(), "runner-one", assignment.ExecutionID,
		assignment.FencingToken, receipt, claimedAt.Add(2*time.Second),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("tampered completion error = %v", err)
	}
	if _, archive, found, err := spool.Claim(
		context.Background(), "runner-one", assignment.LeaseExpiresAt.Add(time.Microsecond),
	); !errors.Is(err, ErrUnavailable) || found || archive != nil {
		if archive != nil {
			_ = archive.Close()
		}
		t.Fatalf("tampered recovery found=%t archive=%v error=%v", found, archive, err)
	}
}

func assignedExecution(
	t *testing.T,
	root string,
	identity byte,
) (*Spool, devopsbuildv1.Request, devopsbuildv1.Assignment, time.Time) {
	t.Helper()
	spool, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := executionFixture(t, identity, fixtureStart())
	if _, err := spool.Create(
		context.Background(), submissionFrame(t, request, archive),
	); err != nil {
		t.Fatal(err)
	}
	claimedAt := request.StartedAt.Add(time.Second)
	assignment, source, found, err := spool.Claim(
		context.Background(), "runner-one", claimedAt,
	)
	if err != nil || !found || source == nil {
		t.Fatalf("claim = %#v / %v / %t / %v", assignment, source, found, err)
	}
	if _, err := io.Copy(io.Discard, source); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	return spool, request, assignment, claimedAt
}

func spoolLogBatch(
	request devopsbuildv1.Request,
	stepIndex int,
	previous devopsbuildv1.LogProgress,
	contents []string,
) devopsbuildv1.LogBatch {
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		panic(err)
	}
	batch := devopsbuildv1.LogBatch{
		ExecutionID: executionID, Step: request.Steps[stepIndex], Previous: previous,
		Chunks: make([]devopsbuildv1.LogChunk, len(contents)),
	}
	var contentBytes int64
	for index, content := range contents {
		chunk := devopsbuildv1.LogChunk{
			Sequence: previous.LastSequence + uint64(index) + 1,
			Content:  content,
		}
		chunk.ContentDigest = devopsbuildv1.DigestLogChunk(
			executionID, batch.Step, chunk,
		)
		batch.Chunks[index] = chunk
		contentBytes += int64(len(content))
	}
	batch.Next = devopsbuildv1.LogProgress{
		NativeBytes:     previous.NativeBytes + contentBytes,
		NormalizedBytes: previous.NormalizedBytes + contentBytes,
		LastSequence:    previous.LastSequence + uint64(len(contents)),
	}
	batch.ContentDigest = devopsbuildv1.DigestLogBatch(batch)
	return batch
}

func cloneSpoolLogBatch(value devopsbuildv1.LogBatch) devopsbuildv1.LogBatch {
	value.Chunks = append([]devopsbuildv1.LogChunk(nil), value.Chunks...)
	return value
}
