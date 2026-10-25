package executorspoolfile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

// AppendLogs atomically stores one normalized step batch under the current
// runner lease. Equal batches can replay under a later same-runner fence;
// changed or out-of-order sequence reuse conflicts.
func (spool *Spool) AppendLogs(
	ctx context.Context,
	runnerID string,
	executionID string,
	fencingToken uint64,
	batch devopsbuildv1.LogBatch,
	observedAt time.Time,
) error {
	if spool == nil || ctx == nil ||
		devopsv1.ValidateID("runnerId", runnerID) != nil ||
		executionKey(executionID) == "" || fencingToken == 0 ||
		fencingToken > devopsv1.MaximumContractInteger ||
		validateSpoolTime(observedAt) != nil {
		return ErrInvalid
	}
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	root, err := spool.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	execution, found, err := readExecution(
		ctx, root, executionKey(executionID), nil, false,
	)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	if execution.state.Phase != phaseAssigned ||
		execution.state.RunnerID != runnerID ||
		execution.state.FencingToken != fencingToken ||
		execution.state.LeaseExpiresAt == nil ||
		!observedAt.Before(*execution.state.LeaseExpiresAt) ||
		!observedAt.Before(execution.request.DeadlineAt) {
		return ErrStaleAssignment
	}
	if batch.ExecutionID != executionID ||
		devopsbuildv1.ValidateLogBatch(execution.request, batch) != nil {
		return ErrInvalid
	}
	batches, err := readLogBatches(ctx, root, execution)
	if err != nil {
		return err
	}
	content, err := devopsbuildv1.EncodeLogBatch(execution.request, batch)
	if err != nil {
		return errors.Join(ErrInvalid, err)
	}
	for _, existing := range batches {
		if existing.Next.LastSequence != batch.Next.LastSequence {
			continue
		}
		existingContent, encodeErr := devopsbuildv1.EncodeLogBatch(
			execution.request, existing,
		)
		if encodeErr != nil {
			return errors.Join(ErrUnavailable, encodeErr)
		}
		if bytes.Equal(existingContent, content) {
			if err := syncDirectory(root, execution.key); err != nil {
				return errors.Join(ErrOutcomeUnknown, err)
			}
			return nil
		}
		return ErrConflict
	}
	current := devopsbuildv1.LogProgress{}
	var lastStep uint32
	if len(batches) > 0 {
		current = batches[len(batches)-1].Next
		lastStep = batches[len(batches)-1].Step.Ordinal
	}
	if batch.Previous != current || batch.Step.Ordinal <= lastStep ||
		len(batches) >= maximumLogBatches {
		return ErrConflict
	}
	return appendLogBatch(root, execution, batch, content)
}

// ReadLogs returns the next complete durable batch after an exact sequence
// boundary. A cursor into the middle of a batch is rejected.
func (spool *Spool) ReadLogs(
	ctx context.Context,
	request devopsbuildv1.Request,
	afterSequence uint64,
) (devopsbuildv1.LogBatch, bool, error) {
	if spool == nil || ctx == nil || devopsbuildv1.ValidateRequest(request) != nil ||
		afterSequence > uint64(request.Limits.MaxLogBytes) {
		return devopsbuildv1.LogBatch{}, false, ErrInvalid
	}
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		return devopsbuildv1.LogBatch{}, false, ErrInvalid
	}
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	root, err := spool.openRoot()
	if err != nil {
		return devopsbuildv1.LogBatch{}, false, err
	}
	defer root.Close()
	execution, found, err := readExecution(
		ctx, root, executionKey(executionID), &request, false,
	)
	if err != nil {
		return devopsbuildv1.LogBatch{}, false, err
	}
	if !found {
		return devopsbuildv1.LogBatch{}, false, ErrNotFound
	}
	batches, err := readLogBatches(ctx, root, execution)
	if err != nil {
		return devopsbuildv1.LogBatch{}, false, err
	}
	for _, batch := range batches {
		if batch.Previous.LastSequence == afterSequence {
			return batch, true, nil
		}
		if afterSequence > batch.Previous.LastSequence &&
			afterSequence < batch.Next.LastSequence {
			return devopsbuildv1.LogBatch{}, false, ErrConflict
		}
	}
	lastSequence := uint64(0)
	if len(batches) > 0 {
		lastSequence = batches[len(batches)-1].Next.LastSequence
	}
	if afterSequence != lastSequence {
		return devopsbuildv1.LogBatch{}, false, ErrConflict
	}
	return devopsbuildv1.LogBatch{}, false, nil
}

func readLogBatches(
	ctx context.Context,
	root *os.Root,
	execution storedExecution,
) ([]devopsbuildv1.LogBatch, error) {
	batches := make([]devopsbuildv1.LogBatch, 0, len(execution.entries.logNames))
	current := devopsbuildv1.LogProgress{}
	var lastStep uint32
	for _, name := range execution.entries.logNames {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		content, err := readPrivateFile(
			root,
			execution.key+"/"+name,
			int(devopsbuildv1.MaximumLogDocumentBytes),
		)
		if err != nil {
			return nil, err
		}
		batch, err := devopsbuildv1.DecodeLogBatch(execution.request, content)
		if err != nil || logFileName(batch.Next.LastSequence) != name ||
			batch.Previous != current || batch.Step.Ordinal <= lastStep {
			return nil, errors.Join(ErrUnavailable, err)
		}
		batches = append(batches, batch)
		current = batch.Next
		lastStep = batch.Step.Ordinal
	}
	return batches, nil
}

func appendLogBatch(
	root *os.Root,
	execution storedExecution,
	batch devopsbuildv1.LogBatch,
	content []byte,
) error {
	temporary, file, err := createLogTemporary(
		root, execution.key, batch.Next.LastSequence,
	)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	published := false
	defer func() {
		if !published {
			_ = root.Remove(temporary)
		}
	}()
	written, writeErr := file.Write(content)
	if writeErr == nil && written != len(content) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(ErrUnavailable, writeErr, closeErr)
	}
	if err := root.Rename(
		temporary, execution.key+"/"+logFileName(batch.Next.LastSequence),
	); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	published = true
	if err := syncDirectory(root, execution.key); err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	return nil
}

func createLogTemporary(
	root *os.Root,
	key string,
	lastSequence uint64,
) (string, *os.File, error) {
	for attempt := 0; attempt < stagingAttempts; attempt++ {
		random, err := randomHex(8)
		if err != nil {
			return "", nil, err
		}
		name := fmt.Sprintf(
			".logs-%s-%020d-%s.tmp", key, lastSequence, random,
		)
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return name, file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, ErrUnavailable
}

func logFileName(lastSequence uint64) string {
	return fmt.Sprintf("logs-%020d.json", lastSequence)
}

func logLastSequence(name string) (uint64, bool) {
	if len(name) != len("logs-")+20+len(".json") ||
		!strings.HasPrefix(name, "logs-") || !strings.HasSuffix(name, ".json") {
		return 0, false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(name, "logs-"), ".json")
	sequence, err := strconv.ParseUint(value, 10, 64)
	return sequence, err == nil && sequence > 0 && logFileName(sequence) == name
}

func validLogTemporaryName(value string) bool {
	if !strings.HasPrefix(value, ".logs-") || !strings.HasSuffix(value, ".tmp") {
		return false
	}
	parts := strings.Split(
		strings.TrimSuffix(strings.TrimPrefix(value, ".logs-"), ".tmp"), "-",
	)
	if len(parts) != 3 || !validExecutionKey(parts[0]) || len(parts[1]) != 20 ||
		len(parts[2]) != 16 || !lowerHex(parts[2]) {
		return false
	}
	sequence, err := strconv.ParseUint(parts[1], 10, 64)
	return err == nil && sequence > 0
}
