// Package executorspoolfile owns the private durable execution spool used by
// the Matrix Native executor gateway. It has no database or product authority.
package executorspoolfile

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const RunnerLeaseDuration = 30 * time.Second

var (
	ErrInvalid         = errors.New("executor spool input is invalid")
	ErrNotFound        = errors.New("executor spool execution was not found")
	ErrUnavailable     = errors.New("executor spool is unavailable")
	ErrConflict        = errors.New("executor spool identity conflicts")
	ErrOutcomeUnknown  = errors.New("executor spool outcome is unknown")
	ErrStaleAssignment = errors.New("executor assignment is stale")
)

type Spool struct {
	rootPath string
	mutex    sync.Mutex
}

func New(rootPath string) (*Spool, error) {
	cleaned, err := validateRoot(rootPath)
	if err != nil {
		return nil, err
	}
	spool := &Spool{rootPath: cleaned}
	root, err := spool.openRoot()
	if err != nil {
		return nil, err
	}
	recoveryErr := recoverTemporaryEntries(root)
	if recoveryErr == nil {
		_, recoveryErr = listExecutionKeys(root)
	}
	closeErr := root.Close()
	if recoveryErr != nil || closeErr != nil {
		return nil, errors.Join(ErrUnavailable, recoveryErr, closeErr)
	}
	return spool, nil
}

// Create validates and durably publishes one framed submission. Equal replay
// observes the original execution; changed authority at the same deterministic
// identity conflicts.
func (spool *Spool) Create(
	ctx context.Context,
	submission io.Reader,
) (devopsbuildv1.Observation, error) {
	if spool == nil || ctx == nil || submission == nil {
		return devopsbuildv1.Observation{}, ErrInvalid
	}
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	root, err := spool.openRoot()
	if err != nil {
		return devopsbuildv1.Observation{}, err
	}
	defer root.Close()
	staging, err := createStaging(root)
	if err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrUnavailable, err)
	}
	published := false
	defer func() {
		if !published && validStagingName(staging) {
			_ = root.RemoveAll(staging)
		}
	}()

	archiveFile, err := root.OpenFile(
		staging+"/"+archiveName,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrUnavailable, err)
	}
	trackedArchive := &errorTrackingWriter{destination: archiveFile}
	request, submissionErr := devopsbuildv1.ReadSubmission(
		&contextReader{ctx: ctx, reader: submission},
		trackedArchive,
	)
	var syncErr error
	if submissionErr == nil {
		syncErr = archiveFile.Sync()
	}
	closeErr := archiveFile.Close()
	if err := ctx.Err(); err != nil {
		return devopsbuildv1.Observation{}, err
	}
	if trackedArchive.err != nil || syncErr != nil || closeErr != nil {
		return devopsbuildv1.Observation{}, errors.Join(
			ErrUnavailable, trackedArchive.err, syncErr, closeErr,
		)
	}
	if submissionErr != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrInvalid, submissionErr)
	}
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrInvalid, err)
	}
	key := executionKey(executionID)
	if existing, found, readErr := readExecution(ctx, root, key, &request, true); readErr != nil {
		return devopsbuildv1.Observation{}, readErr
	} else if found {
		return observation(existing.request, existing.state)
	}

	verifiedArchive, err := openVerifiedArchive(
		ctx, root, staging+"/"+archiveName, request,
	)
	if err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrInvalid, err)
	}
	if err := verifiedArchive.Close(); err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrUnavailable, err)
	}
	submissionDocument, err := devopsbuildv1.EncodeSubmission(request)
	if err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrInvalid, err)
	}
	if err := writePrivateFile(root, staging+"/"+submissionName, submissionDocument); err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrUnavailable, err)
	}
	state, err := initialState(request)
	if err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrInvalid, err)
	}
	stateDocument, err := encodeState(request, state)
	if err != nil {
		return devopsbuildv1.Observation{}, err
	}
	if err := writePrivateFile(
		root, staging+"/"+stateFileName(state.Version), stateDocument,
	); err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrUnavailable, err)
	}
	if err := syncDirectory(root, staging); err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrUnavailable, err)
	}
	if err := root.Rename(staging, key); err != nil {
		if existing, found, readErr := readExecution(ctx, root, key, &request, true); readErr == nil && found {
			return observation(existing.request, existing.state)
		}
		return devopsbuildv1.Observation{}, errors.Join(ErrUnavailable, err)
	}
	published = true
	if err := syncDirectory(root, "."); err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrOutcomeUnknown, err)
	}
	return observation(request, state)
}

func (spool *Spool) Observe(
	ctx context.Context,
	request devopsbuildv1.Request,
) (devopsbuildv1.Observation, error) {
	if spool == nil || ctx == nil || devopsbuildv1.ValidateRequest(request) != nil {
		return devopsbuildv1.Observation{}, ErrInvalid
	}
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	root, err := spool.openRoot()
	if err != nil {
		return devopsbuildv1.Observation{}, err
	}
	defer root.Close()
	executionID, _ := devopsbuildv1.ExecutionID(request)
	execution, found, err := readExecution(
		ctx, root, executionKey(executionID), &request, true,
	)
	if err != nil {
		return devopsbuildv1.Observation{}, err
	}
	if !found {
		return devopsbuildv1.Observation{}, ErrNotFound
	}
	return observation(execution.request, execution.state)
}

func (spool *Spool) Cancel(
	ctx context.Context,
	request devopsbuildv1.Request,
) (devopsbuildv1.Observation, error) {
	if spool == nil || ctx == nil || devopsbuildv1.ValidateRequest(request) != nil {
		return devopsbuildv1.Observation{}, ErrInvalid
	}
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	root, err := spool.openRoot()
	if err != nil {
		return devopsbuildv1.Observation{}, err
	}
	defer root.Close()
	executionID, _ := devopsbuildv1.ExecutionID(request)
	execution, found, err := readExecution(
		ctx, root, executionKey(executionID), &request, true,
	)
	if err != nil {
		return devopsbuildv1.Observation{}, err
	}
	if !found {
		return devopsbuildv1.Observation{}, ErrNotFound
	}
	current := execution.state
	switch current.Phase {
	case phaseQueued:
		next := nextState(current)
		next.Phase = phaseCancelled
		next.CancellationRequested = true
		sealState(&next)
		if err := appendState(root, execution, next); err != nil {
			return devopsbuildv1.Observation{}, err
		}
		current = next
	case phaseAssigned:
		if !current.CancellationRequested {
			next := nextState(current)
			next.CancellationRequested = true
			sealState(&next)
			if err := appendState(root, execution, next); err != nil {
				return devopsbuildv1.Observation{}, err
			}
			current = next
		}
	case phaseTerminal, phaseCancelled:
	default:
		return devopsbuildv1.Observation{}, ErrUnavailable
	}
	return observation(request, current)
}

// Claim returns the oldest eligible assignment. A first claim may execute;
// only the same certificate-derived runner may recover an expired assignment.
func (spool *Spool) Claim(
	ctx context.Context,
	runnerID string,
	observedAt time.Time,
) (devopsbuildv1.Assignment, io.ReadCloser, bool, error) {
	if spool == nil || ctx == nil ||
		devopsv1.ValidateID("runnerId", runnerID) != nil || validateSpoolTime(observedAt) != nil {
		return devopsbuildv1.Assignment{}, nil, false, ErrInvalid
	}
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	root, err := spool.openRoot()
	if err != nil {
		return devopsbuildv1.Assignment{}, nil, false, err
	}
	defer root.Close()
	keys, err := listExecutionKeys(root)
	if err != nil {
		return devopsbuildv1.Assignment{}, nil, false, errors.Join(ErrUnavailable, err)
	}
	type candidate struct {
		execution storedExecution
		mode      devopsbuildv1.AssignmentMode
	}
	candidates := make([]candidate, 0, len(keys))
	for _, key := range keys {
		execution, found, readErr := readExecution(ctx, root, key, nil, false)
		if readErr != nil || !found {
			return devopsbuildv1.Assignment{}, nil, false, errors.Join(ErrUnavailable, readErr)
		}
		if observedAt.Before(execution.request.StartedAt) ||
			!observedAt.Before(execution.request.DeadlineAt) {
			continue
		}
		switch execution.state.Phase {
		case phaseQueued:
			candidates = append(candidates, candidate{
				execution: execution,
				mode:      devopsbuildv1.AssignmentExecute,
			})
		case phaseAssigned:
			if execution.state.RunnerID == runnerID &&
				execution.state.LeaseExpiresAt != nil &&
				!observedAt.Before(*execution.state.LeaseExpiresAt) {
				mode := devopsbuildv1.AssignmentObserve
				if execution.state.CancellationRequested {
					mode = devopsbuildv1.AssignmentCancel
				}
				candidates = append(candidates, candidate{
					execution: execution,
					mode:      mode,
				})
			}
		}
	}
	if len(candidates) == 0 {
		return devopsbuildv1.Assignment{}, nil, false, nil
	}
	sort.Slice(candidates, func(left, right int) bool {
		leftRequest := candidates[left].execution.request
		rightRequest := candidates[right].execution.request
		if leftRequest.StartedAt.Equal(rightRequest.StartedAt) {
			return candidates[left].execution.key < candidates[right].execution.key
		}
		return leftRequest.StartedAt.Before(rightRequest.StartedAt)
	})
	selected := candidates[0]
	execution, found, err := readExecution(
		ctx, root, selected.execution.key, nil, true,
	)
	if err != nil || !found {
		return devopsbuildv1.Assignment{}, nil, false, errors.Join(ErrUnavailable, err)
	}
	leaseExpiresAt := observedAt.Add(RunnerLeaseDuration)
	if leaseExpiresAt.After(execution.request.DeadlineAt) {
		leaseExpiresAt = execution.request.DeadlineAt
	}
	next := nextState(execution.state)
	next.Phase = phaseAssigned
	next.RunnerID = runnerID
	next.LeaseExpiresAt = &leaseExpiresAt
	if selected.mode == devopsbuildv1.AssignmentExecute {
		next.FencingToken = 1
	} else {
		if next.FencingToken == devopsv1.MaximumContractInteger {
			return devopsbuildv1.Assignment{}, nil, false, ErrUnavailable
		}
		next.FencingToken++
	}
	sealState(&next)

	var archive io.ReadCloser
	if selected.mode == devopsbuildv1.AssignmentExecute {
		archive, err = openVerifiedArchive(
			ctx, root, execution.key+"/"+archiveName, execution.request,
		)
		if err != nil {
			return devopsbuildv1.Assignment{}, nil, false, err
		}
	}
	if err := appendState(root, execution, next); err != nil {
		if archive != nil {
			_ = archive.Close()
		}
		return devopsbuildv1.Assignment{}, nil, false, err
	}
	assignment := devopsbuildv1.Assignment{
		APIVersion:     devopsbuildv1.APIVersion,
		Kind:           devopsbuildv1.AssignmentKind,
		Mode:           selected.mode,
		ExecutionID:    execution.state.ExecutionID,
		FencingToken:   next.FencingToken,
		LeaseExpiresAt: leaseExpiresAt,
		Request:        execution.request,
	}
	if err := devopsbuildv1.ValidateAssignment(assignment); err != nil {
		if archive != nil {
			_ = archive.Close()
		}
		return devopsbuildv1.Assignment{}, nil, false, errors.Join(ErrUnavailable, err)
	}
	return assignment, archive, true, nil
}

func (spool *Spool) Renew(
	ctx context.Context,
	runnerID string,
	executionID string,
	fencingToken uint64,
	observedAt time.Time,
) (devopsbuildv1.Renewal, error) {
	if spool == nil || ctx == nil || devopsv1.ValidateID("runnerId", runnerID) != nil ||
		executionKey(executionID) == "" || fencingToken == 0 ||
		fencingToken > devopsv1.MaximumContractInteger || validateSpoolTime(observedAt) != nil {
		return devopsbuildv1.Renewal{}, ErrInvalid
	}
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	root, err := spool.openRoot()
	if err != nil {
		return devopsbuildv1.Renewal{}, err
	}
	defer root.Close()
	execution, found, err := readExecution(
		ctx, root, executionKey(executionID), nil, false,
	)
	if err != nil {
		return devopsbuildv1.Renewal{}, err
	}
	if !found || execution.state.Phase != phaseAssigned ||
		execution.state.RunnerID != runnerID ||
		execution.state.FencingToken != fencingToken ||
		execution.state.LeaseExpiresAt == nil ||
		!observedAt.Before(*execution.state.LeaseExpiresAt) ||
		!observedAt.Before(execution.request.DeadlineAt) {
		return devopsbuildv1.Renewal{}, ErrStaleAssignment
	}
	leaseExpiresAt := observedAt.Add(RunnerLeaseDuration)
	if leaseExpiresAt.After(execution.request.DeadlineAt) {
		leaseExpiresAt = execution.request.DeadlineAt
	}
	if leaseExpiresAt.After(*execution.state.LeaseExpiresAt) {
		next := nextState(execution.state)
		next.LeaseExpiresAt = &leaseExpiresAt
		sealState(&next)
		if err := appendState(root, execution, next); err != nil {
			return devopsbuildv1.Renewal{}, err
		}
		execution.state = next
	}
	renewal := devopsbuildv1.Renewal{
		APIVersion:            devopsbuildv1.APIVersion,
		Kind:                  devopsbuildv1.RenewalKind,
		ExecutionID:           executionID,
		FencingToken:          fencingToken,
		LeaseExpiresAt:        *execution.state.LeaseExpiresAt,
		CancellationRequested: execution.state.CancellationRequested,
	}
	if err := devopsbuildv1.ValidateRenewal(execution.request, renewal); err != nil {
		return devopsbuildv1.Renewal{}, errors.Join(ErrUnavailable, err)
	}
	return renewal, nil
}

func (spool *Spool) Complete(
	ctx context.Context,
	runnerID string,
	executionID string,
	fencingToken uint64,
	receipt devopsbuildv1.Receipt,
	observedAt time.Time,
) (devopsbuildv1.Observation, error) {
	if spool == nil || ctx == nil || devopsv1.ValidateID("runnerId", runnerID) != nil ||
		executionKey(executionID) == "" || fencingToken == 0 ||
		fencingToken > devopsv1.MaximumContractInteger || validateSpoolTime(observedAt) != nil {
		return devopsbuildv1.Observation{}, ErrInvalid
	}
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	root, err := spool.openRoot()
	if err != nil {
		return devopsbuildv1.Observation{}, err
	}
	defer root.Close()
	execution, found, err := readExecution(
		ctx, root, executionKey(executionID), nil, true,
	)
	if err != nil {
		return devopsbuildv1.Observation{}, err
	}
	if !found {
		return devopsbuildv1.Observation{}, ErrNotFound
	}
	if execution.state.Phase == phaseTerminal {
		if execution.state.RunnerID == runnerID &&
			execution.state.FencingToken == fencingToken &&
			execution.state.Receipt != nil && *execution.state.Receipt == receipt {
			return observation(execution.request, execution.state)
		}
		return devopsbuildv1.Observation{}, ErrConflict
	}
	if execution.state.Phase != phaseAssigned ||
		execution.state.RunnerID != runnerID ||
		execution.state.FencingToken != fencingToken ||
		execution.state.LeaseExpiresAt == nil ||
		!observedAt.Before(*execution.state.LeaseExpiresAt) ||
		!observedAt.Before(execution.request.DeadlineAt) {
		return devopsbuildv1.Observation{}, ErrStaleAssignment
	}
	if err := devopsbuildv1.ValidateReceipt(execution.request, receipt); err != nil ||
		receipt.ExecutorID != runnerID {
		return devopsbuildv1.Observation{}, errors.Join(ErrInvalid, err)
	}
	next := nextState(execution.state)
	next.Phase = phaseTerminal
	next.LeaseExpiresAt = nil
	next.Receipt = &receipt
	sealState(&next)
	if err := appendState(root, execution, next); err != nil {
		return devopsbuildv1.Observation{}, err
	}
	return observation(execution.request, next)
}

// Request returns the immutable request already owned by one execution. It is
// intended for gateway transport validation before accepting runner output.
func (spool *Spool) Request(
	ctx context.Context,
	executionID string,
) (devopsbuildv1.Request, error) {
	if spool == nil || ctx == nil || executionKey(executionID) == "" {
		return devopsbuildv1.Request{}, ErrInvalid
	}
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	root, err := spool.openRoot()
	if err != nil {
		return devopsbuildv1.Request{}, err
	}
	defer root.Close()
	execution, found, err := readExecution(
		ctx, root, executionKey(executionID), nil, false,
	)
	if err != nil {
		return devopsbuildv1.Request{}, err
	}
	if !found {
		return devopsbuildv1.Request{}, ErrNotFound
	}
	return execution.request, nil
}
