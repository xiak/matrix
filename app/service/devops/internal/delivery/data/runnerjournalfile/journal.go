// Package runnerjournalfile owns the private durable journal that separates a
// runner's gateway transport from its local sandbox side effect.
package runnerjournalfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

var (
	ErrInvalid        = errors.New("runner journal input is invalid")
	ErrNotFound       = errors.New("runner journal execution was not found")
	ErrUnavailable    = errors.New("runner journal is unavailable")
	ErrConflict       = errors.New("runner journal state conflicts")
	ErrStale          = errors.New("runner journal assignment is stale")
	ErrOutcomeUnknown = errors.New("runner journal outcome is unknown")
)

type Entry struct {
	Assignment            devopsbuildv1.Assignment
	Phase                 Phase
	EffectID              string
	CancellationRequested bool
	Steps                 [2]StepProgress
	Receipt               *devopsbuildv1.Receipt
}

type Journal struct {
	rootPath string
	runnerID string
	mutex    sync.Mutex
}

type Claim struct {
	journal    *Journal
	staging    string
	mutex      sync.Mutex
	assignment *devopsbuildv1.Assignment
	archive    *os.File
	done       bool
}

type identityDocument struct {
	SchemaVersion uint32 `json:"schemaVersion"`
	RunnerID      string `json:"runnerId"`
	ContentDigest string `json:"contentDigest"`
}

func New(rootPath, runnerID string) (*Journal, error) {
	cleaned, err := validateRoot(rootPath)
	if err != nil || !validRunnerID(runnerID) {
		return nil, ErrInvalid
	}
	journal := &Journal{rootPath: cleaned, runnerID: runnerID}
	root, err := journal.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := recoverStaging(root); err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	if err := ensureIdentity(root, runnerID); err != nil {
		return nil, err
	}
	keys, err := listExecutionKeys(root)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	for _, key := range keys {
		if _, found, readErr := readExecution(
			context.Background(), root, key, runnerID, true,
		); readErr != nil || !found {
			return nil, errors.Join(ErrUnavailable, readErr)
		}
	}
	return journal, nil
}

func (journal *Journal) RunnerID() string {
	if journal == nil {
		return ""
	}
	return journal.runnerID
}

func (journal *Journal) BeginClaim(ctx context.Context) (*Claim, error) {
	if journal == nil || ctx == nil || !validRunnerID(journal.runnerID) {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	root, err := journal.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	staging, err := createStaging(root)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	if err := syncDirectory(root, "."); err != nil {
		_ = root.RemoveAll(staging)
		return nil, errors.Join(ErrUnavailable, err)
	}
	return &Claim{journal: journal, staging: staging}, nil
}

// Destination is passed directly to RunnerClient. It durably binds the
// canonical assignment before returning the archive writer, but does not make
// the claim executable until Commit publishes the complete verified staging
// directory.
func (claim *Claim) Destination(
	assignment devopsbuildv1.Assignment,
) (io.Writer, error) {
	if claim == nil {
		return nil, ErrInvalid
	}
	claim.mutex.Lock()
	defer claim.mutex.Unlock()
	if claim.done || claim.journal == nil || claim.assignment != nil ||
		devopsbuildv1.ValidateAssignment(assignment) != nil {
		return nil, ErrInvalid
	}
	root, err := claim.journal.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(claim.staging)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		!privateMode(info.Mode(), 0o700) {
		return nil, errors.Join(ErrUnavailable, err)
	}
	content, err := devopsbuildv1.EncodeAssignment(assignment)
	if err != nil || writePrivateFile(
		root, claim.staging+"/"+assignmentName, content,
	) != nil {
		return nil, ErrUnavailable
	}
	if err := syncDirectory(root, claim.staging); err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	copy := assignment
	claim.assignment = &copy
	if assignment.Mode != devopsbuildv1.AssignmentExecute {
		return nil, nil
	}
	archive, err := root.OpenFile(
		claim.staging+"/"+archiveName,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	claim.archive = archive
	return archive, nil
}

func (claim *Claim) Commit(ctx context.Context) (Entry, error) {
	if claim == nil || ctx == nil {
		return Entry{}, ErrInvalid
	}
	claim.mutex.Lock()
	defer claim.mutex.Unlock()
	if claim.done || claim.journal == nil || claim.assignment == nil {
		return Entry{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	if claim.archive != nil {
		syncErr := claim.archive.Sync()
		closeErr := claim.archive.Close()
		claim.archive = nil
		if syncErr != nil || closeErr != nil {
			return Entry{}, errors.Join(ErrUnavailable, syncErr, closeErr)
		}
	}
	claim.journal.mutex.Lock()
	defer claim.journal.mutex.Unlock()
	root, err := claim.journal.openRoot()
	if err != nil {
		return Entry{}, err
	}
	defer root.Close()
	content, err := readPrivateFile(
		root, claim.staging+"/"+assignmentName, devopsbuildv1.MaximumDocumentBytes,
	)
	if err != nil {
		return Entry{}, err
	}
	assignment, err := devopsbuildv1.DecodeAssignment(content)
	if err != nil || assignment != *claim.assignment {
		return Entry{}, errors.Join(ErrUnavailable, err)
	}
	if assignment.Mode == devopsbuildv1.AssignmentExecute {
		return claim.commitExecute(ctx, root, assignment)
	}
	return claim.commitRecovery(ctx, root, assignment)
}

func (claim *Claim) commitExecute(
	ctx context.Context,
	root *os.Root,
	assignment devopsbuildv1.Assignment,
) (Entry, error) {
	archive, err := openVerifiedArchive(
		ctx, root, claim.staging+"/"+archiveName, assignment.Request,
	)
	if err != nil {
		return Entry{}, err
	}
	if err := archive.Close(); err != nil {
		return Entry{}, errors.Join(ErrUnavailable, err)
	}
	key := executionKey(assignment.ExecutionID)
	if _, err := root.Lstat(key); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return Entry{}, ErrConflict
		}
		return Entry{}, errors.Join(ErrUnavailable, err)
	}
	executionCount, err := countExecutionDirectories(root)
	if err != nil || executionCount >= maximumJournalExecutions {
		return Entry{}, errors.Join(ErrUnavailable, err)
	}
	state, err := initialState(claim.journal.runnerID, assignment)
	if err != nil {
		return Entry{}, err
	}
	stateContent, err := encodeState(assignment.Request, state)
	if err != nil || writePrivateFile(
		root, claim.staging+"/"+stateFileName(state.Version), stateContent,
	) != nil {
		return Entry{}, ErrUnavailable
	}
	if err := syncDirectory(root, claim.staging); err != nil {
		return Entry{}, errors.Join(ErrUnavailable, err)
	}
	if err := validateStagingShape(
		root, claim.staging, true, stateFileName(state.Version),
	); err != nil {
		return Entry{}, err
	}
	if err := root.Rename(claim.staging, key); err != nil {
		return Entry{}, errors.Join(ErrUnavailable, err)
	}
	claim.done = true
	if err := syncDirectory(root, "."); err != nil {
		return Entry{}, errors.Join(ErrOutcomeUnknown, err)
	}
	return entryFrom(assignment, state), nil
}

func (claim *Claim) commitRecovery(
	ctx context.Context,
	root *os.Root,
	assignment devopsbuildv1.Assignment,
) (Entry, error) {
	if assignment.Mode != devopsbuildv1.AssignmentObserve &&
		assignment.Mode != devopsbuildv1.AssignmentCancel {
		return Entry{}, ErrInvalid
	}
	if err := validateStagingShape(root, claim.staging, false, ""); err != nil {
		return Entry{}, err
	}
	key := executionKey(assignment.ExecutionID)
	execution, found, err := readExecution(
		ctx, root, key, claim.journal.runnerID, true,
	)
	if err != nil {
		return Entry{}, err
	}
	if !found {
		return Entry{}, ErrNotFound
	}
	if execution.assignment.Request != assignment.Request ||
		execution.state.Phase == PhaseTerminal || execution.state.Phase == PhaseAcknowledged ||
		assignment.FencingToken <= execution.state.FencingToken ||
		!assignment.LeaseExpiresAt.After(execution.state.LeaseExpiresAt) ||
		(assignment.Mode == devopsbuildv1.AssignmentObserve &&
			execution.state.CancellationRequested) {
		return Entry{}, ErrStale
	}
	next := nextState(execution.state)
	next.Mode = assignment.Mode
	next.FencingToken = assignment.FencingToken
	next.LeaseExpiresAt = assignment.LeaseExpiresAt
	next.CancellationRequested = execution.state.CancellationRequested ||
		assignment.Mode == devopsbuildv1.AssignmentCancel
	sealState(&next)
	if err := appendState(root, execution, next); err != nil {
		return Entry{}, err
	}
	claim.done = true
	removeErr := root.RemoveAll(claim.staging)
	syncErr := syncDirectory(root, ".")
	if removeErr != nil || syncErr != nil {
		return Entry{}, errors.Join(ErrOutcomeUnknown, removeErr, syncErr)
	}
	return entryFrom(assignment, next), nil
}

func (claim *Claim) Abort() error {
	if claim == nil {
		return nil
	}
	claim.mutex.Lock()
	defer claim.mutex.Unlock()
	if claim.done {
		return nil
	}
	if claim.archive != nil {
		_ = claim.archive.Close()
		claim.archive = nil
	}
	if claim.journal == nil || !validStagingName(claim.staging) {
		claim.done = true
		return ErrInvalid
	}
	claim.journal.mutex.Lock()
	defer claim.journal.mutex.Unlock()
	root, err := claim.journal.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	removeErr := root.RemoveAll(claim.staging)
	syncErr := syncDirectory(root, ".")
	claim.done = true
	if removeErr != nil || syncErr != nil {
		return errors.Join(ErrUnavailable, removeErr, syncErr)
	}
	return nil
}

func (journal *Journal) Load(
	ctx context.Context,
	executionID string,
) (Entry, error) {
	if journal == nil || ctx == nil || executionKey(executionID) == "" {
		return Entry{}, ErrInvalid
	}
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	root, err := journal.openRoot()
	if err != nil {
		return Entry{}, err
	}
	defer root.Close()
	execution, found, err := readExecution(
		ctx, root, executionKey(executionID), journal.runnerID, true,
	)
	if err != nil {
		return Entry{}, err
	}
	if !found {
		return Entry{}, ErrNotFound
	}
	return entryFromCurrent(execution), nil
}

func (journal *Journal) Entries(ctx context.Context) ([]Entry, error) {
	if journal == nil || ctx == nil {
		return nil, ErrInvalid
	}
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	root, err := journal.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	keys, err := listExecutionKeys(root)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(keys))
	for _, key := range keys {
		execution, found, readErr := readExecution(
			ctx, root, key, journal.runnerID, true,
		)
		if readErr != nil || !found {
			return nil, errors.Join(ErrUnavailable, readErr)
		}
		entries = append(entries, entryFromCurrent(execution))
	}
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].Assignment.Request.StartedAt.Equal(
			entries[right].Assignment.Request.StartedAt,
		) {
			return entries[left].Assignment.ExecutionID < entries[right].Assignment.ExecutionID
		}
		return entries[left].Assignment.Request.StartedAt.Before(
			entries[right].Assignment.Request.StartedAt,
		)
	})
	return entries, nil
}

func (journal *Journal) MarkEffectStarted(
	ctx context.Context,
	assignment devopsbuildv1.Assignment,
	observedAt time.Time,
) (Entry, error) {
	return journal.change(ctx, assignment, func(execution storedExecution) (stateRecord, bool, error) {
		if validateJournalTime(observedAt) != nil ||
			observedAt.Before(assignment.Request.StartedAt) ||
			!observedAt.Before(assignment.LeaseExpiresAt) ||
			!observedAt.Before(assignment.Request.DeadlineAt) {
			return stateRecord{}, false, ErrStale
		}
		if execution.state.Phase == PhaseEffectStarted {
			return execution.state, false, nil
		}
		if execution.state.Phase != PhaseReceived ||
			execution.state.Mode != devopsbuildv1.AssignmentExecute ||
			execution.state.CancellationRequested {
			return stateRecord{}, false, ErrConflict
		}
		next := nextState(execution.state)
		next.Phase = PhaseEffectStarted
		sealState(&next)
		return next, true, nil
	})
}

func (journal *Journal) ApplyRenewal(
	ctx context.Context,
	assignment devopsbuildv1.Assignment,
	renewal devopsbuildv1.Renewal,
) (Entry, error) {
	if devopsbuildv1.ValidateRenewal(assignment.Request, renewal) != nil ||
		renewal.ExecutionID != assignment.ExecutionID ||
		renewal.FencingToken != assignment.FencingToken {
		return Entry{}, ErrInvalid
	}
	return journal.change(ctx, assignment, func(execution storedExecution) (stateRecord, bool, error) {
		if execution.state.Phase != PhaseReceived &&
			execution.state.Phase != PhaseEffectStarted {
			return stateRecord{}, false, ErrConflict
		}
		if renewal.LeaseExpiresAt.Before(execution.state.LeaseExpiresAt) ||
			(execution.state.CancellationRequested && !renewal.CancellationRequested) {
			return stateRecord{}, false, ErrStale
		}
		if renewal.LeaseExpiresAt.Equal(execution.state.LeaseExpiresAt) &&
			renewal.CancellationRequested == execution.state.CancellationRequested {
			return execution.state, false, nil
		}
		next := nextState(execution.state)
		next.LeaseExpiresAt = renewal.LeaseExpiresAt
		next.CancellationRequested = renewal.CancellationRequested
		sealState(&next)
		return next, true, nil
	})
}

// MarkStepStarted durably authorizes exactly one next fixed sandbox step. The
// caller must commit this transition before creating or starting its container.
func (journal *Journal) MarkStepStarted(
	ctx context.Context,
	assignment devopsbuildv1.Assignment,
	step devopsv1.VerificationStep,
) (Entry, error) {
	index, found := requestStepIndex(assignment.Request, step)
	if !found {
		return Entry{}, ErrInvalid
	}
	return journal.change(ctx, assignment, func(execution storedExecution) (stateRecord, bool, error) {
		current := execution.state.Steps[index].Phase
		if current == StepStarted {
			return execution.state, false, nil
		}
		if execution.state.Phase != PhaseEffectStarted ||
			execution.state.CancellationRequested || current != StepPending ||
			(index == 1 && execution.state.Steps[0].Phase != StepPassed) {
			return stateRecord{}, false, ErrConflict
		}
		next := nextState(execution.state)
		next.Steps[index].Phase = StepStarted
		if !validStepProgress(assignment.Request, next.Steps) {
			return stateRecord{}, false, ErrConflict
		}
		sealState(&next)
		return next, true, nil
	})
}

// RecordStepConclusion seals normalized sandbox evidence before a later
// terminal receipt can be accepted. A pending step may become CANCELLED only
// when the durable assignment already carries cancellation.
func (journal *Journal) RecordStepConclusion(
	ctx context.Context,
	assignment devopsbuildv1.Assignment,
	step devopsv1.VerificationStep,
	conclusion devopsbuildv1.StepConclusion,
) (Entry, error) {
	index, found := requestStepIndex(assignment.Request, step)
	want := stepPhaseFromConclusion(conclusion)
	if !found || want == "" {
		return Entry{}, ErrInvalid
	}
	return journal.change(ctx, assignment, func(execution storedExecution) (stateRecord, bool, error) {
		current := execution.state.Steps[index].Phase
		if current == want {
			return execution.state, false, nil
		}
		if execution.state.Phase != PhaseReceived &&
			execution.state.Phase != PhaseEffectStarted {
			return stateRecord{}, false, ErrConflict
		}
		if current == StepPending &&
			(want != StepCancelled || !execution.state.CancellationRequested) {
			return stateRecord{}, false, ErrConflict
		}
		if current != StepPending && current != StepStarted {
			return stateRecord{}, false, ErrConflict
		}
		next := nextState(execution.state)
		next.Steps[index].Phase = want
		if !validStepProgress(assignment.Request, next.Steps) {
			return stateRecord{}, false, ErrConflict
		}
		sealState(&next)
		return next, true, nil
	})
}

func (journal *Journal) RecordReceipt(
	ctx context.Context,
	assignment devopsbuildv1.Assignment,
	receipt devopsbuildv1.Receipt,
) (Entry, error) {
	if devopsbuildv1.ValidateReceipt(assignment.Request, receipt) != nil ||
		receipt.ExecutorID != journal.RunnerID() {
		return Entry{}, ErrInvalid
	}
	return journal.change(ctx, assignment, func(execution storedExecution) (stateRecord, bool, error) {
		if execution.state.Phase == PhaseTerminal && execution.state.Receipt != nil &&
			*execution.state.Receipt == receipt {
			return execution.state, false, nil
		}
		if !progressMatchesReceipt(execution.state.Steps, receipt) ||
			(execution.state.Phase != PhaseEffectStarted &&
				(execution.state.Phase != PhaseReceived ||
					!execution.state.CancellationRequested)) {
			return stateRecord{}, false, ErrConflict
		}
		next := nextState(execution.state)
		next.Phase = PhaseTerminal
		next.Receipt = &receipt
		sealState(&next)
		return next, true, nil
	})
}

func (journal *Journal) Acknowledge(
	ctx context.Context,
	assignment devopsbuildv1.Assignment,
	receipt devopsbuildv1.Receipt,
) (Entry, error) {
	return journal.change(ctx, assignment, func(execution storedExecution) (stateRecord, bool, error) {
		if execution.state.Receipt == nil || *execution.state.Receipt != receipt {
			return stateRecord{}, false, ErrConflict
		}
		if execution.state.Phase == PhaseAcknowledged {
			return execution.state, false, nil
		}
		if execution.state.Phase != PhaseTerminal {
			return stateRecord{}, false, ErrConflict
		}
		next := nextState(execution.state)
		next.Phase = PhaseAcknowledged
		sealState(&next)
		return next, true, nil
	})
}

func (journal *Journal) OpenArchive(
	ctx context.Context,
	executionID string,
) (io.ReadCloser, error) {
	if journal == nil || ctx == nil || executionKey(executionID) == "" {
		return nil, ErrInvalid
	}
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	root, err := journal.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	execution, found, err := readExecution(
		ctx, root, executionKey(executionID), journal.runnerID, false,
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	return openVerifiedArchive(
		ctx, root, execution.key+"/"+archiveName, execution.assignment.Request,
	)
}

func (journal *Journal) change(
	ctx context.Context,
	assignment devopsbuildv1.Assignment,
	transition func(storedExecution) (stateRecord, bool, error),
) (Entry, error) {
	if journal == nil || ctx == nil || transition == nil ||
		devopsbuildv1.ValidateAssignment(assignment) != nil {
		return Entry{}, ErrInvalid
	}
	journal.mutex.Lock()
	defer journal.mutex.Unlock()
	root, err := journal.openRoot()
	if err != nil {
		return Entry{}, err
	}
	defer root.Close()
	execution, found, err := readExecution(
		ctx, root, executionKey(assignment.ExecutionID), journal.runnerID, true,
	)
	if err != nil {
		return Entry{}, err
	}
	if !found {
		return Entry{}, ErrNotFound
	}
	current := currentAssignment(execution)
	if current != assignment {
		return Entry{}, ErrStale
	}
	next, changed, err := transition(execution)
	if err != nil {
		return Entry{}, err
	}
	if !changed {
		return entryFrom(current, execution.state), nil
	}
	if err := appendState(root, execution, next); err != nil {
		return Entry{}, err
	}
	return entryFrom(currentAssignment(storedExecution{
		assignment: execution.assignment, state: next,
	}), next), nil
}

func currentAssignment(execution storedExecution) devopsbuildv1.Assignment {
	assignment := execution.assignment
	assignment.Mode = execution.state.Mode
	assignment.FencingToken = execution.state.FencingToken
	assignment.LeaseExpiresAt = execution.state.LeaseExpiresAt
	return assignment
}

func entryFromCurrent(execution storedExecution) Entry {
	return entryFrom(currentAssignment(execution), execution.state)
}

func entryFrom(assignment devopsbuildv1.Assignment, state stateRecord) Entry {
	entry := Entry{
		Assignment: assignment, Phase: state.Phase, EffectID: state.EffectID,
		CancellationRequested: state.CancellationRequested, Steps: state.Steps,
	}
	if state.Receipt != nil {
		receipt := *state.Receipt
		entry.Receipt = &receipt
	}
	return entry
}

func stepPhaseFromConclusion(value devopsbuildv1.StepConclusion) StepPhase {
	switch value {
	case devopsbuildv1.StepConclusionPassed:
		return StepPassed
	case devopsbuildv1.StepConclusionFailed:
		return StepFailed
	case devopsbuildv1.StepConclusionCancelled:
		return StepCancelled
	default:
		return ""
	}
}

func ensureIdentity(root *os.Root, runnerID string) error {
	content, err := readPrivateFile(root, identityName, devopsbuildv1.MaximumDocumentBytes)
	if err == nil {
		identity, decodeErr := decodeIdentity(content)
		if decodeErr != nil || identity.RunnerID != runnerID {
			return errors.Join(ErrConflict, decodeErr)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, ErrUnavailable) {
		return err
	}
	if _, statErr := root.Lstat(identityName); !errors.Is(statErr, os.ErrNotExist) {
		return ErrUnavailable
	}
	directory, openErr := root.Open(".")
	if openErr != nil {
		return errors.Join(ErrUnavailable, openErr)
	}
	entries, readErr := directory.ReadDir(2)
	closeErr := directory.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(entries) > 1 {
		return errors.Join(ErrUnavailable, readErr, closeErr)
	}
	if len(entries) == 1 {
		info, infoErr := entries[0].Info()
		if entries[0].Name() != ownershipLockName || infoErr != nil ||
			!validOwnershipFile(info) {
			return errors.Join(ErrUnavailable, infoErr)
		}
	}
	identity := identityDocument{SchemaVersion: 1, RunnerID: runnerID}
	identity.ContentDigest = digestIdentity(identity)
	encoded, err := encodeIdentity(identity)
	if err != nil {
		return err
	}
	if err := writePrivateFile(root, identityTemporaryName, encoded); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	published := false
	defer func() {
		if !published {
			_ = root.Remove(identityTemporaryName)
		}
	}()
	if err := root.Rename(identityTemporaryName, identityName); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	published = true
	if err := syncDirectory(root, "."); err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	return nil
}

func encodeIdentity(value identityDocument) ([]byte, error) {
	if !validIdentity(value) {
		return nil, ErrInvalid
	}
	content, err := json.Marshal(value)
	if err != nil || len(content) == 0 || len(content) > devopsbuildv1.MaximumDocumentBytes {
		return nil, ErrUnavailable
	}
	return content, nil
}

func decodeIdentity(content []byte) (identityDocument, error) {
	var value identityDocument
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return identityDocument{}, ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || !validIdentity(value) {
		return identityDocument{}, ErrUnavailable
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, content) {
		return identityDocument{}, ErrUnavailable
	}
	return value, nil
}

func validIdentity(value identityDocument) bool {
	return value.SchemaVersion == 1 && validRunnerID(value.RunnerID) &&
		value.ContentDigest == digestIdentity(value)
}

func digestIdentity(value identityDocument) string {
	digest := sha256.New()
	writeStateString(digest, "matrix-devops-runner-journal-identity-v1")
	writeStateUint64(digest, uint64(value.SchemaVersion))
	writeStateString(digest, value.RunnerID)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}
