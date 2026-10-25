package runnerjournalfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"strings"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

type stateRecord struct {
	SchemaVersion         uint32                       `json:"schemaVersion"`
	Version               uint64                       `json:"version"`
	ExecutionID           string                       `json:"executionId"`
	RequestDigest         string                       `json:"requestDigest"`
	RunnerID              string                       `json:"runnerId"`
	Phase                 port.RunnerJournalPhase      `json:"phase"`
	Mode                  devopsbuildv1.AssignmentMode `json:"mode"`
	FencingToken          uint64                       `json:"fencingToken"`
	LeaseExpiresAt        time.Time                    `json:"leaseExpiresAt"`
	EffectID              string                       `json:"effectId"`
	CancellationRequested bool                         `json:"cancellationRequested"`
	Steps                 [2]port.RunnerStepProgress   `json:"steps"`
	LogProgress           runnerlog.Progress           `json:"logProgress"`
	Receipt               *devopsbuildv1.Receipt       `json:"receipt"`
	PreviousDigest        string                       `json:"previousDigest"`
	ContentDigest         string                       `json:"contentDigest"`
}

func initialState(
	runnerID string,
	assignment devopsbuildv1.Assignment,
) (stateRecord, error) {
	if !validRunnerID(runnerID) || devopsbuildv1.ValidateAssignment(assignment) != nil ||
		assignment.Mode != devopsbuildv1.AssignmentExecute || assignment.FencingToken != 1 {
		return stateRecord{}, ErrInvalid
	}
	requestDigest, err := devopsbuildv1.DigestRequest(assignment.Request)
	if err != nil {
		return stateRecord{}, ErrInvalid
	}
	state := stateRecord{
		SchemaVersion:  3,
		Version:        1,
		ExecutionID:    assignment.ExecutionID,
		RequestDigest:  requestDigest,
		RunnerID:       runnerID,
		Phase:          port.RunnerJournalReceived,
		Mode:           assignment.Mode,
		FencingToken:   assignment.FencingToken,
		LeaseExpiresAt: assignment.LeaseExpiresAt,
		EffectID:       effectID(assignment.ExecutionID),
		Steps:          initialStepProgress(assignment.Request),
	}
	sealState(&state)
	if err := validateState(assignment.Request, state); err != nil {
		return stateRecord{}, err
	}
	return state, nil
}

func nextState(previous stateRecord) stateRecord {
	next := previous
	next.Version++
	next.PreviousDigest = previous.ContentDigest
	next.ContentDigest = ""
	return next
}

func sealState(value *stateRecord) {
	value.ContentDigest = digestState(*value)
}

func encodeState(
	request devopsbuildv1.Request,
	value stateRecord,
) ([]byte, error) {
	if err := validateState(request, value); err != nil {
		return nil, err
	}
	content, err := json.Marshal(value)
	if err != nil || len(content) == 0 || len(content) > devopsbuildv1.MaximumDocumentBytes {
		return nil, ErrUnavailable
	}
	return content, nil
}

func decodeState(
	request devopsbuildv1.Request,
	content []byte,
) (stateRecord, error) {
	if len(content) == 0 || len(content) > devopsbuildv1.MaximumDocumentBytes {
		return stateRecord{}, ErrUnavailable
	}
	var value stateRecord
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return stateRecord{}, errors.Join(ErrUnavailable, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return stateRecord{}, ErrUnavailable
	}
	if err := validateState(request, value); err != nil {
		return stateRecord{}, err
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, content) {
		return stateRecord{}, ErrUnavailable
	}
	return value, nil
}

func validateState(request devopsbuildv1.Request, value stateRecord) error {
	executionID, err := devopsbuildv1.ExecutionID(request)
	requestDigest, requestDigestErr := devopsbuildv1.DigestRequest(request)
	if err != nil || value.SchemaVersion != 3 || value.Version == 0 ||
		value.Version > devopsv1.MaximumContractInteger || value.ExecutionID != executionID ||
		requestDigestErr != nil || value.RequestDigest != requestDigest ||
		devopsv1.ValidateDigest("runnerState.requestDigest", value.RequestDigest) != nil ||
		!validRunnerID(value.RunnerID) || !validEffectID(value.EffectID, executionID) ||
		value.FencingToken == 0 || value.FencingToken > devopsv1.MaximumContractInteger ||
		validateJournalTime(value.LeaseExpiresAt) != nil ||
		!value.LeaseExpiresAt.After(request.StartedAt) ||
		value.LeaseExpiresAt.After(request.DeadlineAt) ||
		devopsv1.ValidateDigest("runnerState.contentDigest", value.ContentDigest) != nil ||
		value.ContentDigest != digestState(value) ||
		runnerlog.Validate(value.LogProgress) != nil {
		return ErrUnavailable
	}
	if !validStepProgress(request, value.Steps) {
		return ErrUnavailable
	}
	if value.Version == 1 {
		if value.PreviousDigest != "" || value.Phase != port.RunnerJournalReceived ||
			value.Mode != devopsbuildv1.AssignmentExecute || value.FencingToken != 1 ||
			value.CancellationRequested || value.Steps != initialStepProgress(request) ||
			value.LogProgress != (runnerlog.Progress{}) ||
			value.Receipt != nil {
			return ErrUnavailable
		}
	} else if devopsv1.ValidateDigest(
		"runnerState.previousDigest", value.PreviousDigest,
	) != nil {
		return ErrUnavailable
	}
	if value.Mode == devopsbuildv1.AssignmentExecute {
		if value.FencingToken != 1 {
			return ErrUnavailable
		}
	} else if (value.Mode != devopsbuildv1.AssignmentObserve &&
		value.Mode != devopsbuildv1.AssignmentCancel) || value.FencingToken < 2 {
		return ErrUnavailable
	}
	if value.Mode == devopsbuildv1.AssignmentCancel && !value.CancellationRequested {
		return ErrUnavailable
	}
	switch value.Phase {
	case port.RunnerJournalReceived:
		if value.Receipt != nil || (value.Steps != initialStepProgress(request) &&
			(!value.CancellationRequested || !pendingCancellation(value.Steps))) {
			return ErrUnavailable
		}
	case port.RunnerJournalEffectStarted:
		if value.Receipt != nil {
			return ErrUnavailable
		}
	case port.RunnerJournalTerminal, port.RunnerJournalAcknowledged:
		if value.Receipt == nil ||
			devopsbuildv1.ValidateReceipt(request, *value.Receipt) != nil ||
			value.Receipt.ExecutorID != value.RunnerID ||
			!progressMatchesReceipt(value.Steps, *value.Receipt) {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	return nil
}

func validateTransition(previous, next stateRecord) error {
	if next.Version != previous.Version+1 ||
		next.PreviousDigest != previous.ContentDigest ||
		next.ExecutionID != previous.ExecutionID || next.RunnerID != previous.RunnerID ||
		next.RequestDigest != previous.RequestDigest ||
		next.EffectID != previous.EffectID || next.FencingToken < previous.FencingToken ||
		next.LeaseExpiresAt.Before(previous.LeaseExpiresAt) ||
		(previous.CancellationRequested && !next.CancellationRequested) {
		return ErrUnavailable
	}
	if next.FencingToken > previous.FencingToken {
		if next.Mode == devopsbuildv1.AssignmentExecute ||
			next.Phase != previous.Phase || next.Steps != previous.Steps ||
			next.LogProgress != previous.LogProgress ||
			!equalReceipt(next.Receipt, previous.Receipt) ||
			(previous.Phase != port.RunnerJournalReceived && previous.Phase != port.RunnerJournalEffectStarted &&
				previous.Phase != port.RunnerJournalTerminal) ||
			!next.LeaseExpiresAt.After(previous.LeaseExpiresAt) ||
			(next.Mode == devopsbuildv1.AssignmentObserve && next.CancellationRequested) ||
			(next.Mode == devopsbuildv1.AssignmentCancel && !next.CancellationRequested) {
			return ErrUnavailable
		}
		return nil
	}
	if next.Mode != previous.Mode || next.FencingToken != previous.FencingToken {
		return ErrUnavailable
	}
	if next.Phase == previous.Phase {
		if next.Steps != previous.Steps {
			if !next.LeaseExpiresAt.Equal(previous.LeaseExpiresAt) ||
				next.CancellationRequested != previous.CancellationRequested ||
				!equalReceipt(next.Receipt, previous.Receipt) ||
				(previous.Phase != port.RunnerJournalEffectStarted &&
					(previous.Phase != port.RunnerJournalReceived || !next.CancellationRequested)) ||
				!validStepTransition(
					previous.Steps, next.Steps, next.CancellationRequested,
					previous.LogProgress, next.LogProgress,
				) {
				return ErrUnavailable
			}
			return nil
		}
		if next.LogProgress != previous.LogProgress ||
			(next.Phase != port.RunnerJournalReceived && next.Phase != port.RunnerJournalEffectStarted) ||
			!equalReceipt(next.Receipt, previous.Receipt) ||
			(next.LeaseExpiresAt.Equal(previous.LeaseExpiresAt) &&
				next.CancellationRequested == previous.CancellationRequested) {
			return ErrUnavailable
		}
		return nil
	}
	if !next.LeaseExpiresAt.Equal(previous.LeaseExpiresAt) ||
		next.LogProgress != previous.LogProgress ||
		next.CancellationRequested != previous.CancellationRequested {
		return ErrUnavailable
	}
	switch {
	case previous.Phase == port.RunnerJournalReceived && next.Phase == port.RunnerJournalEffectStarted &&
		previous.Mode == devopsbuildv1.AssignmentExecute &&
		!previous.CancellationRequested && next.Steps == previous.Steps:
		return nil
	case previous.Phase == port.RunnerJournalReceived && next.Phase == port.RunnerJournalTerminal &&
		previous.CancellationRequested && next.CancellationRequested &&
		next.Steps == previous.Steps:
		return nil
	case previous.Phase == port.RunnerJournalEffectStarted && next.Phase == port.RunnerJournalTerminal &&
		next.Steps == previous.Steps:
		return nil
	case previous.Phase == port.RunnerJournalTerminal && next.Phase == port.RunnerJournalAcknowledged &&
		next.Steps == previous.Steps:
		return nil
	default:
		return ErrUnavailable
	}
}

func digestState(value stateRecord) string {
	digest := sha256.New()
	writeStateString(digest, "matrix-devops-runner-journal-state-v3")
	writeStateUint64(digest, uint64(value.SchemaVersion))
	writeStateUint64(digest, value.Version)
	for _, field := range []string{
		value.ExecutionID,
		value.RequestDigest,
		value.RunnerID,
		string(value.Phase),
		string(value.Mode),
		value.LeaseExpiresAt.Format(time.RFC3339Nano),
		value.EffectID,
		value.PreviousDigest,
	} {
		writeStateString(digest, field)
	}
	writeStateUint64(digest, value.FencingToken)
	if value.CancellationRequested {
		writeStateUint64(digest, 1)
	} else {
		writeStateUint64(digest, 0)
	}
	for _, step := range value.Steps {
		writeStateUint64(digest, uint64(step.Ordinal))
		writeStateString(digest, string(step.Kind))
		writeStateString(digest, string(step.Phase))
		writeStateString(digest, step.StartedAt.Format(time.RFC3339Nano))
	}
	writeStateUint64(digest, uint64(value.LogProgress.NativeBytes))
	writeStateUint64(digest, uint64(value.LogProgress.NormalizedBytes))
	writeStateUint64(digest, value.LogProgress.LastSequence)
	if value.Receipt == nil {
		writeStateString(digest, "")
	} else {
		writeStateString(digest, value.Receipt.ContentDigest)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func initialStepProgress(request devopsbuildv1.Request) [2]port.RunnerStepProgress {
	return [2]port.RunnerStepProgress{
		{Ordinal: request.Steps[0].Ordinal, Kind: request.Steps[0].Kind, Phase: port.RunnerStepPending},
		{Ordinal: request.Steps[1].Ordinal, Kind: request.Steps[1].Kind, Phase: port.RunnerStepPending},
	}
}

func validStepProgress(
	request devopsbuildv1.Request,
	steps [2]port.RunnerStepProgress) bool {
	for index, step := range steps {
		if step.Ordinal != request.Steps[index].Ordinal ||
			step.Kind != request.Steps[index].Kind {
			return false
		}
		switch step.Phase {
		case port.RunnerStepPending:
			if !step.StartedAt.IsZero() {
				return false
			}
		case port.RunnerStepStarted, port.RunnerStepPassed, port.RunnerStepFailed:
			if !validStepStart(request, step.StartedAt) {
				return false
			}
		case port.RunnerStepCancelled:
			if !step.StartedAt.IsZero() && !validStepStart(request, step.StartedAt) {
				return false
			}
		default:
			return false
		}
	}
	left, right := steps[0].Phase, steps[1].Phase
	validOrder := (left == port.RunnerStepPending && right == port.RunnerStepPending) ||
		(left == port.RunnerStepStarted && right == port.RunnerStepPending) ||
		(left == port.RunnerStepPassed && right == port.RunnerStepPending) ||
		(left == port.RunnerStepFailed && right == port.RunnerStepPending) ||
		(left == port.RunnerStepCancelled && right == port.RunnerStepPending) ||
		(left == port.RunnerStepPassed && right == port.RunnerStepStarted) ||
		(left == port.RunnerStepPassed && right == port.RunnerStepPassed) ||
		(left == port.RunnerStepPassed && right == port.RunnerStepFailed) ||
		(left == port.RunnerStepPassed && right == port.RunnerStepCancelled)
	if !validOrder {
		return false
	}
	return steps[1].StartedAt.IsZero() ||
		(!steps[0].StartedAt.IsZero() && !steps[1].StartedAt.Before(steps[0].StartedAt))
}

func validStepStart(request devopsbuildv1.Request, value time.Time) bool {
	return validateJournalTime(value) == nil && !value.Before(request.StartedAt) &&
		value.Before(request.DeadlineAt)
}

func pendingCancellation(steps [2]port.RunnerStepProgress) bool {
	return (steps[0].Phase == port.RunnerStepCancelled && steps[1].Phase == port.RunnerStepPending) ||
		(steps[0].Phase == port.RunnerStepPassed && steps[1].Phase == port.RunnerStepCancelled)
}

func progressMatchesReceipt(
	steps [2]port.RunnerStepProgress, receipt devopsbuildv1.Receipt,
) bool {
	for index, step := range steps {
		if step.Ordinal != receipt.Steps[index].Ordinal ||
			step.Kind != receipt.Steps[index].Kind ||
			stepReceiptConclusion(step.Phase) != receipt.Steps[index].Conclusion {
			return false
		}
	}
	return true
}

func stepReceiptConclusion(value port.RunnerStepPhase) devopsbuildv1.StepConclusion {
	switch value {
	case port.RunnerStepPassed:
		return devopsbuildv1.StepConclusionPassed
	case port.RunnerStepFailed:
		return devopsbuildv1.StepConclusionFailed
	case port.RunnerStepCancelled:
		return devopsbuildv1.StepConclusionCancelled
	case port.RunnerStepPending:
		return devopsbuildv1.StepConclusionNotRun
	default:
		return ""
	}
}

func validStepTransition(
	previous [2]port.RunnerStepProgress, next [2]port.RunnerStepProgress, cancellationRequested bool,
	previousLog runnerlog.Progress,
	nextLog runnerlog.Progress,
) bool {
	changed := -1
	for index := range previous {
		if previous[index].Ordinal != next[index].Ordinal ||
			previous[index].Kind != next[index].Kind {
			return false
		}
		if previous[index].Phase == next[index].Phase {
			if previous[index].StartedAt != next[index].StartedAt {
				return false
			}
		} else {
			if changed >= 0 {
				return false
			}
			changed = index
		}
	}
	if changed < 0 {
		return false
	}
	from, to := previous[changed].Phase, next[changed].Phase
	if from == port.RunnerStepPending {
		return nextLog == previousLog &&
			((!cancellationRequested && to == port.RunnerStepStarted &&
				!next[changed].StartedAt.IsZero()) ||
				(cancellationRequested && to == port.RunnerStepCancelled &&
					next[changed].StartedAt.IsZero()))
	}
	return from == port.RunnerStepStarted &&
		previous[changed].StartedAt == next[changed].StartedAt &&
		(to == port.RunnerStepPassed || to == port.RunnerStepFailed || to == port.RunnerStepCancelled) &&
		runnerlog.ValidateAdvance(previousLog, nextLog) == nil
}

func requestStepIndex(
	request devopsbuildv1.Request,
	step devopsv1.VerificationStep,
) (int, bool) {
	for index, expected := range request.Steps {
		if expected == step {
			return index, true
		}
	}
	return 0, false
}

func equalReceipt(left, right *devopsbuildv1.Receipt) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func effectID(executionID string) string {
	return "matrix-build-" + strings.TrimPrefix(executionID, "sha256:")[:48]
}

func validEffectID(value, executionID string) bool {
	return strings.HasPrefix(executionID, "sha256:") &&
		len(strings.TrimPrefix(executionID, "sha256:")) == sha256.Size*2 &&
		value == effectID(executionID)
}

func validRunnerID(value string) bool {
	return len(value) == len("runner-")+sha256.Size*2 &&
		strings.HasPrefix(value, "runner-") && lowerHex(value[len("runner-"):])
}

func lowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validateJournalTime(value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return ErrInvalid
	}
	return nil
}

func writeStateString(destination hash.Hash, value string) {
	writeStateUint64(destination, uint64(len(value)))
	_, _ = destination.Write([]byte(value))
}

func writeStateUint64(destination hash.Hash, value uint64) {
	var framed [8]byte
	binary.BigEndian.PutUint64(framed[:], value)
	_, _ = destination.Write(framed[:])
}
