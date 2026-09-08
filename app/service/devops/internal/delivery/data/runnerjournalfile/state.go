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
)

type Phase string

const (
	PhaseReceived      Phase = "RECEIVED"
	PhaseEffectStarted Phase = "EFFECT_STARTED"
	PhaseTerminal      Phase = "TERMINAL"
	PhaseAcknowledged  Phase = "ACKNOWLEDGED"
)

type stateRecord struct {
	SchemaVersion         uint32                       `json:"schemaVersion"`
	Version               uint64                       `json:"version"`
	ExecutionID           string                       `json:"executionId"`
	RequestDigest         string                       `json:"requestDigest"`
	RunnerID              string                       `json:"runnerId"`
	Phase                 Phase                        `json:"phase"`
	Mode                  devopsbuildv1.AssignmentMode `json:"mode"`
	FencingToken          uint64                       `json:"fencingToken"`
	LeaseExpiresAt        time.Time                    `json:"leaseExpiresAt"`
	EffectID              string                       `json:"effectId"`
	CancellationRequested bool                         `json:"cancellationRequested"`
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
		SchemaVersion:  1,
		Version:        1,
		ExecutionID:    assignment.ExecutionID,
		RequestDigest:  requestDigest,
		RunnerID:       runnerID,
		Phase:          PhaseReceived,
		Mode:           assignment.Mode,
		FencingToken:   assignment.FencingToken,
		LeaseExpiresAt: assignment.LeaseExpiresAt,
		EffectID:       effectID(assignment.ExecutionID),
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
	if err != nil || value.SchemaVersion != 1 || value.Version == 0 ||
		value.Version > devopsv1.MaximumContractInteger || value.ExecutionID != executionID ||
		requestDigestErr != nil || value.RequestDigest != requestDigest ||
		devopsv1.ValidateDigest("runnerState.requestDigest", value.RequestDigest) != nil ||
		!validRunnerID(value.RunnerID) || !validEffectID(value.EffectID, executionID) ||
		value.FencingToken == 0 || value.FencingToken > devopsv1.MaximumContractInteger ||
		validateJournalTime(value.LeaseExpiresAt) != nil ||
		!value.LeaseExpiresAt.After(request.StartedAt) ||
		value.LeaseExpiresAt.After(request.DeadlineAt) ||
		devopsv1.ValidateDigest("runnerState.contentDigest", value.ContentDigest) != nil ||
		value.ContentDigest != digestState(value) {
		return ErrUnavailable
	}
	if value.Version == 1 {
		if value.PreviousDigest != "" || value.Phase != PhaseReceived ||
			value.Mode != devopsbuildv1.AssignmentExecute || value.FencingToken != 1 ||
			value.CancellationRequested || value.Receipt != nil {
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
	case PhaseReceived, PhaseEffectStarted:
		if value.Receipt != nil {
			return ErrUnavailable
		}
	case PhaseTerminal, PhaseAcknowledged:
		if value.Receipt == nil ||
			devopsbuildv1.ValidateReceipt(request, *value.Receipt) != nil ||
			value.Receipt.ExecutorID != value.RunnerID {
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
			next.Phase != previous.Phase || !equalReceipt(next.Receipt, previous.Receipt) ||
			(previous.Phase != PhaseReceived && previous.Phase != PhaseEffectStarted) ||
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
		if (next.Phase != PhaseReceived && next.Phase != PhaseEffectStarted) ||
			!equalReceipt(next.Receipt, previous.Receipt) ||
			(next.LeaseExpiresAt.Equal(previous.LeaseExpiresAt) &&
				next.CancellationRequested == previous.CancellationRequested) {
			return ErrUnavailable
		}
		return nil
	}
	if !next.LeaseExpiresAt.Equal(previous.LeaseExpiresAt) ||
		next.CancellationRequested != previous.CancellationRequested {
		return ErrUnavailable
	}
	switch {
	case previous.Phase == PhaseReceived && next.Phase == PhaseEffectStarted &&
		previous.Mode == devopsbuildv1.AssignmentExecute &&
		!previous.CancellationRequested:
		return nil
	case previous.Phase == PhaseEffectStarted && next.Phase == PhaseTerminal:
		return nil
	case previous.Phase == PhaseTerminal && next.Phase == PhaseAcknowledged:
		return nil
	default:
		return ErrUnavailable
	}
}

func digestState(value stateRecord) string {
	digest := sha256.New()
	writeStateString(digest, "matrix-devops-runner-journal-state-v1")
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
	if value.Receipt == nil {
		writeStateString(digest, "")
	} else {
		writeStateString(digest, value.Receipt.ContentDigest)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
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
