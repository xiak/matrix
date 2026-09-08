package executorspoolfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"strconv"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	stateFormat = "matrix-devops-executor-spool/v1"
	stateKind   = "ExecutionState"
)

type phase string

const (
	phaseQueued    phase = "QUEUED"
	phaseAssigned  phase = "ASSIGNED"
	phaseTerminal  phase = "TERMINAL"
	phaseCancelled phase = "CANCELLED"
)

type stateRecord struct {
	Format                string                 `json:"format"`
	Kind                  string                 `json:"kind"`
	Version               uint64                 `json:"version"`
	PreviousDigest        string                 `json:"previousDigest"`
	ContentDigest         string                 `json:"contentDigest"`
	ExecutionID           string                 `json:"executionId"`
	RequestDigest         string                 `json:"requestDigest"`
	Phase                 phase                  `json:"phase"`
	CancellationRequested bool                   `json:"cancellationRequested"`
	RunnerID              string                 `json:"runnerId"`
	FencingToken          uint64                 `json:"fencingToken"`
	LeaseExpiresAt        *time.Time             `json:"leaseExpiresAt"`
	Receipt               *devopsbuildv1.Receipt `json:"receipt"`
}

func initialState(request devopsbuildv1.Request) (stateRecord, error) {
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		return stateRecord{}, err
	}
	requestDigest, err := devopsbuildv1.DigestRequest(request)
	if err != nil {
		return stateRecord{}, err
	}
	value := stateRecord{
		Format: stateFormat, Kind: stateKind, Version: 1,
		ExecutionID: executionID, RequestDigest: requestDigest, Phase: phaseQueued,
	}
	value.ContentDigest = digestState(value)
	if err := validateState(request, value); err != nil {
		return stateRecord{}, err
	}
	return value, nil
}

func nextState(previous stateRecord) stateRecord {
	return stateRecord{
		Format:                stateFormat,
		Kind:                  stateKind,
		Version:               previous.Version + 1,
		PreviousDigest:        previous.ContentDigest,
		ExecutionID:           previous.ExecutionID,
		RequestDigest:         previous.RequestDigest,
		Phase:                 previous.Phase,
		CancellationRequested: previous.CancellationRequested,
		RunnerID:              previous.RunnerID,
		FencingToken:          previous.FencingToken,
		LeaseExpiresAt:        copyTime(previous.LeaseExpiresAt),
		Receipt:               copyReceipt(previous.Receipt),
	}
}

func sealState(value *stateRecord) {
	value.ContentDigest = digestState(*value)
}

func encodeState(request devopsbuildv1.Request, value stateRecord) ([]byte, error) {
	if err := validateState(request, value); err != nil {
		return nil, err
	}
	content, err := json.Marshal(value)
	if err != nil || len(content) == 0 || len(content) > devopsbuildv1.MaximumDocumentBytes {
		return nil, ErrUnavailable
	}
	return content, nil
}

func decodeState(request devopsbuildv1.Request, content []byte) (stateRecord, error) {
	if len(content) == 0 || len(content) > devopsbuildv1.MaximumDocumentBytes {
		return stateRecord{}, ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var value stateRecord
	if err := decoder.Decode(&value); err != nil {
		return stateRecord{}, errors.Join(ErrUnavailable, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return stateRecord{}, ErrUnavailable
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, content) || validateState(request, value) != nil {
		return stateRecord{}, ErrUnavailable
	}
	return value, nil
}

func validateState(request devopsbuildv1.Request, value stateRecord) error {
	executionID, err := devopsbuildv1.ExecutionID(request)
	requestDigest, requestDigestErr := devopsbuildv1.DigestRequest(request)
	if err != nil || value.Format != stateFormat || value.Kind != stateKind ||
		value.Version == 0 || value.Version > devopsv1.MaximumContractInteger ||
		requestDigestErr != nil || value.ExecutionID != executionID ||
		value.RequestDigest != requestDigest ||
		devopsv1.ValidateDigest("executorState.requestDigest", value.RequestDigest) != nil ||
		value.ContentDigest != digestState(value) ||
		devopsv1.ValidateDigest("executorState.contentDigest", value.ContentDigest) != nil {
		return ErrUnavailable
	}
	if value.Version == 1 {
		if value.PreviousDigest != "" {
			return ErrUnavailable
		}
	} else if devopsv1.ValidateDigest(
		"executorState.previousDigest", value.PreviousDigest,
	) != nil {
		return ErrUnavailable
	}

	switch value.Phase {
	case phaseQueued:
		if value.Version != 1 || value.CancellationRequested || value.RunnerID != "" ||
			value.FencingToken != 0 || value.LeaseExpiresAt != nil || value.Receipt != nil {
			return ErrUnavailable
		}
	case phaseAssigned:
		if devopsv1.ValidateID("executorState.runnerId", value.RunnerID) != nil ||
			value.FencingToken == 0 ||
			value.FencingToken > devopsv1.MaximumContractInteger ||
			value.LeaseExpiresAt == nil || value.Receipt != nil ||
			validateSpoolTime(*value.LeaseExpiresAt) != nil ||
			!value.LeaseExpiresAt.After(request.StartedAt) ||
			value.LeaseExpiresAt.After(request.DeadlineAt) {
			return ErrUnavailable
		}
	case phaseTerminal:
		if devopsv1.ValidateID("executorState.runnerId", value.RunnerID) != nil ||
			value.FencingToken == 0 ||
			value.FencingToken > devopsv1.MaximumContractInteger ||
			value.LeaseExpiresAt != nil || value.Receipt == nil ||
			devopsbuildv1.ValidateReceipt(request, *value.Receipt) != nil {
			return ErrUnavailable
		}
	case phaseCancelled:
		if !value.CancellationRequested || value.RunnerID != "" ||
			value.FencingToken != 0 || value.LeaseExpiresAt != nil || value.Receipt != nil {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	return nil
}

func validateTransition(
	request devopsbuildv1.Request,
	previous stateRecord,
	next stateRecord,
) error {
	if validateState(request, previous) != nil || validateState(request, next) != nil ||
		previous.Version == devopsv1.MaximumContractInteger ||
		next.Version != previous.Version+1 ||
		next.PreviousDigest != previous.ContentDigest ||
		next.ExecutionID != previous.ExecutionID ||
		next.RequestDigest != previous.RequestDigest ||
		(previous.CancellationRequested && !next.CancellationRequested) {
		return ErrUnavailable
	}
	switch previous.Phase {
	case phaseQueued:
		if (next.Phase != phaseAssigned && next.Phase != phaseCancelled) ||
			(next.Phase == phaseAssigned && next.FencingToken != 1) {
			return ErrUnavailable
		}
	case phaseAssigned:
		switch next.Phase {
		case phaseAssigned:
			if next.RunnerID != previous.RunnerID || next.LeaseExpiresAt == nil ||
				previous.LeaseExpiresAt == nil ||
				next.LeaseExpiresAt.Before(*previous.LeaseExpiresAt) {
				return ErrUnavailable
			}
			sameFence := next.FencingToken == previous.FencingToken
			recoveryFence := previous.FencingToken < devopsv1.MaximumContractInteger &&
				next.FencingToken == previous.FencingToken+1 &&
				next.LeaseExpiresAt.After(*previous.LeaseExpiresAt)
			if !sameFence && !recoveryFence {
				return ErrUnavailable
			}
			if sameFence && next.LeaseExpiresAt.Equal(*previous.LeaseExpiresAt) &&
				next.CancellationRequested == previous.CancellationRequested {
				return ErrUnavailable
			}
		case phaseTerminal:
			if next.RunnerID != previous.RunnerID ||
				next.FencingToken != previous.FencingToken ||
				next.CancellationRequested != previous.CancellationRequested {
				return ErrUnavailable
			}
		default:
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	return nil
}

func observation(
	request devopsbuildv1.Request,
	state stateRecord,
) (devopsbuildv1.Observation, error) {
	value := devopsbuildv1.Observation{
		APIVersion:  devopsbuildv1.APIVersion,
		Kind:        devopsbuildv1.ObservationKind,
		ExecutionID: state.ExecutionID,
	}
	switch state.Phase {
	case phaseQueued:
		value.State = devopsbuildv1.ExecutionQueued
	case phaseAssigned:
		if state.CancellationRequested {
			value.State = devopsbuildv1.ExecutionCancellationRequested
		} else {
			value.State = devopsbuildv1.ExecutionAssigned
		}
	case phaseTerminal:
		value.State = devopsbuildv1.ExecutionTerminal
		value.Receipt = copyReceipt(state.Receipt)
	case phaseCancelled:
		value.State = devopsbuildv1.ExecutionCancelled
	default:
		return devopsbuildv1.Observation{}, ErrUnavailable
	}
	if err := devopsbuildv1.ValidateObservation(request, value); err != nil {
		return devopsbuildv1.Observation{}, errors.Join(ErrUnavailable, err)
	}
	return value, nil
}

func digestState(value stateRecord) string {
	digest := sha256.New()
	writeStateString(digest, "matrix-devops-executor-spool-state-v1")
	writeStateString(digest, value.Format)
	writeStateString(digest, value.Kind)
	writeStateUint64(digest, value.Version)
	writeStateString(digest, value.PreviousDigest)
	writeStateString(digest, value.ExecutionID)
	writeStateString(digest, value.RequestDigest)
	writeStateString(digest, string(value.Phase))
	writeStateString(digest, strconv.FormatBool(value.CancellationRequested))
	writeStateString(digest, value.RunnerID)
	writeStateUint64(digest, value.FencingToken)
	lease := ""
	if value.LeaseExpiresAt != nil {
		lease = value.LeaseExpiresAt.Format(time.RFC3339Nano)
	}
	writeStateString(digest, lease)
	receiptDigest := ""
	if value.Receipt != nil {
		receiptDigest = value.Receipt.ContentDigest
	}
	writeStateString(digest, receiptDigest)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func validateSpoolTime(value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return ErrInvalid
	}
	return nil
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func copyReceipt(value *devopsbuildv1.Receipt) *devopsbuildv1.Receipt {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
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
