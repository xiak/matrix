package devopsbuildv1

import (
	"bytes"
	"errors"
)

const (
	ControlKind     = "BuildControl"
	ObservationKind = "BuildObservation"
)

type ControlAction string

const (
	ControlObserve ControlAction = "OBSERVE"
	ControlCancel  ControlAction = "CANCEL"
)

type ExecutionState string

const (
	ExecutionQueued                ExecutionState = "QUEUED"
	ExecutionAssigned              ExecutionState = "ASSIGNED"
	ExecutionCancellationRequested ExecutionState = "CANCELLATION_REQUESTED"
	ExecutionTerminal              ExecutionState = "TERMINAL"
	ExecutionCancelled             ExecutionState = "CANCELLED"
)

// Control is sent only on the build-worker administrative listener. The
// complete request is repeated so a same-identity, changed-authority replay
// cannot be mistaken for an observation or cancellation of the original.
type Control struct {
	APIVersion  string        `json:"apiVersion"`
	Kind        string        `json:"kind"`
	Action      ControlAction `json:"action"`
	ExecutionID string        `json:"executionId"`
	Request     Request       `json:"request"`
}

// Observation exposes only the provider-neutral state needed by the build
// worker. Runner identity, lease, native output, and spool layout stay private
// to the gateway.
type Observation struct {
	APIVersion  string         `json:"apiVersion"`
	Kind        string         `json:"kind"`
	ExecutionID string         `json:"executionId"`
	State       ExecutionState `json:"state"`
	Receipt     *Receipt       `json:"receipt"`
}

func EncodeControl(action ControlAction, request Request) ([]byte, error) {
	executionID, err := ExecutionID(request)
	if err != nil || !validControlAction(action) {
		return nil, ErrInvalidDocument
	}
	return encodeDocument(Control{
		APIVersion:  APIVersion,
		Kind:        ControlKind,
		Action:      action,
		ExecutionID: executionID,
		Request:     request,
	})
}

func DecodeControl(content []byte) (ControlAction, Request, error) {
	var document Control
	if err := decodeDocument(content, &document); err != nil ||
		document.APIVersion != APIVersion || document.Kind != ControlKind ||
		!validControlAction(document.Action) || ValidateRequest(document.Request) != nil {
		return "", Request{}, ErrInvalidDocument
	}
	executionID, err := ExecutionID(document.Request)
	if err != nil || document.ExecutionID != executionID {
		return "", Request{}, ErrInvalidDocument
	}
	canonical, err := EncodeControl(document.Action, document.Request)
	if err != nil || !bytes.Equal(canonical, content) {
		return "", Request{}, ErrInvalidDocument
	}
	return document.Action, document.Request, nil
}

func EncodeObservation(request Request, observation Observation) ([]byte, error) {
	if err := ValidateObservation(request, observation); err != nil {
		return nil, err
	}
	return encodeDocument(observation)
}

func DecodeObservation(request Request, content []byte) (Observation, error) {
	var document Observation
	if err := decodeDocument(content, &document); err != nil ||
		ValidateObservation(request, document) != nil {
		return Observation{}, ErrInvalidDocument
	}
	canonical, err := EncodeObservation(request, document)
	if err != nil || !bytes.Equal(canonical, content) {
		return Observation{}, ErrInvalidDocument
	}
	return document, nil
}

func ValidateObservation(request Request, value Observation) error {
	executionID, err := ExecutionID(request)
	if err != nil {
		return errors.Join(ErrInvalidDocument, err)
	}
	if value.APIVersion != APIVersion || value.Kind != ObservationKind ||
		value.ExecutionID != executionID {
		return ErrInvalidDocument
	}
	switch value.State {
	case ExecutionQueued, ExecutionAssigned, ExecutionCancellationRequested:
		if value.Receipt != nil {
			return ErrInvalidDocument
		}
	case ExecutionTerminal:
		if value.Receipt == nil || ValidateReceipt(request, *value.Receipt) != nil {
			return ErrInvalidDocument
		}
	case ExecutionCancelled:
		if value.Receipt != nil {
			return ErrInvalidDocument
		}
	default:
		return ErrInvalidDocument
	}
	return nil
}

func validControlAction(value ControlAction) bool {
	return value == ControlObserve || value == ControlCancel
}
