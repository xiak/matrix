// Package nodev1 defines the closed, internal node observation protocol.
// Installation access configuration and credentials are never wire payloads.
package nodev1

import (
	"errors"
	"io"
	"net/url"
	"time"

	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	APIVersion                 = "node.adapter.matrix.xiak.com/v1"
	ObservationRequestKind     = "ExecutionTargetObservationRequest"
	ObservationResponseKind    = "ExecutionTargetObservationResponse"
	ObservationPath            = "/adapter/node/v1/observation"
	MaximumObservationBytes    = 64 * 1024
	MaximumObservationDuration = 30 * time.Second
	MaximumObservationAge      = 15 * time.Second
)

var ErrInvalidObservation = errors.New("node observation document is invalid")

type Identity struct {
	InstallationID    string            `json:"installationId"`
	ExecutionTargetID paasv1.ResourceID `json:"executionTargetId"`
}

type ObservationRequest struct {
	APIVersion string                        `json:"apiVersion"`
	Kind       string                        `json:"kind"`
	Identity   Identity                      `json:"identity"`
	Command    paasv1.AdapterCommandEnvelope `json:"command"`
}

type ObservationResponse struct {
	APIVersion  string                            `json:"apiVersion"`
	Kind        string                            `json:"kind"`
	Identity    Identity                          `json:"identity"`
	CommandID   paasv1.CommandID                  `json:"commandId"`
	Observation paasv1.ExecutionTargetObservation `json:"observation"`
}

func ValidateIdentity(value Identity) error {
	if paasv1.ValidateID("installationId", value.InstallationID) != nil ||
		paasv1.ValidateID("executionTargetId", string(value.ExecutionTargetID)) != nil {
		return ErrInvalidObservation
	}
	return nil
}

// NodeURI and ControllerURI bind certificates to an exact installation and
// role. A common name, wildcard, second URI or another installation is not an
// alternative identity. No identity-discovery service is required.
func NodeURI(value Identity) (string, error) {
	if ValidateIdentity(value) != nil {
		return "", ErrInvalidObservation
	}
	return identityURI(value.InstallationID, "nodes", string(value.ExecutionTargetID)), nil
}

func ControllerURI(installationID, controllerID string) (string, error) {
	if paasv1.ValidateID("installationId", installationID) != nil ||
		paasv1.ValidateID("controllerId", controllerID) != nil {
		return "", ErrInvalidObservation
	}
	return identityURI(installationID, "controllers", controllerID), nil
}

func MatchesIdentity(uris []*url.URL, expected string) bool {
	return expected != "" && len(uris) == 1 && uris[0] != nil && uris[0].String() == expected
}

func identityURI(installationID, role, id string) string {
	value := url.URL{
		Scheme: "spiffe", Host: "matrix.xiak.com",
		Path: "/installations/" + installationID + "/" + role + "/" + id,
	}
	return value.String()
}

func ValidateObservationRequest(value ObservationRequest) error {
	if value.APIVersion != APIVersion || value.Kind != ObservationRequestKind ||
		ValidateIdentity(value.Identity) != nil ||
		value.Command.ExecutionTargetID != value.Identity.ExecutionTargetID {
		return ErrInvalidObservation
	}
	var err error
	switch value.Command.Action {
	case paasv1.AdapterInspectExecutionTarget:
		err = paasv1.ValidateInspectExecutionTargetRequest(paasv1.InspectExecutionTargetRequest{Command: value.Command})
	case paasv1.AdapterObserveExecutionTarget:
		err = paasv1.ValidateObserveExecutionTargetRequest(paasv1.ObserveExecutionTargetRequest{Command: value.Command})
	default:
		return ErrInvalidObservation
	}
	if err != nil {
		return ErrInvalidObservation
	}
	return nil
}

func ValidateObservationResponse(value ObservationResponse) error {
	if value.APIVersion != APIVersion || value.Kind != ObservationResponseKind ||
		ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateID("commandId", string(value.CommandID)) != nil ||
		value.Observation.ExecutionTargetID != value.Identity.ExecutionTargetID ||
		paasv1.ValidateExecutionTargetObservation(value.Observation) != nil {
		return ErrInvalidObservation
	}
	return nil
}

func DecodeObservationRequest(reader io.Reader) (ObservationRequest, error) {
	var value ObservationRequest
	if err := contractjson.DecodeObject(reader, MaximumObservationBytes, &value); err != nil {
		return ObservationRequest{}, ErrInvalidObservation
	}
	if err := ValidateObservationRequest(value); err != nil {
		return ObservationRequest{}, err
	}
	return value, nil
}

func DecodeObservationResponse(reader io.Reader) (ObservationResponse, error) {
	var value ObservationResponse
	if err := contractjson.DecodeObject(reader, MaximumObservationBytes, &value); err != nil {
		return ObservationResponse{}, ErrInvalidObservation
	}
	if err := ValidateObservationResponse(value); err != nil {
		return ObservationResponse{}, err
	}
	return value, nil
}
