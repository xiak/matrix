package nodev1

import (
	"errors"
	"io"
	"time"

	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	DeploymentTerminalSessionPath = "/adapter/node/v1/deployment-terminal-sessions"
	TerminalSubprotocol           = "matrix.terminal.v1"
	TerminalOpenRequestKind       = "TerminalOpenRequest"
	MaximumTerminalControlBytes   = 4096
	MaximumTerminalOpenBytes      = 64 * 1024
)

var ErrInvalidTerminal = errors.New("node terminal document is invalid")

// TerminalOpenRequest reuses the exact current-runtime proof. It exposes no
// provider identity, executable selector, user, environment, work directory,
// host namespace or privilege override.
type TerminalOpenRequest struct {
	APIVersion        string                                 `json:"apiVersion"`
	Kind              string                                 `json:"kind"`
	Identity          Identity                               `json:"identity"`
	BindingRef        string                                 `json:"bindingRef"`
	TerminalSessionID paasv1.ResourceID                      `json:"terminalSessionId"`
	Request           paasv1.ObserveDeploymentRuntimeRequest `json:"request"`
	InstanceID        paasv1.ResourceID                      `json:"instanceId"`
	Size              paasv1.TerminalSize                    `json:"size"`
	ExpiresAt         time.Time                              `json:"expiresAt"`
}

type TerminalClientControlType string

const (
	TerminalClientResize TerminalClientControlType = "RESIZE"
	TerminalClientClose  TerminalClientControlType = "CLOSE"
)

type TerminalClientControl struct {
	Type TerminalClientControlType `json:"type"`
	Size *paasv1.TerminalSize      `json:"size,omitempty"`
}

type TerminalServerControlType string

const (
	TerminalServerReady TerminalServerControlType = "READY"
	TerminalServerExit  TerminalServerControlType = "EXIT"
	TerminalServerError TerminalServerControlType = "ERROR"
)

type TerminalErrorCode string

const (
	TerminalErrorUnsupported TerminalErrorCode = "UNSUPPORTED"
	TerminalErrorUnavailable TerminalErrorCode = "UNAVAILABLE"
	TerminalErrorFailed      TerminalErrorCode = "FAILED"
)

type TerminalServerControl struct {
	Type     TerminalServerControlType `json:"type"`
	ExitCode *int32                    `json:"exitCode,omitempty"`
	Error    TerminalErrorCode         `json:"error,omitempty"`
}

func ValidateTerminalOpenRequest(value TerminalOpenRequest) error {
	if value.APIVersion != APIVersion || value.Kind != TerminalOpenRequestKind ||
		ValidateIdentity(value.Identity) != nil ||
		paasv1.ValidateID("bindingRef", value.BindingRef) != nil ||
		paasv1.ValidateTerminalSessionID(value.TerminalSessionID) != nil ||
		paasv1.ValidateObserveDeploymentRuntimeRequest(value.Request) != nil ||
		value.Request.ExecutionTargetID != value.Identity.ExecutionTargetID ||
		string(value.Request.RequestID) != string(value.TerminalSessionID) ||
		paasv1.ValidateCreateTerminalSessionRequest(paasv1.CreateTerminalSessionRequest{
			InstanceID: value.InstanceID, Size: value.Size,
		}) != nil ||
		value.ExpiresAt.IsZero() || value.ExpiresAt.Location() != time.UTC ||
		value.ExpiresAt.Nanosecond()%1000 != 0 ||
		!value.ExpiresAt.After(value.Request.Deadline) ||
		value.ExpiresAt.Sub(value.Request.Deadline) > paasv1.MaximumTerminalSessionDuration {
		return ErrInvalidTerminal
	}
	return nil
}

func ValidateTerminalClientControl(value TerminalClientControl) error {
	switch value.Type {
	case TerminalClientResize:
		if value.Size == nil || paasv1.ValidateTerminalSize(*value.Size) != nil {
			return ErrInvalidTerminal
		}
	case TerminalClientClose:
		if value.Size != nil {
			return ErrInvalidTerminal
		}
	default:
		return ErrInvalidTerminal
	}
	return nil
}

func ValidateTerminalServerControl(value TerminalServerControl) error {
	switch value.Type {
	case TerminalServerReady:
		if value.ExitCode != nil || value.Error != "" {
			return ErrInvalidTerminal
		}
	case TerminalServerExit:
		if value.ExitCode == nil || value.Error != "" {
			return ErrInvalidTerminal
		}
	case TerminalServerError:
		if value.ExitCode != nil ||
			(value.Error != TerminalErrorUnsupported && value.Error != TerminalErrorUnavailable && value.Error != TerminalErrorFailed) {
			return ErrInvalidTerminal
		}
	default:
		return ErrInvalidTerminal
	}
	return nil
}

func DecodeTerminalOpenRequest(reader io.Reader) (TerminalOpenRequest, error) {
	var value TerminalOpenRequest
	if contractjson.DecodeObject(reader, MaximumTerminalOpenBytes, &value) != nil ||
		ValidateTerminalOpenRequest(value) != nil {
		return TerminalOpenRequest{}, ErrInvalidTerminal
	}
	return value, nil
}

func DecodeTerminalClientControl(reader io.Reader) (TerminalClientControl, error) {
	var value TerminalClientControl
	if contractjson.DecodeObject(reader, MaximumTerminalControlBytes, &value) != nil ||
		ValidateTerminalClientControl(value) != nil {
		return TerminalClientControl{}, ErrInvalidTerminal
	}
	return value, nil
}

func DecodeTerminalServerControl(reader io.Reader) (TerminalServerControl, error) {
	var value TerminalServerControl
	if contractjson.DecodeObject(reader, MaximumTerminalControlBytes, &value) != nil ||
		ValidateTerminalServerControl(value) != nil {
		return TerminalServerControl{}, ErrInvalidTerminal
	}
	return value, nil
}
