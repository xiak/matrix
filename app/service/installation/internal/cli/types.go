package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
)

const OutputAPIVersion = "cli.matrix.xiak.com/v1"

type Streams struct {
	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer
}

type Request struct {
	Action        lifecycle.Action
	Root          string
	Bundle        string
	TrustKey      string
	BackupID      string
	SupportOutput string
}

type Result struct {
	State         string `json:"state"`
	ReleaseID     string `json:"releaseId,omitempty"`
	PreviousID    string `json:"previousId,omitempty"`
	BackupID      string `json:"backupId,omitempty"`
	Changed       bool   `json:"changed"`
	CorrelationID string `json:"correlationId,omitempty"`
}

type Backend interface {
	Run(context.Context, Request) (Result, error)
}

type FaultClass string

const (
	FaultInvalidArgument FaultClass = "INVALID_ARGUMENT"
	FaultPrecondition    FaultClass = "PRECONDITION_FAILED"
	FaultConflict        FaultClass = "CONFLICT"
	FaultVerification    FaultClass = "VERIFICATION_FAILED"
	FaultUnavailable     FaultClass = "UNAVAILABLE"
	FaultInterrupted     FaultClass = "INTERRUPTED"
	FaultInternal        FaultClass = "INTERNAL"
)

type Fault struct {
	Class FaultClass
	Code  string
}

func (fault *Fault) Error() string {
	if fault == nil {
		return ""
	}
	return fault.Code
}

var (
	faultCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
	safeStatePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
	safeIDPattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`)
)

func NewFault(class FaultClass, code string) (*Fault, error) {
	fault := &Fault{Class: class, Code: code}
	if err := validateFault(fault); err != nil {
		return nil, err
	}
	return fault, nil
}

func validateStreams(streams Streams) error {
	if streams.In == nil || streams.Out == nil || streams.ErrOut == nil {
		return errors.New("CLI streams are required")
	}
	return nil
}

func validateResult(result Result) error {
	var problems []error
	if !safeStatePattern.MatchString(result.State) {
		problems = append(problems, errors.New("platform result state is invalid"))
	}
	for label, value := range map[string]string{
		"release": result.ReleaseID, "previous release": result.PreviousID,
		"backup": result.BackupID, "correlation": result.CorrelationID,
	} {
		if value != "" && !safeIDPattern.MatchString(value) {
			problems = append(problems, fmt.Errorf("platform result %s identity is invalid", label))
		}
	}
	return errors.Join(problems...)
}

func validateFault(fault *Fault) error {
	if fault == nil || !knownFaultClass(fault.Class) || strings.TrimSpace(fault.Code) != fault.Code ||
		!faultCodePattern.MatchString(fault.Code) {
		return errors.New("platform fault is invalid")
	}
	return nil
}

func knownFaultClass(class FaultClass) bool {
	switch class {
	case FaultInvalidArgument, FaultPrecondition, FaultConflict, FaultVerification,
		FaultUnavailable, FaultInterrupted, FaultInternal:
		return true
	default:
		return false
	}
}
