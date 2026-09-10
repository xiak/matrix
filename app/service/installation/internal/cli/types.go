package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
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

type PlatformBackend interface {
	Run(context.Context, Request) (Result, error)
}

type SourceCredentialOperation string

const (
	SourceCredentialApply          SourceCredentialOperation = "APPLY"
	SourceCredentialRetirePrevious SourceCredentialOperation = "RETIRE_PREVIOUS"
)

type SourceCredentialRequest struct {
	Operation SourceCredentialOperation
	Root      string
	TenantID  string
	Purpose   sourcecredential.Purpose
	Reference string
	FromFile  string
}

type SourceCredentialResult struct {
	State     string                   `json:"state"`
	Purpose   sourcecredential.Purpose `json:"purpose"`
	TenantID  string                   `json:"tenant"`
	Reference string                   `json:"reference"`
}

type SourceCredentialBackend interface {
	RunSourceCredential(context.Context, SourceCredentialRequest) (SourceCredentialResult, error)
}

type SourceTrustOperation string

const (
	SourceTrustApply  SourceTrustOperation = "APPLY"
	SourceTrustRemove SourceTrustOperation = "REMOVE"
)

type SourceTrustRequest struct {
	Operation      SourceTrustOperation
	Root           string
	TenantID       string
	EndpointOrigin string
	FromFile       string
}

type SourceTrustResult struct {
	State          string `json:"state"`
	TenantID       string `json:"tenant"`
	EndpointOrigin string `json:"endpointOrigin"`
}

type SourceTrustBackend interface {
	RunSourceTrust(context.Context, SourceTrustRequest) (SourceTrustResult, error)
}

type RunnerNodeOperation string

const (
	RunnerNodeExportRelease RunnerNodeOperation = "EXPORT_RELEASE"
	RunnerNodeCreateRequest RunnerNodeOperation = "REQUEST"
	RunnerNodeEnroll        RunnerNodeOperation = "ENROLL"
	RunnerNodeInstall       RunnerNodeOperation = "INSTALL"
)

type RunnerNodeRequest struct {
	Operation      RunnerNodeOperation
	Root           string
	Release        string
	TrustKey       string
	InstallationID string
	NodeID         string
	Slots          uint8
	GatewayOrigin  string
	ServerCAPin    string
	RunnerCAPin    string
	RequestFile    string
	EnrollmentFile string
	Output         string
}

type RunnerNodeResult struct {
	State          string `json:"state"`
	ReleaseID      string `json:"releaseId"`
	InstallationID string `json:"installationId,omitempty"`
	NodeID         string `json:"nodeId,omitempty"`
	Slots          uint8  `json:"slots,omitempty"`
	RequestDigest  string `json:"requestDigest,omitempty"`
	ServerCAPin    string `json:"serverCAFingerprint,omitempty"`
	RunnerCAPin    string `json:"runnerCAFingerprint,omitempty"`
}

type RunnerNodeBackend interface {
	RunRunnerNode(context.Context, RunnerNodeRequest) (RunnerNodeResult, error)
}

type Backends struct {
	Platform         PlatformBackend
	SourceCredential SourceCredentialBackend
	SourceTrust      SourceTrustBackend
	RunnerNode       RunnerNodeBackend
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
	sha256Pattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
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

func validateSourceCredentialResult(
	request SourceCredentialRequest,
	result SourceCredentialResult,
) error {
	validState := request.Operation == SourceCredentialApply &&
		(result.State == "APPLIED" || result.State == "UNCHANGED") ||
		request.Operation == SourceCredentialRetirePrevious && result.State == "PREVIOUS_RETIRED"
	if !validState || result.Purpose != request.Purpose ||
		result.TenantID != request.TenantID || result.Reference != request.Reference {
		return errors.New("source credential result state is invalid")
	}
	return errors.Join(
		sourcecredential.ValidatePurpose(result.Purpose),
		devopsv1.ValidateResourceScope(devopsv1.ResourceScope{
			TenantID: devopsv1.TenantID(result.TenantID),
		}),
		devopsv1.ValidateID("sourceCredentialRef", result.Reference),
	)
}

func validateSourceTrustResult(request SourceTrustRequest, result SourceTrustResult) error {
	validState := request.Operation == SourceTrustApply &&
		(result.State == "APPLIED" || result.State == "UNCHANGED") ||
		request.Operation == SourceTrustRemove && result.State == "REMOVED"
	if !validState || result.TenantID != request.TenantID ||
		result.EndpointOrigin != request.EndpointOrigin {
		return errors.New("source trust result state is invalid")
	}
	return errors.Join(
		devopsv1.ValidateResourceScope(devopsv1.ResourceScope{
			TenantID: devopsv1.TenantID(result.TenantID),
		}),
		devopsv1.ValidateEndpointOrigin(result.EndpointOrigin),
	)
}

func validateRunnerNodeResult(
	request RunnerNodeRequest,
	result RunnerNodeResult,
) error {
	wantState := ""
	switch request.Operation {
	case RunnerNodeExportRelease:
		wantState = "EXPORTED"
	case RunnerNodeCreateRequest:
		wantState = "REQUESTED"
	case RunnerNodeEnroll:
		wantState = "ENROLLED"
	case RunnerNodeInstall:
		wantState = "INSTALLED"
	default:
		return errors.New("runner node operation is invalid")
	}
	if result.State != wantState || !safeIDPattern.MatchString(result.ReleaseID) ||
		(request.Operation != RunnerNodeExportRelease &&
			(!safeIDPattern.MatchString(result.InstallationID) ||
				!safeIDPattern.MatchString(result.NodeID) || result.Slots == 0 || result.Slots > 4 ||
				!sha256Pattern.MatchString(result.RequestDigest))) {
		return errors.New("runner node result state is invalid")
	}
	if request.Operation == RunnerNodeExportRelease {
		if !sha256Pattern.MatchString(result.ServerCAPin) ||
			!sha256Pattern.MatchString(result.RunnerCAPin) || result.ServerCAPin == result.RunnerCAPin ||
			result.InstallationID != "" || result.NodeID != "" || result.Slots != 0 ||
			result.RequestDigest != "" {
			return errors.New("runner release trust result is invalid")
		}
	} else if result.ServerCAPin != "" || result.RunnerCAPin != "" {
		return errors.New("runner node result authority is invalid")
	}
	if request.Operation == RunnerNodeCreateRequest &&
		(result.InstallationID != request.InstallationID || result.NodeID != request.NodeID ||
			result.Slots != request.Slots) {
		return errors.New("runner node result identity is invalid")
	}
	return nil
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
