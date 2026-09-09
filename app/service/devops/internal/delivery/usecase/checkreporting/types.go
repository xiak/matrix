// Package checkreporting owns the fenced REPORT workflow that turns one
// normalized build receipt into one provider-visible terminal check.
package checkreporting

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

const (
	LeaseDuration       = 30 * time.Second
	HeartbeatInterval   = 10 * time.Second
	HeartbeatMaximumAge = 30 * time.Second
	ProviderDeadline    = 5 * time.Second
	ReconciliationDelay = time.Minute

	PassedDescription = "Matrix verification passed"
	FailedDescription = "Matrix verification failed"
)

var (
	ErrInvalidCommand    = errors.New("check reporting command is invalid")
	ErrInvalidReceipt    = errors.New("check reporting receipt is invalid")
	ErrReportUnavailable = errors.New("check reporter is unavailable")
	ErrReportConflict    = errors.New("provider check conflicts with the report command")
	ErrOutcomeUnknown    = errors.New("provider check outcome is unknown")
)

type CheckState string

const (
	CheckSuccess CheckState = "success"
	CheckFailure CheckState = "failure"
)

// Command closes every mutable lookup except the purpose-bound credential
// value. Connection may carry a rotated credential reference, while its
// endpoint and adapter identity are immutable for the life of the resource.
type Command struct {
	Lease           runlifecycle.Lease
	Connection      devopsv1.SourceConnection
	BindingRevision devopsv1.RepositoryBinding
	Revision        devopsv1.PipelineRevision
	BuildReceipt    devopsbuildv1.Receipt
}

// Receipt is provider-neutral, path-free evidence that the exact deterministic
// check exists. Provider users, URLs, response text, and credentials are
// deliberately absent.
type Receipt struct {
	TenantID                devopsv1.TenantID   `json:"tenantId"`
	RunID                   devopsv1.ResourceID `json:"runId"`
	CommandID               string              `json:"commandId"`
	InputDigest             string              `json:"inputDigest"`
	AdapterID               devopsv1.ResourceID `json:"adapterId"`
	SourceConnectionID      devopsv1.ResourceID `json:"sourceConnectionId"`
	RepositoryBindingID     devopsv1.ResourceID `json:"repositoryBindingId"`
	RepositoryBindingDigest string              `json:"repositoryBindingDigest"`
	HeadCommit              string              `json:"headCommit"`
	PipelineRevisionID      devopsv1.ResourceID `json:"pipelineRevisionId"`
	PipelineRevisionDigest  string              `json:"pipelineRevisionDigest"`
	BuildReceiptDigest      string              `json:"buildReceiptDigest"`
	ProviderStatusID        uint64              `json:"providerStatusId"`
	RequestDigest           string              `json:"requestDigest"`
	ContentDigest           string              `json:"contentDigest"`
}

type Repository interface {
	Heartbeat(context.Context, string) (time.Time, error)
	Claim(context.Context, string, time.Duration) (Command, bool, error)
	Complete(context.Context, Completion) (devopsv1.PipelineRun, error)
	MarkUncertain(context.Context, runlifecycle.Reconciliation) (devopsv1.PipelineRun, error)
	Defer(context.Context, runlifecycle.Reconciliation) (uint64, error)
	Readiness(context.Context) (devopsv1.Readiness, error)
}

type Reporter interface {
	Create(context.Context, Command) (Receipt, error)
	Observe(context.Context, Command) (Receipt, bool, error)
}

type Completion struct {
	Command Command
	State   devopsv1.PipelineRunState
	Reason  devopsv1.PipelineRunReason
	Receipt *Receipt
}

type Config struct {
	WorkerID      string
	LeaseDuration time.Duration
	Deadline      time.Duration
	RetryDelay    time.Duration
	Now           func() time.Time
}

type Result struct {
	Claimed                bool
	CommandID              string
	Run                    devopsv1.PipelineRun
	ReconciliationAttempts uint64
}

func ValidateCommand(value Command) error {
	var problems []error
	problems = append(problems,
		runlifecycle.ValidateLease(value.Lease),
		devopsv1.ValidateSourceConnection(value.Connection),
		devopsv1.ValidateRepositoryBinding(value.BindingRevision),
		devopsv1.ValidatePipelineRevision(value.Revision),
		devopsbuildv1.ValidateReceiptShape(value.BuildReceipt),
	)
	lease := value.Lease
	run := lease.Run
	if (run.Status.State != devopsv1.PipelineRunReporting &&
		run.Status.State != devopsv1.PipelineRunReconciling) ||
		lease.Intent.Stage != devopsv1.PipelineRunStageReport ||
		(run.Status.State == devopsv1.PipelineRunReconciling &&
			lease.Mode != runlifecycle.ClaimObserve) {
		problems = append(problems, errors.New("lease is not a REPORT command"))
	}
	tenantID := lease.TenantID
	if value.Connection.Metadata.Scope.TenantID != tenantID ||
		value.BindingRevision.Metadata.Scope.TenantID != tenantID ||
		value.Revision.Scope.TenantID != tenantID ||
		value.BuildReceipt.TenantID != tenantID {
		problems = append(problems, errors.New("check report command crosses a tenant boundary"))
	}
	if value.BindingRevision.Metadata.ID != run.Input.RepositoryBindingID ||
		value.BindingRevision.ContentDigest != run.Input.RepositoryBindingDigest ||
		value.BindingRevision.ProjectID != run.ProjectID ||
		value.BindingRevision.Spec.SourceConnectionID != value.Connection.Metadata.ID {
		problems = append(problems, errors.New("RepositoryBinding revision does not bind the PipelineRun"))
	}
	if value.Revision.ID != run.Input.PipelineRevisionID ||
		value.Revision.ContentDigest != run.Input.PipelineRevisionDigest ||
		value.Revision.PipelineID != run.PipelineID ||
		value.Revision.ProjectID != run.ProjectID ||
		value.Revision.Spec.RepositoryBindingID != run.Input.RepositoryBindingID ||
		value.Revision.Spec.RepositoryBindingDigest != run.Input.RepositoryBindingDigest ||
		value.Revision.Spec.ReporterPolicy != devopsv1.ReporterChangeCheckV1 {
		problems = append(problems, errors.New("PipelineRevision does not bind the check report"))
	}
	receipt := value.BuildReceipt
	if receipt.RunID != run.ID || receipt.InputDigest != run.InputDigest ||
		receipt.PipelineRevisionID != run.Input.PipelineRevisionID ||
		receipt.PipelineRevisionDigest != run.Input.PipelineRevisionDigest ||
		receipt.Conclusion != devopsbuildv1.ConclusionPassed &&
			receipt.Conclusion != devopsbuildv1.ConclusionFailed {
		problems = append(problems, errors.New("build receipt does not bind the check report"))
	}
	if err := errors.Join(problems...); err != nil {
		return errors.Join(ErrInvalidCommand, err)
	}
	return nil
}

func CheckContext(value Command) (string, error) {
	if err := ValidateCommand(value); err != nil {
		return "", err
	}
	return "matrix/" + string(value.Lease.Run.PipelineID) + "/" +
		string(value.Lease.Run.ID), nil
}

func CheckOutcome(value Command) (CheckState, string, error) {
	if err := ValidateCommand(value); err != nil {
		return "", "", err
	}
	switch value.BuildReceipt.Conclusion {
	case devopsbuildv1.ConclusionPassed:
		return CheckSuccess, PassedDescription, nil
	case devopsbuildv1.ConclusionFailed:
		return CheckFailure, FailedDescription, nil
	default:
		return "", "", ErrInvalidCommand
	}
}

func RequestDigest(value Command) (string, error) {
	if err := ValidateCommand(value); err != nil {
		return "", err
	}
	contextName, _ := CheckContext(value)
	state, description, _ := CheckOutcome(value)
	digest := sha256.New()
	writeString(digest, "matrix-devops-check-request-v1")
	for _, field := range []string{
		value.Lease.Intent.CommandID,
		value.Lease.Run.InputDigest,
		string(value.Connection.Spec.AdapterID),
		value.Connection.Spec.EndpointOrigin,
		string(value.BindingRevision.Metadata.ID),
		value.BindingRevision.ContentDigest,
		string(value.BindingRevision.Spec.ExternalRepositoryID),
		value.BindingRevision.Spec.RepositoryPath,
		value.Lease.Run.Input.Change.HeadCommit,
		string(value.Lease.Run.PipelineID),
		string(value.Revision.ID),
		value.Revision.ContentDigest,
		value.BuildReceipt.ContentDigest,
		contextName,
		string(state),
		description,
		"",
	} {
		writeString(digest, field)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func NewReceipt(value Command, providerStatusID uint64) (Receipt, error) {
	requestDigest, err := RequestDigest(value)
	if err != nil || providerStatusID == 0 ||
		providerStatusID > devopsv1.MaximumContractInteger {
		return Receipt{}, ErrInvalidReceipt
	}
	receipt := Receipt{
		TenantID:                value.Lease.TenantID,
		RunID:                   value.Lease.Run.ID,
		CommandID:               value.Lease.Intent.CommandID,
		InputDigest:             value.Lease.Run.InputDigest,
		AdapterID:               value.Connection.Spec.AdapterID,
		SourceConnectionID:      value.Connection.Metadata.ID,
		RepositoryBindingID:     value.BindingRevision.Metadata.ID,
		RepositoryBindingDigest: value.BindingRevision.ContentDigest,
		HeadCommit:              value.Lease.Run.Input.Change.HeadCommit,
		PipelineRevisionID:      value.Revision.ID,
		PipelineRevisionDigest:  value.Revision.ContentDigest,
		BuildReceiptDigest:      value.BuildReceipt.ContentDigest,
		ProviderStatusID:        providerStatusID,
		RequestDigest:           requestDigest,
	}
	receipt.ContentDigest = DigestReceipt(receipt)
	if err := ValidateReceipt(value, receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func ValidateReceipt(command Command, value Receipt) error {
	requestDigest, commandErr := RequestDigest(command)
	var problems []error
	problems = append(problems,
		commandErr,
		devopsv1.ValidateID("checkReceipt.tenantId", string(value.TenantID)),
		devopsv1.ValidatePipelineRunID("checkReceipt.runId", value.RunID),
		devopsv1.ValidateID("checkReceipt.commandId", value.CommandID),
		devopsv1.ValidateDigest("checkReceipt.inputDigest", value.InputDigest),
		devopsv1.ValidateID("checkReceipt.adapterId", string(value.AdapterID)),
		devopsv1.ValidateID("checkReceipt.sourceConnectionId", string(value.SourceConnectionID)),
		devopsv1.ValidateID("checkReceipt.repositoryBindingId", string(value.RepositoryBindingID)),
		devopsv1.ValidateDigest("checkReceipt.repositoryBindingDigest", value.RepositoryBindingDigest),
		devopsv1.ValidateID("checkReceipt.pipelineRevisionId", string(value.PipelineRevisionID)),
		devopsv1.ValidateDigest("checkReceipt.pipelineRevisionDigest", value.PipelineRevisionDigest),
		devopsv1.ValidateDigest("checkReceipt.buildReceiptDigest", value.BuildReceiptDigest),
		devopsv1.ValidateDigest("checkReceipt.requestDigest", value.RequestDigest),
		devopsv1.ValidateDigest("checkReceipt.contentDigest", value.ContentDigest),
	)
	if value.TenantID != command.Lease.TenantID ||
		value.RunID != command.Lease.Run.ID ||
		value.CommandID != command.Lease.Intent.CommandID ||
		value.InputDigest != command.Lease.Run.InputDigest ||
		value.AdapterID != command.Connection.Spec.AdapterID ||
		value.SourceConnectionID != command.Connection.Metadata.ID ||
		value.RepositoryBindingID != command.BindingRevision.Metadata.ID ||
		value.RepositoryBindingDigest != command.BindingRevision.ContentDigest ||
		value.HeadCommit != command.Lease.Run.Input.Change.HeadCommit ||
		value.PipelineRevisionID != command.Revision.ID ||
		value.PipelineRevisionDigest != command.Revision.ContentDigest ||
		value.BuildReceiptDigest != command.BuildReceipt.ContentDigest ||
		value.RequestDigest != requestDigest ||
		value.ProviderStatusID == 0 ||
		value.ProviderStatusID > devopsv1.MaximumContractInteger ||
		value.ContentDigest != DigestReceipt(value) {
		problems = append(problems, errors.New("check receipt does not bind its command"))
	}
	if len(value.HeadCommit) != 40 {
		problems = append(problems, errors.New("check receipt head commit is invalid"))
	}
	if err := errors.Join(problems...); err != nil {
		return errors.Join(ErrInvalidReceipt, err)
	}
	return nil
}

func ValidateCompletion(value Completion) error {
	if err := ValidateCommand(value.Command); err != nil {
		return err
	}
	if err := domain.ValidatePipelineRunTransition(
		value.Command.Lease.Run.Status.State, value.State, value.Reason,
	); err != nil {
		return errors.Join(ErrInvalidCommand, err)
	}
	switch value.State {
	case devopsv1.PipelineRunSucceeded:
		if value.Reason != devopsv1.PipelineRunReasonCompleted ||
			value.Command.BuildReceipt.Conclusion != devopsbuildv1.ConclusionPassed ||
			value.Receipt == nil {
			return ErrInvalidReceipt
		}
	case devopsv1.PipelineRunFailed:
		switch value.Reason {
		case devopsv1.PipelineRunReasonVerificationFailed:
			if value.Command.BuildReceipt.Conclusion != devopsbuildv1.ConclusionFailed ||
				value.Receipt == nil {
				return ErrInvalidReceipt
			}
		case devopsv1.PipelineRunReasonReportUnavailable,
			devopsv1.PipelineRunReasonReportConflict:
			if value.Receipt != nil {
				return ErrInvalidReceipt
			}
		default:
			return ErrInvalidCommand
		}
	case devopsv1.PipelineRunCancelled:
		if value.Reason != devopsv1.PipelineRunReasonCancelled ||
			value.Command.Lease.Run.Status.CancellationRequestedAt == nil ||
			value.Receipt != nil {
			return ErrInvalidCommand
		}
	case devopsv1.PipelineRunManualIntervention:
		if value.Reason != devopsv1.PipelineRunReasonReconciliationExhausted ||
			value.Command.Lease.ReconciliationAttempts <
				runlifecycle.MaximumReconciliationAttempts || value.Receipt != nil {
			return ErrInvalidCommand
		}
	default:
		return ErrInvalidCommand
	}
	if value.Receipt != nil {
		return ValidateReceipt(value.Command, *value.Receipt)
	}
	return nil
}

func DigestReceipt(value Receipt) string {
	digest := sha256.New()
	writeString(digest, "matrix-devops-check-receipt-v1")
	for _, field := range []string{
		string(value.TenantID), string(value.RunID), value.CommandID,
		value.InputDigest, string(value.AdapterID), string(value.SourceConnectionID),
		string(value.RepositoryBindingID), value.RepositoryBindingDigest,
		value.HeadCommit, string(value.PipelineRevisionID),
		value.PipelineRevisionDigest, value.BuildReceiptDigest,
		strconv.FormatUint(value.ProviderStatusID, 10), value.RequestDigest,
	} {
		writeString(digest, field)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func writeString(destination hash.Hash, value string) {
	var framed [8]byte
	binary.BigEndian.PutUint64(framed[:], uint64(len(value)))
	_, _ = destination.Write(framed[:])
	_, _ = destination.Write([]byte(value))
}
