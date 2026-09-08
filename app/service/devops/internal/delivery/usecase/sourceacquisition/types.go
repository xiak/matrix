// Package sourceacquisition owns the fenced FETCH workflow that turns one
// immutable source change into one content-addressed archive receipt.
package sourceacquisition

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

const (
	LeaseDuration       = 30 * time.Second
	HeartbeatInterval   = 10 * time.Second
	HeartbeatMaximumAge = 30 * time.Second
	AcquisitionDeadline = 2 * time.Minute

	MaximumArchiveBytes  = sourcearchive.MaximumArchiveBytes
	MaximumExpandedBytes = sourcearchive.MaximumExpandedBytes
	MaximumPathCount     = sourcearchive.MaximumPathCount

	ArchiveMediaType = sourcearchive.MediaType
)

var (
	ErrInvalidCommand    = errors.New("source acquisition command is invalid")
	ErrInvalidReceipt    = errors.New("source archive receipt is invalid")
	ErrSourceUnavailable = errors.New("source is unavailable")
	ErrCommitMismatch    = errors.New("source commit does not match the admitted change")
	ErrArchiveMissing    = errors.New("source archive is missing")
	ErrArchiveUncertain  = errors.New("source archive publication is uncertain")
)

// Command closes every mutable lookup before an adapter effect. BindingRevision
// is the immutable RepositoryBinding document selected by its content digest,
// not the current configuration row.
type Command struct {
	Lease           runlifecycle.Lease
	Connection      devopsv1.SourceConnection
	BindingRevision devopsv1.RepositoryBinding
	Revision        devopsv1.PipelineRevision
	Event           devopsv1.SourceEvent
}

type ArchiveContent = sourcearchive.Content

type ArchiveWriter func(io.Writer) (ArchiveContent, error)

type Repository interface {
	Heartbeat(context.Context, string) (time.Time, error)
	Claim(context.Context, string, time.Duration) (Command, bool, error)
	Renew(context.Context, runlifecycle.LeaseGuard, time.Duration) (time.Time, error)
	Complete(context.Context, Completion) (devopsv1.PipelineRun, error)
	Readiness(context.Context) (devopsv1.Readiness, error)
}

type SourceFetcher interface {
	Fetch(context.Context, Command, io.Writer) (ArchiveContent, error)
}

type ArchiveStore interface {
	Publish(context.Context, Command, ArchiveWriter) (sourcearchive.Receipt, error)
	Observe(context.Context, Command) (sourcearchive.Receipt, bool, error)
}

type Completion struct {
	Command Command
	State   devopsv1.PipelineRunState
	Reason  devopsv1.PipelineRunReason
	Receipt *sourcearchive.Receipt
}

type Config struct {
	WorkerID      string
	LeaseDuration time.Duration
	Deadline      time.Duration
}

type Result struct {
	Claimed   bool
	CommandID string
	Run       devopsv1.PipelineRun
}

func ValidateCommand(value Command) error {
	var problems []error
	problems = append(problems,
		runlifecycle.ValidateLease(value.Lease),
		devopsv1.ValidateSourceConnection(value.Connection),
		devopsv1.ValidateRepositoryBinding(value.BindingRevision),
		devopsv1.ValidatePipelineRevision(value.Revision),
		devopsv1.ValidateSourceEvent(value.Event),
	)
	run := value.Lease.Run
	tenantID := value.Lease.TenantID
	if run.Status.State != devopsv1.PipelineRunFetching ||
		value.Lease.Intent.Stage != devopsv1.PipelineRunStageFetch ||
		value.Lease.ReconciliationAttempts != 0 {
		problems = append(problems, errors.New("lease is not a FETCH command"))
	}
	if value.Connection.Metadata.Scope.TenantID != tenantID ||
		value.BindingRevision.Metadata.Scope.TenantID != tenantID ||
		value.Revision.Scope.TenantID != tenantID || value.Event.Scope.TenantID != tenantID {
		problems = append(problems, errors.New("source command crosses a tenant boundary"))
	}
	if value.Event.ID != run.Input.SourceEventID ||
		value.Event.ContentDigest != run.Input.SourceEventDigest ||
		value.Event.Spec.ProjectID != run.ProjectID ||
		value.Event.Spec.Change != run.Input.Change ||
		value.Event.ReceivedAt != run.CreatedAt ||
		value.Event.ReceivedAt.Before(value.Revision.ActivatedAt) {
		problems = append(problems, errors.New("SourceEvent does not bind the PipelineRun"))
	}
	if value.Revision.ID != run.Input.PipelineRevisionID ||
		value.Revision.ContentDigest != run.Input.PipelineRevisionDigest ||
		value.Revision.PipelineID != run.PipelineID || value.Revision.ProjectID != run.ProjectID ||
		value.Revision.Spec.RepositoryBindingID != run.Input.RepositoryBindingID ||
		value.Revision.Spec.RepositoryBindingDigest != run.Input.RepositoryBindingDigest {
		problems = append(problems, errors.New("PipelineRevision does not bind the PipelineRun"))
	}
	if value.BindingRevision.Metadata.ID != run.Input.RepositoryBindingID ||
		value.BindingRevision.ContentDigest != run.Input.RepositoryBindingDigest ||
		value.BindingRevision.ProjectID != run.ProjectID ||
		value.BindingRevision.Spec.SourceConnectionID != value.Connection.Metadata.ID {
		problems = append(problems, errors.New("RepositoryBinding revision does not bind the PipelineRun"))
	}
	if value.Event.Spec.SourceConnectionID != value.Connection.Metadata.ID ||
		value.Event.Spec.RepositoryBindingID != value.BindingRevision.Metadata.ID ||
		value.Event.Spec.RepositoryBindingDigest != value.BindingRevision.ContentDigest ||
		value.Event.Spec.ExternalRepositoryID != value.BindingRevision.Spec.ExternalRepositoryID {
		problems = append(problems, errors.New("source configuration does not bind the SourceEvent"))
	}
	if err := errors.Join(problems...); err != nil {
		return errors.Join(ErrInvalidCommand, err)
	}
	return nil
}

func ValidateArchiveContent(value ArchiveContent) error {
	if value.ExpandedBytes < 0 || value.ExpandedBytes > MaximumExpandedBytes ||
		value.PathCount > MaximumPathCount {
		return ErrInvalidReceipt
	}
	return nil
}

func ValidateReceipt(command Command, value sourcearchive.Receipt) error {
	var problems []error
	problems = append(problems,
		ValidateCommand(command),
		devopsv1.ValidateID("sourceArchive.commandId", value.CommandID),
		devopsv1.ValidateDigest("sourceArchive.inputDigest", value.InputDigest),
		devopsv1.ValidateDigest("sourceArchive.archiveDigest", value.ArchiveDigest),
	)
	if value.TenantID != command.Lease.TenantID ||
		value.RunID != command.Lease.Run.ID ||
		value.CommandID != command.Lease.Intent.CommandID ||
		value.InputDigest != command.Lease.Run.InputDigest ||
		value.HeadCommit != command.Lease.Run.Input.Change.HeadCommit ||
		value.TrustedBaseCommit != command.Lease.Run.Input.Change.TrustedBaseCommit ||
		value.MediaType != ArchiveMediaType {
		problems = append(problems, errors.New("source archive receipt does not bind its command"))
	}
	if value.ArchiveBytes <= 0 || value.ArchiveBytes > MaximumArchiveBytes ||
		value.ExpandedBytes < 0 || value.ExpandedBytes > MaximumExpandedBytes ||
		value.PathCount > MaximumPathCount {
		problems = append(problems, errors.New("source archive receipt exceeds its closed limits"))
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
		return fmt.Errorf("source acquisition completion is invalid: %w", err)
	}
	switch value.State {
	case devopsv1.PipelineRunVerifying:
		if value.Reason != "" || value.Receipt == nil {
			return errors.New("successful source acquisition requires one receipt")
		}
		return ValidateReceipt(value.Command, *value.Receipt)
	case devopsv1.PipelineRunFailed:
		if value.Receipt != nil ||
			(value.Reason != devopsv1.PipelineRunReasonSourceUnavailable &&
				value.Reason != devopsv1.PipelineRunReasonCommitMismatch &&
				value.Reason != devopsv1.PipelineRunReasonDeadlineExceeded) {
			return errors.New("failed source acquisition has an invalid reason or receipt")
		}
	case devopsv1.PipelineRunCancelled:
		if value.Receipt != nil || value.Reason != devopsv1.PipelineRunReasonCancelled ||
			value.Command.Lease.Run.Status.CancellationRequestedAt == nil {
			return errors.New("cancelled source acquisition has invalid evidence")
		}
	default:
		return errors.New("source acquisition completion target is invalid")
	}
	return nil
}

func validateCanonicalTime(name string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}
