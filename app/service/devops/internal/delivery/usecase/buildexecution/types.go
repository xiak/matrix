// Package buildexecution owns the fenced VERIFY workflow that turns one
// immutable source archive into one normalized BuildExecutor receipt.
package buildexecution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

const (
	LeaseDuration       = 30 * time.Second
	HeartbeatInterval   = 10 * time.Second
	HeartbeatMaximumAge = 30 * time.Second
	ExecutionDeadline   = time.Duration(devopsv1.FixedRunTimeoutSeconds) * time.Second
	CancellationGrace   = 30 * time.Second
)

var (
	ErrInvalidCommand     = errors.New("build execution command is invalid")
	ErrInvalidReceipt     = errors.New("build execution receipt is invalid")
	ErrArchiveUnavailable = errors.New("source archive is unavailable to the build executor")
	ErrExecutionUncertain = errors.New("build execution requires fenced observation")
)

// Command closes every mutable lookup before an executor effect. Revision and
// Archive are the exact immutable records selected by the PipelineRun input.
type Command struct {
	Lease      runlifecycle.Lease
	Revision   devopsv1.PipelineRevision
	Archive    sourcearchive.Receipt
	StartedAt  time.Time
	DeadlineAt time.Time
}

type Repository interface {
	Heartbeat(context.Context, string) (time.Time, error)
	Claim(context.Context, string, time.Duration) (Command, bool, error)
	Renew(context.Context, runlifecycle.LeaseGuard, time.Duration) (time.Time, error)
	Complete(context.Context, Completion) (devopsv1.PipelineRun, error)
	Readiness(context.Context) (devopsv1.Readiness, error)
}

type ArchiveReader interface {
	Open(context.Context, sourcearchive.Receipt) (io.ReadCloser, error)
}

type Completion struct {
	Command Command
	State   devopsv1.PipelineRunState
	Reason  devopsv1.PipelineRunReason
	Receipt *devopsbuildv1.Receipt
}

type Config struct {
	WorkerID      string
	LeaseDuration time.Duration
	Deadline      time.Duration
	CancelGrace   time.Duration
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
		devopsv1.ValidatePipelineRevision(value.Revision),
		sourcearchive.ValidateReceipt(value.Archive),
		validateCanonicalTime("build.startedAt", value.StartedAt),
		validateCanonicalTime("build.deadlineAt", value.DeadlineAt),
	)
	lease := value.Lease
	run := lease.Run
	if run.Status.State != devopsv1.PipelineRunVerifying ||
		lease.Intent.Stage != devopsv1.PipelineRunStageVerify ||
		lease.ReconciliationAttempts != 0 {
		problems = append(problems, errors.New("lease is not a VERIFY command"))
	}
	if value.Revision.Scope.TenantID != lease.TenantID ||
		value.Revision.ID != run.Input.PipelineRevisionID ||
		value.Revision.ContentDigest != run.Input.PipelineRevisionDigest ||
		value.Revision.PipelineID != run.PipelineID ||
		value.Revision.ProjectID != run.ProjectID ||
		value.Revision.Spec.RepositoryBindingID != run.Input.RepositoryBindingID ||
		value.Revision.Spec.RepositoryBindingDigest != run.Input.RepositoryBindingDigest ||
		value.Revision.ActivatedAt.After(run.CreatedAt) {
		problems = append(problems, errors.New("PipelineRevision does not bind the PipelineRun"))
	}
	if value.Archive.TenantID != lease.TenantID ||
		value.Archive.RunID != run.ID ||
		value.Archive.InputDigest != run.InputDigest ||
		value.Archive.HeadCommit != run.Input.Change.HeadCommit ||
		value.Archive.TrustedBaseCommit != run.Input.Change.TrustedBaseCommit ||
		value.Archive.MediaType != sourcearchive.MediaType ||
		!validStageCommandID(value.Archive.CommandID, run.ID, "fetch") {
		problems = append(problems, errors.New("source archive does not bind the PipelineRun"))
	}
	if value.StartedAt.Before(run.UpdatedAt) ||
		!value.StartedAt.Before(lease.LeaseExpiresAt) ||
		value.DeadlineAt.Sub(value.StartedAt) != ExecutionDeadline {
		problems = append(problems, errors.New("build execution time boundary is invalid"))
	}
	request, err := requestForCommand(value)
	if err == nil {
		err = devopsbuildv1.ValidateRequest(request)
	}
	problems = append(problems, err)
	if err := errors.Join(problems...); err != nil {
		return errors.Join(ErrInvalidCommand, err)
	}
	return nil
}

func requestForCommand(value Command) (devopsbuildv1.Request, error) {
	steps := value.Revision.Spec.Steps
	if len(steps) != 2 {
		return devopsbuildv1.Request{}, ErrInvalidCommand
	}
	request := devopsbuildv1.Request{
		TenantID:               value.Lease.TenantID,
		RunID:                  value.Lease.Run.ID,
		CommandID:              value.Lease.Intent.CommandID,
		InputDigest:            value.Lease.Run.InputDigest,
		SourceArchiveDigest:    value.Archive.ArchiveDigest,
		SourceArchiveBytes:     value.Archive.ArchiveBytes,
		SourceExpandedBytes:    value.Archive.ExpandedBytes,
		SourcePathCount:        value.Archive.PathCount,
		PipelineRevisionID:     value.Revision.ID,
		PipelineRevisionDigest: value.Revision.ContentDigest,
		VerificationProfile:    value.Revision.Spec.VerificationProfile,
		ExecutorProfile:        value.Revision.Spec.ExecutorProfile,
		ToolchainImageDigest:   value.Revision.Spec.ToolchainImageDigest,
		DependencyEgress:       value.Revision.Spec.DependencyEgress,
		Steps:                  [2]devopsv1.VerificationStep{steps[0], steps[1]},
		Limits:                 value.Revision.Spec.Limits,
		StartedAt:              value.StartedAt,
		DeadlineAt:             value.DeadlineAt,
	}
	if err := devopsbuildv1.ValidateRequest(request); err != nil {
		return devopsbuildv1.Request{}, errors.Join(ErrInvalidCommand, err)
	}
	return request, nil
}

func ValidateCompletion(value Completion) error {
	if err := ValidateCommand(value.Command); err != nil {
		return err
	}
	if err := domain.ValidatePipelineRunTransition(
		value.Command.Lease.Run.Status.State,
		value.State,
		value.Reason,
	); err != nil {
		return fmt.Errorf("build execution completion is invalid: %w", err)
	}
	request, err := requestForCommand(value.Command)
	if err != nil {
		return err
	}
	if value.Receipt != nil {
		if err := devopsbuildv1.ValidateReceipt(request, *value.Receipt); err != nil {
			return errors.Join(ErrInvalidReceipt, err)
		}
	}
	switch value.State {
	case devopsv1.PipelineRunReporting:
		if value.Reason != "" || value.Receipt == nil ||
			value.Command.Lease.Run.Status.CancellationRequestedAt != nil ||
			(value.Receipt.Conclusion != devopsbuildv1.ConclusionPassed &&
				value.Receipt.Conclusion != devopsbuildv1.ConclusionFailed) {
			return errors.New("reporting requires one definitive build receipt")
		}
	case devopsv1.PipelineRunFailed:
		if value.Reason != devopsv1.PipelineRunReasonExecutorUnavailable &&
			value.Reason != devopsv1.PipelineRunReasonDeadlineExceeded {
			return errors.New("failed build execution has an invalid reason")
		}
		if value.Receipt != nil &&
			value.Receipt.Conclusion != devopsbuildv1.ConclusionCancelled {
			return errors.New("failed build execution has a contradictory receipt")
		}
	case devopsv1.PipelineRunCancelled:
		if value.Reason != devopsv1.PipelineRunReasonCancelled ||
			value.Command.Lease.Run.Status.CancellationRequestedAt == nil {
			return errors.New("cancelled build execution has invalid evidence")
		}
	default:
		return errors.New("build execution completion target is invalid")
	}
	return nil
}

func validStageCommandID(
	commandID string,
	runID devopsv1.ResourceID,
	stage string,
) bool {
	prefix := string(runID) + ":" + stage + ":"
	attemptText := strings.TrimPrefix(commandID, prefix)
	attempt, err := strconv.ParseUint(attemptText, 10, 64)
	return err == nil && attempt >= 1 && attempt <= 100 &&
		strconv.FormatUint(attempt, 10) == attemptText && commandID == prefix+attemptText
}

func validateCanonicalTime(name string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}
