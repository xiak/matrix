package runlifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
)

func NewQueue(repository Repository, config Config) (*Queue, error) {
	if repository == nil {
		return nil, errors.New("PipelineRun task repository is required")
	}
	if config.LeaseDuration < time.Second ||
		config.LeaseDuration > maximumLeaseDuration ||
		config.LeaseDuration%time.Second != 0 {
		return nil, errors.New("PipelineRun task lease must use whole seconds between 1 and 300")
	}
	return &Queue{repository: repository, config: config}, nil
}

func (queue *Queue) ClaimNext(ctx context.Context, workerID string) (Lease, bool, error) {
	if queue == nil || queue.repository == nil {
		return Lease{}, false, errors.New("PipelineRun task queue is nil")
	}
	if ctx == nil {
		return Lease{}, false, errors.New("PipelineRun task claim context is nil")
	}
	if err := devopsv1.ValidateID("workerId", workerID); err != nil {
		return Lease{}, false, err
	}
	lease, found, err := queue.repository.Claim(ctx, workerID, queue.config.LeaseDuration)
	if err != nil || !found {
		return Lease{}, found, err
	}
	if err := ValidateLease(lease); err != nil {
		return Lease{}, false, fmt.Errorf("repository returned an invalid PipelineRun task lease: %w", err)
	}
	if lease.WorkerID != workerID {
		return Lease{}, false, errors.New("repository returned a PipelineRun task lease for another worker")
	}
	return lease, true, nil
}

func (queue *Queue) Renew(ctx context.Context, lease Lease) (Lease, error) {
	if queue == nil || queue.repository == nil {
		return Lease{}, errors.New("PipelineRun task queue is nil")
	}
	if ctx == nil {
		return Lease{}, errors.New("PipelineRun task renewal context is nil")
	}
	if err := ValidateLease(lease); err != nil {
		return Lease{}, err
	}
	expiresAt, err := queue.repository.Renew(ctx, lease.Guard(), queue.config.LeaseDuration)
	if err != nil {
		return Lease{}, err
	}
	if expiresAt.IsZero() || expiresAt.Location() != time.UTC ||
		expiresAt != expiresAt.Round(0) || expiresAt.Nanosecond()%1_000 != 0 ||
		expiresAt.Before(lease.LeaseExpiresAt) {
		return Lease{}, errors.New("repository returned an invalid PipelineRun task renewal")
	}
	lease.LeaseExpiresAt = expiresAt
	return lease, nil
}

// Advance commits a definitive adapter result and closes the current command
// intent. REPORTING uncertainty uses MarkReportUncertain so the same intent is
// preserved for observation.
func (queue *Queue) Advance(
	ctx context.Context,
	transition Transition,
) (devopsv1.PipelineRun, error) {
	if queue == nil || queue.repository == nil {
		return devopsv1.PipelineRun{}, errors.New("PipelineRun task queue is nil")
	}
	if ctx == nil {
		return devopsv1.PipelineRun{}, errors.New("PipelineRun task transition context is nil")
	}
	if err := ValidateLease(transition.Lease); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if transition.State == devopsv1.PipelineRunReconciling {
		return devopsv1.PipelineRun{}, errors.New("report uncertainty must retain its command intent")
	}
	if err := domain.ValidatePipelineRunTransition(
		transition.Lease.Run.Status.State,
		transition.State,
		transition.Reason,
	); err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("%w: %v", ErrInvalidTransition, err)
	}
	if transition.State == devopsv1.PipelineRunManualIntervention &&
		transition.Lease.ReconciliationAttempts < MaximumReconciliationAttempts {
		return devopsv1.PipelineRun{}, errors.New("manual intervention requires exhausted reconciliation")
	}
	updated, err := queue.repository.Advance(ctx, transition)
	if err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if err := ValidateReturnedTransition(transition.Lease.Run, updated, transition.State, transition.Reason); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	return updated, nil
}

func (queue *Queue) MarkReportUncertain(
	ctx context.Context,
	reconciliation Reconciliation,
) (devopsv1.PipelineRun, error) {
	if queue == nil || queue.repository == nil {
		return devopsv1.PipelineRun{}, errors.New("PipelineRun task queue is nil")
	}
	if ctx == nil {
		return devopsv1.PipelineRun{}, errors.New("PipelineRun reconciliation context is nil")
	}
	if err := ValidateLease(reconciliation.Lease); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if reconciliation.Lease.Run.Status.State != devopsv1.PipelineRunReporting ||
		reconciliation.Lease.Intent.Stage != devopsv1.PipelineRunStageReport {
		return devopsv1.PipelineRun{}, errors.New("only a reporting task can enter reconciliation")
	}
	if err := validateDeferralTime(reconciliation.Lease.Run.UpdatedAt, reconciliation.NextAttemptAt); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	updated, err := queue.repository.MarkReportUncertain(ctx, reconciliation)
	if err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if err := ValidateReturnedTransition(
		reconciliation.Lease.Run,
		updated,
		devopsv1.PipelineRunReconciling,
		devopsv1.PipelineRunReasonExternalEffectUncertain,
	); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	return updated, nil
}

func (queue *Queue) DeferReconciliation(
	ctx context.Context,
	reconciliation Reconciliation,
) (uint64, error) {
	if queue == nil || queue.repository == nil {
		return 0, errors.New("PipelineRun task queue is nil")
	}
	if ctx == nil {
		return 0, errors.New("PipelineRun reconciliation context is nil")
	}
	if err := ValidateLease(reconciliation.Lease); err != nil {
		return 0, err
	}
	if reconciliation.Lease.Run.Status.State != devopsv1.PipelineRunReconciling ||
		reconciliation.Lease.Mode != ClaimObserve {
		return 0, errors.New("only an observed reconciling report can be deferred")
	}
	if reconciliation.Lease.ReconciliationAttempts >= MaximumReconciliationAttempts {
		return 0, ErrReconciliationExhausted
	}
	if err := validateDeferralTime(reconciliation.Lease.Run.UpdatedAt, reconciliation.NextAttemptAt); err != nil {
		return 0, err
	}
	attempts, err := queue.repository.DeferReconciliation(ctx, reconciliation)
	if err != nil {
		return 0, err
	}
	if attempts != reconciliation.Lease.ReconciliationAttempts+1 ||
		attempts > MaximumReconciliationAttempts {
		return 0, errors.New("repository returned invalid reconciliation attempt progress")
	}
	return attempts, nil
}

func ValidateLease(lease Lease) error {
	var problems []error
	problems = append(problems,
		devopsv1.ValidateID("tenantId", string(lease.TenantID)),
		devopsv1.ValidatePipelineRun(lease.Run),
		devopsv1.ValidateID("task.commandId", lease.Intent.CommandID),
		devopsv1.ValidateID("workerId", lease.WorkerID),
		devopsv1.ValidateDigest("task.inputDigest", lease.Intent.InputDigest),
	)
	if lease.Run.Scope.TenantID != lease.TenantID ||
		lease.Intent.RunID != lease.Run.ID ||
		lease.Intent.InputDigest != lease.Run.InputDigest ||
		lease.Intent.Stage != lease.Run.Status.Stage ||
		lease.Intent.CommandID != TaskCommandID(lease.Run.ID, lease.Intent.Stage, lease.Intent.Attempt) {
		problems = append(problems, errors.New("PipelineRun task intent does not bind its run"))
	}
	if lease.Intent.Stage == devopsv1.PipelineRunStageReceive {
		problems = append(problems, errors.New("RECEIVE is not an external task stage"))
	}
	switch lease.Run.Status.State {
	case devopsv1.PipelineRunFetching:
		if lease.Intent.Stage != devopsv1.PipelineRunStageFetch {
			problems = append(problems, errors.New("fetching PipelineRun has a non-fetch task"))
		}
	case devopsv1.PipelineRunVerifying:
		if lease.Intent.Stage != devopsv1.PipelineRunStageVerify {
			problems = append(problems, errors.New("verifying PipelineRun has a non-verify task"))
		}
	case devopsv1.PipelineRunReporting, devopsv1.PipelineRunReconciling:
		if lease.Intent.Stage != devopsv1.PipelineRunStageReport {
			problems = append(problems, errors.New("reporting PipelineRun has a non-report task"))
		}
	default:
		problems = append(problems, errors.New("PipelineRun task lease is not active"))
	}
	if lease.Intent.Attempt == 0 || lease.Intent.Attempt > maximumTaskAttempts {
		problems = append(problems, errors.New("PipelineRun task attempt is invalid"))
	}
	if lease.FencingToken == 0 || lease.FencingToken > devopsv1.MaximumContractInteger {
		problems = append(problems, errors.New("PipelineRun task fencing token is invalid"))
	}
	if lease.ReconciliationAttempts > MaximumReconciliationAttempts {
		problems = append(problems, errors.New("PipelineRun reconciliation attempt is invalid"))
	}
	if lease.Run.Status.State != devopsv1.PipelineRunReconciling && lease.ReconciliationAttempts != 0 {
		problems = append(problems, errors.New("non-reconciling PipelineRun contains reconciliation attempts"))
	}
	if lease.LeaseExpiresAt.IsZero() || lease.LeaseExpiresAt.Location() != time.UTC ||
		lease.LeaseExpiresAt != lease.LeaseExpiresAt.Round(0) ||
		lease.LeaseExpiresAt.Nanosecond()%1_000 != 0 ||
		!lease.LeaseExpiresAt.After(lease.Run.UpdatedAt) {
		problems = append(problems, errors.New("PipelineRun task lease expiry is invalid"))
	}
	switch lease.Mode {
	case ClaimExecute:
		if lease.FencingToken != 1 || lease.Run.Status.State == devopsv1.PipelineRunReconciling {
			problems = append(problems, errors.New("execute claim is not a first effect attempt"))
		}
	case ClaimObserve:
		if lease.FencingToken < 2 {
			problems = append(problems, errors.New("observe claim has no prior effect possibility"))
		}
	default:
		problems = append(problems, errors.New("PipelineRun task claim mode is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateLeaseGuard(guard LeaseGuard) error {
	var problems []error
	problems = append(problems,
		devopsv1.ValidateID("tenantId", string(guard.TenantID)),
		devopsv1.ValidateID("runId", string(guard.RunID)),
		devopsv1.ValidateID("task.commandId", guard.CommandID),
		devopsv1.ValidateID("workerId", guard.WorkerID),
	)
	if guard.FencingToken == 0 || guard.FencingToken > devopsv1.MaximumContractInteger {
		problems = append(problems, errors.New("PipelineRun task fencing token is invalid"))
	}
	return errors.Join(problems...)
}

func ValidateReturnedTransition(
	current, updated devopsv1.PipelineRun,
	state devopsv1.PipelineRunState,
	reason devopsv1.PipelineRunReason,
) error {
	if err := devopsv1.ValidatePipelineRun(updated); err != nil {
		return fmt.Errorf("repository returned an invalid PipelineRun: %w", err)
	}
	if updated.ID != current.ID || updated.Scope != current.Scope ||
		updated.ProjectID != current.ProjectID || updated.PipelineID != current.PipelineID ||
		updated.Input != current.Input || updated.InputDigest != current.InputDigest ||
		!equalReplay(updated.Replay, current.Replay) ||
		!equalTimePointer(
			updated.Status.CancellationRequestedAt,
			current.Status.CancellationRequestedAt,
		) || updated.CreatedAt != current.CreatedAt || updated.Status.State != state ||
		updated.Status.Reason != reason ||
		updated.Status.ResourceVersion != current.Status.ResourceVersion+1 ||
		!updated.UpdatedAt.After(current.UpdatedAt) {
		return errors.New("repository returned a mismatched PipelineRun transition")
	}
	return nil
}

func equalReplay(left, right *devopsv1.PipelineRunReplay) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func equalTimePointer(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validateDeferralTime(current, next time.Time) error {
	if next.IsZero() || next.Location() != time.UTC || next != next.Round(0) ||
		next.Nanosecond()%1_000 != 0 || !next.After(current) || next.Sub(current) > maximumDeferral {
		return errors.New("PipelineRun next observation time is invalid")
	}
	return nil
}
