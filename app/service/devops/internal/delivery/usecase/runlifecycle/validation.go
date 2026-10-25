package runlifecycle

import (
	"errors"
	"fmt"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

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
