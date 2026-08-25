package operationqueue

import (
	"context"
	"errors"
	"fmt"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
)

const maximumLeaseDuration = 5 * time.Minute

func NewQueue(repository Repository, config Config) (*Queue, error) {
	if repository == nil {
		return nil, errors.New("Operation queue repository is required")
	}
	if config.LeaseDuration < time.Second ||
		config.LeaseDuration > maximumLeaseDuration ||
		config.LeaseDuration%time.Second != 0 {
		return nil, errors.New("Operation lease duration must be whole seconds between 1 and 300")
	}
	return &Queue{repository: repository, config: config}, nil
}

func (queue *Queue) ClaimNext(ctx context.Context, workerID string) (Lease, bool, error) {
	if queue == nil || queue.repository == nil {
		return Lease{}, false, errors.New("Operation queue is nil")
	}
	if ctx == nil {
		return Lease{}, false, errors.New("Operation claim context is nil")
	}
	if err := paasv1.ValidateID("workerId", workerID); err != nil {
		return Lease{}, false, err
	}
	lease, found, err := queue.repository.ClaimOperation(
		ctx,
		workerID,
		queue.config.LeaseDuration,
	)
	if err != nil || !found {
		return Lease{}, found, err
	}
	if err := validateLease(lease); err != nil {
		return Lease{}, false, fmt.Errorf("repository returned an invalid Operation lease: %w", err)
	}
	if lease.WorkerID != workerID {
		return Lease{}, false, errors.New("repository returned an Operation lease for another worker")
	}
	return lease, true, nil
}

func (queue *Queue) Advance(
	ctx context.Context,
	transition Transition,
) (Lease, error) {
	if queue == nil || queue.repository == nil {
		return Lease{}, errors.New("Operation queue is nil")
	}
	if ctx == nil {
		return Lease{}, errors.New("Operation transition context is nil")
	}
	if err := validateLease(transition.Lease); err != nil {
		return Lease{}, err
	}
	if err := domain.ValidateOperationTransition(
		transition.Lease.Operation.State,
		transition.State,
	); err != nil {
		return Lease{}, fmt.Errorf("%w: %v", ErrInvalidTransition, err)
	}
	if err := validateCompletion(transition); err != nil {
		return Lease{}, err
	}
	operation, err := queue.repository.AdvanceOperation(ctx, transition)
	if err != nil {
		return Lease{}, err
	}
	if err := paasv1.ValidateOperation(operation); err != nil {
		return Lease{}, fmt.Errorf("repository returned an invalid Operation: %w", err)
	}
	if operation.ID != transition.Lease.Operation.ID ||
		operation.Scope != transition.Lease.Operation.Scope ||
		operation.State != transition.State ||
		operation.Attempt != transition.Lease.Operation.Attempt {
		return Lease{}, errors.New("repository returned a mismatched Operation transition")
	}
	next := transition.Lease
	next.Operation = operation
	if transition.ReleaseLease {
		next.WorkerID = ""
		next.FencingToken = 0
		next.LeaseExpiresAt = time.Time{}
	}
	return next, nil
}

func validateLease(lease Lease) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("tenantId", string(lease.TenantID)),
		paasv1.ValidateID("workerId", lease.WorkerID),
		paasv1.ValidateOperation(lease.Operation),
	)
	if lease.Operation.Scope.Kind != paasv1.AuthorityTenant ||
		lease.Operation.Scope.TenantID != lease.TenantID {
		problems = append(problems, errors.New("Operation lease tenant identity does not match"))
	}
	if lease.FencingToken == 0 || lease.FencingToken > 9007199254740991 {
		problems = append(problems, errors.New("Operation fencing token is invalid"))
	}
	if lease.LeaseExpiresAt.IsZero() ||
		lease.LeaseExpiresAt.Location() != time.UTC ||
		lease.LeaseExpiresAt != lease.LeaseExpiresAt.Round(0) ||
		lease.LeaseExpiresAt.Nanosecond()%1_000 != 0 ||
		!lease.LeaseExpiresAt.After(lease.Operation.UpdatedAt) {
		problems = append(problems, errors.New("Operation lease expiry is invalid"))
	}
	return errors.Join(problems...)
}

func validateCompletion(transition Transition) error {
	terminal := domain.IsTerminalOperationState(transition.State)
	if terminal && !transition.ReleaseLease {
		return errors.New("terminal Operation transition must release its lease")
	}
	needsProblem := transition.State == paasv1.OperationFailed ||
		transition.State == paasv1.OperationManualIntervention
	if needsProblem != (transition.Problem != nil) {
		return errors.New("Operation failure transition has an invalid Problem")
	}
	if transition.Problem != nil {
		if err := paasv1.ValidateProblem(*transition.Problem); err != nil {
			return err
		}
	}
	if transition.ReleaseLease && !terminal {
		if transition.NextAttemptAt == nil ||
			transition.NextAttemptAt.Location() != time.UTC ||
			*transition.NextAttemptAt != transition.NextAttemptAt.Round(0) ||
			transition.NextAttemptAt.Nanosecond()%1_000 != 0 {
			return errors.New("released non-terminal Operation requires a valid next attempt time")
		}
	} else if transition.NextAttemptAt != nil {
		return errors.New("retained or terminal Operation cannot schedule a next attempt")
	}
	return nil
}
