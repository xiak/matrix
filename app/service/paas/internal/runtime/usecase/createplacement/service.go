package createplacement

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	paasv1 "matrix/api/paas/v1"
	"matrix/app/service/paas/internal/runtime/domain/placement"
)

const maxPendingReservationTTL = 24 * time.Hour

func NewUsecase(
	planner *placement.Planner,
	repository Repository,
	config Config,
) (*Usecase, error) {
	if planner == nil {
		return nil, errors.New("placement planner is required")
	}
	if repository == nil {
		return nil, errors.New("placement repository is required")
	}
	if config.PendingReservationTTL <= 0 ||
		config.PendingReservationTTL > maxPendingReservationTTL ||
		config.PendingReservationTTL%time.Microsecond != 0 {
		return nil, errors.New(
			"pending reservation TTL must be whole microseconds between 1 microsecond and 24 hours",
		)
	}
	if config.MaxTransactionAttempts < 1 || config.MaxTransactionAttempts > 10 {
		return nil, errors.New("maximum transaction attempts must be between 1 and 10")
	}
	return &Usecase{planner: planner, repository: repository, config: config}, nil
}

func (usecase *Usecase) CreatePlacement(ctx context.Context, command Command) (Result, error) {
	if usecase == nil {
		return Result{}, errors.New("create placement use case is nil")
	}
	if ctx == nil {
		return Result{}, errors.New("placement context is nil")
	}
	if err := validateCommand(command); err != nil {
		return Result{}, err
	}

	var result Result
	var transactionErr error
	for attempt := 1; attempt <= usecase.config.MaxTransactionAttempts; attempt++ {
		result = Result{}
		transactionErr = usecase.repository.WithinTransaction(
			ctx,
			command.TenantID,
			func(transactionContext context.Context, transaction Transaction) error {
				var err error
				result, err = usecase.createInTransaction(
					transactionContext,
					transaction,
					command,
				)
				return err
			},
		)
		if transactionErr == nil {
			return result, nil
		}
		if !errors.Is(transactionErr, ErrRetryableTransaction) {
			return Result{}, transactionErr
		}
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
	}
	return Result{}, fmt.Errorf(
		"placement transaction attempts exhausted: %w",
		transactionErr,
	)
}

func (usecase *Usecase) createInTransaction(
	ctx context.Context,
	transaction Transaction,
	command Command,
) (Result, error) {
	if transaction == nil {
		return Result{}, errors.New("placement transaction is nil")
	}
	stored, found, err := transaction.FindDecisionByOperation(ctx, command.OperationID)
	if err != nil {
		return Result{}, err
	}
	if found {
		if err := validateReplay(command, stored); err != nil {
			return Result{}, err
		}
		return Result{Decision: stored.Decision, Replayed: true}, nil
	}

	transactionTime, err := transaction.TransactionTime(ctx)
	if err != nil {
		return Result{}, err
	}
	snapshot, err := transaction.LoadAndLockSnapshot(
		ctx,
		command.WorkloadReleaseID,
		command.PlacementPolicyID,
	)
	if err != nil {
		return Result{}, err
	}
	if snapshot.Release.Metadata.ID != command.WorkloadReleaseID ||
		snapshot.Policy.Metadata.ID != command.PlacementPolicyID {
		return Result{}, errors.New("placement repository returned a mismatched release or policy")
	}

	plan, err := usecase.planner.Plan(placement.Input{
		TenantID:      command.TenantID,
		OperationID:   command.OperationID,
		DecisionID:    command.DecisionID,
		RequestDigest: command.RequestDigest,
		TraceID:       command.TraceID,
		DecidedAt:     transactionTime,
		Snapshot:      snapshot,
	})
	if err != nil {
		return Result{}, err
	}
	creation := DecisionCreation{
		OperationID:   command.OperationID,
		RequestDigest: command.RequestDigest,
		Decision:      plan.Decision,
	}
	if plan.Decision.Outcome == paasv1.PlacementScheduled {
		expiresAt := transactionTime.Add(usecase.config.PendingReservationTTL)
		if !expiresAt.After(transactionTime) {
			return Result{}, errors.New("pending reservation lease time overflows")
		}
		creation.Reservation = &CapacityReservationCreation{
			ID:                reservationID(command.DecisionID),
			TenantID:          command.TenantID,
			WorkloadReleaseID: command.WorkloadReleaseID,
			DecisionID:        command.DecisionID,
			RuntimeTargetID:   plan.Decision.RuntimeTargetID,
			Isolation:         plan.Decision.GrantedIsolation,
			Resources:         plan.Requirements,
			State:             placement.CapacityClaimPending,
			LeaseExpiresAt:    expiresAt,
			ResourceVersion:   1,
		}
	}
	if err := transaction.CreateDecision(ctx, creation); err != nil {
		return Result{}, err
	}
	return Result{Decision: plan.Decision}, nil
}

func validateCommand(command Command) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("tenantId", string(command.TenantID)),
		paasv1.ValidateID("operationId", string(command.OperationID)),
		paasv1.ValidateID("decisionId", string(command.DecisionID)),
		paasv1.ValidateID("workloadReleaseId", string(command.WorkloadReleaseID)),
		paasv1.ValidateID("placementPolicyId", string(command.PlacementPolicyID)),
		paasv1.ValidateDigest("requestDigest", command.RequestDigest),
		paasv1.ValidateID("traceId", command.TraceID),
	)
	return errors.Join(problems...)
}

func validateReplay(command Command, stored StoredDecision) error {
	if stored.RequestDigest != command.RequestDigest ||
		stored.Decision.Metadata.Scope.TenantID != command.TenantID ||
		stored.Decision.WorkloadReleaseID != command.WorkloadReleaseID ||
		stored.Decision.PlacementPolicyID != command.PlacementPolicyID {
		return ErrIdempotencyConflict
	}
	if err := paasv1.ValidateDigest("stored request digest", stored.RequestDigest); err != nil {
		return fmt.Errorf("stored placement replay is invalid: %w", err)
	}
	if err := paasv1.ValidatePlacementDecision(stored.Decision); err != nil {
		return fmt.Errorf("stored placement replay is invalid: %w", err)
	}
	return nil
}

func reservationID(decisionID paasv1.ResourceID) paasv1.ResourceID {
	digest := sha256.Sum256([]byte(decisionID))
	return paasv1.ResourceID(fmt.Sprintf("reservation-%x", digest[:10]))
}
