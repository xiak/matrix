package createplacement

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	appdomain "github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
)

const maxPendingReservationTTL = 24 * time.Hour

type stopCandidateIdentity struct {
	Version            string            `json:"version"`
	TenantID           paasv1.TenantID   `json:"tenantId"`
	DeploymentID       paasv1.ResourceID `json:"deploymentId"`
	Generation         uint64            `json:"generation"`
	PreviousDecisionID paasv1.ResourceID `json:"previousDecisionId"`
	ReservationID      paasv1.ResourceID `json:"reservationId"`
	ExecutionTargetID  paasv1.ResourceID `json:"executionTargetId"`
	TargetVersion      uint64            `json:"targetVersion"`
	PolicyVersion      uint64            `json:"policyVersion"`
}

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

func (usecase *Usecase) CreatePlacement(
	ctx context.Context,
	command Command,
	guard operationqueue.LeaseGuard,
) (Result, error) {
	if usecase == nil {
		return Result{}, errors.New("create placement use case is nil")
	}
	if ctx == nil {
		return Result{}, errors.New("placement context is nil")
	}
	if err := validateCommandAndGuard(command, guard); err != nil {
		return Result{}, err
	}

	var result Result
	var transactionErr error
	for attempt := 1; attempt <= usecase.config.MaxTransactionAttempts; attempt++ {
		result = Result{}
		transactionErr = usecase.repository.WithinTransaction(
			ctx,
			command.TenantID,
			guard,
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

func (usecase *Usecase) BindStopPlacement(
	ctx context.Context,
	command Command,
	guard operationqueue.LeaseGuard,
) (Result, error) {
	if usecase == nil {
		return Result{}, errors.New("create placement use case is nil")
	}
	if ctx == nil {
		return Result{}, errors.New("placement context is nil")
	}
	if err := validateCommandAndGuard(command, guard); err != nil {
		return Result{}, err
	}

	var result Result
	var transactionErr error
	for attempt := 1; attempt <= usecase.config.MaxTransactionAttempts; attempt++ {
		result = Result{}
		transactionErr = usecase.repository.WithinTransaction(
			ctx,
			command.TenantID,
			guard,
			func(transactionContext context.Context, transaction Transaction) error {
				var err error
				result, err = bindStopInTransaction(
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
		"stop placement transaction attempts exhausted: %w",
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
		command.DeploymentID,
	)
	if err != nil {
		return Result{}, err
	}
	if snapshot.Deployment.Metadata.ID != command.DeploymentID {
		return Result{}, errors.New("placement repository returned a mismatched deployment")
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
			DeploymentID:      command.DeploymentID,
			DecisionID:        command.DecisionID,
			ExecutionTargetID: plan.Decision.ExecutionTargetID,
			Isolation:         plan.Decision.GrantedIsolationGuarantee,
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

func bindStopInTransaction(
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
	binding, err := transaction.LoadStopBinding(ctx, command.DeploymentID)
	if err != nil {
		return Result{}, err
	}
	if err := validateStopBinding(command, binding); err != nil {
		return Result{}, err
	}
	encodedIdentity, err := json.Marshal(stopCandidateIdentity{
		Version: "stop-placement-v1", TenantID: command.TenantID,
		DeploymentID: command.DeploymentID, Generation: binding.Generation.Generation,
		PreviousDecisionID: binding.PreviousDecision.Metadata.ID,
		ReservationID:      binding.ReservationID,
		ExecutionTargetID:  binding.ExecutionTarget.Metadata.ID,
		TargetVersion:      binding.ExecutionTarget.Metadata.ResourceVersion,
		PolicyVersion:      binding.Policy.Metadata.ResourceVersion,
	})
	if err != nil {
		return Result{}, fmt.Errorf("encode stop placement identity: %w", err)
	}
	nameDigest := sha256.Sum256([]byte(command.DecisionID))
	decision := paasv1.PlacementDecision{
		APIVersion: paasv1.APIVersion,
		Kind:       "PlacementDecision",
		Metadata: paasv1.ResourceMetadata{
			ID: command.DecisionID, Name: fmt.Sprintf("placement-%x", nameDigest[:10]),
			Scope:           paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: command.TenantID},
			ResourceVersion: 1, CreatedAt: transactionTime, UpdatedAt: transactionTime,
		},
		DeploymentID:                   command.DeploymentID,
		DeploymentGeneration:           binding.Generation.Generation,
		DeploymentResourceVersion:      binding.Deployment.Metadata.ResourceVersion,
		ApplicationRevisionID:          binding.Generation.Spec.ApplicationRevisionID,
		PlacementPolicyID:              binding.Policy.Metadata.ID,
		PolicyResourceVersion:          binding.Policy.Metadata.ResourceVersion,
		RequestedIsolationGuarantee:    binding.PreviousDecision.GrantedIsolationGuarantee,
		Outcome:                        paasv1.PlacementScheduled,
		ExecutionTargetID:              binding.ExecutionTarget.Metadata.ID,
		ExecutionTargetResourceVersion: binding.ExecutionTarget.Metadata.ResourceVersion,
		GrantedIsolationGuarantee:      binding.PreviousDecision.GrantedIsolationGuarantee,
		CandidateSetDigest:             appdomain.DigestPayload(encodedIdentity),
		DecidedAt:                      transactionTime,
	}
	if err := paasv1.ValidatePlacementDecision(decision); err != nil {
		return Result{}, fmt.Errorf("stop binding produced an invalid PlacementDecision: %w", err)
	}
	if err := transaction.CreateDecision(ctx, DecisionCreation{
		OperationID: command.OperationID, RequestDigest: command.RequestDigest,
		Decision: decision, ReusesActiveReservation: true,
	}); err != nil {
		return Result{}, err
	}
	return Result{Decision: decision}, nil
}

func validateStopBinding(command Command, binding StopBinding) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateDeployment(binding.Deployment),
		paasv1.ValidateDeploymentGeneration(binding.Generation),
		paasv1.ValidatePlacementPolicy(binding.Policy),
		paasv1.ValidatePlacementDecision(binding.PreviousDecision),
		paasv1.ValidateExecutionTarget(binding.ExecutionTarget),
		paasv1.ValidateID("reservationId", string(binding.ReservationID)),
	)
	if binding.Deployment.Metadata.Scope.TenantID != command.TenantID ||
		binding.Deployment.Metadata.ID != command.DeploymentID ||
		binding.Deployment.Spec.DesiredState != paasv1.DeploymentDesiredStopped ||
		binding.Deployment.Status.Phase != paasv1.DeploymentPending ||
		binding.Generation.Scope != binding.Deployment.Metadata.Scope ||
		binding.Generation.DeploymentID != command.DeploymentID ||
		binding.Generation.Generation != binding.Deployment.Generation ||
		binding.Generation.CreatedByOperationID != command.OperationID ||
		binding.Generation.ContentDigest !=
			paasv1.DeploymentSpecContentDigest(binding.Deployment.Spec) ||
		binding.Policy.Metadata.Scope != binding.Deployment.Metadata.Scope ||
		binding.Policy.Metadata.ID != binding.Generation.Spec.PlacementPolicyID ||
		binding.PreviousDecision.Metadata.Scope != binding.Deployment.Metadata.Scope ||
		binding.PreviousDecision.Metadata.ID != binding.Deployment.Status.PlacementDecisionID ||
		binding.PreviousDecision.Outcome != paasv1.PlacementScheduled ||
		binding.PreviousDecision.DeploymentID != command.DeploymentID ||
		binding.PreviousDecision.DeploymentGeneration !=
			binding.Deployment.Status.ObservedGeneration ||
		binding.PreviousDecision.ApplicationRevisionID !=
			binding.Deployment.Status.ObservedApplicationRevisionID ||
		binding.PreviousDecision.ExecutionTargetID != binding.ExecutionTarget.Metadata.ID {
		problems = append(problems, errors.New(
			"stop placement does not match the current observed active binding",
		))
	}
	return errors.Join(problems...)
}

func validateCommand(command Command) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("tenantId", string(command.TenantID)),
		paasv1.ValidateID("operationId", string(command.OperationID)),
		paasv1.ValidateID("decisionId", string(command.DecisionID)),
		paasv1.ValidateID("deploymentId", string(command.DeploymentID)),
		paasv1.ValidateDigest("requestDigest", command.RequestDigest),
		paasv1.ValidateID("traceId", command.TraceID),
	)
	return errors.Join(problems...)
}

func validateCommandAndGuard(command Command, guard operationqueue.LeaseGuard) error {
	if err := validateCommand(command); err != nil {
		return err
	}
	if err := operationqueue.ValidateLeaseGuard(guard); err != nil {
		return err
	}
	if guard.TenantID != command.TenantID || guard.OperationID != command.OperationID {
		return errors.New("placement command and Operation lease identities differ")
	}
	return nil
}

func validateReplay(command Command, stored StoredDecision) error {
	if stored.RequestDigest != command.RequestDigest ||
		stored.Decision.Metadata.Scope.TenantID != command.TenantID ||
		stored.Decision.DeploymentID != command.DeploymentID {
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
