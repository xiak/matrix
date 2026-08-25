package reconciledeployment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
)

const maximumWorkerSteps = 16

type placementIdentity struct {
	Version         string                 `json:"version"`
	OperationDigest string                 `json:"operationDigest"`
	DeploymentID    paasv1.ResourceID      `json:"deploymentId"`
	Generation      uint64                 `json:"generation"`
	ContentDigest   string                 `json:"contentDigest"`
	Action          paasv1.OperationAction `json:"action"`
}

func NewWorker(
	queue OperationQueue,
	placement Placement,
	repository Repository,
	executor port.DeploymentExecutor,
	config Config,
) (*Worker, error) {
	var problems []error
	if queue == nil {
		problems = append(problems, errors.New("Operation queue is required"))
	}
	if placement == nil {
		problems = append(problems, errors.New("placement use case is required"))
	}
	if repository == nil {
		problems = append(problems, errors.New("Deployment reconciliation repository is required"))
	}
	if executor == nil {
		problems = append(problems, errors.New("Deployment executor is required"))
	}
	problems = append(problems, paasv1.ValidateID("bindingRef", config.BindingRef))
	if config.EffectTimeout < time.Second ||
		config.EffectTimeout > 5*time.Minute ||
		config.EffectTimeout%time.Microsecond != 0 {
		problems = append(problems, errors.New(
			"effect timeout must be whole microseconds between one second and five minutes",
		))
	}
	if config.ReconcileBackoff < time.Millisecond ||
		config.ReconcileBackoff > time.Hour ||
		config.ReconcileBackoff%time.Microsecond != 0 {
		problems = append(problems, errors.New(
			"reconciliation backoff must be whole microseconds between one millisecond and one hour",
		))
	}
	if config.MaxAttempts < 2 || config.MaxAttempts > 100 {
		problems = append(problems, errors.New("maximum Operation attempts must be between 2 and 100"))
	}
	if config.Clock == nil {
		problems = append(problems, errors.New("worker clock is required"))
	}
	if err := errors.Join(problems...); err != nil {
		return nil, err
	}
	return &Worker{
		queue: queue, placement: placement, repository: repository,
		executor: executor, config: config,
	}, nil
}

// ProcessNext claims and advances at most one durable Operation. It may finish
// a successful effect in one lease, but every external-effect boundary is
// recoverable from persisted command intent and observation.
func (worker *Worker) ProcessNext(
	ctx context.Context,
	workerID string,
) (bool, error) {
	if worker == nil || worker.queue == nil {
		return false, errors.New("Deployment worker is nil")
	}
	if ctx == nil {
		return false, errors.New("Deployment worker context is nil")
	}
	lease, found, err := worker.queue.ClaimNext(ctx, workerID)
	if err != nil || !found {
		return found, err
	}
	return true, worker.processLease(ctx, lease)
}

func (worker *Worker) processLease(
	ctx context.Context,
	lease operationqueue.Lease,
) error {
	safeToExecute := false
	for step := 0; step < maximumWorkerSteps; step++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch lease.Operation.State {
		case paasv1.OperationAccepted:
			next, err := worker.queue.Advance(ctx, operationqueue.Transition{
				Lease: lease, State: paasv1.OperationPlanning,
			})
			if err != nil {
				return err
			}
			lease = next

		case paasv1.OperationPlanning:
			state, err := worker.repository.Load(ctx, lease.Guard())
			if err != nil {
				return err
			}
			placementResult, err := worker.ensurePlacement(ctx, lease, state)
			if err != nil {
				return err
			}
			if placementResult.Decision.Outcome == paasv1.PlacementUnschedulable {
				if placementResult.Decision.Reason == nil {
					return errors.New("unschedulable placement has no normalized Problem")
				}
				_, _, err = worker.repository.FinalizeTerminal(
					ctx,
					lease,
					Terminal{State: paasv1.OperationFailed, Problem: placementResult.Decision.Reason},
				)
				return err
			}
			phase := paasv1.DeploymentPlacing
			if lease.Operation.Action == paasv1.OperationStop {
				phase = paasv1.DeploymentStopping
			}
			if _, err := worker.repository.UpdatePhase(ctx, lease.Guard(), phase); err != nil {
				return err
			}
			next, err := worker.queue.Advance(ctx, operationqueue.Transition{
				Lease: lease, State: paasv1.OperationQueued,
			})
			if err != nil {
				return err
			}
			lease = next

		case paasv1.OperationQueued:
			action, err := effectAction(lease.Operation.Action)
			if err != nil {
				return err
			}
			deadline, err := worker.effectDeadline(lease)
			if err != nil {
				return err
			}
			if _, _, err := worker.repository.PrepareEffect(
				ctx, lease, action, worker.config.BindingRef, deadline,
			); err != nil {
				return err
			}
			if lease.Operation.Action != paasv1.OperationStop {
				if _, err := worker.repository.UpdatePhase(
					ctx, lease.Guard(), paasv1.DeploymentApplying,
				); err != nil {
					return err
				}
			}
			next, err := worker.queue.Advance(ctx, operationqueue.Transition{
				Lease: lease, State: paasv1.OperationExecuting,
			})
			if err != nil {
				return err
			}
			lease = next
			safeToExecute = true

		case paasv1.OperationExecuting:
			state, err := worker.repository.Load(ctx, lease.Guard())
			if err != nil {
				return err
			}
			if state.Receipt != nil &&
				!(safeToExecute &&
					(state.Receipt.State == paasv1.AdapterResultUnknown ||
						state.Receipt.State == paasv1.AdapterResultInProgress)) {
				next, done, err := worker.resumeReceipt(ctx, lease, *state.Receipt)
				if err != nil || done {
					return err
				}
				lease = next
				safeToExecute = false
				continue
			}
			if state.EffectRequest == nil {
				return errors.New("executing Operation has no persisted effect command")
			}
			if !safeToExecute {
				next, err := worker.queue.Advance(ctx, operationqueue.Transition{
					Lease: lease, State: paasv1.OperationReconciling,
				})
				if err != nil {
					return err
				}
				lease = next
				continue
			}
			result := worker.invokeEffect(ctx, lease.Operation.Action, *state.EffectRequest)
			if _, err := worker.repository.RecordResult(
				ctx,
				lease.Guard(),
				state.EffectRequest.Command.RequestDigest,
				result,
			); err != nil {
				return err
			}
			next, done, err := worker.acceptResult(ctx, lease, result)
			if err != nil || done {
				return err
			}
			lease = next
			safeToExecute = false

		case paasv1.OperationVerifying:
			done, next, err := worker.observe(ctx, lease, false)
			if err != nil || done {
				return err
			}
			lease = next

		case paasv1.OperationReconciling:
			if lease.Operation.Attempt >= worker.config.MaxAttempts {
				problem := manualProblem(traceID(lease.Operation.ID))
				_, _, err := worker.repository.FinalizeTerminal(ctx, lease, Terminal{
					State: paasv1.OperationManualIntervention, Problem: &problem,
				})
				return err
			}
			done, next, retryEffect, err := worker.reconcile(ctx, lease)
			if err != nil || done {
				return err
			}
			lease = next
			safeToExecute = retryEffect

		default:
			return fmt.Errorf("claimed Operation has unsupported state %q", lease.Operation.State)
		}
	}
	return errors.New("Deployment worker exceeded its bounded internal step count")
}

func (worker *Worker) ensurePlacement(
	ctx context.Context,
	lease operationqueue.Lease,
	state State,
) (createplacement.Result, error) {
	if state.Placement != nil {
		return createplacement.Result{Decision: *state.Placement, Replayed: true}, nil
	}
	command, err := placementCommand(lease.Operation, state.Generation)
	if err != nil {
		return createplacement.Result{}, err
	}
	if lease.Operation.Action == paasv1.OperationStop {
		return worker.placement.BindStopPlacement(ctx, command, lease.Guard())
	}
	return worker.placement.CreatePlacement(ctx, command, lease.Guard())
}

func placementCommand(
	operation paasv1.Operation,
	generation paasv1.DeploymentGeneration,
) (createplacement.Command, error) {
	encoded, err := json.Marshal(placementIdentity{
		Version: "deployment-placement-v1", OperationDigest: operation.RequestDigest,
		DeploymentID: generation.DeploymentID, Generation: generation.Generation,
		ContentDigest: generation.ContentDigest, Action: operation.Action,
	})
	if err != nil {
		return createplacement.Command{}, fmt.Errorf("encode placement command identity: %w", err)
	}
	digest := sha256.Sum256([]byte(operation.ID))
	return createplacement.Command{
		TenantID: operation.Scope.TenantID, OperationID: operation.ID,
		DecisionID:    paasv1.ResourceID("placement-" + hex.EncodeToString(digest[:10])),
		DeploymentID:  generation.DeploymentID,
		RequestDigest: domain.DigestPayload(encoded), TraceID: traceID(operation.ID),
	}, nil
}

func (worker *Worker) resumeReceipt(
	ctx context.Context,
	lease operationqueue.Lease,
	receipt StoredReceipt,
) (operationqueue.Lease, bool, error) {
	switch receipt.State {
	case paasv1.AdapterResultSucceeded:
		next, err := worker.queue.Advance(ctx, operationqueue.Transition{
			Lease: lease, State: paasv1.OperationVerifying,
		})
		return next, false, err
	case paasv1.AdapterResultFailed:
		problem := problemFromNormalized(receipt.Error, traceID(lease.Operation.ID))
		_, _, err := worker.repository.FinalizeTerminal(ctx, lease, Terminal{
			State: paasv1.OperationFailed, Problem: &problem, ReleasePending: true,
		})
		return operationqueue.Lease{}, true, err
	case paasv1.AdapterResultUnknown, paasv1.AdapterResultInProgress:
		nextAttempt := worker.nextAttempt(lease)
		next, err := worker.queue.Advance(ctx, operationqueue.Transition{
			Lease: lease, State: paasv1.OperationReconciling,
			NextAttemptAt: &nextAttempt, ReleaseLease: true,
		})
		return next, true, err
	default:
		return operationqueue.Lease{}, true, errors.New("stored adapter receipt state is invalid")
	}
}

func (worker *Worker) acceptResult(
	ctx context.Context,
	lease operationqueue.Lease,
	result paasv1.AdapterResult,
) (operationqueue.Lease, bool, error) {
	switch result.State {
	case paasv1.AdapterResultSucceeded:
		next, err := worker.queue.Advance(ctx, operationqueue.Transition{
			Lease: lease, State: paasv1.OperationVerifying,
		})
		return next, false, err
	case paasv1.AdapterResultFailed:
		problem := problemFromNormalized(result.Error, traceID(lease.Operation.ID))
		_, _, err := worker.repository.FinalizeTerminal(ctx, lease, Terminal{
			State: paasv1.OperationFailed, Problem: &problem, ReleasePending: true,
		})
		return operationqueue.Lease{}, true, err
	case paasv1.AdapterResultUnknown, paasv1.AdapterResultInProgress:
		nextAttempt := worker.nextAttempt(lease)
		next, err := worker.queue.Advance(ctx, operationqueue.Transition{
			Lease: lease, State: paasv1.OperationReconciling,
			NextAttemptAt: &nextAttempt, ReleaseLease: true,
		})
		return next, true, err
	default:
		return operationqueue.Lease{}, true, errors.New("adapter result state is invalid")
	}
}

func (worker *Worker) observe(
	ctx context.Context,
	lease operationqueue.Lease,
	reconciling bool,
) (bool, operationqueue.Lease, error) {
	if resumed, next, err := worker.resumeStoredObservation(
		ctx,
		lease,
		reconciling,
	); err != nil || resumed {
		return true, next, err
	}
	deadline, err := worker.effectDeadline(lease)
	if err != nil {
		return true, operationqueue.Lease{}, err
	}
	request, _, err := worker.repository.PrepareObservation(
		ctx, lease, worker.config.BindingRef, deadline,
	)
	if err != nil {
		return true, operationqueue.Lease{}, err
	}
	observeContext, cancel := context.WithDeadline(ctx, request.Command.Deadline)
	observation, err := worker.executor.ObserveDeployment(observeContext, request)
	cancel()
	if err != nil {
		nextAttempt := worker.nextAttempt(lease)
		next, advanceErr := worker.queue.Advance(ctx, operationqueue.Transition{
			Lease: lease, State: paasv1.OperationReconciling,
			NextAttemptAt: &nextAttempt, ReleaseLease: true,
		})
		if advanceErr != nil {
			return true, operationqueue.Lease{}, advanceErr
		}
		return true, next, nil
	}
	if err := validateObservation(request, observation); err != nil {
		nextAttempt := worker.nextAttempt(lease)
		next, advanceErr := worker.queue.Advance(ctx, operationqueue.Transition{
			Lease: lease, State: paasv1.OperationReconciling,
			NextAttemptAt: &nextAttempt, ReleaseLease: true,
		})
		if advanceErr != nil {
			return true, operationqueue.Lease{}, advanceErr
		}
		return true, next, nil
	}
	if _, err := worker.repository.RecordObservation(
		ctx, lease.Guard(), request.Command.CommandID, observation,
	); err != nil {
		return true, operationqueue.Lease{}, err
	}
	if observationComplete(lease.Operation.Action, request, observation) {
		if reconciling {
			next, err := worker.queue.Advance(ctx, operationqueue.Transition{
				Lease: lease, State: paasv1.OperationVerifying,
			})
			if err != nil {
				return true, operationqueue.Lease{}, err
			}
			lease = next
		}
		_, _, err := worker.repository.FinalizeSuccess(ctx, lease, observation)
		return true, operationqueue.Lease{}, err
	}
	nextAttempt := worker.nextAttempt(lease)
	next, err := worker.queue.Advance(ctx, operationqueue.Transition{
		Lease: lease, State: paasv1.OperationReconciling,
		NextAttemptAt: &nextAttempt, ReleaseLease: true,
	})
	return true, next, err
}

func (worker *Worker) reconcile(
	ctx context.Context,
	lease operationqueue.Lease,
) (bool, operationqueue.Lease, bool, error) {
	if resumed, next, err := worker.resumeStoredObservation(
		ctx,
		lease,
		true,
	); err != nil || resumed {
		return true, next, false, err
	}
	deadline, err := worker.effectDeadline(lease)
	if err != nil {
		return true, operationqueue.Lease{}, false, err
	}
	request, _, err := worker.repository.PrepareObservation(
		ctx, lease, worker.config.BindingRef, deadline,
	)
	if err != nil {
		return true, operationqueue.Lease{}, false, err
	}
	observeContext, cancel := context.WithDeadline(ctx, request.Command.Deadline)
	observation, observeErr := worker.executor.ObserveDeployment(observeContext, request)
	cancel()
	if observeErr != nil {
		if isNotFound(observeErr) {
			if lease.Operation.Action == paasv1.OperationStop {
				observation = stoppedObservation(request, worker.now())
			} else {
				return worker.retryEffect(ctx, lease)
			}
		} else {
			next, err := worker.queue.Release(ctx, lease, worker.nextAttempt(lease))
			return true, next, false, err
		}
	}
	if err := validateObservation(request, observation); err != nil {
		next, releaseErr := worker.queue.Release(ctx, lease, worker.nextAttempt(lease))
		return true, next, false, releaseErr
	}
	if _, err := worker.repository.RecordObservation(
		ctx, lease.Guard(), request.Command.CommandID, observation,
	); err != nil {
		return true, operationqueue.Lease{}, false, err
	}
	if observationComplete(lease.Operation.Action, request, observation) {
		next, err := worker.queue.Advance(ctx, operationqueue.Transition{
			Lease: lease, State: paasv1.OperationVerifying,
		})
		if err != nil {
			return true, operationqueue.Lease{}, false, err
		}
		_, _, err = worker.repository.FinalizeSuccess(ctx, next, observation)
		return true, operationqueue.Lease{}, false, err
	}
	if shouldRetryEffect(lease.Operation.Action, observation) {
		return worker.retryEffect(ctx, lease)
	}
	next, err := worker.queue.Release(ctx, lease, worker.nextAttempt(lease))
	return true, next, false, err
}

func (worker *Worker) retryEffect(
	ctx context.Context,
	lease operationqueue.Lease,
) (bool, operationqueue.Lease, bool, error) {
	next, err := worker.queue.Advance(ctx, operationqueue.Transition{
		Lease: lease, State: paasv1.OperationExecuting,
	})
	if err != nil {
		return true, operationqueue.Lease{}, false, err
	}
	action, err := effectAction(next.Operation.Action)
	if err != nil {
		return true, operationqueue.Lease{}, false, err
	}
	deadline, err := worker.effectDeadline(next)
	if err != nil {
		return true, operationqueue.Lease{}, false, err
	}
	if _, _, err := worker.repository.PrepareEffect(
		ctx, next, action, worker.config.BindingRef, deadline,
	); err != nil {
		return true, operationqueue.Lease{}, false, err
	}
	return false, next, true, nil
}

func (worker *Worker) invokeEffect(
	ctx context.Context,
	action paasv1.OperationAction,
	request paasv1.DeploymentExecutionRequest,
) paasv1.AdapterResult {
	effectContext, cancel := context.WithDeadline(ctx, request.Command.Deadline)
	defer cancel()
	var result paasv1.AdapterResult
	var err error
	switch action {
	case paasv1.OperationDeploy, paasv1.OperationUpdate:
		result, err = worker.executor.ApplyDeployment(effectContext, request)
	case paasv1.OperationRollback:
		result, err = worker.executor.RollbackDeployment(effectContext, request)
	case paasv1.OperationStop:
		result, err = worker.executor.StopDeployment(effectContext, request)
	default:
		err = errors.New("unsupported Deployment effect")
	}
	if err != nil {
		return normalizedFailure(request.Command.CommandID, err, worker.now())
	}
	if result.CommandID != request.Command.CommandID || paasv1.ValidateAdapterResult(result) != nil {
		return unknownResult(
			request.Command.CommandID,
			"Deployment executor returned an invalid normalized result.",
			worker.now(),
		)
	}
	return result
}

func (worker *Worker) resumeStoredObservation(
	ctx context.Context,
	lease operationqueue.Lease,
	reconciling bool,
) (bool, operationqueue.Lease, error) {
	state, err := worker.repository.Load(ctx, lease.Guard())
	if err != nil {
		return false, operationqueue.Lease{}, err
	}
	if state.Observation == nil ||
		state.ObserveRequest == nil ||
		!observationComplete(
			lease.Operation.Action,
			*state.ObserveRequest,
			*state.Observation,
		) {
		return false, lease, nil
	}
	if reconciling {
		next, err := worker.queue.Advance(ctx, operationqueue.Transition{
			Lease: lease, State: paasv1.OperationVerifying,
		})
		if err != nil {
			return true, operationqueue.Lease{}, err
		}
		lease = next
	}
	_, _, err = worker.repository.FinalizeSuccess(ctx, lease, *state.Observation)
	return true, operationqueue.Lease{}, err
}

func normalizedFailure(
	commandID paasv1.CommandID,
	err error,
	observedAt time.Time,
) paasv1.AdapterResult {
	var fault paasv1.AdapterFault
	if errors.As(err, &fault) && paasv1.ValidateNormalizedAdapterError(fault.Normalized) == nil {
		state := paasv1.AdapterResultFailed
		if fault.Normalized.Class == paasv1.AdapterErrorUnknownOutcome {
			state = paasv1.AdapterResultUnknown
		}
		normalized := fault.Normalized
		return paasv1.AdapterResult{
			CommandID: commandID, State: state, Error: &normalized,
			ObservedAt: observedAt,
		}
	}
	return unknownResult(
		commandID,
		"Deployment executor returned an unclassified failure.",
		observedAt,
	)
}

func unknownResult(
	commandID paasv1.CommandID,
	message string,
	observedAt time.Time,
) paasv1.AdapterResult {
	normalized := paasv1.NormalizedAdapterError{
		Class: paasv1.AdapterErrorUnknownOutcome, Code: paasv1.ErrorAdapterOutcomeUnknown,
		Message: message, Retryable: true,
	}
	return paasv1.AdapterResult{
		CommandID: commandID, State: paasv1.AdapterResultUnknown,
		Error: &normalized, ObservedAt: observedAt,
	}
}

func effectAction(action paasv1.OperationAction) (paasv1.AdapterAction, error) {
	switch action {
	case paasv1.OperationDeploy, paasv1.OperationUpdate:
		return paasv1.AdapterApplyDeployment, nil
	case paasv1.OperationRollback:
		return paasv1.AdapterRollbackDeployment, nil
	case paasv1.OperationStop:
		return paasv1.AdapterStopDeployment, nil
	default:
		return "", fmt.Errorf("Operation action %q has no Deployment effect", action)
	}
}

func validateObservation(
	request paasv1.ObserveDeploymentRequest,
	observation paasv1.DeploymentObservation,
) error {
	if err := paasv1.ValidateDeploymentObservation(observation); err != nil {
		return err
	}
	if observation.DeploymentID != request.Command.DeploymentID ||
		observation.Generation != request.Generation ||
		observation.ApplicationRevisionID != request.Command.ApplicationRevisionID {
		return errors.New("Deployment observation does not match exact request identity")
	}
	return nil
}

func observationComplete(
	action paasv1.OperationAction,
	request paasv1.ObserveDeploymentRequest,
	observation paasv1.DeploymentObservation,
) bool {
	if action == paasv1.OperationStop {
		return observation.Phase == paasv1.DeploymentStopped &&
			observation.ReadyComponents == 0
	}
	return observation.Phase == paasv1.DeploymentReady &&
		observation.Generation == request.Generation
}

func shouldRetryEffect(
	action paasv1.OperationAction,
	observation paasv1.DeploymentObservation,
) bool {
	if action == paasv1.OperationStop {
		return observation.Phase != paasv1.DeploymentStopped
	}
	return observation.Phase == paasv1.DeploymentFailed ||
		observation.Phase == paasv1.DeploymentStopped
}

func stoppedObservation(
	request paasv1.ObserveDeploymentRequest,
	observedAt time.Time,
) paasv1.DeploymentObservation {
	return paasv1.DeploymentObservation{
		DeploymentID: request.Command.DeploymentID, Generation: request.Generation,
		ApplicationRevisionID: request.Command.ApplicationRevisionID,
		Phase:                 paasv1.DeploymentStopped, ReadyComponents: 0,
		ReceiptDigest: domain.DigestPayload([]byte(
			"stop-observed-absent:" + request.Command.RequestDigest,
		)),
		ObservedAt: observedAt,
	}
}

func isNotFound(err error) bool {
	var fault paasv1.AdapterFault
	return errors.As(err, &fault) &&
		fault.Normalized.Class == paasv1.AdapterErrorNotFound
}

func problemFromNormalized(
	normalized *paasv1.NormalizedAdapterError,
	trace string,
) paasv1.Problem {
	if normalized == nil || paasv1.ValidateNormalizedAdapterError(*normalized) != nil {
		return paasv1.Problem{
			Type: "/problems/operation-failed", Title: "Deployment operation failed",
			Status: 500, Code: paasv1.ErrorOperationFailed,
			Detail:  "The deployment executor returned an invalid failure.",
			TraceID: trace, Retryable: false,
		}
	}
	status := 500
	switch normalized.Class {
	case paasv1.AdapterErrorValidation:
		status = 422
	case paasv1.AdapterErrorConflict:
		status = 409
	case paasv1.AdapterErrorPermissionDenied:
		status = 403
	case paasv1.AdapterErrorRateLimited:
		status = 429
	case paasv1.AdapterErrorTimeout:
		status = 504
	case paasv1.AdapterErrorTransient, paasv1.AdapterErrorUnavailable:
		status = 503
	}
	return paasv1.Problem{
		Type: "/problems/deployment-execution", Title: "Deployment execution failed",
		Status: status, Code: normalized.Code, Detail: normalized.Message,
		TraceID: trace, Retryable: normalized.Retryable,
	}
}

func manualProblem(trace string) paasv1.Problem {
	return paasv1.Problem{
		Type: "/problems/manual-intervention", Title: "Manual intervention is required",
		Status: 500, Code: paasv1.ErrorManualIntervention,
		Detail:  "The deployment effect remained uncertain after the bounded reconciliation attempts.",
		TraceID: trace, Retryable: false,
	}
}

func traceID(operationID paasv1.OperationID) string {
	digest := sha256.Sum256([]byte(operationID))
	return "trace-" + hex.EncodeToString(digest[:10])
}

func (worker *Worker) now() time.Time {
	return worker.config.Clock().UTC().Truncate(time.Microsecond)
}

func (worker *Worker) effectDeadline(lease operationqueue.Lease) (time.Time, error) {
	now := worker.now()
	deadline := now.Add(worker.config.EffectTimeout)
	leaseLimit := lease.LeaseExpiresAt.Add(-time.Microsecond)
	if deadline.After(leaseLimit) {
		deadline = leaseLimit
	}
	if !deadline.After(now) {
		return time.Time{}, operationqueue.ErrStaleLease
	}
	return deadline, nil
}

func (worker *Worker) nextAttempt(lease operationqueue.Lease) time.Time {
	base := worker.now()
	if lease.Operation.UpdatedAt.After(base) {
		base = lease.Operation.UpdatedAt
	}
	return base.Add(worker.config.ReconcileBackoff).UTC().Truncate(time.Microsecond)
}
