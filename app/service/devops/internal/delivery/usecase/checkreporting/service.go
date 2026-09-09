package checkreporting

import (
	"context"
	"errors"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

type Service struct {
	repository Repository
	reporter   Reporter
	config     Config
}

func NewService(repository Repository, reporter Reporter, config Config) (*Service, error) {
	if repository == nil || reporter == nil ||
		devopsv1.ValidateID("checkReporter.workerId", config.WorkerID) != nil ||
		config.LeaseDuration != LeaseDuration || config.Deadline != ProviderDeadline ||
		config.RetryDelay != ReconciliationDelay || config.Now == nil {
		return nil, errors.New("check reporting configuration is invalid")
	}
	return &Service{repository: repository, reporter: reporter, config: config}, nil
}

func (service *Service) Heartbeat(ctx context.Context) (time.Time, error) {
	if service == nil || service.repository == nil || ctx == nil {
		return time.Time{}, errors.New("check reporter heartbeat is unavailable")
	}
	observedAt, err := service.repository.Heartbeat(ctx, service.config.WorkerID)
	if err != nil {
		return time.Time{}, err
	}
	if !canonicalTime(observedAt) {
		return time.Time{}, errors.New("check reporter heartbeat is invalid")
	}
	return observedAt, nil
}

func (service *Service) ReportOnce(ctx context.Context) (Result, error) {
	if service == nil || service.repository == nil || service.reporter == nil || ctx == nil {
		return Result{}, errors.New("check reporter is unavailable")
	}
	command, found, err := service.repository.Claim(
		ctx, service.config.WorkerID, service.config.LeaseDuration,
	)
	if err != nil || !found {
		return Result{}, err
	}
	if err := ValidateCommand(command); err != nil {
		return Result{}, err
	}
	if command.Lease.WorkerID != service.config.WorkerID {
		return Result{}, errors.Join(ErrInvalidCommand, errors.New("command belongs to another check reporter"))
	}
	result := Result{
		Claimed: true, CommandID: command.Lease.Intent.CommandID,
		Run:                    command.Lease.Run,
		ReconciliationAttempts: command.Lease.ReconciliationAttempts,
	}
	if command.Lease.Run.Status.CancellationRequestedAt != nil {
		return service.complete(ctx, result, Completion{
			Command: command, State: devopsv1.PipelineRunCancelled,
			Reason: devopsv1.PipelineRunReasonCancelled,
		})
	}
	if command.Lease.Run.Status.State == devopsv1.PipelineRunReconciling &&
		command.Lease.ReconciliationAttempts >= runlifecycle.MaximumReconciliationAttempts {
		return service.complete(ctx, result, Completion{
			Command: command, State: devopsv1.PipelineRunManualIntervention,
			Reason: devopsv1.PipelineRunReasonReconciliationExhausted,
		})
	}

	effectContext, cancel := context.WithTimeout(ctx, service.config.Deadline)
	defer cancel()
	var receipt Receipt
	var retained bool
	switch command.Lease.Mode {
	case runlifecycle.ClaimExecute:
		receipt, err = service.reporter.Create(effectContext, command)
		retained = err == nil
	case runlifecycle.ClaimObserve:
		receipt, retained, err = service.reporter.Observe(effectContext, command)
	default:
		return result, ErrInvalidCommand
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if errors.Is(err, ErrReportConflict) {
		return service.fail(ctx, result, command, devopsv1.PipelineRunReasonReportConflict)
	}
	if command.Lease.Mode == runlifecycle.ClaimExecute &&
		errors.Is(err, ErrReportUnavailable) {
		return service.fail(ctx, result, command, devopsv1.PipelineRunReasonReportUnavailable)
	}
	if err == nil && retained && ValidateReceipt(command, receipt) == nil {
		return service.completeReceipt(ctx, result, command, receipt)
	}
	return service.reconcile(ctx, result, command)
}

func (service *Service) completeReceipt(
	ctx context.Context,
	result Result,
	command Command,
	receipt Receipt,
) (Result, error) {
	completion := Completion{Command: command, Receipt: &receipt}
	switch command.BuildReceipt.Conclusion {
	case devopsbuildv1.ConclusionPassed:
		completion.State = devopsv1.PipelineRunSucceeded
		completion.Reason = devopsv1.PipelineRunReasonCompleted
	case devopsbuildv1.ConclusionFailed:
		completion.State = devopsv1.PipelineRunFailed
		completion.Reason = devopsv1.PipelineRunReasonVerificationFailed
	default:
		return result, ErrInvalidCommand
	}
	return service.complete(ctx, result, completion)
}

func (service *Service) fail(
	ctx context.Context,
	result Result,
	command Command,
	reason devopsv1.PipelineRunReason,
) (Result, error) {
	return service.complete(ctx, result, Completion{
		Command: command, State: devopsv1.PipelineRunFailed, Reason: reason,
	})
}

func (service *Service) reconcile(
	ctx context.Context,
	result Result,
	command Command,
) (Result, error) {
	now := service.config.Now().UTC().Truncate(time.Microsecond)
	if !canonicalTime(now) {
		return result, errors.New("check reporter clock is invalid")
	}
	next := now.Add(service.config.RetryDelay)
	if !next.After(command.Lease.Run.UpdatedAt) {
		next = command.Lease.Run.UpdatedAt.Add(service.config.RetryDelay)
	}
	reconciliation := runlifecycle.Reconciliation{
		Lease: command.Lease, NextAttemptAt: next,
	}
	if command.Lease.Run.Status.State == devopsv1.PipelineRunReporting {
		updated, err := service.repository.MarkUncertain(ctx, reconciliation)
		if err != nil {
			return result, err
		}
		if err := runlifecycle.ValidateReturnedTransition(
			command.Lease.Run, updated, devopsv1.PipelineRunReconciling,
			devopsv1.PipelineRunReasonExternalEffectUncertain,
		); err != nil {
			return result, err
		}
		result.Run = updated
		return result, nil
	}
	attempts, err := service.repository.Defer(ctx, reconciliation)
	if err != nil {
		return result, err
	}
	if attempts != command.Lease.ReconciliationAttempts+1 ||
		attempts > runlifecycle.MaximumReconciliationAttempts {
		return result, errors.New("check reporter reconciliation progress is invalid")
	}
	result.ReconciliationAttempts = attempts
	return result, nil
}

func (service *Service) complete(
	ctx context.Context,
	result Result,
	completion Completion,
) (Result, error) {
	if err := ValidateCompletion(completion); err != nil {
		return result, err
	}
	updated, err := service.repository.Complete(ctx, completion)
	if err != nil {
		return result, err
	}
	if err := runlifecycle.ValidateReturnedTransition(
		completion.Command.Lease.Run, updated, completion.State, completion.Reason,
	); err != nil {
		return result, err
	}
	result.Run = updated
	return result, nil
}

func (service *Service) Readiness(ctx context.Context) (devopsv1.Readiness, error) {
	if service == nil || service.repository == nil || ctx == nil {
		return devopsv1.Readiness{}, errors.New("check reporter readiness is unavailable")
	}
	return service.repository.Readiness(ctx)
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value == value.Round(0) &&
		value.Nanosecond()%1_000 == 0
}
