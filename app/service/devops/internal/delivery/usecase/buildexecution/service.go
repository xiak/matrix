package buildexecution

import (
	"context"
	"errors"
	"fmt"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

type Service struct {
	repository      Repository
	archives        ArchiveReader
	executor        port.BuildExecutor
	logs            port.BuildLogSource
	config          Config
	renewalInterval time.Duration
}

type buildOperation func(context.Context) (devopsbuildv1.Receipt, bool, error)

func NewService(
	repository Repository,
	archives ArchiveReader,
	executor port.BuildExecutor,
	logs port.BuildLogSource,
	config Config,
) (*Service, error) {
	if repository == nil || archives == nil || executor == nil || logs == nil {
		return nil, errors.New("build execution boundaries are required")
	}
	if devopsv1.ValidateID("buildWorker.workerId", config.WorkerID) != nil ||
		config.LeaseDuration != LeaseDuration ||
		config.Deadline != ExecutionDeadline ||
		config.CancelGrace != CancellationGrace {
		return nil, errors.New("build execution configuration is invalid")
	}
	return &Service{
		repository:      repository,
		archives:        archives,
		executor:        executor,
		logs:            logs,
		config:          config,
		renewalInterval: HeartbeatInterval,
	}, nil
}

func (service *Service) Heartbeat(ctx context.Context) (time.Time, error) {
	if service == nil || service.repository == nil || ctx == nil {
		return time.Time{}, errors.New("build worker heartbeat is unavailable")
	}
	observedAt, err := service.repository.Heartbeat(ctx, service.config.WorkerID)
	if err != nil {
		return time.Time{}, err
	}
	if validateCanonicalTime("buildWorker.heartbeatAt", observedAt) != nil {
		return time.Time{}, errors.New("build worker heartbeat is invalid")
	}
	return observedAt, nil
}

func (service *Service) BuildOnce(ctx context.Context) (Result, error) {
	if service == nil || service.repository == nil || service.archives == nil ||
		service.executor == nil || service.logs == nil || ctx == nil {
		return Result{}, errors.New("build worker is unavailable")
	}
	command, found, err := service.repository.Claim(
		ctx,
		service.config.WorkerID,
		service.config.LeaseDuration,
	)
	if err != nil || !found {
		return Result{}, err
	}
	if err := ValidateCommand(command); err != nil {
		return Result{}, err
	}
	if command.Lease.WorkerID != service.config.WorkerID {
		return Result{}, errors.Join(
			ErrInvalidCommand,
			errors.New("command belongs to another build worker"),
		)
	}
	result := Result{Claimed: true, CommandID: command.Lease.Intent.CommandID}
	request, err := requestForCommand(command)
	if err != nil {
		return result, err
	}

	if command.Lease.Run.Status.CancellationRequestedAt != nil {
		if command.Lease.Mode == runlifecycle.ClaimExecute {
			return service.complete(ctx, result, Completion{
				Command: command,
				State:   devopsv1.PipelineRunCancelled,
				Reason:  devopsv1.PipelineRunReasonCancelled,
			})
		}
		return service.settleCancellation(ctx, result, command, request)
	}
	if !command.DeadlineAt.After(time.Now().UTC()) {
		if command.Lease.Mode == runlifecycle.ClaimExecute {
			return service.fail(
				ctx,
				result,
				command,
				devopsv1.PipelineRunReasonDeadlineExceeded,
				nil,
			)
		}
		return service.settleDeadline(ctx, result, command, request)
	}

	var operation buildOperation
	switch command.Lease.Mode {
	case runlifecycle.ClaimExecute:
		operation = func(effectContext context.Context) (devopsbuildv1.Receipt, bool, error) {
			archive, openErr := service.archives.Open(effectContext, command.Archive)
			if openErr != nil || archive == nil {
				if archive != nil {
					_ = archive.Close()
				}
				return devopsbuildv1.Receipt{}, false, ErrArchiveUnavailable
			}
			receipt, executeErr := service.executor.Execute(effectContext, request, archive)
			closeErr := archive.Close()
			retained := executeErr == nil
			if closeErr != nil {
				executeErr = errors.Join(executeErr, port.ErrBuildOutcomeUnknown)
			}
			return service.drainAfterOperation(
				effectContext, command, request, receipt, retained, executeErr,
			)
		}
	case runlifecycle.ClaimObserve:
		operation = func(effectContext context.Context) (devopsbuildv1.Receipt, bool, error) {
			receipt, retained, observeErr := service.executor.Observe(effectContext, request)
			return service.drainAfterOperation(
				effectContext, command, request, receipt, retained, observeErr,
			)
		}
	default:
		return result, ErrInvalidCommand
	}

	receipt, retained, timedOut, operationErr, coordinationErr :=
		service.performWithRenewal(ctx, command, command.DeadlineAt, operation)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if coordinationErr != nil || timedOut || uncertainBuildError(operationErr) {
		return result, ErrExecutionUncertain
	}
	if operationErr != nil || !retained {
		return service.fail(
			ctx,
			result,
			command,
			devopsv1.PipelineRunReasonExecutorUnavailable,
			nil,
		)
	}
	if err := devopsbuildv1.ValidateReceipt(request, receipt); err != nil {
		return service.fail(
			ctx,
			result,
			command,
			devopsv1.PipelineRunReasonExecutorUnavailable,
			nil,
		)
	}
	return service.completeReceipt(ctx, result, command, receipt)
}

func (service *Service) settleCancellation(
	ctx context.Context,
	result Result,
	command Command,
	request devopsbuildv1.Request,
) (Result, error) {
	receipt, retained, operationErr := service.cancelWithRenewal(ctx, command, request)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if uncertainBuildError(operationErr) {
		return result, ErrExecutionUncertain
	}
	if operationErr != nil && retained {
		return service.fail(
			ctx,
			result,
			command,
			devopsv1.PipelineRunReasonExecutorUnavailable,
			nil,
		)
	}
	if errors.Is(operationErr, port.ErrBuildConflict) {
		return service.fail(
			ctx,
			result,
			command,
			devopsv1.PipelineRunReasonExecutorUnavailable,
			nil,
		)
	}
	if operationErr != nil && !errors.Is(operationErr, port.ErrBuildUnavailable) {
		return result, ErrExecutionUncertain
	}
	if retained && devopsbuildv1.ValidateReceipt(request, receipt) != nil {
		return service.fail(
			ctx,
			result,
			command,
			devopsv1.PipelineRunReasonExecutorUnavailable,
			nil,
		)
	}
	var stored *devopsbuildv1.Receipt
	if retained {
		stored = &receipt
	}
	return service.complete(ctx, result, Completion{
		Command: command,
		State:   devopsv1.PipelineRunCancelled,
		Reason:  devopsv1.PipelineRunReasonCancelled,
		Receipt: stored,
	})
}

func (service *Service) settleDeadline(
	ctx context.Context,
	result Result,
	command Command,
	request devopsbuildv1.Request,
) (Result, error) {
	receipt, retained, operationErr := service.cancelWithRenewal(ctx, command, request)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if uncertainBuildError(operationErr) {
		return result, ErrExecutionUncertain
	}
	if operationErr != nil && retained {
		return service.fail(
			ctx,
			result,
			command,
			devopsv1.PipelineRunReasonExecutorUnavailable,
			nil,
		)
	}
	if errors.Is(operationErr, port.ErrBuildConflict) {
		return service.fail(
			ctx,
			result,
			command,
			devopsv1.PipelineRunReasonExecutorUnavailable,
			nil,
		)
	}
	if operationErr != nil &&
		!errors.Is(operationErr, port.ErrBuildUnavailable) &&
		!errors.Is(operationErr, port.ErrBuildConflict) {
		return result, ErrExecutionUncertain
	}
	if retained {
		if err := devopsbuildv1.ValidateReceipt(request, receipt); err != nil {
			return service.fail(
				ctx,
				result,
				command,
				devopsv1.PipelineRunReasonExecutorUnavailable,
				nil,
			)
		}
		if receipt.Conclusion == devopsbuildv1.ConclusionPassed ||
			receipt.Conclusion == devopsbuildv1.ConclusionFailed {
			return service.completeReceipt(ctx, result, command, receipt)
		}
	}
	return service.fail(
		ctx,
		result,
		command,
		devopsv1.PipelineRunReasonDeadlineExceeded,
		optionalReceipt(receipt, retained),
	)
}

func (service *Service) cancelWithRenewal(
	ctx context.Context,
	command Command,
	request devopsbuildv1.Request,
) (devopsbuildv1.Receipt, bool, error) {
	deadline := time.Now().UTC().Add(service.config.CancelGrace)
	receipt, retained, timedOut, operationErr, coordinationErr :=
		service.performWithRenewal(
			ctx,
			command,
			deadline,
			func(effectContext context.Context) (devopsbuildv1.Receipt, bool, error) {
				receipt, retained, cancelErr := service.executor.Cancel(effectContext, request)
				return service.drainAfterOperation(
					effectContext, command, request, receipt, retained, cancelErr,
				)
			},
		)
	if coordinationErr != nil || timedOut {
		return devopsbuildv1.Receipt{}, false, ErrExecutionUncertain
	}
	return receipt, retained, operationErr
}

func (service *Service) drainAfterOperation(
	ctx context.Context,
	command Command,
	request devopsbuildv1.Request,
	receipt devopsbuildv1.Receipt,
	retained bool,
	operationErr error,
) (devopsbuildv1.Receipt, bool, error) {
	if !retained && (errors.Is(operationErr, port.ErrBuildUnavailable) ||
		errors.Is(operationErr, port.ErrBuildConflict) ||
		errors.Is(operationErr, ErrArchiveUnavailable)) {
		return receipt, retained, operationErr
	}
	if err := service.drainLogs(ctx, command, request); err != nil {
		return receipt, retained, ErrExecutionUncertain
	}
	return receipt, retained, operationErr
}

func (service *Service) drainLogs(
	ctx context.Context,
	command Command,
	request devopsbuildv1.Request,
) error {
	progress := devopsbuildv1.LogProgress{}
	var previousStep uint32
	for count := 0; ; count++ {
		batch, found, err := service.logs.ReadLogs(
			ctx, request, progress.LastSequence,
		)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		if count >= len(request.Steps) ||
			devopsbuildv1.ValidateLogBatch(request, batch) != nil ||
			batch.Previous != progress || batch.Step.Ordinal <= previousStep ||
			ValidateLogAppend(command, batch) != nil {
			return ErrInvalidLogs
		}
		if err := service.repository.AppendLogs(ctx, command, batch); err != nil {
			return err
		}
		progress = batch.Next
		previousStep = batch.Step.Ordinal
	}
}

func (service *Service) completeReceipt(
	ctx context.Context,
	result Result,
	command Command,
	receipt devopsbuildv1.Receipt,
) (Result, error) {
	switch receipt.Conclusion {
	case devopsbuildv1.ConclusionPassed, devopsbuildv1.ConclusionFailed:
		return service.complete(ctx, result, Completion{
			Command: command,
			State:   devopsv1.PipelineRunReporting,
			Receipt: &receipt,
		})
	case devopsbuildv1.ConclusionCancelled:
		return service.fail(
			ctx,
			result,
			command,
			devopsv1.PipelineRunReasonExecutorUnavailable,
			&receipt,
		)
	default:
		return service.fail(
			ctx,
			result,
			command,
			devopsv1.PipelineRunReasonExecutorUnavailable,
			nil,
		)
	}
}

func (service *Service) performWithRenewal(
	ctx context.Context,
	command Command,
	deadline time.Time,
	operation buildOperation,
) (devopsbuildv1.Receipt, bool, bool, error, error) {
	effectContext, cancel := context.WithDeadline(ctx, deadline)
	renewalDone := make(chan error, 1)
	go service.renewUntilDone(effectContext, command.Lease, renewalDone, cancel)
	receipt, retained, operationErr := operation(effectContext)
	timedOut := errors.Is(effectContext.Err(), context.DeadlineExceeded) ||
		errors.Is(operationErr, context.DeadlineExceeded)
	cancel()
	renewalErr := <-renewalDone
	return receipt, retained, timedOut, operationErr, renewalErr
}

func (service *Service) renewUntilDone(
	ctx context.Context,
	lease runlifecycle.Lease,
	done chan<- error,
	cancel context.CancelFunc,
) {
	ticker := time.NewTicker(service.renewalInterval)
	defer ticker.Stop()
	lastExpiry := lease.LeaseExpiresAt
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case <-ticker.C:
			expiresAt, err := service.repository.Renew(
				ctx,
				lease.Guard(),
				service.config.LeaseDuration,
			)
			if err == nil {
				err = validateCanonicalTime("buildWorker.leaseExpiresAt", expiresAt)
			}
			if err == nil && !expiresAt.After(lastExpiry) {
				err = errors.New("build execution lease did not advance")
			}
			if err != nil {
				cancel()
				done <- fmt.Errorf("renew build execution lease: %w", err)
				return
			}
			lastExpiry = expiresAt
		}
	}
}

func (service *Service) fail(
	ctx context.Context,
	result Result,
	command Command,
	reason devopsv1.PipelineRunReason,
	receipt *devopsbuildv1.Receipt,
) (Result, error) {
	return service.complete(ctx, result, Completion{
		Command: command,
		State:   devopsv1.PipelineRunFailed,
		Reason:  reason,
		Receipt: receipt,
	})
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
		completion.Command.Lease.Run,
		updated,
		completion.State,
		completion.Reason,
	); err != nil {
		return result, err
	}
	result.Run = updated
	return result, nil
}

func (service *Service) Readiness(ctx context.Context) (devopsv1.Readiness, error) {
	if service == nil || service.repository == nil || ctx == nil {
		return devopsv1.Readiness{}, errors.New("build worker readiness is unavailable")
	}
	return service.repository.Readiness(ctx)
}

func uncertainBuildError(err error) bool {
	return err != nil &&
		!errors.Is(err, port.ErrBuildUnavailable) &&
		!errors.Is(err, port.ErrBuildConflict) &&
		!errors.Is(err, ErrArchiveUnavailable)
}

func optionalReceipt(
	receipt devopsbuildv1.Receipt,
	retained bool,
) *devopsbuildv1.Receipt {
	if !retained {
		return nil
	}
	return &receipt
}
