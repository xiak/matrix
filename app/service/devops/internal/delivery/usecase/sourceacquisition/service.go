package sourceacquisition

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

type Service struct {
	repository      Repository
	fetcher         SourceFetcher
	archiveStore    ArchiveStore
	config          Config
	renewalInterval time.Duration
}

func NewService(
	repository Repository,
	fetcher SourceFetcher,
	archiveStore ArchiveStore,
	config Config,
) (*Service, error) {
	if repository == nil || fetcher == nil || archiveStore == nil {
		return nil, errors.New("source acquisition boundaries are required")
	}
	if devopsv1.ValidateID("sourceFetcher.workerId", config.WorkerID) != nil ||
		config.LeaseDuration != LeaseDuration || config.Deadline != AcquisitionDeadline {
		return nil, errors.New("source acquisition configuration is invalid")
	}
	return &Service{
		repository: repository, fetcher: fetcher, archiveStore: archiveStore,
		config: config, renewalInterval: HeartbeatInterval,
	}, nil
}

func (service *Service) Heartbeat(ctx context.Context) (time.Time, error) {
	if service == nil || service.repository == nil || ctx == nil {
		return time.Time{}, errors.New("source fetcher heartbeat is unavailable")
	}
	observedAt, err := service.repository.Heartbeat(ctx, service.config.WorkerID)
	if err != nil {
		return time.Time{}, err
	}
	if validateCanonicalTime("sourceFetcher.heartbeatAt", observedAt) != nil {
		return time.Time{}, errors.New("source fetcher heartbeat is invalid")
	}
	return observedAt, nil
}

func (service *Service) FetchOnce(ctx context.Context) (Result, error) {
	if service == nil || service.repository == nil || service.fetcher == nil ||
		service.archiveStore == nil || ctx == nil {
		return Result{}, errors.New("source fetcher is unavailable")
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
		return Result{}, errors.Join(ErrInvalidCommand, errors.New("command belongs to another worker"))
	}
	result := Result{Claimed: true, CommandID: command.Lease.Intent.CommandID}
	if command.Lease.Run.Status.CancellationRequestedAt != nil {
		return service.complete(ctx, result, Completion{
			Command: command, State: devopsv1.PipelineRunCancelled,
			Reason: devopsv1.PipelineRunReasonCancelled,
		})
	}

	var operation func(context.Context) (SourceArchiveReceipt, bool, error)
	switch command.Lease.Mode {
	case runlifecycle.ClaimExecute:
		operation = func(effectContext context.Context) (SourceArchiveReceipt, bool, error) {
			receipt, publishErr := service.archiveStore.Publish(
				effectContext,
				command,
				func(destination io.Writer) (ArchiveContent, error) {
					return service.fetcher.Fetch(effectContext, command, destination)
				},
			)
			return receipt, publishErr == nil, publishErr
		}
	case runlifecycle.ClaimObserve:
		operation = func(effectContext context.Context) (SourceArchiveReceipt, bool, error) {
			return service.archiveStore.Observe(effectContext, command)
		}
	default:
		return Result{}, ErrInvalidCommand
	}

	receipt, published, timedOut, operationErr, coordinationErr := service.performWithRenewal(
		ctx, command, operation,
	)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if coordinationErr != nil {
		// Renewal and repository failures are coordination uncertainty. They
		// must leave the intent open for the next fence instead of inventing a
		// terminal provider result.
		return result, coordinationErr
	}
	if errors.Is(operationErr, ErrArchiveUncertain) {
		return result, operationErr
	}
	if timedOut {
		return service.fail(ctx, result, command, devopsv1.PipelineRunReasonDeadlineExceeded)
	}
	if operationErr != nil || !published {
		reason := devopsv1.PipelineRunReasonSourceUnavailable
		if errors.Is(operationErr, ErrCommitMismatch) {
			reason = devopsv1.PipelineRunReasonCommitMismatch
		}
		return service.fail(ctx, result, command, reason)
	}
	if err := ValidateReceipt(command, receipt); err != nil {
		return service.fail(ctx, result, command, devopsv1.PipelineRunReasonSourceUnavailable)
	}
	return service.complete(ctx, result, Completion{
		Command: command, State: devopsv1.PipelineRunVerifying, Receipt: &receipt,
	})
}

func (service *Service) performWithRenewal(
	ctx context.Context,
	command Command,
	operation func(context.Context) (SourceArchiveReceipt, bool, error),
) (SourceArchiveReceipt, bool, bool, error, error) {
	effectContext, cancel := context.WithTimeout(ctx, service.config.Deadline)
	renewalDone := make(chan error, 1)
	go service.renewUntilDone(effectContext, command.Lease, renewalDone, cancel)
	receipt, found, operationErr := operation(effectContext)
	timedOut := errors.Is(effectContext.Err(), context.DeadlineExceeded) ||
		errors.Is(operationErr, context.DeadlineExceeded)
	cancel()
	renewalErr := <-renewalDone
	if renewalErr != nil {
		return SourceArchiveReceipt{}, false, false, operationErr, renewalErr
	}
	if timedOut {
		return SourceArchiveReceipt{}, false, true, context.DeadlineExceeded, nil
	}
	return receipt, found, false, operationErr, nil
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
			expiresAt, err := service.repository.Renew(ctx, lease.Guard(), service.config.LeaseDuration)
			if err == nil {
				err = validateCanonicalTime("sourceFetcher.leaseExpiresAt", expiresAt)
			}
			if err == nil && !expiresAt.After(lastExpiry) {
				err = errors.New("source acquisition lease did not advance")
			}
			if err != nil {
				cancel()
				done <- fmt.Errorf("renew source acquisition lease: %w", err)
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
) (Result, error) {
	return service.complete(ctx, result, Completion{
		Command: command, State: devopsv1.PipelineRunFailed, Reason: reason,
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
	if err := validateReturnedRun(completion, updated); err != nil {
		return result, err
	}
	result.Run = updated
	return result, nil
}

func (service *Service) Readiness(ctx context.Context) (devopsv1.Readiness, error) {
	if service == nil || service.repository == nil || ctx == nil {
		return devopsv1.Readiness{}, errors.New("source fetcher readiness is unavailable")
	}
	return service.repository.Readiness(ctx)
}

func validateReturnedRun(completion Completion, updated devopsv1.PipelineRun) error {
	current := completion.Command.Lease.Run
	if devopsv1.ValidatePipelineRun(updated) != nil ||
		updated.ID != current.ID || updated.Scope != current.Scope ||
		updated.ProjectID != current.ProjectID || updated.PipelineID != current.PipelineID ||
		updated.Input != current.Input || updated.InputDigest != current.InputDigest ||
		!equalReplay(updated.Replay, current.Replay) || updated.CreatedAt != current.CreatedAt ||
		!equalTimePointer(
			updated.Status.CancellationRequestedAt,
			current.Status.CancellationRequestedAt,
		) ||
		updated.Status.State != completion.State || updated.Status.Reason != completion.Reason ||
		updated.Status.ResourceVersion != current.Status.ResourceVersion+1 ||
		!updated.UpdatedAt.After(current.UpdatedAt) {
		return errors.New("repository returned a mismatched source acquisition transition")
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
