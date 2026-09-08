// Package runnerexecution owns the durable workflow of one dedicated runner.
package runnerexecution

import (
	"context"
	"errors"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

type Service struct {
	gateway         port.RunnerGateway
	journal         port.RunnerJournal
	workspaces      port.RunnerWorkspaceStore
	sandbox         port.RunnerSandbox
	logs            port.RunnerLogPublisher
	now             func() time.Time
	renewalInterval time.Duration
	cancelGrace     time.Duration
	cleanupTimeout  time.Duration
}

func NewService(
	gateway port.RunnerGateway,
	journal port.RunnerJournal,
	workspaces port.RunnerWorkspaceStore,
	sandbox port.RunnerSandbox,
	logs port.RunnerLogPublisher,
) (*Service, error) {
	if gateway == nil || journal == nil || workspaces == nil || sandbox == nil || logs == nil ||
		gateway.RunnerID() == "" || gateway.RunnerID() != journal.RunnerID() ||
		devopsv1.ValidateID("runner.id", gateway.RunnerID()) != nil {
		return nil, ErrInvalid
	}
	return &Service{
		gateway: gateway, journal: journal, workspaces: workspaces,
		sandbox: sandbox, logs: logs,
		now: func() time.Time {
			return time.Now().UTC().Truncate(time.Microsecond)
		},
		renewalInterval: RenewalInterval,
		cancelGrace:     CancellationGrace,
		cleanupTimeout:  CleanupTimeout,
	}, nil
}

// WorkOnce first replays locally terminal receipts, then durably receives at
// most one current assignment. No sandbox effect can precede claim commit.
func (service *Service) WorkOnce(ctx context.Context) (Result, error) {
	if service == nil || ctx == nil || service.gateway == nil || service.journal == nil ||
		service.workspaces == nil || service.sandbox == nil || service.logs == nil {
		return Result{}, ErrInvalid
	}
	recoveryErr := service.replayTerminalReceipts(ctx)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	claim, err := service.journal.BeginClaim(ctx)
	if err != nil || claim == nil {
		return Result{}, errors.Join(ErrUnavailable, recoveryErr, err)
	}
	abort := true
	defer func() {
		if abort {
			_ = claim.Abort()
		}
	}()
	assignment, found, err := service.gateway.Claim(ctx, claim.Destination)
	if err != nil {
		return Result{}, errors.Join(ErrOutcomeUnknown, recoveryErr, err)
	}
	if !found {
		abortErr := claim.Abort()
		abort = false
		return Result{}, errors.Join(recoveryErr, abortErr)
	}
	entry, err := claim.Commit(ctx)
	if err != nil {
		return Result{Claimed: true, ExecutionID: assignment.ExecutionID},
			errors.Join(ErrOutcomeUnknown, recoveryErr, err)
	}
	abort = false
	result := Result{Claimed: true, ExecutionID: assignment.ExecutionID}
	if assignment != entry.Assignment || validateEntry(entry, service.gateway.RunnerID()) != nil {
		return result, errors.Join(ErrOutcomeUnknown, recoveryErr)
	}

	acknowledged, deferred, runErr := service.continueEntry(ctx, entry)
	result.Acknowledged = acknowledged
	result.Deferred = deferred
	return result, errors.Join(recoveryErr, runErr)
}

func (service *Service) replayTerminalReceipts(ctx context.Context) error {
	entries, err := service.journal.Entries(ctx)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	var replayErr error
	for _, entry := range entries {
		if err := validateEntry(entry, service.gateway.RunnerID()); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
		if entry.Phase != port.RunnerJournalTerminal {
			continue
		}
		if err := service.completeTerminal(ctx, entry); err != nil {
			replayErr = errors.Join(replayErr, err)
		}
	}
	return replayErr
}

func (service *Service) continueEntry(
	ctx context.Context,
	entry port.RunnerJournalEntry,
) (bool, bool, error) {
	switch entry.Phase {
	case port.RunnerJournalTerminal:
		if err := service.completeTerminal(ctx, entry); err != nil {
			return false, false, err
		}
		return true, false, nil
	case port.RunnerJournalAcknowledged:
		return false, false, ErrOutcomeUnknown
	case port.RunnerJournalReceived:
		if entry.CancellationRequested {
			cancelled, err := service.cancelPending(ctx, entry)
			if err != nil {
				return false, false, err
			}
			if err := service.recordAndComplete(ctx, cancelled); err != nil {
				return false, false, err
			}
			return true, false, nil
		}
		if entry.Assignment.Mode != devopsbuildv1.AssignmentExecute {
			// An OBSERVE fence cannot authorize a first effect. Let this lease
			// expire so a later CANCEL assignment can close it safely.
			return false, true, nil
		}
		startedAt := service.now()
		started, err := service.journal.MarkEffectStarted(
			ctx, entry.Assignment, startedAt,
		)
		if err != nil || validateEntry(started, service.gateway.RunnerID()) != nil {
			return false, false, errors.Join(ErrOutcomeUnknown, err)
		}
		entry = started
	case port.RunnerJournalEffectStarted:
	default:
		return false, false, ErrOutcomeUnknown
	}
	if err := service.execute(ctx, entry); err != nil {
		return false, false, err
	}
	return true, false, nil
}

func (service *Service) cancelPending(
	ctx context.Context,
	entry port.RunnerJournalEntry,
) (port.RunnerJournalEntry, error) {
	index, found := nextStep(entry)
	if !found || entry.Steps[index].Phase != port.RunnerStepPending ||
		!entry.CancellationRequested {
		return port.RunnerJournalEntry{}, ErrInvalid
	}
	return service.journal.RecordStepConclusion(
		ctx,
		entry.Assignment,
		entry.Assignment.Request.Steps[index],
		devopsbuildv1.StepConclusionCancelled,
		entry.LogProgress,
	)
}

func (service *Service) recordAndComplete(
	ctx context.Context,
	entry port.RunnerJournalEntry,
) error {
	if !terminalSteps(entry) {
		return ErrInvalid
	}
	receipt, err := receiptFor(entry, service.gateway.RunnerID())
	if err != nil {
		return err
	}
	terminal, err := service.journal.RecordReceipt(ctx, entry.Assignment, receipt)
	if err != nil || terminal.Phase != port.RunnerJournalTerminal ||
		terminal.Receipt == nil || *terminal.Receipt != receipt {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	return service.completeTerminal(ctx, terminal)
}

func (service *Service) completeTerminal(
	ctx context.Context,
	entry port.RunnerJournalEntry,
) error {
	if entry.Phase != port.RunnerJournalTerminal || entry.Receipt == nil {
		return ErrInvalid
	}
	if err := service.gateway.Complete(ctx, entry.Assignment, *entry.Receipt); err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	acknowledged, err := service.journal.Acknowledge(
		ctx, entry.Assignment, *entry.Receipt,
	)
	if err != nil || acknowledged.Phase != port.RunnerJournalAcknowledged ||
		acknowledged.Receipt == nil || *acknowledged.Receipt != *entry.Receipt {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	return nil
}

func (service *Service) publishAndConclude(
	ctx context.Context,
	session *leaseSession,
	step devopsv1.VerificationStep,
	result port.RunnerSandboxResult,
	conclusion devopsbuildv1.StepConclusion,
) error {
	return session.change(func(entry port.RunnerJournalEntry) (port.RunnerJournalEntry, error) {
		if runnerlog.ValidateBatch(entry.LogProgress, result.LogProgress, result.Chunks) != nil {
			return port.RunnerJournalEntry{}, ErrOutcomeUnknown
		}
		if len(result.Chunks) > 0 {
			if err := service.logs.Publish(
				ctx, entry.Assignment, step, result.Chunks,
			); err != nil {
				return port.RunnerJournalEntry{}, errors.Join(ErrOutcomeUnknown, err)
			}
		}
		next, err := service.journal.RecordStepConclusion(
			ctx, entry.Assignment, step, conclusion, result.LogProgress,
		)
		if err != nil || validateEntry(next, service.gateway.RunnerID()) != nil {
			return port.RunnerJournalEntry{}, errors.Join(ErrOutcomeUnknown, err)
		}
		return next, nil
	})
}
