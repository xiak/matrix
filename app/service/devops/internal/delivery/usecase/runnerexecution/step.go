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

type followOutcome struct {
	result port.RunnerSandboxResult
	err    error
}

func (service *Service) execute(
	ctx context.Context,
	entry port.RunnerJournalEntry,
) error {
	session, err := startLeaseSession(ctx, service, entry)
	if err != nil {
		return err
	}
	defer session.stop()

	archive, err := service.journal.OpenArchive(session.ctx, entry.Assignment.ExecutionID)
	if err != nil || archive == nil {
		if archive != nil {
			_ = archive.Close()
		}
		if failure := session.currentFailure(); failure != nil {
			return failure
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.Join(ErrUnavailable, err)
	}
	workspace, err := service.workspaces.Ensure(
		session.ctx, entry.Assignment.ExecutionID, entry.Assignment.Request, archive,
	)
	if err != nil || workspace.ExecutionID != entry.Assignment.ExecutionID ||
		workspace.SourceRoot == "" ||
		devopsv1.ValidateDigest("runner.workspace.treeDigest", workspace.TreeDigest) != nil {
		if failure := session.currentFailure(); failure != nil {
			return failure
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.Join(ErrOutcomeUnknown, err)
	}
	var cleaned [2]bool

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := session.currentFailure(); err != nil {
			return err
		}
		current := session.current()
		if err := service.cleanupConcluded(ctx, current, workspace, &cleaned); err != nil {
			return err
		}
		if terminalSteps(current) {
			session.stop()
			return service.recordAndComplete(ctx, session.current())
		}
		index, found := nextStep(current)
		if !found {
			return ErrOutcomeUnknown
		}
		if current.CancellationRequested &&
			current.Steps[index].Phase == port.RunnerStepPending {
			err := session.change(func(
				latest port.RunnerJournalEntry,
			) (port.RunnerJournalEntry, error) {
				return service.cancelPending(ctx, latest)
			})
			if err != nil {
				return err
			}
			continue
		}
		if err := service.runStep(ctx, session, workspace, index); err != nil {
			return err
		}
	}
}

func (service *Service) cleanupConcluded(
	ctx context.Context,
	entry port.RunnerJournalEntry,
	workspace port.RunnerWorkspace,
	cleaned *[2]bool,
) error {
	for index, progress := range entry.Steps {
		if cleaned == nil || cleaned[index] || progress.StartedAt.IsZero() ||
			(progress.Phase != port.RunnerStepPassed &&
				progress.Phase != port.RunnerStepFailed &&
				progress.Phase != port.RunnerStepCancelled) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		reference := port.RunnerStepReference{
			EffectID: entry.EffectID,
			Step:     entry.Assignment.Request.Steps[index], SourceRoot: workspace.SourceRoot,
		}
		cleanupContext, cancel := context.WithTimeout(
			context.Background(), service.cleanupTimeout,
		)
		err := service.sandbox.Delete(cleanupContext, reference)
		cancel()
		if err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
		cleaned[index] = true
	}
	return nil
}

func (service *Service) runStep(
	ctx context.Context,
	session *leaseSession,
	workspace port.RunnerWorkspace,
	index int,
) error {
	entry := session.current()
	step := entry.Assignment.Request.Steps[index]
	if entry.Steps[index].Phase == port.RunnerStepPending {
		startedAt := service.now()
		if !startedAt.Before(entry.Assignment.LeaseExpiresAt) ||
			!startedAt.Before(entry.Assignment.Request.DeadlineAt) {
			return ErrUnavailable
		}
		if err := session.change(func(
			latest port.RunnerJournalEntry,
		) (port.RunnerJournalEntry, error) {
			return service.journal.MarkStepStarted(
				ctx, latest.Assignment, step, startedAt,
			)
		}); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
		entry = session.current()
	}
	if entry.Steps[index].Phase != port.RunnerStepStarted {
		return ErrInvalid
	}
	reference := port.RunnerStepReference{
		EffectID: entry.EffectID, Step: step, SourceRoot: workspace.SourceRoot,
	}
	state, err := service.sandbox.Observe(session.ctx, reference)
	if err != nil {
		return service.failStep(ctx, session, reference, err)
	}
	if session.current().CancellationRequested {
		return service.cancelBeforeFollow(
			ctx, session, reference, state, devopsbuildv1.StepConclusionCancelled,
		)
	}
	if state == port.RunnerSandboxAbsent {
		if err := service.sandbox.Create(session.ctx, reference); err != nil {
			return service.failStep(ctx, session, reference, err)
		}
		state = port.RunnerSandboxCreated
	}
	if session.current().CancellationRequested {
		return service.cancelBeforeFollow(
			ctx, session, reference, state, devopsbuildv1.StepConclusionCancelled,
		)
	}
	if state == port.RunnerSandboxCreated {
		if err := service.sandbox.Start(session.ctx, reference); err != nil {
			return service.failStep(ctx, session, reference, err)
		}
		state, err = service.sandbox.Observe(session.ctx, reference)
		if err != nil {
			return service.failStep(ctx, session, reference, err)
		}
	}
	if session.current().CancellationRequested {
		return service.cancelBeforeFollow(
			ctx, session, reference, state, devopsbuildv1.StepConclusionCancelled,
		)
	}
	if state != port.RunnerSandboxRunning && state != port.RunnerSandboxPassed &&
		state != port.RunnerSandboxFailed {
		return service.failStep(ctx, session, reference, ErrOutcomeUnknown)
	}
	return service.followStep(ctx, session, reference, state)
}

func (service *Service) followStep(
	ctx context.Context,
	session *leaseSession,
	reference port.RunnerStepReference,
	observed port.RunnerSandboxState,
) error {
	entry := session.current()
	index := int(reference.Step.Ordinal - 1)
	deadline := boundedDeadline(
		entry.Steps[index].StartedAt, entry.Assignment.Request.DeadlineAt,
	)
	if !service.now().Before(deadline) {
		return service.cancelBeforeFollow(
			ctx, session, reference, observed, devopsbuildv1.StepConclusionFailed,
		)
	}
	outcomes := make(chan followOutcome, 1)
	go func(progress runnerlog.Progress) {
		result, err := service.sandbox.Follow(session.ctx, reference, progress)
		outcomes <- followOutcome{result: result, err: err}
	}(entry.LogProgress)
	timer := time.NewTimer(deadline.Sub(service.now()))
	defer timer.Stop()
	for {
		select {
		case outcome := <-outcomes:
			if outcome.err != nil {
				return service.failStep(ctx, session, reference, outcome.err)
			}
			conclusion, err := stepConclusion(outcome.result.State)
			if err != nil {
				return service.failStep(ctx, session, reference, err)
			}
			return service.publishAndConclude(
				ctx, session, reference.Step, outcome.result, conclusion,
			)
		case event := <-session.events:
			if event.err != nil {
				service.contain(reference)
				return event.err
			}
			if event.cancellation {
				return service.cancelFollowing(
					ctx, session, reference, outcomes,
					devopsbuildv1.StepConclusionCancelled,
				)
			}
		case <-timer.C:
			return service.cancelFollowing(
				ctx, session, reference, outcomes, devopsbuildv1.StepConclusionFailed,
			)
		case <-ctx.Done():
			return ctx.Err()
		case <-session.ctx.Done():
			if err := session.currentFailure(); err != nil {
				service.contain(reference)
				return err
			}
			return session.ctx.Err()
		}
	}
}

func (service *Service) cancelBeforeFollow(
	ctx context.Context,
	session *leaseSession,
	reference port.RunnerStepReference,
	observed port.RunnerSandboxState,
	wanted devopsbuildv1.StepConclusion,
) error {
	if wanted != devopsbuildv1.StepConclusionCancelled &&
		wanted != devopsbuildv1.StepConclusionFailed {
		return ErrInvalid
	}
	entry := session.current()
	if observed == port.RunnerSandboxAbsent {
		return service.publishAndConclude(ctx, session, reference.Step, port.RunnerSandboxResult{
			State: port.RunnerSandboxCancelled, LogProgress: entry.LogProgress,
		}, wanted)
	}
	cancelled, err := service.cancelSandbox(reference)
	if err != nil {
		return service.failStep(ctx, session, reference, err)
	}
	if observed == port.RunnerSandboxCreated {
		if cancelled != port.RunnerSandboxCancelled && cancelled != port.RunnerSandboxAbsent {
			return ErrOutcomeUnknown
		}
		return service.publishAndConclude(ctx, session, reference.Step, port.RunnerSandboxResult{
			State: port.RunnerSandboxCancelled, LogProgress: entry.LogProgress,
		}, wanted)
	}
	if cancelled != port.RunnerSandboxCancelled &&
		cancelled != port.RunnerSandboxPassed && cancelled != port.RunnerSandboxFailed {
		return ErrOutcomeUnknown
	}
	result, err := service.collectTerminal(session, reference, entry.LogProgress)
	if err != nil {
		return service.failStep(ctx, session, reference, err)
	}
	conclusion := wanted
	if cancelled == port.RunnerSandboxPassed || cancelled == port.RunnerSandboxFailed {
		if result.State != cancelled {
			return ErrOutcomeUnknown
		}
		conclusion, err = stepConclusion(cancelled)
		if err != nil {
			return err
		}
	}
	return service.publishAndConclude(ctx, session, reference.Step, result, conclusion)
}

func (service *Service) cancelFollowing(
	ctx context.Context,
	session *leaseSession,
	reference port.RunnerStepReference,
	outcomes <-chan followOutcome,
	wanted devopsbuildv1.StepConclusion,
) error {
	if wanted != devopsbuildv1.StepConclusionCancelled &&
		wanted != devopsbuildv1.StepConclusionFailed {
		return ErrInvalid
	}
	cancelled, err := service.cancelSandbox(reference)
	if err != nil {
		return service.failStep(ctx, session, reference, err)
	}
	if cancelled != port.RunnerSandboxCancelled &&
		cancelled != port.RunnerSandboxPassed && cancelled != port.RunnerSandboxFailed {
		return ErrOutcomeUnknown
	}
	wait := time.NewTimer(service.cancelGrace)
	defer wait.Stop()
	select {
	case outcome := <-outcomes:
		if outcome.err != nil {
			return service.failStep(ctx, session, reference, outcome.err)
		}
		conclusion := wanted
		if cancelled == port.RunnerSandboxPassed || cancelled == port.RunnerSandboxFailed {
			if outcome.result.State != cancelled {
				return ErrOutcomeUnknown
			}
			conclusion, err = stepConclusion(cancelled)
			if err != nil {
				return err
			}
		}
		return service.publishAndConclude(
			ctx, session, reference.Step, outcome.result, conclusion,
		)
	case <-ctx.Done():
		return ctx.Err()
	case <-session.ctx.Done():
		if err := session.currentFailure(); err != nil {
			return err
		}
		return session.ctx.Err()
	case <-wait.C:
		return ErrOutcomeUnknown
	}
}

func (service *Service) collectTerminal(
	session *leaseSession,
	reference port.RunnerStepReference,
	progress runnerlog.Progress,
) (port.RunnerSandboxResult, error) {
	collectContext, cancel := context.WithTimeout(session.ctx, service.cancelGrace)
	defer cancel()
	return service.sandbox.Follow(collectContext, reference, progress)
}

func (service *Service) cancelSandbox(
	reference port.RunnerStepReference,
) (port.RunnerSandboxState, error) {
	cancelContext, cancel := context.WithTimeout(context.Background(), service.cancelGrace)
	defer cancel()
	return service.sandbox.Cancel(cancelContext, reference)
}

func (service *Service) contain(reference port.RunnerStepReference) {
	_, _ = service.cancelSandbox(reference)
}

func (service *Service) failStep(
	ctx context.Context,
	session *leaseSession,
	reference port.RunnerStepReference,
	err error,
) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	service.contain(reference)
	if failure := session.currentFailure(); failure != nil {
		return failure
	}
	return errors.Join(ErrOutcomeUnknown, err)
}
