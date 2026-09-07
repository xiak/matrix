package runlifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
)

func TestQueueClaimsValidatedExecuteAndRecoveryModes(t *testing.T) {
	repository := &fakeRepository{lease: taskLease(t, devopsv1.PipelineRunFetching, ClaimExecute, 1, 0), found: true}
	queue := taskQueue(t, repository)
	claimed, found, err := queue.ClaimNext(context.Background(), "worker-one")
	if err != nil || !found || claimed.Mode != ClaimExecute || claimed.Intent.Stage != devopsv1.PipelineRunStageFetch {
		t.Fatalf("first claim=%#v found=%t err=%v", claimed, found, err)
	}

	repository.lease = taskLease(t, devopsv1.PipelineRunFetching, ClaimObserve, 2, 0)
	claimed, found, err = queue.ClaimNext(context.Background(), "worker-one")
	if err != nil || !found || claimed.Mode != ClaimObserve || claimed.FencingToken != 2 {
		t.Fatalf("recovery claim=%#v found=%t err=%v", claimed, found, err)
	}

	repository.lease.Mode = ClaimExecute
	if _, _, err := queue.ClaimNext(context.Background(), "worker-one"); err == nil {
		t.Fatal("recovered effect was allowed to execute without observation")
	}
}

func TestQueueRenewsOnlyTheCurrentLeaseGuard(t *testing.T) {
	lease := taskLease(t, devopsv1.PipelineRunVerifying, ClaimExecute, 1, 0)
	repository := &fakeRepository{lease: lease, found: true}
	queue := taskQueue(t, repository)
	renewed, err := queue.Renew(context.Background(), lease)
	if err != nil || !renewed.LeaseExpiresAt.After(lease.LeaseExpiresAt) || repository.renewCalls != 1 {
		t.Fatalf("renewed lease=%#v calls=%d err=%v", renewed, repository.renewCalls, err)
	}
	if repository.guard != lease.Guard() {
		t.Fatalf("renewal guard=%#v want=%#v", repository.guard, lease.Guard())
	}
}

func TestQueueAdvancesOnlyTheLeasedRunStateGraph(t *testing.T) {
	lease := taskLease(t, devopsv1.PipelineRunFetching, ClaimExecute, 1, 0)
	repository := &fakeRepository{lease: lease, found: true}
	queue := taskQueue(t, repository)
	updated, err := queue.Advance(context.Background(), Transition{
		Lease: lease, State: devopsv1.PipelineRunVerifying,
	})
	if err != nil || updated.Status.State != devopsv1.PipelineRunVerifying || repository.advanceCalls != 1 {
		t.Fatalf("advance=%#v calls=%d err=%v", updated, repository.advanceCalls, err)
	}
	if _, err := queue.Advance(context.Background(), Transition{
		Lease: lease, State: devopsv1.PipelineRunSucceeded,
		Reason: devopsv1.PipelineRunReasonCompleted,
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("skipped-stage transition error=%v", err)
	}
	if _, err := queue.Advance(context.Background(), Transition{
		Lease: lease, State: devopsv1.PipelineRunReconciling,
		Reason: devopsv1.PipelineRunReasonExternalEffectUncertain,
	}); err == nil {
		t.Fatal("generic transition discarded an uncertain command intent")
	}
}

func TestQueuePreservesReportIntentThroughBoundedReconciliation(t *testing.T) {
	lease := taskLease(t, devopsv1.PipelineRunReporting, ClaimExecute, 1, 0)
	repository := &fakeRepository{lease: lease, found: true}
	queue := taskQueue(t, repository)
	nextAttemptAt := lease.Run.UpdatedAt.Add(time.Minute)
	reconciling, err := queue.MarkReportUncertain(context.Background(), Reconciliation{
		Lease: lease, NextAttemptAt: nextAttemptAt,
	})
	if err != nil || reconciling.Status.State != devopsv1.PipelineRunReconciling ||
		repository.uncertainCalls != 1 {
		t.Fatalf("mark uncertain=%#v calls=%d err=%v", reconciling, repository.uncertainCalls, err)
	}

	observed := taskLease(t, devopsv1.PipelineRunReconciling, ClaimObserve, 2, 9)
	attempts, err := queue.DeferReconciliation(context.Background(), Reconciliation{
		Lease: observed, NextAttemptAt: observed.Run.UpdatedAt.Add(time.Minute),
	})
	if err != nil || attempts != MaximumReconciliationAttempts || repository.deferCalls != 1 {
		t.Fatalf("defer reconciliation attempts=%d calls=%d err=%v", attempts, repository.deferCalls, err)
	}
	observed.ReconciliationAttempts = MaximumReconciliationAttempts
	if _, err := queue.DeferReconciliation(context.Background(), Reconciliation{
		Lease: observed, NextAttemptAt: observed.Run.UpdatedAt.Add(time.Minute),
	}); !errors.Is(err, ErrReconciliationExhausted) {
		t.Fatalf("exhausted deferral error=%v", err)
	}
	manual, err := queue.Advance(context.Background(), Transition{
		Lease:  observed,
		State:  devopsv1.PipelineRunManualIntervention,
		Reason: devopsv1.PipelineRunReasonReconciliationExhausted,
	})
	if err != nil || manual.Status.State != devopsv1.PipelineRunManualIntervention {
		t.Fatalf("manual intervention=%#v err=%v", manual, err)
	}
}

func TestQueueRejectsPrematureManualInterventionAndRepositoryDrift(t *testing.T) {
	lease := taskLease(t, devopsv1.PipelineRunReconciling, ClaimObserve, 2, 9)
	repository := &fakeRepository{lease: lease, found: true}
	queue := taskQueue(t, repository)
	if _, err := queue.Advance(context.Background(), Transition{
		Lease:  lease,
		State:  devopsv1.PipelineRunManualIntervention,
		Reason: devopsv1.PipelineRunReasonReconciliationExhausted,
	}); err == nil {
		t.Fatal("premature manual intervention was accepted")
	}

	lease.ReconciliationAttempts = MaximumReconciliationAttempts
	repository.drift = true
	if _, err := queue.Advance(context.Background(), Transition{
		Lease:  lease,
		State:  devopsv1.PipelineRunManualIntervention,
		Reason: devopsv1.PipelineRunReasonReconciliationExhausted,
	}); err == nil {
		t.Fatal("repository transition drift was accepted")
	}
}

func TestTerminalAuditEventPreservesClosedOutcomeAndHidesWorkerIdentity(t *testing.T) {
	tests := []struct {
		name    string
		state   devopsv1.PipelineRunState
		reason  devopsv1.PipelineRunReason
		outcome string
	}{
		{"succeeded", devopsv1.PipelineRunSucceeded, devopsv1.PipelineRunReasonCompleted, "SUCCEEDED"},
		{"failed", devopsv1.PipelineRunFailed, devopsv1.PipelineRunReasonVerificationFailed, "FAILED"},
		{"cancelled", devopsv1.PipelineRunCancelled, devopsv1.PipelineRunReasonCancelled, "CANCELLED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lease := taskLease(t, devopsv1.PipelineRunReporting, ClaimExecute, 1, 0)
			terminal, err := domain.AdvancePipelineRun(
				lease.Run, test.state, test.reason, lease.Run.UpdatedAt.Add(time.Microsecond),
			)
			if err != nil {
				t.Fatal(err)
			}
			event, err := NewTerminalAuditEvent(terminal, lease.Intent.CommandID)
			if err != nil || string(event.Outcome) != test.outcome ||
				string(event.Reason) != string(test.reason) || event.RequestDigest != terminal.InputDigest ||
				event.Actor.ID != terminalAuditActorID || string(event.Actor.ID) == lease.WorkerID ||
				event.RequestID != lease.Intent.CommandID || event.CorrelationID != string(terminal.ID) {
				t.Fatalf("terminal Audit event=%#v err=%v", event, err)
			}
			replayed, err := NewTerminalAuditEvent(terminal, lease.Intent.CommandID)
			if err != nil || replayed != event {
				t.Fatalf("terminal Audit replay=%#v err=%v", replayed, err)
			}
		})
	}
	lease := taskLease(t, devopsv1.PipelineRunFetching, ClaimExecute, 1, 0)
	if _, err := NewTerminalAuditEvent(lease.Run, lease.Intent.CommandID); err == nil {
		t.Fatal("nonterminal PipelineRun produced a completion Audit event")
	}
}

type fakeRepository struct {
	lease          Lease
	found          bool
	drift          bool
	advanceCalls   int
	uncertainCalls int
	deferCalls     int
	renewCalls     int
	guard          LeaseGuard
}

func (repository *fakeRepository) Claim(context.Context, string, time.Duration) (Lease, bool, error) {
	return repository.lease, repository.found, nil
}

func (repository *fakeRepository) Renew(
	_ context.Context,
	guard LeaseGuard,
	_ time.Duration,
) (time.Time, error) {
	repository.renewCalls++
	repository.guard = guard
	return repository.lease.LeaseExpiresAt.Add(time.Minute), nil
}

func (repository *fakeRepository) Advance(_ context.Context, transition Transition) (devopsv1.PipelineRun, error) {
	repository.advanceCalls++
	updated, err := domain.AdvancePipelineRun(
		transition.Lease.Run,
		transition.State,
		transition.Reason,
		transition.Lease.Run.UpdatedAt.Add(time.Microsecond),
	)
	if repository.drift && err == nil {
		updated.InputDigest = "sha256:" + strings.Repeat("f", 64)
	}
	return updated, err
}

func (repository *fakeRepository) MarkReportUncertain(
	_ context.Context,
	reconciliation Reconciliation,
) (devopsv1.PipelineRun, error) {
	repository.uncertainCalls++
	return domain.AdvancePipelineRun(
		reconciliation.Lease.Run,
		devopsv1.PipelineRunReconciling,
		devopsv1.PipelineRunReasonExternalEffectUncertain,
		reconciliation.Lease.Run.UpdatedAt.Add(time.Microsecond),
	)
}

func (repository *fakeRepository) DeferReconciliation(
	_ context.Context,
	reconciliation Reconciliation,
) (uint64, error) {
	repository.deferCalls++
	return reconciliation.Lease.ReconciliationAttempts + 1, nil
}

func taskQueue(t *testing.T, repository Repository) *Queue {
	t.Helper()
	queue, err := NewQueue(repository, Config{LeaseDuration: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return queue
}

func taskLease(
	t *testing.T,
	state devopsv1.PipelineRunState,
	mode ClaimMode,
	fence, reconciliationAttempts uint64,
) Lease {
	t.Helper()
	run := queuedRun(t)
	path := []struct {
		state  devopsv1.PipelineRunState
		reason devopsv1.PipelineRunReason
	}{
		{state: devopsv1.PipelineRunFetching},
		{state: devopsv1.PipelineRunVerifying},
		{state: devopsv1.PipelineRunReporting},
		{state: devopsv1.PipelineRunReconciling, reason: devopsv1.PipelineRunReasonExternalEffectUncertain},
	}
	for _, step := range path {
		var err error
		run, err = domain.AdvancePipelineRun(run, step.state, step.reason, run.UpdatedAt.Add(time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
		if step.state == state {
			break
		}
	}
	intent := TaskIntent{
		RunID: run.ID, InputDigest: run.InputDigest, Stage: run.Status.Stage, Attempt: 1,
	}
	intent.CommandID = TaskCommandID(intent.RunID, intent.Stage, intent.Attempt)
	return Lease{
		TenantID: run.Scope.TenantID, Run: run, Intent: intent, Mode: mode,
		WorkerID: "worker-one", FencingToken: fence,
		LeaseExpiresAt:         run.UpdatedAt.Add(time.Minute),
		ReconciliationAttempts: reconciliationAttempts,
	}
}

func queuedRun(t *testing.T) devopsv1.PipelineRun {
	t.Helper()
	now := time.Date(2026, 9, 8, 2, 0, 0, 0, time.UTC)
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	input := devopsv1.PipelineRunInput{
		SourceEventID:           devopsv1.ResourceID("source-event-" + strings.Repeat("1", 48)),
		SourceEventDigest:       "sha256:" + strings.Repeat("2", 64),
		PipelineRevisionID:      devopsv1.ResourceID("pipeline-revision-" + strings.Repeat("3", 48)),
		PipelineRevisionDigest:  "sha256:" + strings.Repeat("4", 64),
		RepositoryBindingID:     "binding-one",
		RepositoryBindingDigest: "sha256:" + strings.Repeat("5", 64),
		Change: devopsv1.ChangeIdentity{
			Action: devopsv1.ChangeOpened, Number: 7,
			HeadCommit: strings.Repeat("6", 40), TrustedBaseCommit: strings.Repeat("7", 40),
		},
	}
	digest := devopsv1.PipelineRunInputDigest(input)
	id, err := devopsv1.PipelineRunID(scope, input.SourceEventID, input.PipelineRevisionID, digest)
	if err != nil {
		t.Fatal(err)
	}
	run := devopsv1.PipelineRun{
		APIVersion: devopsv1.APIVersion, Kind: "PipelineRun", ID: id, Scope: scope,
		ProjectID: "project-one", PipelineID: "pipeline-one", Input: input, InputDigest: digest,
		Status: devopsv1.PipelineRunStatus{
			State: devopsv1.PipelineRunQueued, Stage: devopsv1.PipelineRunStageReceive,
			Reason: devopsv1.PipelineRunReasonEventAdmitted, ResourceVersion: 1, ObservedAt: now,
		},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := devopsv1.ValidatePipelineRun(run); err != nil {
		t.Fatal(err)
	}
	return run
}
