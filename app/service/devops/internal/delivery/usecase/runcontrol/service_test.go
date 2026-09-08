package runcontrol

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

func TestRunControlReadsAndCancelsAnEffectFreeRunAtomically(t *testing.T) {
	run := controlRun(t)
	tx := &fakeTransaction{now: run.UpdatedAt.Add(time.Second), run: run}
	service := controlService(t, tx)

	read, err := service.Get(context.Background(), GetQuery{
		Authorization: controlAuthorization(iamv1.ActionDevOpsRunRead, run.ID), RunID: run.ID,
	})
	if err != nil || read != run {
		t.Fatalf("read PipelineRun=%#v err=%v", read, err)
	}
	result, err := service.Cancel(context.Background(), CancelCommand{
		Authorization: controlAuthorization(iamv1.ActionDevOpsRunCancel, run.ID), RunID: run.ID,
		ExpectedResourceVersion: run.Status.ResourceVersion, IdempotencyKey: "cancel-run-one",
	})
	if err != nil || result.Replayed || result.Value.Status.State != devopsv1.PipelineRunCancelled ||
		result.Value.Status.CancellationRequestedAt == nil || tx.submission.TerminalEvent == nil ||
		tx.submission.CancellationEvent.Action != auditv1.ActionDevOpsPipelineRunCancellationRequested ||
		tx.submission.TerminalEvent.Actor.ID != "system-devops-run-control" {
		t.Fatalf("cancel PipelineRun=%#v submission=%#v err=%v", result, tx.submission, err)
	}
	first := result.Value
	tx.now = tx.now.Add(time.Hour)
	replayed, err := service.Cancel(context.Background(), CancelCommand{
		Authorization: controlAuthorization(iamv1.ActionDevOpsRunCancel, run.ID), RunID: run.ID,
		ExpectedResourceVersion: run.Status.ResourceVersion, IdempotencyKey: "cancel-run-one",
	})
	if err != nil || !replayed.Replayed || replayed.Value != first || tx.commitCalls != 1 {
		t.Fatalf("replayed cancellation=%#v commits=%d err=%v", replayed, tx.commitCalls, err)
	}
}

func TestRunControlExposesPendingCancellationAndConflictsChangedReplay(t *testing.T) {
	run, err := domain.AdvancePipelineRun(
		controlRun(t), devopsv1.PipelineRunFetching, "",
		controlRun(t).UpdatedAt.Add(time.Microsecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	tx := &fakeTransaction{now: run.UpdatedAt.Add(time.Second), run: run, effectMayExist: true}
	service := controlService(t, tx)
	command := CancelCommand{
		Authorization: controlAuthorization(iamv1.ActionDevOpsRunCancel, run.ID), RunID: run.ID,
		ExpectedResourceVersion: run.Status.ResourceVersion, IdempotencyKey: "cancel-active-run",
	}
	result, err := service.Cancel(context.Background(), command)
	if err != nil || result.Value.Status.State != devopsv1.PipelineRunFetching ||
		result.Value.Status.CompletedAt != nil || result.Value.Status.CancellationRequestedAt == nil ||
		tx.submission.TerminalEvent != nil {
		t.Fatalf("pending cancellation=%#v submission=%#v err=%v", result, tx.submission, err)
	}
	command.ExpectedResourceVersion++
	if _, err := service.Cancel(context.Background(), command); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed cancellation replay error=%v", err)
	}
}

func TestRunControlRejectsMismatchedAuthorityAndPreconditions(t *testing.T) {
	run := controlRun(t)
	tx := &fakeTransaction{now: run.UpdatedAt.Add(time.Second), run: run}
	service := controlService(t, tx)
	wrong := controlAuthorization(iamv1.ActionDevOpsRunRead, run.ID)
	if _, err := service.Cancel(context.Background(), CancelCommand{
		Authorization: wrong, RunID: run.ID, ExpectedResourceVersion: 1, IdempotencyKey: "cancel-run",
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("mismatched cancellation authority error=%v", err)
	}
	if _, err := service.Get(context.Background(), GetQuery{
		Authorization: controlAuthorization(iamv1.ActionDevOpsRunRead, "another-run"), RunID: run.ID,
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("mismatched read authority error=%v", err)
	}
	if _, err := service.Cancel(context.Background(), CancelCommand{
		Authorization: controlAuthorization(iamv1.ActionDevOpsRunCancel, run.ID), RunID: run.ID,
		ExpectedResourceVersion: 0, IdempotencyKey: "cancel-run",
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("missing cancellation precondition error=%v", err)
	}
	if _, err := service.Replay(context.Background(), ReplayCommand{
		Authorization: controlAuthorization(iamv1.ActionDevOpsRunRead, run.ID),
		SourceRunID:   run.ID, ExpectedResourceVersion: 1, IdempotencyKey: "replay-run",
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("mismatched replay authority error=%v", err)
	}
	if _, err := service.Replay(context.Background(), ReplayCommand{
		Authorization: controlAuthorization(iamv1.ActionDevOpsRunReplay, run.ID),
		SourceRunID:   run.ID, ExpectedResourceVersion: 0, IdempotencyKey: "replay-run",
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("missing replay precondition error=%v", err)
	}
}

func TestRunControlReplaysTerminalRunFromSealedInputAtomically(t *testing.T) {
	source := controlRun(t)
	terminalAt := source.UpdatedAt.Add(time.Microsecond)
	var err error
	source, err = domain.RequestPipelineRunCancellation(
		source, source.Status.ResourceVersion, false, terminalAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	tx := &fakeTransaction{now: terminalAt.Add(time.Second), run: source}
	service := controlService(t, tx)
	command := ReplayCommand{
		Authorization: controlAuthorization(iamv1.ActionDevOpsRunReplay, source.ID),
		SourceRunID:   source.ID, ExpectedResourceVersion: source.Status.ResourceVersion,
		IdempotencyKey: "replay-terminal-run",
	}
	result, err := service.Replay(context.Background(), command)
	if err != nil || result.Replayed || result.Value.Replay == nil ||
		result.Value.Replay.SourceRunID != source.ID ||
		result.Value.Replay.RequestedBy != command.Authorization.Subject ||
		result.Value.Input != source.Input || result.Value.InputDigest != source.InputDigest ||
		result.Value.Status.State != devopsv1.PipelineRunQueued ||
		tx.replaySubmission.AuditEvent.Action != auditv1.ActionDevOpsPipelineRunReplayed {
		t.Fatalf("replayed PipelineRun=%#v submission=%#v err=%v", result, tx.replaySubmission, err)
	}
	first := result.Value
	tx.now = tx.now.Add(time.Hour)
	repeated, err := service.Replay(context.Background(), command)
	if err != nil || !repeated.Replayed || repeated.Value != first || tx.replayCommitCalls != 1 {
		t.Fatalf("equal replay=%#v commits=%d err=%v", repeated, tx.replayCommitCalls, err)
	}
	command.ExpectedResourceVersion++
	if _, err := service.Replay(context.Background(), command); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error=%v", err)
	}
}

func TestRunControlRejectsReplayOfNonterminalRun(t *testing.T) {
	source := controlRun(t)
	tx := &fakeTransaction{now: source.UpdatedAt.Add(time.Second), run: source}
	service := controlService(t, tx)
	_, err := service.Replay(context.Background(), ReplayCommand{
		Authorization: controlAuthorization(iamv1.ActionDevOpsRunReplay, source.ID),
		SourceRunID:   source.ID, ExpectedResourceVersion: source.Status.ResourceVersion,
		IdempotencyKey: "replay-nonterminal-run",
	})
	if !errors.Is(err, ErrNotTerminal) || tx.replayCommitCalls != 0 {
		t.Fatalf("nonterminal replay commits=%d error=%v", tx.replayCommitCalls, err)
	}
}

type fakeRepository struct{ tx *fakeTransaction }

func (repository *fakeRepository) WithinRunControlTransaction(
	ctx context.Context,
	_ devopsv1.TenantID,
	work func(context.Context, Transaction) error,
) error {
	return work(ctx, repository.tx)
}

type fakeTransaction struct {
	now               time.Time
	run               devopsv1.PipelineRun
	effectMayExist    bool
	stored            *StoredCancellation
	storedReplay      *StoredReplay
	submission        Submission
	replaySubmission  ReplaySubmission
	commitCalls       int
	replayCommitCalls int
}

func (tx *fakeTransaction) TransactionTime(context.Context) (time.Time, error) { return tx.now, nil }

func (tx *fakeTransaction) FindCancellation(_ context.Context, fingerprint string) (StoredCancellation, bool, error) {
	if tx.stored == nil || tx.stored.Operation.IdempotencyFingerprint != fingerprint {
		return StoredCancellation{}, false, nil
	}
	return *tx.stored, true, nil
}

func (tx *fakeTransaction) FindReplay(_ context.Context, fingerprint string) (StoredReplay, bool, error) {
	if tx.storedReplay == nil || tx.storedReplay.Operation.IdempotencyFingerprint != fingerprint {
		return StoredReplay{}, false, nil
	}
	return *tx.storedReplay, true, nil
}

func (tx *fakeTransaction) LoadPipelineRun(context.Context, devopsv1.ResourceID) (devopsv1.PipelineRun, bool, error) {
	return tx.run, true, nil
}

func (tx *fakeTransaction) LockPipelineRunForCancellation(
	context.Context,
	devopsv1.ResourceID,
) (devopsv1.PipelineRun, bool, bool, error) {
	return tx.run, tx.effectMayExist, true, nil
}

func (tx *fakeTransaction) LockPipelineRunForReplay(
	_ context.Context,
	_ devopsv1.ResourceID,
	_ uint64,
) (devopsv1.PipelineRun, time.Time, bool, error) {
	return tx.run, tx.now, true, nil
}

func (tx *fakeTransaction) CommitPipelineRunCancellation(
	_ context.Context,
	_ uint64,
	submission Submission,
) error {
	if err := ValidateSubmission(submission); err != nil {
		return err
	}
	tx.commitCalls++
	tx.submission = submission
	tx.run = submission.Result
	tx.stored = &StoredCancellation{Operation: submission.Operation, Result: submission.Result}
	return nil
}

func (tx *fakeTransaction) CommitPipelineRunReplay(
	_ context.Context,
	_ uint64,
	submission ReplaySubmission,
) error {
	if err := ValidateReplaySubmission(submission); err != nil {
		return err
	}
	tx.replayCommitCalls++
	tx.replaySubmission = submission
	tx.storedReplay = &StoredReplay{Operation: submission.Operation, Result: submission.Result}
	return nil
}

func controlService(t *testing.T, tx *fakeTransaction) *Service {
	t.Helper()
	service, err := NewService(&fakeRepository{tx: tx}, Config{MaxTransactionAttempts: 3})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func controlAuthorization(action iamv1.Action, runID devopsv1.ResourceID) port.Authorization {
	return port.Authorization{
		TenantID: "tenant-one", Subject: devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-one"},
		DecisionID: "decision-run-control", Action: action,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourcePipelineRun, ID: string(runID)},
		RequestID: "request-run-control", CorrelationID: "correlation-run-control",
	}
}

func controlRun(t *testing.T) devopsv1.PipelineRun {
	t.Helper()
	now := time.Date(2026, 9, 8, 4, 0, 0, 0, time.UTC)
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	input := devopsv1.PipelineRunInput{
		SourceEventID:          "source-event-" + devopsv1.ResourceID(strings.Repeat("1", 48)),
		SourceEventDigest:      "sha256:" + strings.Repeat("2", 64),
		PipelineRevisionID:     "pipeline-revision-" + devopsv1.ResourceID(strings.Repeat("3", 48)),
		PipelineRevisionDigest: "sha256:" + strings.Repeat("4", 64),
		RepositoryBindingID:    "binding-one", RepositoryBindingDigest: "sha256:" + strings.Repeat("5", 64),
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
