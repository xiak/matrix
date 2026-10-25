package runaudit

import (
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
)

func TestTerminalEventPreservesClosedOutcomeAndNormalizesActor(t *testing.T) {
	tests := []struct {
		name    string
		state   devopsv1.PipelineRunState
		reason  devopsv1.PipelineRunReason
		outcome string
	}{
		{"succeeded", devopsv1.PipelineRunSucceeded, devopsv1.PipelineRunReasonCompleted, "SUCCEEDED"},
		{"failed", devopsv1.PipelineRunFailed, devopsv1.PipelineRunReasonVerificationFailed, "FAILED"},
		{"cancelled", devopsv1.PipelineRunCancelled, devopsv1.PipelineRunReasonCancelled, "CANCELLED"},
		{"manual", devopsv1.PipelineRunManualIntervention, devopsv1.PipelineRunReasonReconciliationExhausted, "MANUAL_INTERVENTION"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run := reportingRun(t)
			if test.state == devopsv1.PipelineRunCancelled {
				var err error
				run, err = domain.RequestPipelineRunCancellation(
					run, run.Status.ResourceVersion, true, run.UpdatedAt.Add(time.Microsecond),
				)
				if err != nil {
					t.Fatal(err)
				}
			}
			if test.state == devopsv1.PipelineRunManualIntervention {
				var err error
				run, err = domain.AdvancePipelineRun(
					run, devopsv1.PipelineRunReconciling,
					devopsv1.PipelineRunReasonExternalEffectUncertain,
					run.UpdatedAt.Add(time.Microsecond),
				)
				if err != nil {
					t.Fatal(err)
				}
			}
			terminal, err := domain.AdvancePipelineRun(
				run, test.state, test.reason, run.UpdatedAt.Add(time.Microsecond),
			)
			if err != nil {
				t.Fatal(err)
			}
			event, err := NewTerminalEvent(terminal, "command-one", WorkerActorID)
			if err != nil || string(event.Outcome) != test.outcome ||
				string(event.Reason) != string(test.reason) || event.RequestDigest != terminal.InputDigest ||
				event.Actor.ID != WorkerActorID || event.RequestID != "command-one" ||
				event.CorrelationID != string(terminal.ID) {
				t.Fatalf("terminal Audit event=%#v err=%v", event, err)
			}
			replayed, err := NewTerminalEvent(terminal, "command-one", WorkerActorID)
			if err != nil || replayed != event {
				t.Fatalf("terminal Audit replay=%#v err=%v", replayed, err)
			}
			if _, err := NewTerminalEvent(terminal, "command-one", ControlActorID); err != nil {
				t.Fatalf("control actor terminal Audit event: %v", err)
			}
		})
	}
}

func TestTerminalEventRejectsNonterminalRunAndUnnormalizedActor(t *testing.T) {
	run := reportingRun(t)
	if _, err := NewTerminalEvent(run, "command-one", WorkerActorID); err == nil {
		t.Fatal("nonterminal PipelineRun produced a completion Audit event")
	}
	terminal, err := domain.AdvancePipelineRun(
		run, devopsv1.PipelineRunSucceeded, devopsv1.PipelineRunReasonCompleted,
		run.UpdatedAt.Add(time.Microsecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTerminalEvent(terminal, "command-one", "worker-instance-one"); err == nil {
		t.Fatal("worker instance identity entered the Audit contract")
	}
}

func reportingRun(t *testing.T) devopsv1.PipelineRun {
	t.Helper()
	now := time.Date(2026, 9, 8, 4, 0, 0, 0, time.UTC)
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	input := devopsv1.PipelineRunInput{
		SourceEventID:           "source-event-" + devopsv1.ResourceID(strings.Repeat("1", 48)),
		SourceEventDigest:       "sha256:" + strings.Repeat("2", 64),
		PipelineRevisionID:      "pipeline-revision-" + devopsv1.ResourceID(strings.Repeat("3", 48)),
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
	for _, step := range []devopsv1.PipelineRunState{
		devopsv1.PipelineRunFetching,
		devopsv1.PipelineRunVerifying,
		devopsv1.PipelineRunReporting,
	} {
		run, err = domain.AdvancePipelineRun(run, step, "", run.UpdatedAt.Add(time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
	}
	return run
}
