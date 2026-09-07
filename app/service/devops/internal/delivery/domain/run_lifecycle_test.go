package domain

import (
	"errors"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestPipelineRunLifecycleSuccessAndReconciliationPaths(t *testing.T) {
	run := lifecycleRun(t)
	steps := []struct {
		state  devopsv1.PipelineRunState
		reason devopsv1.PipelineRunReason
	}{
		{state: devopsv1.PipelineRunFetching},
		{state: devopsv1.PipelineRunVerifying},
		{state: devopsv1.PipelineRunReporting},
		{state: devopsv1.PipelineRunReconciling, reason: devopsv1.PipelineRunReasonExternalEffectUncertain},
		{state: devopsv1.PipelineRunSucceeded, reason: devopsv1.PipelineRunReasonCompleted},
	}
	for index, step := range steps {
		before := run
		observedAt := before.UpdatedAt.Add(time.Microsecond)
		next, err := AdvancePipelineRun(before, step.state, step.reason, observedAt)
		if err != nil {
			t.Fatalf("advance step %d: %v", index, err)
		}
		if next.ID != before.ID || next.Input != before.Input ||
			next.InputDigest != before.InputDigest || next.CreatedAt != before.CreatedAt {
			t.Fatalf("advance step %d changed immutable input: %#v", index, next)
		}
		if next.Status.ResourceVersion != before.Status.ResourceVersion+1 ||
			!next.UpdatedAt.Equal(observedAt) || !next.Status.ObservedAt.Equal(observedAt) {
			t.Fatalf("advance step %d did not version status: %#v", index, next.Status)
		}
		run = next
	}
	if run.Status.CompletedAt == nil || !run.Status.CompletedAt.Equal(run.UpdatedAt) {
		t.Fatalf("success did not seal completion: %#v", run.Status)
	}
	if _, err := AdvancePipelineRun(
		run,
		devopsv1.PipelineRunFailed,
		devopsv1.PipelineRunReasonReportConflict,
		run.UpdatedAt.Add(time.Microsecond),
	); !errors.Is(err, ErrPipelineRunTerminal) {
		t.Fatalf("terminal transition error = %v", err)
	}
}

func TestPipelineRunLifecycleRejectsIllegalTransitionsAndReasons(t *testing.T) {
	queued := lifecycleRun(t)
	for name, test := range map[string]struct {
		state  devopsv1.PipelineRunState
		reason devopsv1.PipelineRunReason
	}{
		"skip fetch":           {state: devopsv1.PipelineRunVerifying},
		"active reason":        {state: devopsv1.PipelineRunFetching, reason: devopsv1.PipelineRunReasonCompleted},
		"wrong queued failure": {state: devopsv1.PipelineRunFailed, reason: devopsv1.PipelineRunReasonSourceUnavailable},
		"early reconciliation": {state: devopsv1.PipelineRunReconciling, reason: devopsv1.PipelineRunReasonExternalEffectUncertain},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := AdvancePipelineRun(
				queued,
				test.state,
				test.reason,
				queued.UpdatedAt.Add(time.Microsecond),
			); !errors.Is(err, ErrInvalidPipelineRunTransition) {
				t.Fatalf("transition error = %v", err)
			}
		})
	}

	fetching, err := AdvancePipelineRun(
		queued,
		devopsv1.PipelineRunFetching,
		"",
		queued.UpdatedAt.Add(time.Microsecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdvancePipelineRun(
		fetching,
		devopsv1.PipelineRunFailed,
		devopsv1.PipelineRunReasonVerificationFailed,
		fetching.UpdatedAt.Add(time.Microsecond),
	); !errors.Is(err, ErrInvalidPipelineRunTransition) {
		t.Fatalf("cross-stage failure reason error = %v", err)
	}
	if _, err := AdvancePipelineRun(
		fetching,
		devopsv1.PipelineRunCancelled,
		devopsv1.PipelineRunReasonCancelled,
		fetching.UpdatedAt,
	); !errors.Is(err, ErrInvalidPipelineRunTransition) {
		t.Fatalf("non-increasing time error = %v", err)
	}
}

func TestPipelineRunLifecycleClosesEveryNonterminalState(t *testing.T) {
	for _, state := range []devopsv1.PipelineRunState{
		devopsv1.PipelineRunQueued,
		devopsv1.PipelineRunFetching,
		devopsv1.PipelineRunVerifying,
		devopsv1.PipelineRunReporting,
		devopsv1.PipelineRunReconciling,
	} {
		run := lifecycleRunAtState(t, state)
		requestedAt := run.UpdatedAt.Add(time.Microsecond)
		requested, err := RequestPipelineRunCancellation(
			run, run.Status.ResourceVersion, state != devopsv1.PipelineRunQueued, requestedAt,
		)
		if err != nil {
			t.Fatalf("request cancellation from %s: %v", state, err)
		}
		if requested.Status.CancellationRequestedAt == nil ||
			!requested.Status.CancellationRequestedAt.Equal(requestedAt) {
			t.Fatalf("request cancellation from %s omitted request time: %#v", state, requested.Status)
		}
		if state == devopsv1.PipelineRunQueued {
			if requested.Status.State != devopsv1.PipelineRunCancelled || requested.Status.CompletedAt == nil {
				t.Fatalf("safe queued cancellation did not complete: %#v", requested.Status)
			}
			continue
		}
		cancelled, err := AdvancePipelineRun(
			requested,
			devopsv1.PipelineRunCancelled,
			devopsv1.PipelineRunReasonCancelled,
			requested.UpdatedAt.Add(time.Microsecond),
		)
		if err != nil {
			t.Fatalf("cancel %s: %v", state, err)
		}
		if cancelled.Status.Stage != run.Status.Stage || cancelled.Status.CompletedAt == nil ||
			cancelled.Status.CancellationRequestedAt == nil {
			t.Fatalf("cancel %s changed stage or omitted completion: %#v", state, cancelled.Status)
		}
	}
}

func TestPipelineRunCancellationPreventsFutureStagesAndKeepsTruthfulTerminal(t *testing.T) {
	fetching := lifecycleRunAtState(t, devopsv1.PipelineRunFetching)
	requested, err := RequestPipelineRunCancellation(
		fetching, fetching.Status.ResourceVersion, true, fetching.UpdatedAt.Add(time.Microsecond),
	)
	if err != nil || requested.Status.State != devopsv1.PipelineRunFetching || requested.Status.CompletedAt != nil {
		t.Fatalf("pending cancellation=%#v err=%v", requested, err)
	}
	if _, err := AdvancePipelineRun(
		requested, devopsv1.PipelineRunVerifying, "", requested.UpdatedAt.Add(time.Microsecond),
	); !errors.Is(err, ErrInvalidPipelineRunTransition) {
		t.Fatalf("cancellation allowed a future stage: %v", err)
	}
	failed, err := AdvancePipelineRun(
		requested, devopsv1.PipelineRunFailed, devopsv1.PipelineRunReasonCommitMismatch,
		requested.UpdatedAt.Add(time.Microsecond),
	)
	if err != nil || failed.Status.State != devopsv1.PipelineRunFailed ||
		failed.Status.CancellationRequestedAt == nil {
		t.Fatalf("definitive effect result after cancellation=%#v err=%v", failed, err)
	}

	queued := lifecycleRunAtState(t, devopsv1.PipelineRunQueued)
	if _, err := RequestPipelineRunCancellation(
		queued, queued.Status.ResourceVersion+1, false, queued.UpdatedAt.Add(time.Microsecond),
	); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale cancellation precondition error=%v", err)
	}
	if _, err := RequestPipelineRunCancellation(
		queued, queued.Status.ResourceVersion, true, queued.UpdatedAt.Add(time.Microsecond),
	); !errors.Is(err, ErrInvalidPipelineRunTransition) {
		t.Fatalf("queued run claimed an external effect: %v", err)
	}
	reporting := lifecycleRunAtState(t, devopsv1.PipelineRunReporting)
	immediate, err := RequestPipelineRunCancellation(
		reporting, reporting.Status.ResourceVersion, false, reporting.UpdatedAt.Add(time.Microsecond),
	)
	if err != nil || immediate.Status.State != devopsv1.PipelineRunCancelled {
		t.Fatalf("effect-free reporting cancellation=%#v err=%v", immediate, err)
	}
}

func FuzzPipelineRunTransitionNeverProducesInvalidStatus(f *testing.F) {
	f.Add(uint8(0), "FETCHING", "")
	f.Add(uint8(3), "RECONCILING", "EXTERNAL_EFFECT_UNCERTAIN")
	f.Add(uint8(4), "MANUAL_INTERVENTION", "RECONCILIATION_EXHAUSTED")
	f.Add(uint8(1), "SUCCEEDED", "COMPLETED")
	f.Fuzz(func(t *testing.T, currentIndex uint8, nextValue, reasonValue string) {
		states := []devopsv1.PipelineRunState{
			devopsv1.PipelineRunQueued,
			devopsv1.PipelineRunFetching,
			devopsv1.PipelineRunVerifying,
			devopsv1.PipelineRunReporting,
			devopsv1.PipelineRunReconciling,
		}
		current := states[int(currentIndex)%len(states)]
		run := lifecycleRunAtState(t, current)
		next, err := AdvancePipelineRun(
			run,
			devopsv1.PipelineRunState(nextValue),
			devopsv1.PipelineRunReason(reasonValue),
			run.UpdatedAt.Add(time.Microsecond),
		)
		if err != nil {
			return
		}
		if err := devopsv1.ValidatePipelineRun(next); err != nil {
			t.Fatalf("accepted transition produced an invalid PipelineRun: %v", err)
		}
		if next.Status.ResourceVersion != run.Status.ResourceVersion+1 ||
			next.Input != run.Input || next.InputDigest != run.InputDigest {
			t.Fatalf("accepted transition changed immutable authority: %#v", next)
		}
	})
}

func lifecycleRunAtState(t *testing.T, target devopsv1.PipelineRunState) devopsv1.PipelineRun {
	t.Helper()
	run := lifecycleRun(t)
	path := []struct {
		state  devopsv1.PipelineRunState
		reason devopsv1.PipelineRunReason
	}{
		{state: devopsv1.PipelineRunFetching},
		{state: devopsv1.PipelineRunVerifying},
		{state: devopsv1.PipelineRunReporting},
		{state: devopsv1.PipelineRunReconciling, reason: devopsv1.PipelineRunReasonExternalEffectUncertain},
	}
	if target == devopsv1.PipelineRunQueued {
		return run
	}
	for _, step := range path {
		var err error
		run, err = AdvancePipelineRun(run, step.state, step.reason, run.UpdatedAt.Add(time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
		if step.state == target {
			return run
		}
	}
	t.Fatalf("unsupported lifecycle fixture state %s", target)
	return devopsv1.PipelineRun{}
}

func lifecycleRun(t *testing.T) devopsv1.PipelineRun {
	t.Helper()
	connection, binding := readySource(t)
	pipeline := mustNewPipeline(t)
	activation, err := ActivatePipeline(
		pipeline,
		pipeline.Metadata.ResourceVersion,
		devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-lifecycle"},
		binding,
		domainTime().Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	event, err := NewSourceEvent(
		normalizedChange(),
		connection,
		binding,
		domainTime().Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	run, err := NewPipelineRun(event, activation.Pipeline, activation.Revision)
	if err != nil {
		t.Fatal(err)
	}
	return run
}
