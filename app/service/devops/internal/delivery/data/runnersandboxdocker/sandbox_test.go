package runnersandboxdocker

import (
	"context"
	"testing"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

func TestSandboxHidesPlansAndRestoresLogProgress(t *testing.T) {
	plan := testStepPlan(t)
	engine := newStepEngine(t, plan)
	client := testStepClient(t, engine)
	sandbox, err := NewSandbox(client)
	if err != nil {
		t.Fatal(err)
	}
	reference := port.RunnerStepReference{
		EffectID: plan.request.Labels["com.xiak.matrix.devops.effect"],
		Step: devopsv1.VerificationStep{
			Ordinal: 1, Kind: devopsv1.VerificationStepGoTest,
		},
		SourceRoot: plan.request.HostConfig.Mounts[0].Source,
	}
	state, err := sandbox.Observe(context.Background(), reference)
	if err != nil || state != port.RunnerSandboxAbsent {
		t.Fatalf("absent state = %q / %v", state, err)
	}
	if err := sandbox.Create(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	if err := sandbox.Start(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	starting := runnerlog.Progress{
		NativeBytes: 1, NormalizedBytes: 10, LastSequence: 1,
	}
	result, err := sandbox.Follow(context.Background(), reference, starting)
	if err != nil || result.State != port.RunnerSandboxPassed ||
		len(result.Chunks) != 1 || result.Chunks[0].Sequence != 2 ||
		result.LogProgress.NativeBytes <= starting.NativeBytes ||
		result.LogProgress.NormalizedBytes <= starting.NormalizedBytes ||
		result.LogProgress.LastSequence != 2 {
		t.Fatalf("follow result = %#v / %v", result, err)
	}
	if err := sandbox.Delete(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
}
