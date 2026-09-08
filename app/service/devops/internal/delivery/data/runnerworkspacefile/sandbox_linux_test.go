//go:build linux

package runnerworkspacefile

import (
	"context"
	"strings"
	"testing"

	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/runnersandboxdocker"
)

func TestPublishedWorkspaceIsTheOnlyStepPlanMount(t *testing.T) {
	_, store, request, source, workspace := publishedWorkspace(t, '9')
	defer store.Close()
	effectID := "matrix-build-" + strings.TrimPrefix(workspace.ExecutionID, "sha256:")[:48]
	for _, step := range request.Steps {
		plan, err := runnersandboxdocker.NewStepPlan(
			effectID, step, workspace.SourceRoot,
		)
		if err != nil {
			t.Fatalf("step %d plan: %v", step.Ordinal, err)
		}
		if plan.Name() == "" {
			t.Fatalf("step %d has no deterministic container name", step.Ordinal)
		}
	}

	archive, err := store.Ensure(
		context.Background(),
		workspace.ExecutionID,
		request,
		archiveReader(source),
	)
	if err != nil || archive != workspace {
		t.Fatalf("workspace replay = %#v, error = %v", archive, err)
	}
}
