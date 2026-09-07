package domain

import (
	"errors"
	"math"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestProjectAndPipelineCreationDeriveServerOwnedState(t *testing.T) {
	at := domainTime()
	scope := devopsv1.ResourceScope{TenantID: "organization-acme"}
	project, err := NewDevOpsProject(devopsv1.CreateDevOpsProjectRequest{
		ID: "devops-project-platform", Name: "platform",
	}, scope, at)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if project.Metadata.Scope != scope || project.Metadata.ResourceVersion != 1 ||
		project.Metadata.CreatedAt != at || project.Metadata.UpdatedAt != at {
		t.Fatalf("project metadata = %#v", project.Metadata)
	}

	pipeline, err := NewPipeline(validCreatePipelineRequest(), scope, at)
	if err != nil {
		t.Fatalf("create Pipeline: %v", err)
	}
	if pipeline.Metadata.ResourceVersion != 1 || pipeline.ActiveRevision != nil {
		t.Fatalf("new Pipeline state = %#v", pipeline)
	}
	if pipeline.Draft.ContentDigest != devopsv1.PipelineDraftSpecDigest(pipeline.Draft.Spec) {
		t.Fatal("new Pipeline did not seal its draft")
	}
}

func TestDraftUpdateIsOptimisticAndDoesNotChangeActiveRevision(t *testing.T) {
	pipeline := mustNewPipeline(t)
	activation, err := ActivatePipeline(
		pipeline,
		pipeline.Metadata.ResourceVersion,
		devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-alice"},
		pipeline.Metadata.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("activate Pipeline: %v", err)
	}
	current := activation.Pipeline
	request := devopsv1.UpdatePipelineDraftRequest{Draft: current.Draft.Spec}
	request.Draft.RepositoryBindingID = "repository-binding-next"
	updated, err := UpdatePipelineDraft(
		current,
		current.Metadata.ResourceVersion,
		request,
		current.Metadata.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("update draft: %v", err)
	}
	if updated.Metadata.ResourceVersion != current.Metadata.ResourceVersion+1 {
		t.Fatalf("resource version = %d", updated.Metadata.ResourceVersion)
	}
	if updated.ActiveRevision == nil || current.ActiveRevision == nil ||
		*updated.ActiveRevision != *current.ActiveRevision {
		t.Fatal("draft update changed the active immutable revision")
	}
	if updated.Draft.ContentDigest == current.Draft.ContentDigest {
		t.Fatal("draft update retained the old digest")
	}
	if current.Draft.Spec.RepositoryBindingID != "repository-binding-api" {
		t.Fatal("draft update mutated the input value")
	}
	updated.ActiveRevision.ID = "pipeline-revision-mutated"
	if current.ActiveRevision.ID == updated.ActiveRevision.ID {
		t.Fatal("draft update shared its active-revision pointer with the input")
	}
}

func TestActivationResolvesOneImmutableTrustedRevision(t *testing.T) {
	pipeline := mustNewPipeline(t)
	actor := devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-alice"}
	activatedAt := pipeline.Metadata.UpdatedAt.Add(time.Minute)
	activation, err := ActivatePipeline(
		pipeline,
		pipeline.Metadata.ResourceVersion,
		actor,
		activatedAt,
	)
	if err != nil {
		t.Fatalf("activate Pipeline: %v", err)
	}
	if err := devopsv1.ValidatePipelineActivation(activation); err != nil {
		t.Fatalf("validate activation: %v", err)
	}
	revision := activation.Revision
	if revision.Revision != 1 || revision.ActivatedBy != actor || revision.ActivatedAt != activatedAt {
		t.Fatalf("revision identity = %#v", revision)
	}
	if revision.Spec.ExecutorProfile != devopsv1.ExecutorMatrixNativeIsolatedV1 ||
		revision.Spec.ToolchainImageDigest != devopsv1.Go126OfflineToolchainImageDigest ||
		revision.Spec.DependencyEgress != devopsv1.DependencyEgressNone ||
		revision.Spec.Limits != devopsv1.FixedVerificationLimits() {
		t.Fatalf("resolved execution profile = %#v", revision.Spec)
	}
	steps := devopsv1.FixedVerificationSteps()
	if len(revision.Spec.Steps) != len(steps) || revision.Spec.Steps[0] != steps[0] ||
		revision.Spec.Steps[1] != steps[1] {
		t.Fatalf("resolved steps = %#v", revision.Spec.Steps)
	}
	if pipeline.ActiveRevision != nil || pipeline.Metadata.ResourceVersion != 1 {
		t.Fatal("activation mutated the input Pipeline")
	}

	wantID, err := devopsv1.PipelineRevisionID(
		revision.Scope,
		revision.PipelineID,
		revision.Revision,
		revision.ContentDigest,
	)
	if err != nil || revision.ID != wantID {
		t.Fatalf("revision ID = %q, want %q, error %v", revision.ID, wantID, err)
	}
}

func TestActivationRejectsUnchangedAndStaleDrafts(t *testing.T) {
	pipeline := mustNewPipeline(t)
	actor := devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-alice"}
	activation, err := ActivatePipeline(
		pipeline,
		pipeline.Metadata.ResourceVersion,
		actor,
		pipeline.Metadata.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("first activation: %v", err)
	}
	_, err = ActivatePipeline(
		activation.Pipeline,
		activation.Pipeline.Metadata.ResourceVersion,
		actor,
		activation.Pipeline.Metadata.UpdatedAt.Add(time.Minute),
	)
	if !errors.Is(err, ErrUnchangedDraft) {
		t.Fatalf("unchanged activation error = %v", err)
	}
	_, err = ActivatePipeline(
		activation.Pipeline,
		pipeline.Metadata.ResourceVersion,
		actor,
		activation.Pipeline.Metadata.UpdatedAt.Add(time.Minute),
	)
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale activation error = %v", err)
	}
}

func TestSecondActivationKeepsFirstRevisionImmutable(t *testing.T) {
	pipeline := mustNewPipeline(t)
	actor := devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-alice"}
	first, err := ActivatePipeline(
		pipeline,
		pipeline.Metadata.ResourceVersion,
		actor,
		pipeline.Metadata.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("first activation: %v", err)
	}
	firstRevision := first.Revision
	request := devopsv1.UpdatePipelineDraftRequest{Draft: first.Pipeline.Draft.Spec}
	request.Draft.RepositoryBindingID = "repository-binding-next"
	updated, err := UpdatePipelineDraft(
		first.Pipeline,
		first.Pipeline.Metadata.ResourceVersion,
		request,
		first.Pipeline.Metadata.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("update draft: %v", err)
	}
	second, err := ActivatePipeline(
		updated,
		updated.Metadata.ResourceVersion,
		actor,
		updated.Metadata.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("second activation: %v", err)
	}
	if second.Revision.Revision != 2 || second.Revision.ID == firstRevision.ID ||
		second.Revision.ContentDigest == firstRevision.ContentDigest {
		t.Fatalf("second revision = %#v", second.Revision)
	}
	if firstRevision.Spec.RepositoryBindingID != "repository-binding-api" {
		t.Fatal("later activation mutated the first revision")
	}
}

func TestPipelineMutationsFailClosedAtBoundaryValues(t *testing.T) {
	pipeline := mustNewPipeline(t)
	request := devopsv1.UpdatePipelineDraftRequest{Draft: pipeline.Draft.Spec}
	request.Draft.RepositoryBindingID = "repository-binding-next"
	if _, err := UpdatePipelineDraft(
		pipeline,
		pipeline.Metadata.ResourceVersion,
		request,
		pipeline.Metadata.UpdatedAt,
	); !errors.Is(err, ErrInvalidTime) {
		t.Fatalf("non-monotonic time error = %v", err)
	}
	pipeline.Metadata.ResourceVersion = math.MaxUint64
	if _, err := UpdatePipelineDraft(
		pipeline,
		math.MaxUint64,
		request,
		pipeline.Metadata.UpdatedAt.Add(time.Minute),
	); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("version exhaustion error = %v", err)
	}
}

func validCreatePipelineRequest() devopsv1.CreatePipelineRequest {
	return devopsv1.CreatePipelineRequest{
		ID: "pipeline-verify-change", Name: "verify-change",
		ProjectID: "devops-project-platform",
		Draft: devopsv1.PipelineDraftSpec{
			RepositoryBindingID: "repository-binding-api",
			TriggerPolicy:       devopsv1.TriggerChange,
			VerificationProfile: devopsv1.VerificationGo126OfflineV1,
			DependencyEgress:    devopsv1.DependencyEgressNone,
			ReporterPolicy:      devopsv1.ReporterChangeCheckV1,
		},
	}
}

func mustNewPipeline(t *testing.T) devopsv1.Pipeline {
	t.Helper()
	pipeline, err := NewPipeline(
		validCreatePipelineRequest(),
		devopsv1.ResourceScope{TenantID: "organization-acme"},
		domainTime(),
	)
	if err != nil {
		t.Fatalf("create Pipeline: %v", err)
	}
	return pipeline
}

func domainTime() time.Time {
	return time.Date(2026, 9, 7, 4, 5, 6, 0, time.UTC)
}
