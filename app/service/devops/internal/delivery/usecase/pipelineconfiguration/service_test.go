package pipelineconfiguration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

func TestPipelineConfigurationJourneyIsAtomicIdempotentAndSnapshotBound(t *testing.T) {
	repository := newMemoryRepository()
	usecase, err := NewUsecase(repository, Config{MaxTransactionAttempts: 3})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	projectRequest := devopsv1.CreateDevOpsProjectRequest{ID: "project-one", Name: "project-one"}
	project, err := usecase.CreateProject(ctx, CreateProjectCommand{
		Authorization: authorization(iamv1.ActionDevOpsProjectCreate, iamv1.ResourceDevOpsProject, projectRequest.ID),
		Request:       projectRequest, IdempotencyKey: "create-project-one",
	})
	if err != nil || project.Replayed {
		t.Fatalf("create project=%#v err=%v", project, err)
	}
	replayedProject, err := usecase.CreateProject(ctx, CreateProjectCommand{
		Authorization: authorization(iamv1.ActionDevOpsProjectCreate, iamv1.ResourceDevOpsProject, projectRequest.ID),
		Request:       projectRequest, IdempotencyKey: "create-project-one",
	})
	if err != nil || !replayedProject.Replayed || replayedProject.Value != project.Value {
		t.Fatalf("replay project=%#v err=%v", replayedProject, err)
	}
	changed := projectRequest
	changed.Name = "changed-project"
	_, err = usecase.CreateProject(ctx, CreateProjectCommand{
		Authorization: authorization(iamv1.ActionDevOpsProjectCreate, iamv1.ResourceDevOpsProject, changed.ID),
		Request:       changed, IdempotencyKey: "create-project-one",
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error=%v", err)
	}

	connectionSpec := devopsv1.SourceConnectionSpec{
		AdapterID:              "source-adapter-gitea-v1",
		AllowedEndpointOrigins: []string{"https://gitea.example.com"},
		WebhookSecretRef:       "secret-webhook-1", FetchCredentialRef: "secret-fetch-1",
		ReportCredentialRef: "secret-report-1",
	}
	connectionRequest := devopsv1.CreateSourceConnectionRequest{ID: "connection-one", Name: "connection-one", Spec: connectionSpec}
	connection, err := usecase.CreateSourceConnection(ctx, CreateSourceConnectionCommand{
		Authorization: authorization(iamv1.ActionDevOpsSourceConnectionCreate, iamv1.ResourceSourceConnection, connectionRequest.ID),
		Request:       connectionRequest, IdempotencyKey: "create-connection-one",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	rotatedSpec := connectionSpec
	rotatedSpec.WebhookSecretRef = "secret-webhook-2"
	rotatedSpec.FetchCredentialRef = "secret-fetch-2"
	rotatedSpec.ReportCredentialRef = "secret-report-2"
	rotated, err := usecase.UpdateSourceConnection(ctx, UpdateSourceConnectionCommand{
		Authorization:      authorization(iamv1.ActionDevOpsSourceConnectionUpdate, iamv1.ResourceSourceConnection, connectionRequest.ID),
		SourceConnectionID: connectionRequest.ID, ExpectedResourceVersion: connection.Value.Metadata.ResourceVersion,
		Request: devopsv1.UpdateSourceConnectionRequest{Spec: rotatedSpec}, IdempotencyKey: "rotate-connection-one",
	})
	if err != nil || rotated.Value.Status.Health != devopsv1.SourceConnectionPending {
		t.Fatalf("rotate connection=%#v err=%v", rotated, err)
	}

	bindingRequest := repositoryRequest("binding-one", projectRequest.ID, connectionRequest.ID, "matrix/service", "main")
	binding, err := usecase.CreateRepositoryBinding(ctx, CreateRepositoryBindingCommand{
		Authorization: authorization(iamv1.ActionDevOpsRepositoryBindingCreate, iamv1.ResourceRepositoryBinding, bindingRequest.ID),
		Request:       bindingRequest, IdempotencyKey: "create-binding-one",
	})
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}
	secondBindingRequest := repositoryRequest("binding-two", projectRequest.ID, connectionRequest.ID, "matrix/other", "main")
	if _, err := usecase.CreateRepositoryBinding(ctx, CreateRepositoryBindingCommand{
		Authorization: authorization(iamv1.ActionDevOpsRepositoryBindingCreate, iamv1.ResourceRepositoryBinding, secondBindingRequest.ID),
		Request:       secondBindingRequest, IdempotencyKey: "create-binding-two",
	}); err != nil {
		t.Fatalf("create second binding: %v", err)
	}

	pipelineRequest := devopsv1.CreatePipelineRequest{
		ID: "pipeline-one", Name: "pipeline-one", ProjectID: projectRequest.ID,
		Draft: pipelineDraft(bindingRequest.ID),
	}
	pipeline, err := usecase.CreatePipeline(ctx, CreatePipelineCommand{
		Authorization: authorization(iamv1.ActionDevOpsPipelineCreate, iamv1.ResourcePipeline, pipelineRequest.ID),
		Request:       pipelineRequest, IdempotencyKey: "create-pipeline-one",
	})
	if err != nil {
		t.Fatalf("create pipeline: %v", err)
	}
	firstActivation, err := usecase.ActivatePipeline(ctx, ActivatePipelineCommand{
		Authorization: authorization(iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, pipelineRequest.ID),
		PipelineID:    pipelineRequest.ID, ExpectedResourceVersion: pipeline.Value.Metadata.ResourceVersion,
		IdempotencyKey: "activate-pipeline-one-v1",
	})
	if err != nil {
		t.Fatalf("activate first revision: %v", err)
	}
	firstBindingDigest := firstActivation.Value.Revision.Spec.RepositoryBindingDigest

	updatedBindingRequest := devopsv1.UpdateRepositoryBindingRequest{Spec: bindingRequest.Spec}
	updatedBindingRequest.Spec.TrustedDefaultBranch = "release"
	updatedBinding, err := usecase.UpdateRepositoryBinding(ctx, UpdateRepositoryBindingCommand{
		Authorization:       authorization(iamv1.ActionDevOpsRepositoryBindingUpdate, iamv1.ResourceRepositoryBinding, bindingRequest.ID),
		RepositoryBindingID: bindingRequest.ID, ExpectedResourceVersion: binding.Value.Metadata.ResourceVersion,
		Request: updatedBindingRequest, IdempotencyKey: "update-binding-one",
	})
	if err != nil {
		t.Fatalf("update binding: %v", err)
	}
	secondActivation, err := usecase.ActivatePipeline(ctx, ActivatePipelineCommand{
		Authorization:           authorization(iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, pipelineRequest.ID),
		PipelineID:              pipelineRequest.ID,
		ExpectedResourceVersion: firstActivation.Value.Pipeline.Metadata.ResourceVersion,
		IdempotencyKey:          "activate-pipeline-one-v2",
	})
	if err != nil {
		t.Fatalf("activate changed binding snapshot: %v", err)
	}
	if secondActivation.Value.Revision.Revision != 2 ||
		secondActivation.Value.Revision.Spec.RepositoryBindingDigest == firstBindingDigest ||
		firstActivation.Value.Revision.Spec.RepositoryBindingDigest != firstBindingDigest {
		t.Fatalf("binding snapshots were not sealed: first=%#v second=%#v", firstActivation.Value.Revision, secondActivation.Value.Revision)
	}

	updatedDraft := devopsv1.UpdatePipelineDraftRequest{Draft: pipelineDraft(secondBindingRequest.ID)}
	draftResult, err := usecase.UpdatePipelineDraft(ctx, UpdatePipelineDraftCommand{
		Authorization:           authorization(iamv1.ActionDevOpsPipelineUpdate, iamv1.ResourcePipeline, pipelineRequest.ID),
		PipelineID:              pipelineRequest.ID,
		ExpectedResourceVersion: secondActivation.Value.Pipeline.Metadata.ResourceVersion,
		Request:                 updatedDraft, IdempotencyKey: "move-pipeline-binding",
	})
	if err != nil {
		t.Fatalf("update Pipeline draft: %v", err)
	}
	thirdActivation, err := usecase.ActivatePipeline(ctx, ActivatePipelineCommand{
		Authorization: authorization(iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, pipelineRequest.ID),
		PipelineID:    pipelineRequest.ID, ExpectedResourceVersion: draftResult.Value.Metadata.ResourceVersion,
		IdempotencyKey: "activate-pipeline-one-v3",
	})
	if err != nil || thirdActivation.Value.Revision.Revision != 3 {
		t.Fatalf("third activation=%#v err=%v", thirdActivation, err)
	}

	replayedDraft, err := usecase.UpdatePipelineDraft(ctx, UpdatePipelineDraftCommand{
		Authorization:           authorization(iamv1.ActionDevOpsPipelineUpdate, iamv1.ResourcePipeline, pipelineRequest.ID),
		PipelineID:              pipelineRequest.ID,
		ExpectedResourceVersion: secondActivation.Value.Pipeline.Metadata.ResourceVersion,
		Request:                 updatedDraft, IdempotencyKey: "move-pipeline-binding",
	})
	if err != nil || !replayedDraft.Replayed || replayedDraft.Value.Metadata.ResourceVersion != draftResult.Value.Metadata.ResourceVersion ||
		replayedDraft.Value.Metadata.ResourceVersion == thirdActivation.Value.Pipeline.Metadata.ResourceVersion {
		t.Fatalf("draft replay did not preserve original snapshot: %#v err=%v", replayedDraft, err)
	}
	for _, stored := range repository.state.mutations {
		if stored.Record.Kind != MutationCreateProject {
			continue
		}
		tamperedID := stored
		tamperedID.Record.ID = "operation-tampered"
		if ValidateStoredMutation(tamperedID) == nil {
			t.Fatal("non-deterministic mutation ID was accepted")
		}
		tamperedTarget := stored
		projectCopy := *stored.Result.Project
		projectCopy.Metadata.ID = "project-other"
		tamperedTarget.Result.Project = &projectCopy
		tamperedTarget.Record.Target.ID = "project-other"
		if ValidateStoredMutation(tamperedTarget) == nil {
			t.Fatal("mutation result was retargeted away from its command")
		}
		break
	}

	if len(repository.state.mutations) != 11 || len(repository.state.audits) != 11 {
		t.Fatalf("mutation/audit count=%d/%d", len(repository.state.mutations), len(repository.state.audits))
	}
	for _, event := range repository.state.audits {
		if err := auditv1.ValidateEventForSource(auditv1.SourceDevOps, event); err != nil {
			t.Fatalf("invalid Audit event: %v", err)
		}
	}
	if updatedBinding.Value.ContentDigest == firstBindingDigest {
		t.Fatal("binding update did not change digest")
	}
}

func TestPipelineConfigurationRejectsMismatchedAuthorityAndRetriesSerialization(t *testing.T) {
	repository := newMemoryRepository()
	repository.retryOnce = true
	usecase, _ := NewUsecase(repository, Config{MaxTransactionAttempts: 3})
	request := devopsv1.CreateDevOpsProjectRequest{ID: "project-retry", Name: "project-retry"}
	result, err := usecase.CreateProject(context.Background(), CreateProjectCommand{
		Authorization: authorization(iamv1.ActionDevOpsProjectCreate, iamv1.ResourceDevOpsProject, request.ID),
		Request:       request, IdempotencyKey: "retry-project",
	})
	if err != nil || result.Replayed || repository.calls != 2 {
		t.Fatalf("retry result=%#v calls=%d err=%v", result, repository.calls, err)
	}

	wrong := authorization(iamv1.ActionDevOpsProjectRead, iamv1.ResourceDevOpsProject, "project-wrong")
	_, err = usecase.CreateProject(context.Background(), CreateProjectCommand{
		Authorization:  wrong,
		Request:        devopsv1.CreateDevOpsProjectRequest{ID: "project-wrong", Name: "project-wrong"},
		IdempotencyKey: "wrong-authority",
	})
	if !errors.Is(err, ErrInvalidArgument) || repository.calls != 2 {
		t.Fatalf("authority error=%v calls=%d", err, repository.calls)
	}
}

func authorization(action iamv1.Action, kind iamv1.ResourceKind, id devopsv1.ResourceID) port.Authorization {
	return port.Authorization{
		TenantID: "tenant-one", Subject: devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-one"},
		DecisionID: "decision-" + string(id), Action: action,
		Resource:  iamv1.ResourceReference{Kind: kind, ID: string(id)},
		RequestID: "request-one", CorrelationID: "correlation-one",
		TraceParent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
	}
}

func repositoryRequest(id, projectID, connectionID devopsv1.ResourceID, path, branch string) devopsv1.CreateRepositoryBindingRequest {
	return devopsv1.CreateRepositoryBindingRequest{
		ID: id, Name: string(id), ProjectID: projectID,
		Spec: devopsv1.RepositoryBindingSpec{
			SourceConnectionID: connectionID, ExternalRepositoryID: "external-" + id,
			RepositoryPath: path, TrustedDefaultBranch: branch,
		},
	}
}

func pipelineDraft(bindingID devopsv1.ResourceID) devopsv1.PipelineDraftSpec {
	return devopsv1.PipelineDraftSpec{
		RepositoryBindingID: bindingID, TriggerPolicy: devopsv1.TriggerChange,
		VerificationProfile: devopsv1.VerificationGo126OfflineV1,
		DependencyEgress:    devopsv1.DependencyEgressNone, ReporterPolicy: devopsv1.ReporterChangeCheckV1,
	}
}

type memoryState struct {
	projects    map[devopsv1.ResourceID]devopsv1.DevOpsProject
	connections map[devopsv1.ResourceID]devopsv1.SourceConnection
	bindings    map[devopsv1.ResourceID]devopsv1.RepositoryBinding
	pipelines   map[devopsv1.ResourceID]devopsv1.Pipeline
	mutations   map[string]StoredMutation
	audits      map[string]auditv1.Event
}

type memoryRepository struct {
	mu        sync.Mutex
	state     *memoryState
	now       time.Time
	retryOnce bool
	calls     int
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{state: &memoryState{
		projects: map[devopsv1.ResourceID]devopsv1.DevOpsProject{}, connections: map[devopsv1.ResourceID]devopsv1.SourceConnection{},
		bindings: map[devopsv1.ResourceID]devopsv1.RepositoryBinding{}, pipelines: map[devopsv1.ResourceID]devopsv1.Pipeline{},
		mutations: map[string]StoredMutation{}, audits: map[string]auditv1.Event{},
	}, now: time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)}
}

func (r *memoryRepository) WithinTransaction(ctx context.Context, tenant devopsv1.TenantID, callback func(context.Context, Transaction) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.retryOnce {
		r.retryOnce = false
		return ErrRetryableTransaction
	}
	if tenant != "tenant-one" {
		return fmt.Errorf("unexpected tenant %s", tenant)
	}
	return callback(ctx, &memoryTransaction{repository: r})
}

type memoryTransaction struct{ repository *memoryRepository }

func (tx *memoryTransaction) TransactionTime(context.Context) (time.Time, error) {
	tx.repository.now = tx.repository.now.Add(time.Microsecond)
	return tx.repository.now, nil
}
func (tx *memoryTransaction) FindMutation(_ context.Context, fingerprint string) (StoredMutation, bool, error) {
	v, ok := tx.repository.state.mutations[fingerprint]
	return v, ok, nil
}
func (tx *memoryTransaction) LoadProject(_ context.Context, id devopsv1.ResourceID) (devopsv1.DevOpsProject, bool, error) {
	v, ok := tx.repository.state.projects[id]
	return v, ok, nil
}
func (tx *memoryTransaction) LoadSourceConnection(_ context.Context, id devopsv1.ResourceID) (devopsv1.SourceConnection, bool, error) {
	v, ok := tx.repository.state.connections[id]
	return v, ok, nil
}
func (tx *memoryTransaction) LoadRepositoryBinding(_ context.Context, id devopsv1.ResourceID) (devopsv1.RepositoryBinding, bool, error) {
	v, ok := tx.repository.state.bindings[id]
	return v, ok, nil
}
func (tx *memoryTransaction) LoadPipeline(_ context.Context, id devopsv1.ResourceID) (devopsv1.Pipeline, bool, error) {
	v, ok := tx.repository.state.pipelines[id]
	return v, ok, nil
}
func (tx *memoryTransaction) CreateProject(_ context.Context, v devopsv1.DevOpsProject, s Submission) error {
	tx.repository.state.projects[v.Metadata.ID] = v
	return tx.record(s)
}
func (tx *memoryTransaction) CreateSourceConnection(_ context.Context, v devopsv1.SourceConnection, s Submission) error {
	tx.repository.state.connections[v.Metadata.ID] = v
	return tx.record(s)
}
func (tx *memoryTransaction) UpdateSourceConnection(_ context.Context, _ uint64, v devopsv1.SourceConnection, s Submission) error {
	tx.repository.state.connections[v.Metadata.ID] = v
	return tx.record(s)
}
func (tx *memoryTransaction) CreateRepositoryBinding(_ context.Context, v devopsv1.RepositoryBinding, s Submission) error {
	tx.repository.state.bindings[v.Metadata.ID] = v
	return tx.record(s)
}
func (tx *memoryTransaction) UpdateRepositoryBinding(_ context.Context, _ uint64, v devopsv1.RepositoryBinding, s Submission) error {
	tx.repository.state.bindings[v.Metadata.ID] = v
	return tx.record(s)
}
func (tx *memoryTransaction) CreatePipeline(_ context.Context, v devopsv1.Pipeline, s Submission) error {
	tx.repository.state.pipelines[v.Metadata.ID] = v
	return tx.record(s)
}
func (tx *memoryTransaction) UpdatePipelineDraft(_ context.Context, _ uint64, v devopsv1.Pipeline, s Submission) error {
	tx.repository.state.pipelines[v.Metadata.ID] = v
	return tx.record(s)
}
func (tx *memoryTransaction) ActivatePipeline(_ context.Context, _ uint64, v devopsv1.PipelineActivation, s Submission) error {
	tx.repository.state.pipelines[v.Pipeline.Metadata.ID] = v.Pipeline
	return tx.record(s)
}
func (tx *memoryTransaction) record(s Submission) error {
	tx.repository.state.mutations[s.Record.IdempotencyFingerprint] = StoredMutation{Record: s.Record, Result: s.Result}
	tx.repository.state.audits[string(s.AuditEvent.EventID)] = s.AuditEvent
	return nil
}
