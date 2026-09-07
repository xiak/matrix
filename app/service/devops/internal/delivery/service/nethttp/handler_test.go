package nethttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
)

func TestHandlerReadinessIsAnonymousExactAndSanitized(t *testing.T) {
	readyErr := error(nil)
	readiness := devopsv1.Readiness{
		APIVersion: devopsv1.APIVersion, Kind: "Readiness", State: devopsv1.ReadinessReady,
		SchemaVersion: 1, CheckedAt: time.Date(2026, 9, 8, 4, 5, 6, 789_000, time.UTC),
	}
	handler, err := NewHandler(&fakeAuthorizer{}, newFakeWorkflow(t), Config{
		Readiness:     func(context.Context) (devopsv1.Readiness, error) { return readiness, readyErr },
		NewRequestID:  func() (string, error) { return "request-test", nil },
		SourceIngress: &fakeSourceIngress{},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if response.Code != http.StatusOK || response.Header().Get("Matrix-Request-ID") != "request-test" {
		t.Fatalf("readiness status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var got devopsv1.Readiness
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || got != readiness {
		t.Fatalf("readiness=%#v err=%v", got, err)
	}
	readyErr = errors.New("database credential=do-not-expose")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
	assertProblem(t, response, http.StatusServiceUnavailable, devopsv1.ErrorUnavailable)
	if strings.Contains(response.Body.String(), "credential") || strings.Contains(response.Body.String(), "do-not-expose") {
		t.Fatalf("native readiness error leaked: %s", response.Body.String())
	}
}

func TestHandlerCreatesProjectWithExactIAMAuthorityAndNoCallerTenant(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := newFakeWorkflow(t)
	handler := mustHandler(t, authorizer, workflow)
	request := jsonRequest(t, http.MethodPost, "/v1/projects", devopsv1.CreateDevOpsProjectRequest{
		ID: "project-one", Name: "project-one",
	})
	request.Header.Set("Authorization", "Bearer caller-credential")
	request.Header.Set("Idempotency-Key", "create-project-one")
	request.Header.Set("Matrix-Correlation-ID", "correlation-one")
	request.Header.Set("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("Location") != "/v1/projects/project-one" ||
		response.Header().Get("ETag") != `"1"` {
		t.Fatalf("create status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if authorizer.request.Resource != (iamv1.ResourceReference{Kind: iamv1.ResourceDevOpsProject, ID: "project-one"}) ||
		authorizer.request.Action != iamv1.ActionDevOpsProjectCreate ||
		authorizer.request.Credential != "Bearer caller-credential" ||
		authorizer.request.CorrelationID != "correlation-one" ||
		workflow.createProject.Authorization.TenantID != "tenant-authorized" ||
		workflow.createProject.Authorization.Subject.ID != "user-authorized" {
		t.Fatalf("authorization=%#v command=%#v", authorizer.request, workflow.createProject)
	}

	for _, forbiddenHeader := range forbiddenAuthorityHeaders {
		request = jsonRequest(t, http.MethodPost, "/v1/projects", devopsv1.CreateDevOpsProjectRequest{
			ID: "project-one", Name: "project-one",
		})
		request.Header.Set("Authorization", "Bearer caller-credential")
		request.Header.Set("Idempotency-Key", "create-project-one")
		request.Header.Set(forbiddenHeader, "forged")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assertProblem(t, response, http.StatusBadRequest, devopsv1.ErrorInvalidArgument)
	}
	if workflow.createProjectCalls != 1 {
		t.Fatalf("forged authority headers reached workflow %d times", workflow.createProjectCalls)
	}
}

func TestHandlerRequiresMissingIfMatchAs428AndBindsUpdateVersion(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := newFakeWorkflow(t)
	handler := mustHandler(t, authorizer, workflow)
	update := devopsv1.UpdateSourceConnectionRequest{Spec: workflow.connection.Spec}
	request := jsonRequest(t, http.MethodPut, "/v1/source-connections/connection-one", update)
	request.Header.Set("Authorization", "Bearer caller-credential")
	request.Header.Set("Idempotency-Key", "rotate-connection")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusPreconditionRequired, devopsv1.ErrorPreconditionRequired)
	if authorizer.calls != 0 || workflow.updateConnectionCalls != 0 {
		t.Fatal("update without If-Match crossed an authority boundary")
	}

	request = jsonRequest(t, http.MethodPut, "/v1/source-connections/connection-one", update)
	request.Header.Set("Authorization", "Bearer caller-credential")
	request.Header.Set("Idempotency-Key", "rotate-connection")
	request.Header.Set("If-Match", `"7"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` {
		t.Fatalf("update status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if workflow.updateConnection.ExpectedResourceVersion != 7 ||
		authorizer.request.Action != iamv1.ActionDevOpsSourceConnectionUpdate ||
		authorizer.request.Resource.ID != "connection-one" {
		t.Fatalf("update command=%#v authorization=%#v", workflow.updateConnection, authorizer.request)
	}
}

func TestHandlerReadsRevisionThroughParentPipelineAuthority(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := newFakeWorkflow(t)
	handler := mustHandler(t, authorizer, workflow)
	path := "/v1/pipelines/pipeline-one/revisions/" + string(workflow.revision.ID)
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer caller-credential")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != quotedETag(workflow.revision.ContentDigest) {
		t.Fatalf("revision status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if authorizer.request.Action != iamv1.ActionDevOpsPipelineRead ||
		authorizer.request.Resource != (iamv1.ResourceReference{Kind: iamv1.ResourcePipeline, ID: "pipeline-one"}) ||
		workflow.getRevision.PipelineID != "pipeline-one" || workflow.getRevision.PipelineRevisionID != workflow.revision.ID {
		t.Fatalf("revision authorization=%#v query=%#v", authorizer.request, workflow.getRevision)
	}
	legacy := httptest.NewRequest(http.MethodGet, "/v1/pipeline-revisions/"+string(workflow.revision.ID), nil)
	legacy.Header.Set("Authorization", "Bearer caller-credential")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, legacy)
	assertProblem(t, response, http.StatusNotFound, devopsv1.ErrorNotFound)
}

func TestHandlerRejectsAmbiguousOversizeAndUnsupportedDocumentsBeforeIAM(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := newFakeWorkflow(t)
	handler := mustHandler(t, authorizer, workflow)
	tests := []struct {
		name        string
		contentType string
		body        string
		status      int
		code        devopsv1.ErrorCode
	}{
		{"unknown authority", "application/json", `{"id":"project-one","name":"project-one","tenantId":"forged"}`, 400, devopsv1.ErrorInvalidArgument},
		{"duplicate", "application/json", `{"id":"project-one","id":"project-two","name":"project-one"}`, 400, devopsv1.ErrorInvalidArgument},
		{"unsupported", "text/plain", `{}`, 415, devopsv1.ErrorUnsupportedMediaType},
		{"oversize", "application/json", `{"id":"` + strings.Repeat("x", int(devopsv1.MaxDocumentBytes)) + `"}`, 413, devopsv1.ErrorPayloadTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/projects", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Authorization", "Bearer caller-credential")
			request.Header.Set("Idempotency-Key", "create-project")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertProblem(t, response, test.status, test.code)
		})
	}
	if authorizer.calls != 0 || workflow.createProjectCalls != 0 {
		t.Fatal("invalid client documents crossed the IAM or workflow boundary")
	}
}

func TestHandlerFailsClosedOnIAMDenialAndDecisionDrift(t *testing.T) {
	workflow := newFakeWorkflow(t)
	authorizer := &fakeAuthorizer{err: errors.Join(port.ErrPermissionDenied, errors.New("token=do-not-expose"))}
	handler := mustHandler(t, authorizer, workflow)
	request := httptest.NewRequest(http.MethodGet, "/v1/projects/project-one", nil)
	request.Header.Set("Authorization", "Bearer caller-credential")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusForbidden, devopsv1.ErrorForbidden)
	if strings.Contains(response.Body.String(), "do-not-expose") || workflow.getProjectCalls != 0 {
		t.Fatal("IAM denial leaked or reached workflow")
	}

	authorizer = &fakeAuthorizer{driftRequestID: true}
	handler = mustHandler(t, authorizer, workflow)
	request = httptest.NewRequest(http.MethodGet, "/v1/projects/project-one", nil)
	request.Header.Set("Authorization", "Bearer caller-credential")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusServiceUnavailable, devopsv1.ErrorUnavailable)
	if workflow.getProjectCalls != 0 {
		t.Fatal("drifted IAM decision reached workflow")
	}
}

func TestHandlerNormalizesMethodAndWorkflowFailures(t *testing.T) {
	workflow := newFakeWorkflow(t)
	handler := mustHandler(t, &fakeAuthorizer{}, workflow)
	request := httptest.NewRequest(http.MethodDelete, "/v1/projects/project-one", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusMethodNotAllowed, devopsv1.ErrorMethodNotAllowed)
	if response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("Allow=%q", response.Header().Get("Allow"))
	}

	workflow.err = errors.Join(pipelineconfiguration.ErrResourceVersionConflict, errors.New("native SQL detail"))
	request = jsonRequest(t, http.MethodPut, "/v1/source-connections/connection-one",
		devopsv1.UpdateSourceConnectionRequest{Spec: workflow.connection.Spec})
	request.Header.Set("Authorization", "Bearer caller-credential")
	request.Header.Set("Idempotency-Key", "rotate-connection")
	request.Header.Set("If-Match", `"1"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusPreconditionFailed, devopsv1.ErrorPreconditionFailed)
	if strings.Contains(response.Body.String(), "native SQL") {
		t.Fatal("native workflow error leaked")
	}
}

func mustHandler(t *testing.T, authorizer *fakeAuthorizer, workflow *fakeWorkflow) http.Handler {
	t.Helper()
	readiness := devopsv1.Readiness{
		APIVersion: devopsv1.APIVersion, Kind: "Readiness", State: devopsv1.ReadinessReady,
		SchemaVersion: 1, CheckedAt: time.Date(2026, 9, 8, 4, 5, 6, 0, time.UTC),
	}
	handler, err := NewHandler(authorizer, workflow, Config{
		Readiness:     func(context.Context) (devopsv1.Readiness, error) { return readiness, nil },
		NewRequestID:  func() (string, error) { return "request-test", nil },
		SourceIngress: &fakeSourceIngress{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func jsonRequest(t *testing.T, method, path string, value any) *http.Request {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func assertProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code devopsv1.ErrorCode) {
	t.Helper()
	if response.Code != status || response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("problem status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var problem devopsv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil ||
		devopsv1.ValidateProblem(problem) != nil || problem.Code != code || problem.Status != status {
		t.Fatalf("problem=%#v err=%v", problem, err)
	}
}

type fakeAuthorizer struct {
	request        port.AuthorizationRequest
	calls          int
	err            error
	driftRequestID bool
}

func (authorizer *fakeAuthorizer) Authorize(_ context.Context, request port.AuthorizationRequest) (port.Authorization, error) {
	authorizer.calls++
	authorizer.request = request
	if authorizer.err != nil {
		return port.Authorization{}, authorizer.err
	}
	requestID := request.RequestID
	if authorizer.driftRequestID {
		requestID = "request-other"
	}
	return port.Authorization{
		TenantID: "tenant-authorized", Subject: devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-authorized"},
		DecisionID: "decision-authorized", Action: request.Action, Resource: request.Resource,
		RequestID: requestID, CorrelationID: request.CorrelationID, TraceParent: request.TraceParent,
	}, nil
}

type fakeWorkflow struct {
	project    devopsv1.DevOpsProject
	connection devopsv1.SourceConnection
	binding    devopsv1.RepositoryBinding
	pipeline   devopsv1.Pipeline
	revision   devopsv1.PipelineRevision
	activation devopsv1.PipelineActivation
	err        error

	createProject         pipelineconfiguration.CreateProjectCommand
	createProjectCalls    int
	updateConnection      pipelineconfiguration.UpdateSourceConnectionCommand
	updateConnectionCalls int
	getProjectCalls       int
	getRevision           pipelineconfiguration.GetPipelineRevisionQuery
}

func newFakeWorkflow(t *testing.T) *fakeWorkflow {
	t.Helper()
	now := time.Date(2026, 9, 8, 4, 0, 0, 0, time.UTC)
	scope := devopsv1.ResourceScope{TenantID: "tenant-authorized"}
	project, err := domain.NewDevOpsProject(devopsv1.CreateDevOpsProjectRequest{ID: "project-one", Name: "project-one"}, scope, now)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := domain.NewSourceConnection(devopsv1.CreateSourceConnectionRequest{
		ID: "connection-one", Name: "connection-one",
		Spec: devopsv1.SourceConnectionSpec{
			AdapterID: "source-adapter-one", AllowedEndpointOrigins: []string{"https://git.example.com"},
			WebhookSecretRef: "secret-webhook", FetchCredentialRef: "secret-fetch", ReportCredentialRef: "secret-report",
		},
	}, scope, now)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := domain.NewRepositoryBinding(devopsv1.CreateRepositoryBindingRequest{
		ID: "binding-one", Name: "binding-one", ProjectID: project.Metadata.ID,
		Spec: devopsv1.RepositoryBindingSpec{
			SourceConnectionID: connection.Metadata.ID, ExternalRepositoryID: "repository-one",
			RepositoryPath: "matrix/service", TrustedDefaultBranch: "main",
		},
	}, project, connection, now)
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := domain.NewPipeline(devopsv1.CreatePipelineRequest{
		ID: "pipeline-one", Name: "pipeline-one", ProjectID: project.Metadata.ID,
		Draft: devopsv1.PipelineDraftSpec{
			RepositoryBindingID: binding.Metadata.ID, TriggerPolicy: devopsv1.TriggerChange,
			VerificationProfile: devopsv1.VerificationGo126OfflineV1,
			DependencyEgress:    devopsv1.DependencyEgressNone, ReporterPolicy: devopsv1.ReporterChangeCheckV1,
		},
	}, project, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := domain.ActivatePipeline(
		pipeline, pipeline.Metadata.ResourceVersion,
		devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-authorized"}, binding, now.Add(time.Microsecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeWorkflow{
		project: project, connection: connection, binding: binding,
		pipeline: activation.Pipeline, revision: activation.Revision, activation: activation,
	}
}

func (workflow *fakeWorkflow) GetProject(_ context.Context, query pipelineconfiguration.GetProjectQuery) (devopsv1.DevOpsProject, error) {
	workflow.getProjectCalls++
	return workflow.project, workflow.err
}
func (workflow *fakeWorkflow) GetSourceConnection(context.Context, pipelineconfiguration.GetSourceConnectionQuery) (devopsv1.SourceConnection, error) {
	return workflow.connection, workflow.err
}
func (workflow *fakeWorkflow) GetRepositoryBinding(context.Context, pipelineconfiguration.GetRepositoryBindingQuery) (devopsv1.RepositoryBinding, error) {
	return workflow.binding, workflow.err
}
func (workflow *fakeWorkflow) GetPipeline(context.Context, pipelineconfiguration.GetPipelineQuery) (devopsv1.Pipeline, error) {
	return workflow.pipeline, workflow.err
}
func (workflow *fakeWorkflow) GetPipelineRevision(_ context.Context, query pipelineconfiguration.GetPipelineRevisionQuery) (devopsv1.PipelineRevision, error) {
	workflow.getRevision = query
	return workflow.revision, workflow.err
}
func (workflow *fakeWorkflow) CreateProject(_ context.Context, command pipelineconfiguration.CreateProjectCommand) (pipelineconfiguration.Result[devopsv1.DevOpsProject], error) {
	workflow.createProjectCalls++
	workflow.createProject = command
	return pipelineconfiguration.Result[devopsv1.DevOpsProject]{Value: workflow.project}, workflow.err
}
func (workflow *fakeWorkflow) CreateSourceConnection(context.Context, pipelineconfiguration.CreateSourceConnectionCommand) (pipelineconfiguration.Result[devopsv1.SourceConnection], error) {
	return pipelineconfiguration.Result[devopsv1.SourceConnection]{Value: workflow.connection}, workflow.err
}
func (workflow *fakeWorkflow) UpdateSourceConnection(_ context.Context, command pipelineconfiguration.UpdateSourceConnectionCommand) (pipelineconfiguration.Result[devopsv1.SourceConnection], error) {
	workflow.updateConnectionCalls++
	workflow.updateConnection = command
	return pipelineconfiguration.Result[devopsv1.SourceConnection]{Value: workflow.connection}, workflow.err
}
func (workflow *fakeWorkflow) CreateRepositoryBinding(context.Context, pipelineconfiguration.CreateRepositoryBindingCommand) (pipelineconfiguration.Result[devopsv1.RepositoryBinding], error) {
	return pipelineconfiguration.Result[devopsv1.RepositoryBinding]{Value: workflow.binding}, workflow.err
}
func (workflow *fakeWorkflow) UpdateRepositoryBinding(context.Context, pipelineconfiguration.UpdateRepositoryBindingCommand) (pipelineconfiguration.Result[devopsv1.RepositoryBinding], error) {
	return pipelineconfiguration.Result[devopsv1.RepositoryBinding]{Value: workflow.binding}, workflow.err
}
func (workflow *fakeWorkflow) CreatePipeline(context.Context, pipelineconfiguration.CreatePipelineCommand) (pipelineconfiguration.Result[devopsv1.Pipeline], error) {
	return pipelineconfiguration.Result[devopsv1.Pipeline]{Value: workflow.pipeline}, workflow.err
}
func (workflow *fakeWorkflow) UpdatePipelineDraft(context.Context, pipelineconfiguration.UpdatePipelineDraftCommand) (pipelineconfiguration.Result[devopsv1.Pipeline], error) {
	return pipelineconfiguration.Result[devopsv1.Pipeline]{Value: workflow.pipeline}, workflow.err
}
func (workflow *fakeWorkflow) ActivatePipeline(context.Context, pipelineconfiguration.ActivatePipelineCommand) (pipelineconfiguration.Result[devopsv1.PipelineActivation], error) {
	return pipelineconfiguration.Result[devopsv1.PipelineActivation]{Value: workflow.activation}, workflow.err
}
