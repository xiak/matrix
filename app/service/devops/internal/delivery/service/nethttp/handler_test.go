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
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runcontrol"
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
		RunControl:    newFakeRunControl(t),
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

func TestHandlerReadsAndCancelsPipelineRunThroughExactIAMAuthority(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	workflow := newFakeWorkflow(t)
	control := newFakeRunControl(t)
	handler := mustHandlerWithControl(t, authorizer, workflow, control)
	path := "/v1/runs/" + string(control.run.ID)

	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer caller-credential")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` ||
		authorizer.request.Action != iamv1.ActionDevOpsRunRead ||
		authorizer.request.Resource != (iamv1.ResourceReference{
			Kind: iamv1.ResourcePipelineRun, ID: string(control.run.ID),
		}) || control.get.RunID != control.run.ID {
		t.Fatalf("read status=%d headers=%#v authority=%#v query=%#v body=%s",
			response.Code, response.Header(), authorizer.request, control.get, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, path+"/cancel", nil)
	request.Header.Set("Authorization", "Bearer caller-credential")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Idempotency-Key", "cancel-run-one")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` ||
		authorizer.request.Action != iamv1.ActionDevOpsRunCancel ||
		control.cancel.RunID != control.run.ID || control.cancel.ExpectedResourceVersion != 1 ||
		control.cancel.IdempotencyKey != "cancel-run-one" {
		t.Fatalf("cancel status=%d headers=%#v authority=%#v command=%#v body=%s",
			response.Code, response.Header(), authorizer.request, control.cancel, response.Body.String())
	}
	var cancelled devopsv1.PipelineRun
	if err := json.Unmarshal(response.Body.Bytes(), &cancelled); err != nil ||
		cancelled.Status.State != devopsv1.PipelineRunCancelled ||
		cancelled.Status.CancellationRequestedAt == nil {
		t.Fatalf("cancelled run=%#v err=%v", cancelled, err)
	}
}

func TestHandlerRejectsPipelineRunCancellationBodyAndMissingGuardBeforeIAM(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	control := newFakeRunControl(t)
	handler := mustHandlerWithControl(t, authorizer, newFakeWorkflow(t), control)
	path := "/v1/runs/" + string(control.run.ID) + "/cancel"

	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer caller-credential")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Idempotency-Key", "cancel-run-one")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, devopsv1.ErrorInvalidArgument)

	request = httptest.NewRequest(http.MethodPost, path, nil)
	request.Header.Set("Authorization", "Bearer caller-credential")
	request.Header.Set("Idempotency-Key", "cancel-run-one")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusPreconditionRequired, devopsv1.ErrorPreconditionRequired)
	if authorizer.calls != 0 || control.cancelCalls != 0 {
		t.Fatal("invalid cancellation crossed the IAM or run-control boundary")
	}
}

func TestHandlerReplaysPipelineRunThroughExactIAMAuthority(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	control := newFakeRunControl(t)
	terminal, err := domain.RequestPipelineRunCancellation(
		control.run, control.run.Status.ResourceVersion, false,
		control.run.UpdatedAt.Add(time.Microsecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	control.run = terminal
	handler := mustHandlerWithControl(t, authorizer, newFakeWorkflow(t), control)
	path := "/v1/runs/" + string(terminal.ID) + "/replay"
	request := httptest.NewRequest(http.MethodPost, path, nil)
	request.Header.Set("Authorization", "Bearer caller-credential")
	request.Header.Set("If-Match", `"2"`)
	request.Header.Set("Idempotency-Key", "replay-run-one")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` ||
		authorizer.request.Action != iamv1.ActionDevOpsRunReplay ||
		control.replay.SourceRunID != terminal.ID || control.replay.ExpectedResourceVersion != 2 ||
		control.replay.IdempotencyKey != "replay-run-one" {
		t.Fatalf("replay status=%d headers=%#v authority=%#v command=%#v body=%s",
			response.Code, response.Header(), authorizer.request, control.replay, response.Body.String())
	}
	var replayed devopsv1.PipelineRun
	if err := json.Unmarshal(response.Body.Bytes(), &replayed); err != nil ||
		replayed.Replay == nil || replayed.Replay.SourceRunID != terminal.ID ||
		response.Header().Get("Location") != "/v1/runs/"+string(replayed.ID) {
		t.Fatalf("replayed run=%#v headers=%#v err=%v", replayed, response.Header(), err)
	}
}

func TestHandlerRejectsPipelineRunReplayBodyAndMissingGuardBeforeIAM(t *testing.T) {
	authorizer := &fakeAuthorizer{}
	control := newFakeRunControl(t)
	handler := mustHandlerWithControl(t, authorizer, newFakeWorkflow(t), control)
	path := "/v1/runs/" + string(control.run.ID) + "/replay"

	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer caller-credential")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Idempotency-Key", "replay-run-one")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, devopsv1.ErrorInvalidArgument)

	request = httptest.NewRequest(http.MethodPost, path, nil)
	request.Header.Set("Authorization", "Bearer caller-credential")
	request.Header.Set("Idempotency-Key", "replay-run-one")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusPreconditionRequired, devopsv1.ErrorPreconditionRequired)

	request = httptest.NewRequest(http.MethodPost, "/v1/runs/pipeline-run-forged/replay", nil)
	request.Header.Set("Authorization", "Bearer caller-credential")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Idempotency-Key", "replay-run-one")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, devopsv1.ErrorInvalidArgument)
	if authorizer.calls != 0 || control.replayCalls != 0 {
		t.Fatal("invalid replay crossed the IAM or run-control boundary")
	}
}

func TestHandlerNormalizesPipelineRunControlFailures(t *testing.T) {
	tests := map[string]struct {
		err    error
		status int
		code   devopsv1.ErrorCode
	}{
		"invalid":              {runcontrol.ErrInvalidArgument, 422, devopsv1.ErrorInvalidArgument},
		"not found":            {runcontrol.ErrNotFound, 404, devopsv1.ErrorNotFound},
		"idempotency conflict": {runcontrol.ErrIdempotencyConflict, 409, devopsv1.ErrorConflict},
		"version conflict":     {runcontrol.ErrResourceVersionConflict, 412, devopsv1.ErrorPreconditionFailed},
		"already requested":    {runcontrol.ErrNoDesiredChange, 409, devopsv1.ErrorConflict},
		"terminal":             {runcontrol.ErrTerminal, 409, devopsv1.ErrorConflict},
		"not terminal":         {runcontrol.ErrNotTerminal, 409, devopsv1.ErrorConflict},
		"queue capacity":       {runcontrol.ErrQueueCapacityExceeded, 429, devopsv1.ErrorResourceExhausted},
		"retryable":            {runcontrol.ErrRetryableTransaction, 503, devopsv1.ErrorUnavailable},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			control := newFakeRunControl(t)
			control.err = errors.Join(test.err, errors.New("native cancellation detail must not leak"))
			handler := mustHandlerWithControl(t, &fakeAuthorizer{}, newFakeWorkflow(t), control)
			request := httptest.NewRequest(
				http.MethodPost, "/v1/runs/"+string(control.run.ID)+"/cancel", nil,
			)
			request.Header.Set("Authorization", "Bearer caller-credential")
			request.Header.Set("If-Match", `"1"`)
			request.Header.Set("Idempotency-Key", "cancel-run-one")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertProblem(t, response, test.status, test.code)
			if test.status == http.StatusTooManyRequests && response.Header().Get("Retry-After") != "30" {
				t.Fatalf("Retry-After=%q", response.Header().Get("Retry-After"))
			}
			if strings.Contains(response.Body.String(), "native cancellation") {
				t.Fatal("native PipelineRun control error leaked")
			}
		})
	}
}

func mustHandler(t *testing.T, authorizer *fakeAuthorizer, workflow *fakeWorkflow) http.Handler {
	return mustHandlerWithControl(t, authorizer, workflow, newFakeRunControl(t))
}

func mustHandlerWithControl(
	t *testing.T,
	authorizer *fakeAuthorizer,
	workflow *fakeWorkflow,
	control *fakeRunControl,
) http.Handler {
	t.Helper()
	readiness := devopsv1.Readiness{
		APIVersion: devopsv1.APIVersion, Kind: "Readiness", State: devopsv1.ReadinessReady,
		SchemaVersion: 1, CheckedAt: time.Date(2026, 9, 8, 4, 5, 6, 0, time.UTC),
	}
	handler, err := NewHandler(authorizer, workflow, Config{
		Readiness:     func(context.Context) (devopsv1.Readiness, error) { return readiness, nil },
		NewRequestID:  func() (string, error) { return "request-test", nil },
		SourceIngress: &fakeSourceIngress{},
		RunControl:    control,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

type fakeRunControl struct {
	run         devopsv1.PipelineRun
	get         runcontrol.GetQuery
	cancel      runcontrol.CancelCommand
	replay      runcontrol.ReplayCommand
	err         error
	getCalls    int
	cancelCalls int
	replayCalls int
}

func newFakeRunControl(t *testing.T) *fakeRunControl {
	t.Helper()
	now := time.Date(2026, 9, 8, 4, 0, 0, 0, time.UTC)
	scope := devopsv1.ResourceScope{TenantID: "tenant-authorized"}
	input := devopsv1.PipelineRunInput{
		SourceEventID:           "source-event-111111111111111111111111111111111111111111111111",
		SourceEventDigest:       "sha256:" + strings.Repeat("1", 64),
		PipelineRevisionID:      "pipeline-revision-222222222222222222222222222222222222222222222222",
		PipelineRevisionDigest:  "sha256:" + strings.Repeat("2", 64),
		RepositoryBindingID:     "binding-one",
		RepositoryBindingDigest: "sha256:" + strings.Repeat("3", 64),
		Change: devopsv1.ChangeIdentity{
			Number: 1, Action: devopsv1.ChangeOpened,
			HeadCommit: strings.Repeat("4", 40), TrustedBaseCommit: strings.Repeat("5", 40),
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
	return &fakeRunControl{run: run}
}

func (control *fakeRunControl) Get(
	_ context.Context,
	query runcontrol.GetQuery,
) (devopsv1.PipelineRun, error) {
	control.getCalls++
	control.get = query
	return control.run, control.err
}

func (control *fakeRunControl) Cancel(
	_ context.Context,
	command runcontrol.CancelCommand,
) (runcontrol.Result, error) {
	control.cancelCalls++
	control.cancel = command
	if control.err != nil {
		return runcontrol.Result{}, control.err
	}
	cancelled, err := domain.RequestPipelineRunCancellation(
		control.run, command.ExpectedResourceVersion, false,
		control.run.UpdatedAt.Add(time.Microsecond),
	)
	return runcontrol.Result{Value: cancelled}, err
}

func (control *fakeRunControl) Replay(
	_ context.Context,
	command runcontrol.ReplayCommand,
) (runcontrol.Result, error) {
	control.replayCalls++
	control.replay = command
	if control.err != nil {
		return runcontrol.Result{}, control.err
	}
	replayed, err := domain.ReplayPipelineRun(
		control.run, "operation-"+devopsv1.ResourceID(strings.Repeat("9", 64)),
		command.Authorization.Subject, control.run.UpdatedAt.Add(time.Microsecond),
	)
	return runcontrol.Result{Value: replayed}, err
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
