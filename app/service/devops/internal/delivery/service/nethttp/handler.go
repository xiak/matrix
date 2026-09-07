// Package nethttp exposes the strict Matrix DevOps delivery v1 HTTP boundary.
package nethttp

import (
	"context"
	"errors"
	"net/http"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
)

type Workflow interface {
	GetProject(context.Context, pipelineconfiguration.GetProjectQuery) (devopsv1.DevOpsProject, error)
	GetSourceConnection(context.Context, pipelineconfiguration.GetSourceConnectionQuery) (devopsv1.SourceConnection, error)
	GetRepositoryBinding(context.Context, pipelineconfiguration.GetRepositoryBindingQuery) (devopsv1.RepositoryBinding, error)
	GetPipeline(context.Context, pipelineconfiguration.GetPipelineQuery) (devopsv1.Pipeline, error)
	GetPipelineRevision(context.Context, pipelineconfiguration.GetPipelineRevisionQuery) (devopsv1.PipelineRevision, error)
	CreateProject(context.Context, pipelineconfiguration.CreateProjectCommand) (pipelineconfiguration.Result[devopsv1.DevOpsProject], error)
	CreateSourceConnection(context.Context, pipelineconfiguration.CreateSourceConnectionCommand) (pipelineconfiguration.Result[devopsv1.SourceConnection], error)
	UpdateSourceConnection(context.Context, pipelineconfiguration.UpdateSourceConnectionCommand) (pipelineconfiguration.Result[devopsv1.SourceConnection], error)
	CreateRepositoryBinding(context.Context, pipelineconfiguration.CreateRepositoryBindingCommand) (pipelineconfiguration.Result[devopsv1.RepositoryBinding], error)
	UpdateRepositoryBinding(context.Context, pipelineconfiguration.UpdateRepositoryBindingCommand) (pipelineconfiguration.Result[devopsv1.RepositoryBinding], error)
	CreatePipeline(context.Context, pipelineconfiguration.CreatePipelineCommand) (pipelineconfiguration.Result[devopsv1.Pipeline], error)
	UpdatePipelineDraft(context.Context, pipelineconfiguration.UpdatePipelineDraftCommand) (pipelineconfiguration.Result[devopsv1.Pipeline], error)
	ActivatePipeline(context.Context, pipelineconfiguration.ActivatePipelineCommand) (pipelineconfiguration.Result[devopsv1.PipelineActivation], error)
}

type Config struct {
	Readiness     func(context.Context) (devopsv1.Readiness, error)
	NewRequestID  func() (string, error)
	SourceIngress SourceIngress
}

type SourceIngress interface {
	Receive(context.Context, sourceingress.Command) (runadmission.Result, error)
}

type handler struct {
	authorizer port.Authorizer
	workflow   Workflow
	ingress    SourceIngress
	config     Config
	routes     *http.ServeMux
}

type requestIDContextKey struct{}

func NewHandler(authorizer port.Authorizer, workflow Workflow, config Config) (http.Handler, error) {
	if authorizer == nil || workflow == nil {
		return nil, errors.New("DevOps HTTP Authorizer and workflow are required")
	}
	if config.Readiness == nil || config.SourceIngress == nil {
		return nil, errors.New("DevOps HTTP readiness and source ingress are required")
	}
	if config.NewRequestID == nil {
		config.NewRequestID = newRequestID
	}
	value := &handler{authorizer: authorizer, workflow: workflow, ingress: config.SourceIngress, config: config}
	routes := http.NewServeMux()
	routes.HandleFunc("/ready", value.ready)
	routes.HandleFunc("/v1/projects", value.projects)
	routes.HandleFunc("/v1/projects/{projectId}", value.project)
	routes.HandleFunc("/v1/source-connections", value.sourceConnections)
	routes.HandleFunc("/v1/source-connections/{sourceConnectionId}", value.sourceConnection)
	routes.HandleFunc("/v1/source-ingress/{tenantId}/{sourceConnectionId}", value.sourceWebhook)
	routes.HandleFunc("/v1/repository-bindings", value.repositoryBindings)
	routes.HandleFunc("/v1/repository-bindings/{repositoryBindingId}", value.repositoryBinding)
	routes.HandleFunc("/v1/pipelines", value.pipelines)
	routes.HandleFunc("/v1/pipelines/{pipelineId}", value.pipeline)
	routes.HandleFunc("/v1/pipelines/{pipelineId}/draft", value.pipelineDraft)
	routes.HandleFunc("/v1/pipelines/{pipelineId}/activate", value.pipelineActivation)
	routes.HandleFunc("/v1/pipelines/{pipelineId}/revisions/{pipelineRevisionId}", value.pipelineRevision)
	routes.HandleFunc("/", value.notFound)
	value.routes = routes
	return value, nil
}

func (value *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID, err := value.config.NewRequestID()
	if err != nil || devopsv1.ValidateID("requestId", requestID) != nil {
		writeProblem(response, "request-unavailable", http.StatusInternalServerError,
			devopsv1.ErrorInternal, "Internal error", "request identity could not be established", false)
		return
	}
	response.Header().Set("Matrix-Request-ID", requestID)
	request = request.WithContext(context.WithValue(request.Context(), requestIDContextKey{}, requestID))
	value.routes.ServeHTTP(response, request)
}

func (value *handler) ready(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodGet, false) {
		return
	}
	readiness, err := value.config.Readiness(request.Context())
	if err != nil || readiness.State != devopsv1.ReadinessReady || devopsv1.ValidateReadiness(readiness) != nil {
		writeProblem(response, requestID(request), http.StatusServiceUnavailable,
			devopsv1.ErrorUnavailable, "DevOps unavailable", "DevOps readiness checks failed", true)
		return
	}
	writeJSON(response, http.StatusOK, readiness)
}

func (value *handler) projects(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodPost, true) {
		return
	}
	body, ok := decodeJSON[devopsv1.CreateDevOpsProjectRequest](response, request)
	if !ok || !validateRequest(response, request, devopsv1.ValidateCreateDevOpsProjectRequest(body)) {
		return
	}
	idempotencyKey, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsProjectCreate, iamv1.ResourceDevOpsProject, body.ID)
	if !ok {
		return
	}
	result, err := value.workflow.CreateProject(request.Context(), pipelineconfiguration.CreateProjectCommand{
		Authorization: authorization, Request: body, IdempotencyKey: idempotencyKey,
	})
	writeMutation(response, request, http.StatusCreated, "/v1/projects/"+string(body.ID),
		result.Value.Metadata.ResourceVersion, result.Value, devopsv1.ValidateDevOpsProject, err)
}

func (value *handler) project(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodGet, false) {
		return
	}
	id, ok := pathID(response, request, "projectId")
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsProjectRead, iamv1.ResourceDevOpsProject, id)
	if !ok {
		return
	}
	resource, err := value.workflow.GetProject(request.Context(), pipelineconfiguration.GetProjectQuery{
		Authorization: authorization, ProjectID: id,
	})
	writeResource(response, request, resource.Metadata.ResourceVersion, resource, devopsv1.ValidateDevOpsProject, err)
}

func (value *handler) sourceConnections(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodPost, true) {
		return
	}
	body, ok := decodeJSON[devopsv1.CreateSourceConnectionRequest](response, request)
	if !ok || !validateRequest(response, request, devopsv1.ValidateCreateSourceConnectionRequest(body)) {
		return
	}
	idempotencyKey, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsSourceConnectionCreate, iamv1.ResourceSourceConnection, body.ID)
	if !ok {
		return
	}
	result, err := value.workflow.CreateSourceConnection(request.Context(), pipelineconfiguration.CreateSourceConnectionCommand{
		Authorization: authorization, Request: body, IdempotencyKey: idempotencyKey,
	})
	writeMutation(response, request, http.StatusCreated, "/v1/source-connections/"+string(body.ID),
		result.Value.Metadata.ResourceVersion, result.Value, devopsv1.ValidateSourceConnection, err)
}

func (value *handler) sourceConnection(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		value.getSourceConnection(response, request)
	case http.MethodPut:
		value.updateSourceConnection(response, request)
	default:
		methodNotAllowed(response, request, http.MethodGet+", "+http.MethodPut)
	}
}

func (value *handler) getSourceConnection(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodGet, false) {
		return
	}
	id, ok := pathID(response, request, "sourceConnectionId")
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsSourceConnectionRead, iamv1.ResourceSourceConnection, id)
	if !ok {
		return
	}
	resource, err := value.workflow.GetSourceConnection(request.Context(), pipelineconfiguration.GetSourceConnectionQuery{
		Authorization: authorization, SourceConnectionID: id,
	})
	writeResource(response, request, resource.Metadata.ResourceVersion, resource, devopsv1.ValidateSourceConnection, err)
}

func (value *handler) updateSourceConnection(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodPut, true) {
		return
	}
	id, ok := pathID(response, request, "sourceConnectionId")
	if !ok {
		return
	}
	body, ok := decodeJSON[devopsv1.UpdateSourceConnectionRequest](response, request)
	if !ok || !validateRequest(response, request, devopsv1.ValidateUpdateSourceConnectionRequest(body)) {
		return
	}
	version, ok := ifMatch(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsSourceConnectionUpdate, iamv1.ResourceSourceConnection, id)
	if !ok {
		return
	}
	result, err := value.workflow.UpdateSourceConnection(request.Context(), pipelineconfiguration.UpdateSourceConnectionCommand{
		Authorization: authorization, SourceConnectionID: id, ExpectedResourceVersion: version,
		Request: body, IdempotencyKey: key,
	})
	writeMutation(response, request, http.StatusOK, "", result.Value.Metadata.ResourceVersion,
		result.Value, devopsv1.ValidateSourceConnection, err)
}

func (value *handler) repositoryBindings(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodPost, true) {
		return
	}
	body, ok := decodeJSON[devopsv1.CreateRepositoryBindingRequest](response, request)
	if !ok || !validateRequest(response, request, devopsv1.ValidateCreateRepositoryBindingRequest(body)) {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsRepositoryBindingCreate, iamv1.ResourceRepositoryBinding, body.ID)
	if !ok {
		return
	}
	result, err := value.workflow.CreateRepositoryBinding(request.Context(), pipelineconfiguration.CreateRepositoryBindingCommand{
		Authorization: authorization, Request: body, IdempotencyKey: key,
	})
	writeMutation(response, request, http.StatusCreated, "/v1/repository-bindings/"+string(body.ID),
		result.Value.Metadata.ResourceVersion, result.Value, devopsv1.ValidateRepositoryBinding, err)
}

func (value *handler) repositoryBinding(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		value.getRepositoryBinding(response, request)
	case http.MethodPut:
		value.updateRepositoryBinding(response, request)
	default:
		methodNotAllowed(response, request, http.MethodGet+", "+http.MethodPut)
	}
}

func (value *handler) getRepositoryBinding(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodGet, false) {
		return
	}
	id, ok := pathID(response, request, "repositoryBindingId")
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsRepositoryBindingRead, iamv1.ResourceRepositoryBinding, id)
	if !ok {
		return
	}
	resource, err := value.workflow.GetRepositoryBinding(request.Context(), pipelineconfiguration.GetRepositoryBindingQuery{
		Authorization: authorization, RepositoryBindingID: id,
	})
	writeResource(response, request, resource.Metadata.ResourceVersion, resource, devopsv1.ValidateRepositoryBinding, err)
}

func (value *handler) updateRepositoryBinding(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodPut, true) {
		return
	}
	id, ok := pathID(response, request, "repositoryBindingId")
	if !ok {
		return
	}
	body, ok := decodeJSON[devopsv1.UpdateRepositoryBindingRequest](response, request)
	if !ok || !validateRequest(response, request, devopsv1.ValidateUpdateRepositoryBindingRequest(body)) {
		return
	}
	version, ok := ifMatch(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsRepositoryBindingUpdate, iamv1.ResourceRepositoryBinding, id)
	if !ok {
		return
	}
	result, err := value.workflow.UpdateRepositoryBinding(request.Context(), pipelineconfiguration.UpdateRepositoryBindingCommand{
		Authorization: authorization, RepositoryBindingID: id, ExpectedResourceVersion: version,
		Request: body, IdempotencyKey: key,
	})
	writeMutation(response, request, http.StatusOK, "", result.Value.Metadata.ResourceVersion,
		result.Value, devopsv1.ValidateRepositoryBinding, err)
}

func (value *handler) pipelines(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodPost, true) {
		return
	}
	body, ok := decodeJSON[devopsv1.CreatePipelineRequest](response, request)
	if !ok || !validateRequest(response, request, devopsv1.ValidateCreatePipelineRequest(body)) {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsPipelineCreate, iamv1.ResourcePipeline, body.ID)
	if !ok {
		return
	}
	result, err := value.workflow.CreatePipeline(request.Context(), pipelineconfiguration.CreatePipelineCommand{
		Authorization: authorization, Request: body, IdempotencyKey: key,
	})
	writeMutation(response, request, http.StatusCreated, "/v1/pipelines/"+string(body.ID),
		result.Value.Metadata.ResourceVersion, result.Value, devopsv1.ValidatePipeline, err)
}

func (value *handler) pipeline(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodGet, false) {
		return
	}
	id, ok := pathID(response, request, "pipelineId")
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsPipelineRead, iamv1.ResourcePipeline, id)
	if !ok {
		return
	}
	resource, err := value.workflow.GetPipeline(request.Context(), pipelineconfiguration.GetPipelineQuery{
		Authorization: authorization, PipelineID: id,
	})
	writeResource(response, request, resource.Metadata.ResourceVersion, resource, devopsv1.ValidatePipeline, err)
}

func (value *handler) pipelineDraft(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodPut, true) {
		return
	}
	id, ok := pathID(response, request, "pipelineId")
	if !ok {
		return
	}
	body, ok := decodeJSON[devopsv1.UpdatePipelineDraftRequest](response, request)
	if !ok || !validateRequest(response, request, devopsv1.ValidateUpdatePipelineDraftRequest(body)) {
		return
	}
	version, ok := ifMatch(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsPipelineUpdate, iamv1.ResourcePipeline, id)
	if !ok {
		return
	}
	result, err := value.workflow.UpdatePipelineDraft(request.Context(), pipelineconfiguration.UpdatePipelineDraftCommand{
		Authorization: authorization, PipelineID: id, ExpectedResourceVersion: version,
		Request: body, IdempotencyKey: key,
	})
	writeMutation(response, request, http.StatusOK, "", result.Value.Metadata.ResourceVersion,
		result.Value, devopsv1.ValidatePipeline, err)
}

func (value *handler) pipelineActivation(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodPost, false) {
		return
	}
	id, ok := pathID(response, request, "pipelineId")
	if !ok {
		return
	}
	version, ok := ifMatch(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsPipelineActivate, iamv1.ResourcePipeline, id)
	if !ok {
		return
	}
	result, err := value.workflow.ActivatePipeline(request.Context(), pipelineconfiguration.ActivatePipelineCommand{
		Authorization: authorization, PipelineID: id, ExpectedResourceVersion: version, IdempotencyKey: key,
	})
	location := ""
	if err == nil {
		location = "/v1/pipelines/" + string(id) + "/revisions/" + string(result.Value.Revision.ID)
	}
	writeMutation(response, request, http.StatusCreated, location, result.Value.Pipeline.Metadata.ResourceVersion,
		result.Value, devopsv1.ValidatePipelineActivation, err)
}

func (value *handler) pipelineRevision(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodGet, false) {
		return
	}
	pipelineID, ok := pathID(response, request, "pipelineId")
	if !ok {
		return
	}
	revisionID, ok := pathID(response, request, "pipelineRevisionId")
	if !ok {
		return
	}
	authorization, ok := value.authorize(response, request, iamv1.ActionDevOpsPipelineRead, iamv1.ResourcePipeline, pipelineID)
	if !ok {
		return
	}
	revision, err := value.workflow.GetPipelineRevision(request.Context(), pipelineconfiguration.GetPipelineRevisionQuery{
		Authorization: authorization, PipelineID: pipelineID, PipelineRevisionID: revisionID,
	})
	writeResourceWithETag(response, request, quotedETag(revision.ContentDigest), revision,
		devopsv1.ValidatePipelineRevision, err)
}

func (value *handler) notFound(response http.ResponseWriter, request *http.Request) {
	writeProblem(response, requestID(request), http.StatusNotFound,
		devopsv1.ErrorNotFound, "Not found", "the requested DevOps route does not exist", false)
}
