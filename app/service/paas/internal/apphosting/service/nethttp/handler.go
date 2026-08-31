// Package nethttp exposes the minimal authenticated Phase 1 apphosting HTTP
// workflow on the standard library HTTP stack.
package nethttp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	pathpkg "path"
	"strconv"
	"strings"

	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/terminalsession"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/verifyinstallation"
)

const (
	defaultMaximumBodyBytes = int64(16 * 1024 * 1024)
	terminalTicketCookie    = "matrix_terminal_ticket"
	defaultTerminalBasePath = "/v1"
)

type Workflow interface {
	CreateApplication(
		context.Context,
		applicationlifecycle.CreateApplicationCommand,
	) (paasv1.Application, paasv1.Operation, bool, error)
	CreateConfiguration(
		context.Context,
		applicationlifecycle.CreateConfigurationCommand,
	) (paasv1.Configuration, paasv1.Operation, bool, error)
	CreateConfigurationRevision(
		context.Context,
		applicationlifecycle.CreateConfigurationRevisionCommand,
	) (paasv1.ConfigurationRevision, paasv1.Operation, bool, error)
	CreateApplicationRevision(
		context.Context,
		applicationlifecycle.CreateApplicationRevisionCommand,
	) (paasv1.ApplicationRevision, paasv1.Operation, bool, error)
	Submit(context.Context, applicationlifecycle.SubmitCommand) (applicationlifecycle.Result, error)
	Rollback(context.Context, applicationlifecycle.RollbackCommand) (applicationlifecycle.Result, error)
	GetApplication(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.Application, error)
	GetConfiguration(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.Configuration, error)
	GetConfigurationRevision(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.ConfigurationRevision, error)
	GetApplicationRevision(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.ApplicationRevision, error)
	GetDeployment(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.Deployment, error)
	ListDeployments(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.DeploymentList, error)
	GetDeploymentRuntime(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.DeploymentRuntimeSnapshot, error)
	GetDeploymentGeneration(context.Context, port.Authorization, paasv1.ResourceID, uint64) (paasv1.DeploymentGeneration, error)
	GetOperation(context.Context, port.Authorization, paasv1.OperationID) (paasv1.Operation, error)
}

type Config struct {
	MaximumBodyBytes       int64
	TerminalPublicBasePath string
	TerminalCookieSecure   bool
	NewRequestID           func() (string, error)
	NewTerminalTicket      func() (string, string, error)
	Readiness              func(context.Context) (paasv1.Readiness, error)
}

type TerminalWorkflow interface {
	Create(context.Context, terminalsession.CreateCommand) (terminalsession.CreateResult, error)
	Consume(context.Context, paasv1.ResourceID, string) (terminalsession.StoredSession, error)
	Activate(context.Context, terminalsession.StoredSession) (terminalsession.StoredSession, error)
	End(context.Context, paasv1.TenantID, paasv1.ResourceID, paasv1.TerminalSessionOutcome) (terminalsession.StoredSession, bool, error)
	Close(context.Context, terminalsession.CloseCommand) (terminalsession.StoredSession, bool, error)
}

type InstallationVerifier interface {
	VerifyInstallation(
		context.Context,
		verifyinstallation.Command,
	) (paasv1.InstallationVerification, error)
}

type handler struct {
	authorizer           port.Authorizer
	workflow             Workflow
	execution            ExecutionWorkflow
	terminal             TerminalWorkflow
	terminalConnector    port.TerminalConnector
	installationVerifier InstallationVerifier
	config               Config
	routes               *http.ServeMux
	terminalRegistry     *terminalRegistry
}

func NewHandler(
	authorizer port.Authorizer,
	workflow Workflow,
	execution ExecutionWorkflow,
	terminal TerminalWorkflow,
	terminalConnector port.TerminalConnector,
	installationVerifier InstallationVerifier,
	config Config,
) (http.Handler, error) {
	if authorizer == nil || workflow == nil || execution == nil || terminal == nil ||
		terminalConnector == nil || installationVerifier == nil {
		return nil, errors.New("HTTP Authorizer, application, execution and terminal dependencies, and installation verifier are required")
	}
	if config.Readiness == nil {
		return nil, errors.New("HTTP readiness check is required")
	}
	if config.MaximumBodyBytes == 0 {
		config.MaximumBodyBytes = defaultMaximumBodyBytes
	}
	if config.MaximumBodyBytes < 1024 || config.MaximumBodyBytes > 64*1024*1024 {
		return nil, errors.New("HTTP maximum body size must be between 1 KiB and 64 MiB")
	}
	if config.TerminalPublicBasePath == "" {
		config.TerminalPublicBasePath = defaultTerminalBasePath
	}
	if !validTerminalPublicBasePath(config.TerminalPublicBasePath) {
		return nil, errors.New("terminal public base path is invalid")
	}
	if config.NewRequestID == nil {
		config.NewRequestID = newRequestID
	}
	if config.NewTerminalTicket == nil {
		config.NewTerminalTicket = newTerminalTicket
	}
	value := &handler{
		authorizer: authorizer, workflow: workflow, execution: execution,
		terminal: terminal, terminalConnector: terminalConnector,
		installationVerifier: installationVerifier, config: config,
		terminalRegistry: newTerminalRegistry(),
	}
	routes := http.NewServeMux()
	routes.HandleFunc("GET /ready", value.ready)
	routes.HandleFunc("POST /v1/execution-pools", value.createExecutionPool)
	routes.HandleFunc("GET /v1/execution-pools/{executionPoolId}", value.getExecutionPool)
	routes.HandleFunc("POST /v1/execution-targets", value.registerExecutionTarget)
	routes.HandleFunc("GET /v1/execution-targets", value.listExecutionTargets)
	routes.HandleFunc("GET /v1/execution-targets/{executionTargetId}", value.getExecutionTarget)
	routes.HandleFunc("POST /v1/execution-targets/{executionTargetId}/drain", value.drainExecutionTarget)
	routes.HandleFunc("POST /v1/execution-targets/{executionTargetId}/activate", value.activateExecutionTarget)
	routes.HandleFunc("POST /v1/execution-targets/{executionTargetId}/remove", value.removeExecutionTarget)
	routes.HandleFunc("GET /v1/platform/operations/{operationId}", value.getPlatformOperation)
	routes.HandleFunc("POST /v1/applications", value.createApplication)
	routes.HandleFunc("GET /v1/applications/{applicationId}", value.getApplication)
	routes.HandleFunc("POST /v1/configurations", value.createConfiguration)
	routes.HandleFunc("GET /v1/configurations/{configurationId}", value.getConfiguration)
	routes.HandleFunc("POST /v1/configuration-revisions", value.createConfigurationRevision)
	routes.HandleFunc("GET /v1/configuration-revisions/{configurationRevisionId}", value.getConfigurationRevision)
	routes.HandleFunc("POST /v1/application-revisions", value.createApplicationRevision)
	routes.HandleFunc("GET /v1/application-revisions/{applicationRevisionId}", value.getApplicationRevision)
	routes.HandleFunc("POST /v1/deployments", value.createDeployment)
	routes.HandleFunc("GET /v1/deployments", value.listDeployments)
	routes.HandleFunc("GET /v1/deployments/{deploymentId}", value.getDeployment)
	routes.HandleFunc("GET /v1/deployments/{deploymentId}/runtime", value.getDeploymentRuntime)
	routes.HandleFunc("POST /v1/deployments/{deploymentId}/terminal-sessions", value.createTerminalSession)
	routes.HandleFunc("PUT /v1/deployments/{deploymentId}", value.updateDeployment)
	routes.HandleFunc("POST /v1/deployments/{deploymentId}/rollback", value.rollbackDeployment)
	routes.HandleFunc("GET /v1/deployments/{deploymentId}/generations/{generation}", value.getDeploymentGeneration)
	routes.HandleFunc("GET /v1/operations/{operationId}", value.getOperation)
	routes.HandleFunc("DELETE /v1/terminal-sessions/{terminalSessionId}", value.closeTerminalSession)
	routes.HandleFunc("GET /v1/terminal-sessions/{terminalSessionId}/connect", value.connectTerminalSession)
	routes.HandleFunc("POST /v1/installation:verify", value.verifyInstallation)
	value.routes = routes
	return value, nil
}

func (value *handler) verifyInstallation(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "installation verification accepts no query", false)
		return
	}
	if len(request.Header.Values("Matrix-Subject-Credential")) != 0 {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "installation verification accepts no subject credential", false)
		return
	}
	credential := request.Header.Get("Authorization")
	if credential == "" {
		writeProblem(response, requestID, http.StatusUnauthorized, paasv1.ErrorUnauthenticated, "Unauthenticated", "a verifier service credential is required", false)
		return
	}
	body, ok := decodeJSON[paasv1.VerifyInstallationRequest](value, response, request, requestID)
	if !ok {
		return
	}
	verification, err := value.installationVerifier.VerifyInstallation(
		request.Context(),
		verifyinstallation.Command{
			Credential: credential, RequestID: requestID,
			IdempotencyKey: request.Header.Get("Idempotency-Key"), Request: body,
		},
	)
	if err != nil {
		value.writeInstallationVerificationError(response, requestID, err)
		return
	}
	if paasv1.ValidateInstallationVerification(verification) != nil {
		writeProblem(response, requestID, http.StatusInternalServerError, paasv1.ErrorInternal, "Internal error", "installation verification returned an invalid result", true)
		return
	}
	writeJSON(response, http.StatusOK, verification)
}

func (*handler) writeInstallationVerificationError(
	response http.ResponseWriter,
	requestID string,
	err error,
) {
	switch {
	case errors.Is(err, port.ErrUnauthenticated):
		writeProblem(response, requestID, http.StatusUnauthorized, paasv1.ErrorUnauthenticated, "Unauthenticated", "verifier authentication failed", false)
	case errors.Is(err, port.ErrPermissionDenied):
		writeProblem(response, requestID, http.StatusForbidden, paasv1.ErrorPermissionDenied, "Permission denied", "IAM denied installation verification", false)
	case errors.Is(err, port.ErrAuthorizationUnavailable):
		writeProblem(response, requestID, http.StatusServiceUnavailable, paasv1.ErrorIdentityUnavailable, "Identity unavailable", "IAM installation verification is unavailable", true)
	case errors.Is(err, verifyinstallation.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "installation verification request is invalid", false)
	case errors.Is(err, verifyinstallation.ErrConflict):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorConflict, "Verification conflict", "installation verification does not match the running release", false)
	case errors.Is(err, context.DeadlineExceeded):
		writeProblem(response, requestID, http.StatusGatewayTimeout, paasv1.ErrorDeadlineExceeded, "Deadline exceeded", "installation verification deadline was exceeded", true)
	default:
		writeProblem(response, requestID, http.StatusServiceUnavailable, paasv1.ErrorInternal, "PaaS unavailable", "installation verification is unavailable", true)
	}
}

func (value *handler) ready(response http.ResponseWriter, request *http.Request) {
	requestID, err := value.config.NewRequestID()
	if err != nil || paasv1.ValidateID("requestId", requestID) != nil {
		writeProblem(response, "request-unavailable", http.StatusServiceUnavailable, paasv1.ErrorInternal, "PaaS unavailable", "PaaS readiness could not be established", true)
		return
	}
	response.Header().Set("X-Request-ID", requestID)
	if request.URL.RawQuery != "" || request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "readiness accepts no query or body", false)
		return
	}
	readiness, err := value.config.Readiness(request.Context())
	if err != nil || readiness.State != paasv1.ReadinessReady ||
		paasv1.ValidateReadiness(readiness) != nil {
		writeProblem(response, requestID, http.StatusServiceUnavailable, paasv1.ErrorInternal, "PaaS unavailable", "PaaS readiness checks failed", true)
		return
	}
	writeJSON(response, http.StatusOK, readiness)
}

func (value *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	value.routes.ServeHTTP(response, request)
}

func (value *handler) createApplication(response http.ResponseWriter, request *http.Request) {
	requestID, authorization, ok := value.authorizeCollection(response, request, port.AuthorizeApplicationCreate, "Application")
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.CreateApplicationRequest](value, response, request, requestID)
	if !ok {
		return
	}
	resource, operation, replayed, err := value.workflow.CreateApplication(request.Context(), applicationlifecycle.CreateApplicationCommand{
		Authorization: authorization, Request: body, IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	value.writeCreation(response, requestID, replayed, resource.Metadata.ResourceVersion,
		"/v1/applications/"+string(resource.Metadata.ID), operation, err)
}

func (value *handler) createConfiguration(response http.ResponseWriter, request *http.Request) {
	requestID, authorization, ok := value.authorizeCollection(response, request, port.AuthorizeConfigurationCreate, "Configuration")
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.CreateConfigurationRequest](value, response, request, requestID)
	if !ok {
		return
	}
	resource, operation, replayed, err := value.workflow.CreateConfiguration(request.Context(), applicationlifecycle.CreateConfigurationCommand{
		Authorization: authorization, Request: body, IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	value.writeCreation(response, requestID, replayed, resource.Metadata.ResourceVersion,
		"/v1/configurations/"+string(resource.Metadata.ID), operation, err)
}

func (value *handler) createConfigurationRevision(response http.ResponseWriter, request *http.Request) {
	requestID, authorization, ok := value.authorizeCollection(response, request, port.AuthorizeConfigurationRevisionCreate, "ConfigurationRevision")
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.CreateConfigurationRevisionRequest](value, response, request, requestID)
	if !ok {
		return
	}
	resource, operation, replayed, err := value.workflow.CreateConfigurationRevision(request.Context(), applicationlifecycle.CreateConfigurationRevisionCommand{
		Authorization: authorization, Request: body, IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	value.writeCreation(response, requestID, replayed, resource.Metadata.ResourceVersion,
		"/v1/configuration-revisions/"+string(resource.Metadata.ID), operation, err)
}

func (value *handler) createApplicationRevision(response http.ResponseWriter, request *http.Request) {
	requestID, authorization, ok := value.authorizeCollection(response, request, port.AuthorizeApplicationRevisionCreate, "ApplicationRevision")
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.CreateApplicationRevisionRequest](value, response, request, requestID)
	if !ok {
		return
	}
	resource, operation, replayed, err := value.workflow.CreateApplicationRevision(request.Context(), applicationlifecycle.CreateApplicationRevisionCommand{
		Authorization: authorization, Request: body, IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	value.writeCreation(response, requestID, replayed, resource.Metadata.ResourceVersion,
		"/v1/application-revisions/"+string(resource.Metadata.ID), operation, err)
}

func (value *handler) createDeployment(response http.ResponseWriter, request *http.Request) {
	requestID, authorization, ok := value.authorizeCollection(response, request, port.AuthorizeDeploymentCreate, "Deployment")
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.CreateDeploymentRequest](value, response, request, requestID)
	if !ok {
		return
	}
	result, err := value.workflow.Submit(request.Context(), applicationlifecycle.SubmitCommand{
		Authorization: authorization, DeploymentID: body.ID, Name: body.Name, Spec: body.Spec,
		IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	value.writeDeploymentMutation(response, requestID, result, err)
}

func (value *handler) updateDeployment(response http.ResponseWriter, request *http.Request) {
	deploymentID, ok := pathResourceID(response, request, "deploymentId")
	if !ok {
		return
	}
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.DeploymentSpec](value, response, request, requestID)
	if !ok {
		return
	}
	action := port.AuthorizeDeploymentUpdate
	if body.DesiredState == paasv1.DeploymentDesiredStopped {
		action = port.AuthorizeDeploymentStop
	}
	authorization, ok := value.authorizeRequest(
		response,
		request,
		requestID,
		action,
		"Deployment",
		deploymentID,
	)
	if !ok {
		return
	}
	expected, ok := parseIfMatch(response, request, requestID)
	if !ok {
		return
	}
	result, err := value.workflow.Submit(request.Context(), applicationlifecycle.SubmitCommand{
		Authorization: authorization, DeploymentID: deploymentID, Spec: body,
		ExpectedResourceVersion: expected, IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	value.writeDeploymentMutation(response, requestID, result, err)
}

func (value *handler) rollbackDeployment(response http.ResponseWriter, request *http.Request) {
	deploymentID, ok := pathResourceID(response, request, "deploymentId")
	if !ok {
		return
	}
	requestID, authorization, ok := value.authorize(response, request, port.AuthorizeDeploymentRollback, "Deployment", deploymentID)
	if !ok {
		return
	}
	expected, ok := parseIfMatch(response, request, requestID)
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.RollbackDeploymentRequest](value, response, request, requestID)
	if !ok {
		return
	}
	result, err := value.workflow.Rollback(request.Context(), applicationlifecycle.RollbackCommand{
		Authorization: authorization, DeploymentID: deploymentID,
		SourceGeneration: body.SourceGeneration, ExpectedResourceVersion: expected,
		IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	value.writeDeploymentMutation(response, requestID, result, err)
}

func (value *handler) getApplication(response http.ResponseWriter, request *http.Request) {
	id, authorization, requestID, ok := value.authorizePath(response, request, "applicationId", port.AuthorizeApplicationRead, "Application")
	if !ok {
		return
	}
	resource, err := value.workflow.GetApplication(request.Context(), authorization, id)
	writeResource(response, requestID, resource, resourceVersionETag(resource.Metadata.ResourceVersion), err)
}

func (value *handler) getConfiguration(response http.ResponseWriter, request *http.Request) {
	id, authorization, requestID, ok := value.authorizePath(response, request, "configurationId", port.AuthorizeConfigurationRead, "Configuration")
	if !ok {
		return
	}
	resource, err := value.workflow.GetConfiguration(request.Context(), authorization, id)
	writeResource(response, requestID, resource, resourceVersionETag(resource.Metadata.ResourceVersion), err)
}

func (value *handler) getConfigurationRevision(response http.ResponseWriter, request *http.Request) {
	id, authorization, requestID, ok := value.authorizePath(response, request, "configurationRevisionId", port.AuthorizeConfigurationRevisionRead, "ConfigurationRevision")
	if !ok {
		return
	}
	resource, err := value.workflow.GetConfigurationRevision(request.Context(), authorization, id)
	writeResource(response, requestID, resource, resourceVersionETag(resource.Metadata.ResourceVersion), err)
}

func (value *handler) getApplicationRevision(response http.ResponseWriter, request *http.Request) {
	id, authorization, requestID, ok := value.authorizePath(response, request, "applicationRevisionId", port.AuthorizeApplicationRevisionRead, "ApplicationRevision")
	if !ok {
		return
	}
	resource, err := value.workflow.GetApplicationRevision(request.Context(), authorization, id)
	writeResource(response, requestID, resource, resourceVersionETag(resource.Metadata.ResourceVersion), err)
}

func (value *handler) getDeployment(response http.ResponseWriter, request *http.Request) {
	id, authorization, requestID, ok := value.authorizePath(response, request, "deploymentId", port.AuthorizeDeploymentRead, "Deployment")
	if !ok {
		return
	}
	resource, err := value.workflow.GetDeployment(request.Context(), authorization, id)
	writeResource(response, requestID, resource, resourceVersionETag(resource.Metadata.ResourceVersion), err)
}

func (value *handler) listDeployments(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "Deployment list accepts no body", false)
		return
	}
	if request.URL.ForceQuery {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "Deployment list query is invalid", false)
		return
	}
	query, queryErr := url.ParseQuery(request.URL.RawQuery)
	if queryErr != nil || len(query) > 1 {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "Deployment list query is invalid", false)
		return
	}
	var after paasv1.ResourceID
	if values, present := query["after"]; present {
		if len(values) != 1 || values[0] == "" || paasv1.ValidateID("after", values[0]) != nil {
			writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "Deployment list cursor is invalid", false)
			return
		}
		after = paasv1.ResourceID(values[0])
	} else if len(query) != 0 {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "Deployment list query is invalid", false)
		return
	}
	authorization, ok := value.authorizeRequest(
		response,
		request,
		requestID,
		port.AuthorizeDeploymentRead,
		"Deployment",
		"collection",
	)
	if !ok {
		return
	}
	resources, err := value.workflow.ListDeployments(request.Context(), authorization, after)
	writeResource(response, requestID, resources, "", err)
}

func (value *handler) getDeploymentRuntime(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "Deployment runtime accepts no selector or body", false)
		return
	}
	id, ok := pathResourceID(response, request, "deploymentId")
	if !ok {
		return
	}
	authorization, ok := value.authorizeRequest(
		response,
		request,
		requestID,
		port.AuthorizeDeploymentRead,
		"Deployment",
		id,
	)
	if !ok {
		return
	}
	resource, err := value.workflow.GetDeploymentRuntime(request.Context(), authorization, id)
	writeResource(response, requestID, resource, "", err)
}

func (value *handler) createTerminalSession(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "terminal session creation accepts no query", false)
		return
	}
	deploymentID, ok := pathResourceID(response, request, "deploymentId")
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.CreateTerminalSessionRequest](value, response, request, requestID)
	if !ok {
		return
	}
	if err := paasv1.ValidateCreateTerminalSessionRequest(body); err != nil {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "terminal session request is invalid", false)
		return
	}
	idempotencyValues := request.Header.Values("Idempotency-Key")
	if len(idempotencyValues) != 1 || idempotencyValues[0] == "" {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "one Idempotency-Key is required", false)
		return
	}
	authorization, ok := value.authorizeRequest(
		response,
		request,
		requestID,
		port.AuthorizeTerminalSessionCreate,
		"TerminalSession",
		"collection",
	)
	if !ok {
		return
	}
	rawTicket, ticketDigest, err := value.config.NewTerminalTicket()
	if err != nil || !validTerminalTicket(rawTicket, ticketDigest) {
		writeProblem(response, requestID, http.StatusInternalServerError, paasv1.ErrorInternal, "Internal error", "terminal ticket could not be generated", false)
		return
	}
	result, err := value.terminal.Create(request.Context(), terminalsession.CreateCommand{
		Authorization:  authorization,
		DeploymentID:   deploymentID,
		Request:        body,
		IdempotencyKey: idempotencyValues[0],
		TicketDigest:   ticketDigest,
	})
	if err != nil {
		writeTerminalError(response, requestID, err)
		return
	}
	if terminalsession.ValidateStoredSession(result.Stored) != nil ||
		result.Stored.Session.State != paasv1.TerminalSessionPending {
		writeProblem(response, requestID, http.StatusInternalServerError, paasv1.ErrorInternal, "Internal error", "terminal workflow returned an invalid session", false)
		return
	}
	if result.ReplacedID != "" {
		value.terminalRegistry.revoke(result.ReplacedID, paasv1.TerminalSessionReplaced)
	}
	path := value.terminalConnectPath(result.Stored.Session.ID)
	http.SetCookie(response, &http.Cookie{
		Name: terminalTicketCookie, Value: rawTicket, Path: path,
		Expires: result.Stored.Session.ConnectBefore, MaxAge: int(paasv1.TerminalSessionConnectTimeout.Seconds()),
		HttpOnly: true, Secure: request.TLS != nil || value.config.TerminalCookieSecure, SameSite: http.SameSiteStrictMode,
	})
	response.Header().Set("Location", value.config.TerminalPublicBasePath+"/terminal-sessions/"+string(result.Stored.Session.ID))
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	writeJSON(response, status, result.Stored.Session)
}

func (value *handler) closeTerminalSession(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "terminal close accepts no query or body", false)
		return
	}
	sessionID, ok := pathTerminalSessionID(response, request, "terminalSessionId")
	if !ok {
		return
	}
	authorization, ok := value.authorizeRequest(
		response,
		request,
		requestID,
		port.AuthorizeTerminalSessionClose,
		"TerminalSession",
		sessionID,
	)
	if !ok {
		return
	}
	_, changed, err := value.terminal.Close(request.Context(), terminalsession.CloseCommand{
		Authorization: authorization, SessionID: sessionID,
	})
	if err != nil {
		writeTerminalError(response, requestID, err)
		return
	}
	if changed {
		value.terminalRegistry.revoke(sessionID, paasv1.TerminalSessionRevoked)
	}
	response.WriteHeader(http.StatusNoContent)
}

func (value *handler) getDeploymentGeneration(response http.ResponseWriter, request *http.Request) {
	id, authorization, requestID, ok := value.authorizePath(response, request, "deploymentId", port.AuthorizeDeploymentRead, "Deployment")
	if !ok {
		return
	}
	generation, err := strconv.ParseUint(request.PathValue("generation"), 10, 64)
	if err != nil || generation == 0 || generation > 9007199254740991 {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "generation is invalid", false)
		return
	}
	resource, readErr := value.workflow.GetDeploymentGeneration(request.Context(), authorization, id, generation)
	etag := ""
	if readErr == nil {
		etag = quotedETag(resource.ContentDigest + ":" + strconv.FormatUint(resource.Generation, 10))
	}
	writeResource(response, requestID, resource, etag, readErr)
}

func (value *handler) getOperation(response http.ResponseWriter, request *http.Request) {
	id, ok := pathOperationID(response, request, "operationId")
	if !ok {
		return
	}
	requestID, authorization, ok := value.authorize(response, request, port.AuthorizeOperationRead, "Operation", paasv1.ResourceID(id))
	if !ok {
		return
	}
	resource, err := value.workflow.GetOperation(request.Context(), authorization, id)
	etag := ""
	if err == nil {
		etag = quotedETag("updated-" + strconv.FormatInt(resource.UpdatedAt.UnixMicro(), 10))
	}
	writeResource(response, requestID, resource, etag, err)
}

func (value *handler) authorizeCollection(
	response http.ResponseWriter,
	request *http.Request,
	action string,
	kind string,
) (string, port.Authorization, bool) {
	return value.authorize(response, request, action, kind, "collection")
}

func (value *handler) authorizePath(
	response http.ResponseWriter,
	request *http.Request,
	pathName string,
	action string,
	kind string,
) (paasv1.ResourceID, port.Authorization, string, bool) {
	id, ok := pathResourceID(response, request, pathName)
	if !ok {
		return "", port.Authorization{}, "", false
	}
	requestID, authorization, ok := value.authorize(response, request, action, kind, id)
	return id, authorization, requestID, ok
}

func (value *handler) authorize(
	response http.ResponseWriter,
	request *http.Request,
	action string,
	kind string,
	id paasv1.ResourceID,
) (string, port.Authorization, bool) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return "", port.Authorization{}, false
	}
	authorization, ok := value.authorizeRequest(response, request, requestID, action, kind, id)
	return requestID, authorization, ok
}

func (value *handler) beginRequest(response http.ResponseWriter) (string, bool) {
	requestID, err := value.config.NewRequestID()
	if err != nil || paasv1.ValidateID("requestId", requestID) != nil {
		writeProblem(response, "request-unavailable", http.StatusInternalServerError, paasv1.ErrorInternal, "Internal error", "request identity could not be established", false)
		return "", false
	}
	response.Header().Set("X-Request-ID", requestID)
	return requestID, true
}

func (value *handler) authorizeRequest(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	action string,
	kind string,
	id paasv1.ResourceID,
) (port.Authorization, bool) {
	authorizationRequest := port.AuthorizationRequest{
		Credential: request.Header.Get("Authorization"),
		Action:     action,
		Resource:   paasv1.ResourceRef{Kind: kind, ID: id},
		RequestID:  requestID,
	}
	if err := port.ValidateAuthorizationRequest(authorizationRequest); err != nil {
		writeProblem(response, requestID, http.StatusUnauthorized, paasv1.ErrorUnauthenticated, "Unauthenticated", "a valid IAM credential is required", false)
		return port.Authorization{}, false
	}
	authorization, err := value.authorizer.Authorize(request.Context(), authorizationRequest)
	if err != nil {
		writeAuthorizationError(response, requestID, err)
		return port.Authorization{}, false
	}
	if err := port.ValidateAuthorizationForRequest(authorization, authorizationRequest); err != nil {
		writeProblem(response, requestID, http.StatusServiceUnavailable, paasv1.ErrorIdentityUnavailable, "Identity unavailable", "IAM returned an invalid authorization decision", true)
		return port.Authorization{}, false
	}
	return authorization, true
}

func (value *handler) writeCreation(
	response http.ResponseWriter,
	requestID string,
	replayed bool,
	resourceVersion uint64,
	location string,
	operation paasv1.Operation,
	err error,
) {
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeOperation(response, status, location, resourceVersion, operation)
}

func (value *handler) writeDeploymentMutation(
	response http.ResponseWriter,
	requestID string,
	result applicationlifecycle.Result,
	err error,
) {
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	status := http.StatusAccepted
	if terminalOperation(result.Operation.State) {
		status = http.StatusOK
	}
	writeOperation(
		response,
		status,
		"/v1/deployments/"+string(result.Deployment.Metadata.ID),
		result.Deployment.Metadata.ResourceVersion,
		result.Operation,
	)
}

func decodeJSON[T any](
	handler *handler,
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) (T, bool) {
	var zero T
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProblem(response, requestID, http.StatusUnsupportedMediaType, paasv1.ErrorInvalidArgument, "Unsupported media type", "Content-Type must be application/json", false)
		return zero, false
	}
	request.Body = http.MaxBytesReader(response, request.Body, handler.config.MaximumBodyBytes)
	var value T
	if err := contractjson.DecodeObject(request.Body, handler.config.MaximumBodyBytes, &value); err != nil {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "request body is not valid JSON", false)
		return zero, false
	}
	return value, true
}

func parseIfMatch(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) (uint64, bool) {
	value := request.Header.Get("If-Match")
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' ||
		strings.HasPrefix(value, "W/") {
		writeProblem(response, requestID, http.StatusPreconditionRequired, paasv1.ErrorResourceVersionConflict, "Precondition required", "If-Match must contain the current resource ETag", false)
		return 0, false
	}
	parsed, err := strconv.ParseUint(value[1:len(value)-1], 10, 64)
	if err != nil || parsed == 0 || parsed > 9007199254740991 {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "If-Match is invalid", false)
		return 0, false
	}
	return parsed, true
}

func pathResourceID(
	response http.ResponseWriter,
	request *http.Request,
	name string,
) (paasv1.ResourceID, bool) {
	id := paasv1.ResourceID(request.PathValue(name))
	if err := paasv1.ValidateID(name, string(id)); err != nil {
		writeProblem(response, "request-invalid", http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", name+" is invalid", false)
		return "", false
	}
	return id, true
}

func pathOperationID(
	response http.ResponseWriter,
	request *http.Request,
	name string,
) (paasv1.OperationID, bool) {
	id, ok := pathResourceID(response, request, name)
	return paasv1.OperationID(id), ok
}

func pathTerminalSessionID(
	response http.ResponseWriter,
	request *http.Request,
	name string,
) (paasv1.ResourceID, bool) {
	id := paasv1.ResourceID(request.PathValue(name))
	if err := paasv1.ValidateTerminalSessionID(id); err != nil {
		writeProblem(response, "request-invalid", http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", name+" is invalid", false)
		return "", false
	}
	return id, true
}

func writeOperation(
	response http.ResponseWriter,
	status int,
	location string,
	resourceVersion uint64,
	operation paasv1.Operation,
) {
	response.Header().Set("Location", location)
	response.Header().Set("Operation-Location", "/v1/operations/"+string(operation.ID))
	if operation.Scope.Kind == paasv1.AuthorityPlatform {
		response.Header().Set("Operation-Location", "/v1/platform/operations/"+string(operation.ID))
	}
	response.Header().Set("ETag", resourceVersionETag(resourceVersion))
	writeJSON(response, status, operation)
}

func writeResource[T any](
	response http.ResponseWriter,
	requestID string,
	resource T,
	etag string,
	err error,
) {
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	if etag != "" {
		response.Header().Set("ETag", etag)
	}
	writeJSON(response, http.StatusOK, resource)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeAuthorizationError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, port.ErrUnauthenticated):
		writeProblem(response, requestID, http.StatusUnauthorized, paasv1.ErrorUnauthenticated, "Unauthenticated", "IAM authentication failed", false)
	case errors.Is(err, port.ErrPermissionDenied):
		writeProblem(response, requestID, http.StatusForbidden, paasv1.ErrorPermissionDenied, "Permission denied", "IAM denied this action", false)
	default:
		writeProblem(response, requestID, http.StatusServiceUnavailable, paasv1.ErrorIdentityUnavailable, "Identity unavailable", "IAM authorization is unavailable", true)
	}
}

func writeWorkflowError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, port.ErrPermissionDenied):
		writeAuthorizationError(response, requestID, err)
	case errors.Is(err, executionadmission.ErrUnavailable), errors.Is(err, executionadmission.ErrRetryableTransaction):
		writeProblem(response, requestID, http.StatusServiceUnavailable, paasv1.ErrorExecutionTargetUnavailable, "Execution target unavailable", "the execution target cannot be observed or admitted now", true)
	case errors.Is(err, executionadmission.ErrConflict):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorConflict, "Execution admission conflict", "the request conflicts with the registered execution authority", false)
	case errors.Is(err, executionadmission.ErrInvalidTransition):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorConflict, "Execution target transition conflict", "the execution target is not in the required lifecycle state", false)
	case errors.Is(err, executionadmission.ErrTargetInUse):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorConflict, "Execution target is in use", "live or unresolved work must be completed before removal", true)
	case errors.Is(err, executionadmission.ErrNotFound):
		writeProblem(response, requestID, http.StatusNotFound, paasv1.ErrorNotFound, "Not found", "the requested installation resource does not exist", false)
	case errors.Is(err, applicationlifecycle.ErrInvalidArgument), errors.Is(err, executionadmission.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "request violates the apphosting contract", false)
	case errors.Is(err, applicationlifecycle.ErrNotFound):
		writeProblem(response, requestID, http.StatusNotFound, paasv1.ErrorNotFound, "Not found", "the requested tenant resource does not exist", false)
	case errors.Is(err, applicationlifecycle.ErrAlreadyExists):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorAlreadyExists, "Already exists", "the resource already exists", false)
	case errors.Is(err, applicationlifecycle.ErrIdempotencyConflict), errors.Is(err, executionadmission.ErrIdempotencyConflict):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorIdempotencyConflict, "Idempotency conflict", "Idempotency-Key was already used for different content", false)
	case errors.Is(err, applicationlifecycle.ErrResourceVersionConflict):
		writeProblem(response, requestID, http.StatusPreconditionFailed, paasv1.ErrorResourceVersionConflict, "Resource version conflict", "If-Match does not identify the current resource version", false)
	case errors.Is(err, executionadmission.ErrResourceVersionConflict):
		writeProblem(response, requestID, http.StatusPreconditionFailed, paasv1.ErrorResourceVersionConflict, "Resource version conflict", "If-Match does not identify the current resource version", false)
	case errors.Is(err, applicationlifecycle.ErrNoDesiredChange):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorConflict, "No desired change", "Deployment desired content is unchanged", false)
	case errors.Is(err, applicationlifecycle.ErrOperationInProgress):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorConflict, "Operation in progress", "Deployment already has an active Operation", true)
	case errors.Is(err, context.DeadlineExceeded):
		writeProblem(response, requestID, http.StatusGatewayTimeout, paasv1.ErrorDeadlineExceeded, "Deadline exceeded", "request deadline was exceeded", true)
	default:
		writeProblem(response, requestID, http.StatusInternalServerError, paasv1.ErrorInternal, "Internal error", "the apphosting request could not be completed", true)
	}
}

func writeTerminalError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, terminalsession.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "terminal session request is invalid", false)
	case errors.Is(err, terminalsession.ErrNotFound):
		writeProblem(response, requestID, http.StatusNotFound, paasv1.ErrorNotFound, "Not found", "terminal session or current runtime instance does not exist", false)
	case errors.Is(err, terminalsession.ErrPermissionDenied):
		writeProblem(response, requestID, http.StatusForbidden, paasv1.ErrorPermissionDenied, "Permission denied", "terminal session belongs to another subject", false)
	case errors.Is(err, terminalsession.ErrIdempotencyConflict):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorIdempotencyConflict, "Idempotency conflict", "Idempotency-Key was already used for different terminal content", false)
	case errors.Is(err, terminalsession.ErrExpired):
		writeProblem(response, requestID, http.StatusGone, paasv1.ErrorConflict, "Terminal expired", "terminal connection ticket has expired", false)
	case errors.Is(err, terminalsession.ErrConflict):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorConflict, "Terminal conflict", "terminal session conflicts with current runtime or lifecycle", false)
	case errors.Is(err, terminalsession.ErrRetryableTransaction):
		writeProblem(response, requestID, http.StatusServiceUnavailable, paasv1.ErrorInternal, "PaaS unavailable", "terminal session could not be committed safely", true)
	case errors.Is(err, context.DeadlineExceeded):
		writeProblem(response, requestID, http.StatusGatewayTimeout, paasv1.ErrorDeadlineExceeded, "Deadline exceeded", "terminal session deadline was exceeded", true)
	default:
		writeProblem(response, requestID, http.StatusInternalServerError, paasv1.ErrorInternal, "Internal error", "terminal session could not be completed", true)
	}
}

func writeProblem(
	response http.ResponseWriter,
	requestID string,
	status int,
	code paasv1.ErrorCode,
	title string,
	detail string,
	retryable bool,
) {
	problem := paasv1.Problem{
		Type:  "https://xiak.com/problems/" + strings.ToLower(strings.ReplaceAll(string(code), "_", "-")),
		Title: title, Status: status, Code: code, Detail: detail,
		TraceID: requestID, Retryable: retryable,
	}
	if err := paasv1.ValidateProblem(problem); err != nil {
		problem = paasv1.Problem{
			Type: "https://xiak.com/problems/internal", Title: "Internal error",
			Status: http.StatusInternalServerError, Code: paasv1.ErrorInternal,
			Detail:  "the error response could not be normalized",
			TraceID: "request-unavailable", Retryable: false,
		}
		status = http.StatusInternalServerError
	}
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(problem)
}

func resourceVersionETag(resourceVersion uint64) string {
	if resourceVersion == 0 {
		return ""
	}
	return quotedETag(strconv.FormatUint(resourceVersion, 10))
}

func quotedETag(value string) string {
	return `"` + value + `"`
}

func terminalOperation(state paasv1.OperationState) bool {
	return state == paasv1.OperationSucceeded ||
		state == paasv1.OperationFailed ||
		state == paasv1.OperationCancelled ||
		state == paasv1.OperationManualIntervention
}

func validTerminalPublicBasePath(value string) bool {
	if len(value) < 2 || len(value) > 128 || value[0] != '/' ||
		strings.HasSuffix(value, "/") || pathpkg.Clean(value) != value {
		return false
	}
	for _, character := range value[1:] {
		if character != '/' && character != '-' && character != '_' && character != '.' &&
			(character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func (value *handler) terminalConnectPath(sessionID paasv1.ResourceID) string {
	return value.config.TerminalPublicBasePath + "/terminal-sessions/" + string(sessionID) + "/connect"
}

func newRequestID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	return "request-" + hex.EncodeToString(raw[:]), nil
}

func newTerminalTicket() (string, string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", errors.New("generate terminal ticket")
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw[:])
	digest := sha256.Sum256([]byte(ticket))
	return ticket, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validTerminalTicket(ticket string, digest string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(ticket)
	if err != nil || len(decoded) != 32 || len(ticket) != 43 ||
		paasv1.ValidateDigest("ticketDigest", digest) != nil {
		return false
	}
	calculated := sha256.Sum256([]byte(ticket))
	return digest == "sha256:"+hex.EncodeToString(calculated[:])
}
