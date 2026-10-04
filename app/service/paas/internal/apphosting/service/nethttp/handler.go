// Package nethttp exposes the minimal authenticated Phase 1 apphosting HTTP
// workflow on the standard library HTTP stack.
package nethttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/internal/externalrequest"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/verifyinstallation"
)

const defaultMaximumBodyBytes = int64(16 * 1024 * 1024)

type Workflow interface {
	CreateApplication(
		context.Context,
		applicationlifecycle.CreateApplicationCommand,
	) (paasv1.Application, paasv1.Operation, bool, error)
	SetApplicationLabel(context.Context, applicationlifecycle.SetApplicationLabelCommand) (applicationlifecycle.ApplicationLabelResult, error)
	DeleteApplicationLabel(context.Context, applicationlifecycle.DeleteApplicationLabelCommand) (applicationlifecycle.ApplicationLabelResult, error)
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
	InspectApplicationAuthorization(context.Context, port.AuthorizationSubjectContext, paasv1.ResourceID) (applicationlifecycle.ApplicationAuthorizationSnapshot, error)
	GetApplication(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.Application, error)
	GetConfiguration(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.Configuration, error)
	GetConfigurationRevision(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.ConfigurationRevision, error)
	GetApplicationRevision(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.ApplicationRevision, error)
	GetDeployment(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.Deployment, error)
	GetDeploymentGeneration(context.Context, port.Authorization, paasv1.ResourceID, uint64) (paasv1.DeploymentGeneration, error)
	GetOperation(context.Context, port.Authorization, paasv1.OperationID) (paasv1.Operation, error)
}

type Config struct {
	MaximumBodyBytes int64
	NorthboundOrigin string
	InstallationID   string
	NewRequestID     func() (string, error)
	Readiness        func(context.Context) (paasv1.Readiness, error)
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
	installationVerifier InstallationVerifier
	accessKeyBoundary    *externalrequest.Boundary
	config               Config
	routes               *http.ServeMux
}

func NewHandler(
	authorizer port.Authorizer,
	workflow Workflow,
	installationVerifier InstallationVerifier,
	config Config,
) (http.Handler, error) {
	if authorizer == nil || workflow == nil || installationVerifier == nil {
		return nil, errors.New("HTTP Authorizer, workflow, and installation verifier are required")
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
	if config.NewRequestID == nil {
		config.NewRequestID = newRequestID
	}
	var accessKeyBoundary *externalrequest.Boundary
	if config.NorthboundOrigin != "" {
		var err error
		accessKeyBoundary, err = externalrequest.NewBoundary(
			config.NorthboundOrigin, "/api/paas", config.InstallationID, iamv1.ProductPaaS,
		)
		if err != nil {
			return nil, errors.New("AccessKey northbound boundary is invalid")
		}
	}
	value := &handler{
		authorizer: authorizer, workflow: workflow,
		installationVerifier: installationVerifier, accessKeyBoundary: accessKeyBoundary, config: config,
	}
	routes := http.NewServeMux()
	routes.HandleFunc("GET /ready", value.ready)
	routes.HandleFunc("POST /v1/applications", value.createApplication)
	routes.HandleFunc("GET /v1/applications/{applicationId}", value.getApplication)
	routes.HandleFunc("PUT /v1/applications/{applicationId}/labels/{labelKey}", value.setApplicationLabel)
	routes.HandleFunc("DELETE /v1/applications/{applicationId}/labels/{labelKey}", value.deleteApplicationLabel)
	routes.HandleFunc("POST /v1/configurations", value.createConfiguration)
	routes.HandleFunc("GET /v1/configurations/{configurationId}", value.getConfiguration)
	routes.HandleFunc("POST /v1/configuration-revisions", value.createConfigurationRevision)
	routes.HandleFunc("GET /v1/configuration-revisions/{configurationRevisionId}", value.getConfigurationRevision)
	routes.HandleFunc("POST /v1/application-revisions", value.createApplicationRevision)
	routes.HandleFunc("GET /v1/application-revisions/{applicationRevisionId}", value.getApplicationRevision)
	routes.HandleFunc("POST /v1/deployments", value.createDeployment)
	routes.HandleFunc("GET /v1/deployments/{deploymentId}", value.getDeployment)
	routes.HandleFunc("PUT /v1/deployments/{deploymentId}", value.updateDeployment)
	routes.HandleFunc("POST /v1/deployments/{deploymentId}/rollback", value.rollbackDeployment)
	routes.HandleFunc("GET /v1/deployments/{deploymentId}/generations/{generation}", value.getDeploymentGeneration)
	routes.HandleFunc("GET /v1/operations/{operationId}", value.getOperation)
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
	if externalrequest.IsAccessKeyAuthorization(request) {
		if !value.prepareAccessKeyRequest(response, request) {
			return
		}
	}
	value.routes.ServeHTTP(response, request)
}

type accessKeyContextKey struct{}

type accessKeyRequestContext struct {
	SignedRequest iamv1.AccessKeySignedRequest
	SourceIP      string
	Actions       []iamv1.Action
}

func accessKeyActionsForRoute(method, path string) ([]iamv1.Action, bool) {
	if method == http.MethodGet {
		for _, route := range []struct {
			prefix string
			idName string
			action iamv1.Action
		}{
			{"/v1/applications/", "applicationId", port.AuthorizeApplicationRead},
			{"/v1/configurations/", "configurationId", port.AuthorizeConfigurationRead},
			{"/v1/configuration-revisions/", "configurationRevisionId", port.AuthorizeConfigurationRevisionRead},
			{"/v1/application-revisions/", "applicationRevisionId", port.AuthorizeApplicationRevisionRead},
			{"/v1/deployments/", "deploymentId", port.AuthorizeDeploymentRead},
			{"/v1/operations/", "operationId", port.AuthorizeOperationRead},
		} {
			id := strings.TrimPrefix(path, route.prefix)
			if id != path && !strings.Contains(id, "/") && paasv1.ValidateID(route.idName, id) == nil {
				return []iamv1.Action{route.action}, true
			}
		}
		const deploymentPrefix = "/v1/deployments/"
		parts := strings.Split(strings.TrimPrefix(path, deploymentPrefix), "/")
		if len(parts) == 3 && parts[1] == "generations" &&
			paasv1.ValidateID("deploymentId", parts[0]) == nil {
			generation, err := strconv.ParseUint(parts[2], 10, 64)
			if err == nil && generation > 0 && generation <= 9007199254740991 {
				return []iamv1.Action{port.AuthorizeDeploymentRead}, true
			}
		}
		return nil, false
	}
	if method == http.MethodPut {
		const applicationPrefix = "/v1/applications/"
		applicationPath := strings.TrimPrefix(path, applicationPrefix)
		parts := strings.Split(applicationPath, "/")
		if applicationPath != path && len(parts) == 3 && parts[1] == "labels" &&
			paasv1.ValidateID("applicationId", parts[0]) == nil &&
			port.ValidateApplicationLabelKeyForAction(port.AuthorizeApplicationLabelSet, parts[2]) == nil {
			return []iamv1.Action{port.AuthorizeApplicationLabelSet}, true
		}
		const deploymentPrefix = "/v1/deployments/"
		id := strings.TrimPrefix(path, deploymentPrefix)
		if id != path && !strings.Contains(id, "/") && paasv1.ValidateID("deploymentId", id) == nil {
			return []iamv1.Action{port.AuthorizeDeploymentUpdate, port.AuthorizeDeploymentStop}, true
		}
		return nil, false
	}
	if method == http.MethodDelete {
		const applicationPrefix = "/v1/applications/"
		applicationPath := strings.TrimPrefix(path, applicationPrefix)
		parts := strings.Split(applicationPath, "/")
		if applicationPath != path && len(parts) == 3 && parts[1] == "labels" &&
			paasv1.ValidateID("applicationId", parts[0]) == nil &&
			port.ValidateApplicationLabelKeyForAction(port.AuthorizeApplicationLabelDelete, parts[2]) == nil {
			return []iamv1.Action{port.AuthorizeApplicationLabelDelete}, true
		}
		return nil, false
	}
	if method != http.MethodPost {
		return nil, false
	}
	const deploymentPrefix = "/v1/deployments/"
	const rollbackSuffix = "/rollback"
	if strings.HasPrefix(path, deploymentPrefix) && strings.HasSuffix(path, rollbackSuffix) {
		id := strings.TrimSuffix(strings.TrimPrefix(path, deploymentPrefix), rollbackSuffix)
		if !strings.Contains(id, "/") && paasv1.ValidateID("deploymentId", id) == nil {
			return []iamv1.Action{port.AuthorizeDeploymentRollback}, true
		}
		return nil, false
	}
	switch path {
	case "/v1/applications":
		return []iamv1.Action{port.AuthorizeApplicationCreate}, true
	case "/v1/configurations":
		return []iamv1.Action{port.AuthorizeConfigurationCreate}, true
	case "/v1/configuration-revisions":
		return []iamv1.Action{port.AuthorizeConfigurationRevisionCreate}, true
	case "/v1/application-revisions":
		return []iamv1.Action{port.AuthorizeApplicationRevisionCreate}, true
	case "/v1/deployments":
		return []iamv1.Action{port.AuthorizeDeploymentCreate}, true
	default:
		return nil, false
	}
}

func (value *handler) prepareAccessKeyRequest(response http.ResponseWriter, request *http.Request) bool {
	var expectedActions []iamv1.Action
	var accepted bool
	if request.URL != nil {
		expectedActions, accepted = accessKeyActionsForRoute(request.Method, request.URL.Path)
	}
	if value.accessKeyBoundary == nil || !accepted || request.URL.RawQuery != "" {
		requestID, ok := value.beginRequest(response)
		if !ok {
			return false
		}
		writeProblem(response, requestID, http.StatusUnauthorized, paasv1.ErrorUnauthenticated,
			"Unauthenticated", "access keys are not accepted for this route", false)
		return false
	}
	bodyReader := http.MaxBytesReader(response, request.Body, value.config.MaximumBodyBytes)
	body, err := io.ReadAll(bodyReader)
	_ = bodyReader.Close()
	if err != nil {
		requestID, ok := value.beginRequest(response)
		if !ok {
			return false
		}
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument,
			"Invalid argument", "signed request body is invalid or too large", false)
		return false
	}
	if request.Method == http.MethodGet && len(body) != 0 {
		clear(body)
		requestID, ok := value.beginRequest(response)
		if !ok {
			return false
		}
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument,
			"Invalid argument", "signed resource reads accept no request body", false)
		return false
	}
	external, err := value.accessKeyBoundary.AccessKeyRequest(request, body)
	if err != nil {
		clear(body)
		requestID, ok := value.beginRequest(response)
		if !ok {
			return false
		}
		writeProblem(response, requestID, http.StatusUnauthorized, paasv1.ErrorUnauthenticated,
			"Unauthenticated", "signed request authentication is invalid", false)
		return false
	}
	request.Body = io.NopCloser(bytes.NewReader(bytes.Clone(body)))
	accessKeyContext := accessKeyRequestContext{
		SignedRequest: external.SignedRequest,
		SourceIP:      external.SourceIP,
		Actions:       expectedActions,
	}
	*request = *request.WithContext(context.WithValue(request.Context(), accessKeyContextKey{}, accessKeyContext))
	clear(body)
	return true
}

func (value *handler) createApplication(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.CreateApplicationRequest](value, response, request, requestID)
	if !ok {
		return
	}
	if err := paasv1.ValidateLabels(body.Labels); err != nil {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "application labels are invalid", false)
		return
	}
	authorization, ok := value.authorizeRequestWithLabels(response, request, requestID,
		port.AuthorizeApplicationCreate, port.ResourceApplication, "collection",
		iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate, body.Labels, nil)
	if !ok {
		return
	}
	resource, operation, replayed, err := value.workflow.CreateApplication(request.Context(), applicationlifecycle.CreateApplicationCommand{
		Authorization: authorization, Request: body, IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	value.writeCreation(response, requestID, replayed, resource.Metadata.ResourceVersion,
		"/v1/applications/"+string(resource.Metadata.ID), operation, err)
}

func (value *handler) setApplicationLabel(response http.ResponseWriter, request *http.Request) {
	applicationID, ok := pathResourceID(response, request, "applicationId")
	if !ok {
		return
	}
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "application label mutation does not accept query parameters", false)
		return
	}
	body, ok := decodeJSON[paasv1.SetApplicationLabelRequest](value, response, request, requestID)
	if !ok {
		return
	}
	if err := paasv1.ValidateSetApplicationLabelRequest(body); err != nil {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "application label value is invalid", false)
		return
	}
	expected, ok := parseIfMatch(response, request, requestID)
	if !ok {
		return
	}
	value.mutateApplicationLabel(response, request, requestID, applicationID,
		port.AuthorizeApplicationLabelSet, &body.Value, expected)
}

func (value *handler) deleteApplicationLabel(response http.ResponseWriter, request *http.Request) {
	applicationID, ok := pathResourceID(response, request, "applicationId")
	if !ok {
		return
	}
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" || request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "application label deletion does not accept query parameters or a request body", false)
		return
	}
	expected, ok := parseIfMatch(response, request, requestID)
	if !ok {
		return
	}
	value.mutateApplicationLabel(response, request, requestID, applicationID,
		port.AuthorizeApplicationLabelDelete, nil, expected)
}

func (value *handler) mutateApplicationLabel(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	applicationID paasv1.ResourceID,
	action iamv1.Action,
	targetValue *string,
	expectedResourceVersion uint64,
) {
	labelKey := request.PathValue("labelKey")
	if port.ValidateApplicationLabelKeyForAction(action, labelKey) != nil {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "application label key is not declared by the current PaaS Profile", false)
		return
	}
	subject, ok := value.resolveRequestSubject(response, request, requestID, action)
	if !ok {
		return
	}
	snapshot, inspectErr := value.workflow.InspectApplicationAuthorization(request.Context(), subject, applicationID)
	found := inspectErr == nil
	if inspectErr != nil && !errors.Is(inspectErr, applicationlifecycle.ErrNotFound) {
		writeWorkflowError(response, requestID, inspectErr)
		return
	}
	var currentLabels map[string]string
	if found {
		currentLabels = snapshot.Labels
	}
	var requestedLabels map[string]string
	if targetValue != nil {
		requestedLabels = map[string]string{labelKey: *targetValue}
	} else if currentValue, present := currentLabels[labelKey]; present {
		requestedLabels = map[string]string{labelKey: currentValue}
	}
	authorization, ok := value.authorizeRequestWithLabels(response, request, requestID,
		action, port.ResourceApplication, applicationID, iamv1.AuthorizationResourceInstance, "",
		requestedLabels, currentLabels)
	if !ok {
		return
	}
	if port.ValidateAuthorizationForSubjectContext(authorization, subject) != nil {
		writeAuthorizationError(response, requestID, port.ErrAuthorizationUnavailable)
		return
	}
	if !found {
		writeWorkflowError(response, requestID, applicationlifecycle.ErrNotFound)
		return
	}
	var result applicationlifecycle.ApplicationLabelResult
	var err error
	if targetValue == nil {
		result, err = value.workflow.DeleteApplicationLabel(request.Context(), applicationlifecycle.DeleteApplicationLabelCommand{
			Authorization: authorization, ApplicationID: applicationID, LabelKey: labelKey,
			ExpectedResourceVersion: expectedResourceVersion, IdempotencyKey: request.Header.Get("Idempotency-Key"),
		})
	} else {
		result, err = value.workflow.SetApplicationLabel(request.Context(), applicationlifecycle.SetApplicationLabelCommand{
			Authorization: authorization, ApplicationID: applicationID, LabelKey: labelKey, Value: *targetValue,
			ExpectedResourceVersion: expectedResourceVersion, IdempotencyKey: request.Header.Get("Idempotency-Key"),
		})
	}
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	writeOperation(response, http.StatusOK, "/v1/applications/"+string(applicationID), result.ResourceVersion, result.Operation)
}

func (value *handler) createConfiguration(response http.ResponseWriter, request *http.Request) {
	requestID, authorization, ok := value.authorizeCreationCollection(response, request, port.AuthorizeConfigurationCreate, port.ResourceConfiguration)
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
	requestID, authorization, ok := value.authorizeCreationCollection(response, request, port.AuthorizeConfigurationRevisionCreate, port.ResourceConfigurationRevision)
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
	requestID, authorization, ok := value.authorizeCreationCollection(response, request, port.AuthorizeApplicationRevisionCreate, port.ResourceApplicationRevision)
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
	requestID, authorization, ok := value.authorizeCreationCollection(response, request, port.AuthorizeDeploymentCreate, port.ResourceDeployment)
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
		port.ResourceDeployment,
		deploymentID,
		iamv1.AuthorizationResourceInstance, "",
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
	requestID, authorization, ok := value.authorize(response, request, port.AuthorizeDeploymentRollback, port.ResourceDeployment, deploymentID, iamv1.AuthorizationResourceInstance, "")
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
	id, ok := pathResourceID(response, request, "applicationId")
	if !ok {
		return
	}
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	subject, ok := value.resolveRequestSubject(response, request, requestID, port.AuthorizeApplicationRead)
	if !ok {
		return
	}
	snapshot, inspectErr := value.workflow.InspectApplicationAuthorization(request.Context(), subject, id)
	found := inspectErr == nil
	if inspectErr != nil && !errors.Is(inspectErr, applicationlifecycle.ErrNotFound) {
		writeWorkflowError(response, requestID, inspectErr)
		return
	}
	var labels map[string]string
	if found {
		labels = snapshot.Labels
	}
	authorization, ok := value.authorizeRequestWithLabels(response, request, requestID,
		port.AuthorizeApplicationRead, port.ResourceApplication, id,
		iamv1.AuthorizationResourceInstance, "", nil, labels)
	if !ok {
		return
	}
	if port.ValidateAuthorizationForSubjectContext(authorization, subject) != nil {
		writeAuthorizationError(response, requestID, port.ErrAuthorizationUnavailable)
		return
	}
	resource, err := value.workflow.GetApplication(request.Context(), authorization, id)
	if err == nil && (!found || resource.Metadata.ID != snapshot.ID ||
		resource.Metadata.ResourceVersion != snapshot.ResourceVersion ||
		port.ValidateAuthorizationResourceTagsForAction(authorization, port.AuthorizeApplicationRead, resource.Metadata.Labels) != nil) {
		writeAuthorizationError(response, requestID, port.ErrAuthorizationUnavailable)
		return
	}
	writeResource(response, requestID, resource, resourceVersionETag(resource.Metadata.ResourceVersion), err)
}

func (value *handler) resolveRequestSubject(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	expectedAction iamv1.Action,
) (port.AuthorizationSubjectContext, bool) {
	var subject port.AuthorizationSubjectContext
	var err error
	if signedContext, present := request.Context().Value(accessKeyContextKey{}).(accessKeyRequestContext); present {
		accessKeyAuthorizer, ok := value.authorizer.(port.AccessKeyAuthorizer)
		if !ok || !slices.Contains(signedContext.Actions, expectedAction) {
			writeAuthorizationError(response, requestID, port.ErrAuthorizationUnavailable)
			return port.AuthorizationSubjectContext{}, false
		}
		subject, err = accessKeyAuthorizer.ResolveAccessKeySubject(request.Context(), signedContext.SignedRequest)
	} else {
		subjectRequest := port.SubjectResolutionRequest{Credential: request.Header.Get("Authorization")}
		if port.ValidateSubjectResolutionRequest(subjectRequest) != nil {
			writeAuthorizationError(response, requestID, port.ErrUnauthenticated)
			return port.AuthorizationSubjectContext{}, false
		}
		subject, err = value.authorizer.ResolveSubject(request.Context(), subjectRequest)
	}
	if err != nil {
		writeAuthorizationError(response, requestID, err)
		return port.AuthorizationSubjectContext{}, false
	}
	if port.ValidateAuthorizationSubjectContext(subject) != nil {
		writeAuthorizationError(response, requestID, port.ErrAuthorizationUnavailable)
		return port.AuthorizationSubjectContext{}, false
	}
	return subject, true
}

func (value *handler) getConfiguration(response http.ResponseWriter, request *http.Request) {
	id, authorization, requestID, ok := value.authorizePath(response, request, "configurationId", port.AuthorizeConfigurationRead, port.ResourceConfiguration)
	if !ok {
		return
	}
	resource, err := value.workflow.GetConfiguration(request.Context(), authorization, id)
	writeResource(response, requestID, resource, resourceVersionETag(resource.Metadata.ResourceVersion), err)
}

func (value *handler) getConfigurationRevision(response http.ResponseWriter, request *http.Request) {
	id, authorization, requestID, ok := value.authorizePath(response, request, "configurationRevisionId", port.AuthorizeConfigurationRevisionRead, port.ResourceConfigurationRevision)
	if !ok {
		return
	}
	resource, err := value.workflow.GetConfigurationRevision(request.Context(), authorization, id)
	writeResource(response, requestID, resource, resourceVersionETag(resource.Metadata.ResourceVersion), err)
}

func (value *handler) getApplicationRevision(response http.ResponseWriter, request *http.Request) {
	id, authorization, requestID, ok := value.authorizePath(response, request, "applicationRevisionId", port.AuthorizeApplicationRevisionRead, port.ResourceApplicationRevision)
	if !ok {
		return
	}
	resource, err := value.workflow.GetApplicationRevision(request.Context(), authorization, id)
	writeResource(response, requestID, resource, resourceVersionETag(resource.Metadata.ResourceVersion), err)
}

func (value *handler) getDeployment(response http.ResponseWriter, request *http.Request) {
	id, authorization, requestID, ok := value.authorizePath(response, request, "deploymentId", port.AuthorizeDeploymentRead, port.ResourceDeployment)
	if !ok {
		return
	}
	resource, err := value.workflow.GetDeployment(request.Context(), authorization, id)
	writeResource(response, requestID, resource, resourceVersionETag(resource.Metadata.ResourceVersion), err)
}

func (value *handler) getDeploymentGeneration(response http.ResponseWriter, request *http.Request) {
	id, authorization, requestID, ok := value.authorizePath(response, request, "deploymentId", port.AuthorizeDeploymentRead, port.ResourceDeployment)
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
	requestID, authorization, ok := value.authorize(response, request, port.AuthorizeOperationRead, port.ResourceOperation, paasv1.ResourceID(id), iamv1.AuthorizationResourceInstance, "")
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

func (value *handler) authorizeCreationCollection(
	response http.ResponseWriter,
	request *http.Request,
	action iamv1.Action,
	kind string,
) (string, port.Authorization, bool) {
	return value.authorize(response, request, action, kind, "collection", iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionCreate)
}

func (value *handler) authorizePath(
	response http.ResponseWriter,
	request *http.Request,
	pathName string,
	action iamv1.Action,
	kind string,
) (paasv1.ResourceID, port.Authorization, string, bool) {
	id, ok := pathResourceID(response, request, pathName)
	if !ok {
		return "", port.Authorization{}, "", false
	}
	requestID, authorization, ok := value.authorize(response, request, action, kind, id, iamv1.AuthorizationResourceInstance, "")
	return id, authorization, requestID, ok
}

func (value *handler) authorize(
	response http.ResponseWriter,
	request *http.Request,
	action iamv1.Action,
	kind string,
	id paasv1.ResourceID,
	mode iamv1.AuthorizationResourceMode,
	usage iamv1.AuthorizationCollectionUsage,
) (string, port.Authorization, bool) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return "", port.Authorization{}, false
	}
	authorization, ok := value.authorizeRequest(response, request, requestID, action, kind, id, mode, usage)
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
	action iamv1.Action,
	kind string,
	id paasv1.ResourceID,
	mode iamv1.AuthorizationResourceMode,
	usage iamv1.AuthorizationCollectionUsage,
) (port.Authorization, bool) {
	return value.authorizeRequestWithLabels(response, request, requestID, action, kind, id, mode, usage, nil, nil)
}

func (value *handler) authorizeRequestWithLabels(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	action iamv1.Action,
	kind string,
	id paasv1.ResourceID,
	mode iamv1.AuthorizationResourceMode,
	usage iamv1.AuthorizationCollectionUsage,
	requestLabels map[string]string,
	resourceLabels map[string]string,
) (port.Authorization, bool) {
	signedContext, signed := request.Context().Value(accessKeyContextKey{}).(accessKeyRequestContext)
	var sourceIP string
	var err error
	if signed {
		sourceIP = signedContext.SourceIP
	} else {
		sourceIP, err = authorizationSourceIP(request.RemoteAddr)
		if err != nil {
			writeProblem(response, requestID, http.StatusServiceUnavailable, paasv1.ErrorIdentityUnavailable, "Identity unavailable", "request network authority could not be established", true)
			return port.Authorization{}, false
		}
	}
	authorizationRequest := port.AuthorizationRequest{
		Credential:   request.Header.Get("Authorization"),
		Action:       action,
		Resource:     paasv1.ResourceRef{Kind: kind, ID: id},
		ResourceMode: mode, CollectionUsage: usage,
		SourceIP:       sourceIP,
		RequestLabels:  maps.Clone(requestLabels),
		ResourceLabels: maps.Clone(resourceLabels),
		RequestID:      requestID,
	}
	if signed {
		if !slices.Contains(signedContext.Actions, action) {
			writeAuthorizationError(response, requestID, port.ErrUnauthenticated)
			return port.Authorization{}, false
		}
		accessKeyAuthorizer, ok := value.authorizer.(port.AccessKeyAuthorizer)
		if !ok {
			writeAuthorizationError(response, requestID, port.ErrAuthorizationUnavailable)
			return port.Authorization{}, false
		}
		accessKeyRequest := port.AccessKeyAuthorizationRequest{
			Action: action, Resource: authorizationRequest.Resource,
			ResourceMode: mode, CollectionUsage: usage, SourceIP: sourceIP,
			RequestLabels: maps.Clone(requestLabels), ResourceLabels: maps.Clone(resourceLabels),
			RequestID: requestID, SignedRequest: signedContext.SignedRequest,
		}
		if port.ValidateAccessKeyAuthorizationRequest(accessKeyRequest) != nil {
			writeAuthorizationError(response, requestID, port.ErrUnauthenticated)
			return port.Authorization{}, false
		}
		authorization, err := accessKeyAuthorizer.AuthorizeAccessKey(request.Context(), accessKeyRequest)
		if err != nil {
			writeAuthorizationError(response, requestID, err)
			return port.Authorization{}, false
		}
		if port.ValidateAccessKeyAuthorizationForRequest(authorization, accessKeyRequest) != nil {
			writeAuthorizationError(response, requestID, port.ErrAuthorizationUnavailable)
			return port.Authorization{}, false
		}
		return authorization, true
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

func authorizationSourceIP(remoteAddress string) (string, error) {
	host, port, err := net.SplitHostPort(remoteAddress)
	if err != nil || host == "" {
		return "", errors.New("request remote address is invalid")
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return "", errors.New("request remote port is invalid")
	}
	address, err := iamv1.ParseAuthorizationSourceIP(host)
	if err != nil {
		return "", err
	}
	return address.String(), nil
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
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "request body is not valid JSON", false)
		return zero, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "request body must contain one JSON document", false)
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

func writeOperation(
	response http.ResponseWriter,
	status int,
	location string,
	resourceVersion uint64,
	operation paasv1.Operation,
) {
	response.Header().Set("Location", location)
	response.Header().Set("Operation-Location", "/v1/operations/"+string(operation.ID))
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
	case errors.Is(err, port.ErrAuthorizationReplay):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorConflict, "Signed request conflict", "the signed request nonce was already consumed", false)
	default:
		writeProblem(response, requestID, http.StatusServiceUnavailable, paasv1.ErrorIdentityUnavailable, "Identity unavailable", "IAM authorization is unavailable", true)
	}
}

func writeWorkflowError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, applicationlifecycle.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "request violates the apphosting contract", false)
	case errors.Is(err, applicationlifecycle.ErrNotFound):
		writeProblem(response, requestID, http.StatusNotFound, paasv1.ErrorNotFound, "Not found", "the requested tenant resource does not exist", false)
	case errors.Is(err, applicationlifecycle.ErrAlreadyExists):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorAlreadyExists, "Already exists", "the resource already exists", false)
	case errors.Is(err, applicationlifecycle.ErrIdempotencyConflict):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorIdempotencyConflict, "Idempotency conflict", "Idempotency-Key was already used for different content", false)
	case errors.Is(err, applicationlifecycle.ErrResourceVersionConflict):
		writeProblem(response, requestID, http.StatusPreconditionFailed, paasv1.ErrorResourceVersionConflict, "Resource version conflict", "If-Match does not identify the current resource version", false)
	case errors.Is(err, applicationlifecycle.ErrNoDesiredChange):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorConflict, "No desired change", "the requested desired state is unchanged", false)
	case errors.Is(err, applicationlifecycle.ErrOperationInProgress):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorConflict, "Operation in progress", "Deployment already has an active Operation", true)
	case errors.Is(err, context.DeadlineExceeded):
		writeProblem(response, requestID, http.StatusGatewayTimeout, paasv1.ErrorDeadlineExceeded, "Deadline exceeded", "request deadline was exceeded", true)
	default:
		writeProblem(response, requestID, http.StatusInternalServerError, paasv1.ErrorInternal, "Internal error", "the apphosting request could not be completed", true)
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

func newRequestID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	return "request-" + hex.EncodeToString(raw[:]), nil
}
