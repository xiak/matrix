// Package nethttp exposes the authenticated managed-service browser workflow.
package nethttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase"
)

type Workflow interface {
	ListOfferings(context.Context, port.Authorization) (managedservicev1.ServiceOfferingList, error)
	ListRegions(context.Context, port.Authorization) (managedservicev1.RegionList, error)
	ListQuotaEntitlements(context.Context, port.Authorization) (managedservicev1.QuotaEntitlementList, error)
	ListServiceInstallations(context.Context, port.Authorization) (managedservicev1.ServiceInstallationList, error)
	ActivateQuota(context.Context, usecase.ActivateQuotaCommand) (managedservicev1.QuotaEntitlement, bool, error)
	CreateInstallation(context.Context, usecase.CreateInstallationCommand) (managedservicev1.ServiceInstallation, bool, error)
}

type Config struct {
	NewRequestID func() (string, error)
}

type handler struct {
	authorizer port.Authorizer
	workflow   Workflow
	config     Config
}

func NewHandler(authorizer port.Authorizer, workflow Workflow, config Config) (http.Handler, error) {
	if authorizer == nil || workflow == nil {
		return nil, errors.New("managed-service HTTP dependencies are required")
	}
	if config.NewRequestID == nil {
		config.NewRequestID = func() (string, error) { return newID("request-") }
	}
	value := &handler{authorizer: authorizer, workflow: workflow, config: config}
	routes := http.NewServeMux()
	routes.HandleFunc("GET /managed-services/v1/offerings", value.listOfferings)
	routes.HandleFunc("GET /managed-services/v1/regions", value.listRegions)
	routes.HandleFunc("GET /managed-services/v1/quota-entitlements", value.listQuotaEntitlements)
	routes.HandleFunc("POST /managed-services/v1/quota-entitlements", value.activateQuota)
	routes.HandleFunc("GET /managed-services/v1/service-installations", value.listServiceInstallations)
	routes.HandleFunc("POST /managed-services/v1/service-installations", value.createInstallation)
	return routes, nil
}

func (value *handler) listOfferings(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeOfferingRead, port.ResourceServiceOffering,
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.ListOfferings(request.Context(), authorization)
	writeResult(response, requestID, result, err)
}

func (value *handler) listRegions(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeRegionRead, port.ResourceRegion,
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.ListRegions(request.Context(), authorization)
	writeResult(response, requestID, result, err)
}

func (value *handler) listQuotaEntitlements(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeQuotaEntitlementRead, port.ResourceQuotaEntitlement,
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.ListQuotaEntitlements(request.Context(), authorization)
	writeResult(response, requestID, result, err)
}

func (value *handler) activateQuota(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeQuotaEntitlementActivate, port.ResourceQuotaEntitlement,
	)
	if !ok {
		return
	}
	body, ok := decodeRequest[managedservicev1.ActivateQuotaRequest](response, request, requestID)
	if !ok {
		return
	}
	result, replayed, err := value.workflow.ActivateQuota(request.Context(), usecase.ActivateQuotaCommand{
		Authorization: authorization, Request: body,
		IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	response.Header().Set("Location", "/managed-services/v1/quota-entitlements/"+result.ID)
	writeJSON(response, status, result)
}

func (value *handler) listServiceInstallations(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeInstallationRead, port.ResourceServiceInstallation,
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.ListServiceInstallations(request.Context(), authorization)
	writeResult(response, requestID, result, err)
}

func (value *handler) createInstallation(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeInstallationCreate, port.ResourceServiceInstallation,
	)
	if !ok {
		return
	}
	body, ok := decodeRequest[managedservicev1.CreateInstallationRequest](response, request, requestID)
	if !ok {
		return
	}
	result, replayed, err := value.workflow.CreateInstallation(request.Context(), usecase.CreateInstallationCommand{
		Authorization: authorization, Request: body,
		IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	status := http.StatusAccepted
	if replayed {
		status = http.StatusOK
	}
	response.Header().Set("Location", "/managed-services/v1/service-installations/"+result.ID)
	writeJSON(response, status, result)
}

func (value *handler) authorizeCollection(
	response http.ResponseWriter,
	request *http.Request,
	action string,
	resourceKind string,
) (port.Authorization, string, bool) {
	requestID, err := value.config.NewRequestID()
	if err != nil || managedservicev1.ValidateID("requestId", requestID) != nil {
		writeProblem(response, "request-unavailable", http.StatusInternalServerError,
			managedservicev1.ErrorInternal, "Internal error", "request identity could not be established", false)
		return port.Authorization{}, "", false
	}
	response.Header().Set("X-Request-ID", requestID)
	authorizationRequest := port.AuthorizationRequest{
		Credential: request.Header.Get("Authorization"), Action: action,
		Resource:  port.ResourceReference{Kind: resourceKind, ID: "collection"},
		RequestID: requestID,
	}
	if port.ValidateAuthorizationRequest(authorizationRequest) != nil {
		writeProblem(response, requestID, http.StatusUnauthorized,
			managedservicev1.ErrorUnauthenticated, "Unauthenticated", "a valid IAM credential is required", false)
		return port.Authorization{}, requestID, false
	}
	authorization, err := value.authorizer.Authorize(request.Context(), authorizationRequest)
	if err != nil {
		writeAuthorizationError(response, requestID, err)
		return port.Authorization{}, requestID, false
	}
	if port.ValidateAuthorizationForRequest(authorization, authorizationRequest) != nil {
		writeProblem(response, requestID, http.StatusServiceUnavailable,
			managedservicev1.ErrorIdentityUnavailable, "Identity unavailable", "IAM returned an invalid authorization decision", true)
		return port.Authorization{}, requestID, false
	}
	return authorization, requestID, true
}

func decodeRequest[T any](
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) (T, bool) {
	var zero T
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProblem(response, requestID, http.StatusUnsupportedMediaType,
			managedservicev1.ErrorInvalidArgument, "Unsupported media type", "Content-Type must be application/json", false)
		return zero, false
	}
	var result T
	if managedservicev1.DecodeRequest(request.Body, &result) != nil {
		writeProblem(response, requestID, http.StatusBadRequest,
			managedservicev1.ErrorInvalidArgument, "Invalid argument", "request body is not one valid managed-service document", false)
		return zero, false
	}
	return result, true
}

func acceptsNoInput(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) bool {
	if request.URL.RawQuery != "" || request.ContentLength > 0 {
		writeProblem(response, requestID, http.StatusBadRequest,
			managedservicev1.ErrorInvalidArgument, "Invalid argument", "collection read accepts no query or body", false)
		return false
	}
	return true
}

func writeResult(response http.ResponseWriter, requestID string, result any, err error) {
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func writeAuthorizationError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, port.ErrUnauthenticated):
		writeProblem(response, requestID, http.StatusUnauthorized,
			managedservicev1.ErrorUnauthenticated, "Unauthenticated", "IAM authentication failed", false)
	case errors.Is(err, port.ErrPermissionDenied):
		writeProblem(response, requestID, http.StatusForbidden,
			managedservicev1.ErrorPermissionDenied, "Permission denied", "IAM denied this action", false)
	default:
		writeProblem(response, requestID, http.StatusServiceUnavailable,
			managedservicev1.ErrorIdentityUnavailable, "Identity unavailable", "IAM authorization is unavailable", true)
	}
}

func writeWorkflowError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, usecase.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusBadRequest,
			managedservicev1.ErrorInvalidArgument, "Invalid argument", "request violates the managed-service contract", false)
	case errors.Is(err, usecase.ErrNotFound):
		writeProblem(response, requestID, http.StatusNotFound,
			managedservicev1.ErrorNotFound, "Not found", "the requested organization resource does not exist", false)
	case errors.Is(err, usecase.ErrAlreadyExists):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorAlreadyExists, "Already exists", "the service installation ID already exists", false)
	case errors.Is(err, usecase.ErrIdempotencyConflict):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorIdempotencyConflict, "Idempotency conflict", "Idempotency-Key was used for different content", false)
	case errors.Is(err, usecase.ErrQuotaExhausted):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorQuotaExhausted, "Quota exhausted", "the selected entitlement has no available instances", false)
	case errors.Is(err, usecase.ErrRegionUnavailable):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorRegionUnavailable, "Region unavailable", "the selected local region is not ready", true)
	case errors.Is(err, context.DeadlineExceeded):
		writeProblem(response, requestID, http.StatusGatewayTimeout,
			managedservicev1.ErrorInternal, "Deadline exceeded", "request deadline was exceeded", true)
	default:
		writeProblem(response, requestID, http.StatusInternalServerError,
			managedservicev1.ErrorInternal, "Internal error", "the managed-service request could not be completed", true)
	}
}

func writeProblem(
	response http.ResponseWriter,
	requestID string,
	status int,
	code managedservicev1.ErrorCode,
	title string,
	detail string,
	retryable bool,
) {
	problem := managedservicev1.Problem{
		Type:  "https://xiak.com/problems/" + strings.ToLower(strings.ReplaceAll(string(code), "_", "-")),
		Title: title, Status: status, Code: code, Detail: detail,
		TraceID: requestID, Retryable: retryable,
	}
	if managedservicev1.ValidateProblem(problem) != nil {
		problem = managedservicev1.Problem{
			Type: "https://xiak.com/problems/internal", Title: "Internal error",
			Status: http.StatusInternalServerError, Code: managedservicev1.ErrorInternal,
			Detail:  "the error response could not be normalized",
			TraceID: "request-unavailable", Retryable: false,
		}
		status = http.StatusInternalServerError
	}
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(problem)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func newID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate managed-service ID: %w", err)
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
