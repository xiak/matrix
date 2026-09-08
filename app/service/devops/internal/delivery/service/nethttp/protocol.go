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
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/xiak/matrix/api/contractjson"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runcontrol"
)

var forbiddenAuthorityHeaders = []string{
	"Matrix-Subject-Credential",
	"Matrix-Tenant-ID",
	"X-Tenant-ID",
	"Matrix-Organization-ID",
	"X-Organization-ID",
}

func (value *handler) acceptEnvelope(
	response http.ResponseWriter,
	request *http.Request,
	method string,
	acceptBody bool,
) bool {
	return value.acceptEnvelopeMode(response, request, method, acceptBody, false)
}

func (value *handler) acceptQueryEnvelope(
	response http.ResponseWriter,
	request *http.Request,
	method string,
) bool {
	return value.acceptEnvelopeMode(response, request, method, false, true)
}

func (value *handler) acceptEnvelopeMode(
	response http.ResponseWriter,
	request *http.Request,
	method string,
	acceptBody bool,
	acceptQuery bool,
) bool {
	if request.Method != method {
		methodNotAllowed(response, request, method)
		return false
	}
	if !acceptQuery && request.URL.RawQuery != "" {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "query parameters are not accepted", false)
		return false
	}
	for _, name := range forbiddenAuthorityHeaders {
		if len(request.Header.Values(name)) != 0 {
			writeProblem(response, requestID(request), http.StatusBadRequest,
				devopsv1.ErrorInvalidArgument, "Invalid argument", "caller authority headers are not accepted", false)
			return false
		}
	}
	if !acceptBody && (request.ContentLength != 0 || len(request.TransferEncoding) != 0) {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "this operation accepts no request body", false)
		return false
	}
	return true
}

func (value *handler) authorize(
	response http.ResponseWriter,
	request *http.Request,
	action iamv1.Action,
	kind iamv1.ResourceKind,
	id devopsv1.ResourceID,
) (port.Authorization, bool) {
	correlationID, traceParent, ok := requestCorrelation(response, request)
	if !ok {
		return port.Authorization{}, false
	}
	credentials := request.Header.Values("Authorization")
	if len(credentials) != 1 {
		writeProblem(response, requestID(request), http.StatusUnauthorized,
			devopsv1.ErrorUnauthenticated, "Unauthenticated", "one valid IAM credential is required", false)
		return port.Authorization{}, false
	}
	authorizationRequest := port.AuthorizationRequest{
		Credential: credentials[0], Action: action,
		Resource:  iamv1.ResourceReference{Kind: kind, ID: string(id)},
		RequestID: requestID(request), CorrelationID: correlationID, TraceParent: traceParent,
	}
	authorization, err := value.authorizer.Authorize(request.Context(), authorizationRequest)
	if err != nil {
		writeAuthorizationError(response, requestID(request), err)
		return port.Authorization{}, false
	}
	if port.ValidateAuthorizationForRequest(authorization, action, kind, id) != nil ||
		authorization.RequestID != authorizationRequest.RequestID ||
		authorization.CorrelationID != authorizationRequest.CorrelationID ||
		authorization.TraceParent != authorizationRequest.TraceParent {
		writeProblem(response, requestID(request), http.StatusServiceUnavailable,
			devopsv1.ErrorUnavailable, "Identity unavailable", "IAM returned an invalid authorization decision", true)
		return port.Authorization{}, false
	}
	return authorization, true
}

func requestCorrelation(response http.ResponseWriter, request *http.Request) (string, string, bool) {
	correlationID := requestID(request)
	correlations := request.Header.Values("Matrix-Correlation-ID")
	if len(correlations) > 1 || len(correlations) == 1 && devopsv1.ValidateID("correlationId", correlations[0]) != nil {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "Matrix-Correlation-ID is invalid", false)
		return "", "", false
	}
	if len(correlations) == 1 {
		correlationID = correlations[0]
	}
	traceParent := ""
	traces := request.Header.Values("traceparent")
	if len(traces) > 1 || len(traces) == 1 && port.ValidateTraceParent(traces[0]) != nil {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "traceparent is invalid", false)
		return "", "", false
	}
	if len(traces) == 1 {
		traceParent = traces[0]
	}
	return correlationID, traceParent, true
}

func decodeJSON[T any](response http.ResponseWriter, request *http.Request) (T, bool) {
	var zero T
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || request.Header.Get("Content-Encoding") != "" {
		writeProblem(response, requestID(request), http.StatusUnsupportedMediaType,
			devopsv1.ErrorUnsupportedMediaType, "Unsupported media type", "Content-Type must be application/json without content encoding", false)
		return zero, false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		writeProblem(response, requestID(request), http.StatusUnsupportedMediaType,
			devopsv1.ErrorUnsupportedMediaType, "Unsupported media type", "Content-Type must be application/json", false)
		return zero, false
	}
	if request.ContentLength > devopsv1.MaxDocumentBytes {
		writeProblem(response, requestID(request), http.StatusRequestEntityTooLarge,
			devopsv1.ErrorPayloadTooLarge, "Payload too large", "request body exceeds the DevOps contract limit", false)
		return zero, false
	}
	var body T
	if err := devopsv1.Decode(request.Body, &body); err != nil {
		if errors.Is(err, contractjson.ErrDocumentTooLarge) {
			writeProblem(response, requestID(request), http.StatusRequestEntityTooLarge,
				devopsv1.ErrorPayloadTooLarge, "Payload too large", "request body exceeds the DevOps contract limit", false)
		} else {
			writeProblem(response, requestID(request), http.StatusBadRequest,
				devopsv1.ErrorInvalidArgument, "Invalid argument", "request body is not one unambiguous DevOps JSON document", false)
		}
		return zero, false
	}
	return body, true
}

func validateRequest(response http.ResponseWriter, request *http.Request, err error) bool {
	if err == nil {
		return true
	}
	writeProblem(response, requestID(request), http.StatusUnprocessableEntity,
		devopsv1.ErrorInvalidArgument, "Invalid argument", "request violates the DevOps contract", false)
	return false
}

func pathID(response http.ResponseWriter, request *http.Request, name string) (devopsv1.ResourceID, bool) {
	id := devopsv1.ResourceID(request.PathValue(name))
	if devopsv1.ValidateID(name, string(id)) != nil {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", name+" is invalid", false)
		return "", false
	}
	return id, true
}

func idempotencyKey(response http.ResponseWriter, request *http.Request) (string, bool) {
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || values[0] == "" || len([]byte(values[0])) > 128 ||
		!utf8.ValidString(values[0]) || strings.TrimSpace(values[0]) != values[0] {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "one valid Idempotency-Key is required", false)
		return "", false
	}
	for _, character := range values[0] {
		if unicode.IsControl(character) {
			writeProblem(response, requestID(request), http.StatusBadRequest,
				devopsv1.ErrorInvalidArgument, "Invalid argument", "Idempotency-Key is invalid", false)
			return "", false
		}
	}
	return values[0], true
}

func ifMatch(response http.ResponseWriter, request *http.Request) (uint64, bool) {
	values := request.Header.Values("If-Match")
	if len(values) == 0 {
		writeProblem(response, requestID(request), http.StatusPreconditionRequired,
			devopsv1.ErrorPreconditionRequired, "Precondition required", "If-Match must identify the current resource version", false)
		return 0, false
	}
	if len(values) != 1 {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "If-Match must contain one strong resource ETag", false)
		return 0, false
	}
	value := values[0]
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' || strings.HasPrefix(value, "W/") {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "If-Match must contain one strong resource ETag", false)
		return 0, false
	}
	parsed, err := strconv.ParseUint(value[1:len(value)-1], 10, 64)
	if err != nil || parsed == 0 || parsed > devopsv1.MaximumContractInteger {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "If-Match resource version is invalid", false)
		return 0, false
	}
	return parsed, true
}

func writeMutation[T any](
	response http.ResponseWriter,
	request *http.Request,
	status int,
	location string,
	resourceVersion uint64,
	resource T,
	validate func(T) error,
	err error,
) {
	if err != nil {
		writeWorkflowError(response, requestID(request), err)
		return
	}
	if validate(resource) != nil || resourceVersion == 0 || resourceVersion > devopsv1.MaximumContractInteger {
		writeProblem(response, requestID(request), http.StatusInternalServerError,
			devopsv1.ErrorInternal, "Internal error", "the DevOps response could not be normalized", true)
		return
	}
	if location != "" {
		response.Header().Set("Location", location)
	}
	response.Header().Set("ETag", resourceVersionETag(resourceVersion))
	writeJSON(response, status, resource)
}

func writeResource[T any](
	response http.ResponseWriter,
	request *http.Request,
	resourceVersion uint64,
	resource T,
	validate func(T) error,
	err error,
) {
	writeResourceWithETag(response, request, resourceVersionETag(resourceVersion), resource, validate, err)
}

func writeResourceWithETag[T any](
	response http.ResponseWriter,
	request *http.Request,
	etag string,
	resource T,
	validate func(T) error,
	err error,
) {
	if err != nil {
		writeWorkflowError(response, requestID(request), err)
		return
	}
	if validate(resource) != nil || etag == "" {
		writeProblem(response, requestID(request), http.StatusInternalServerError,
			devopsv1.ErrorInternal, "Internal error", "the DevOps response could not be normalized", true)
		return
	}
	response.Header().Set("ETag", etag)
	writeJSON(response, http.StatusOK, resource)
}

func writeAuthorizationError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, port.ErrUnauthenticated):
		response.Header().Set("WWW-Authenticate", `Bearer realm="matrix-iam"`)
		writeProblem(response, requestID, http.StatusUnauthorized,
			devopsv1.ErrorUnauthenticated, "Unauthenticated", "IAM authentication failed", false)
	case errors.Is(err, port.ErrPermissionDenied):
		writeProblem(response, requestID, http.StatusForbidden,
			devopsv1.ErrorForbidden, "Forbidden", "IAM denied this DevOps action", false)
	default:
		writeProblem(response, requestID, http.StatusServiceUnavailable,
			devopsv1.ErrorUnavailable, "Identity unavailable", "IAM authorization is unavailable", true)
	}
}

func writeWorkflowError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, pipelineconfiguration.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusUnprocessableEntity,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "request violates the DevOps workflow contract", false)
	case errors.Is(err, pipelineconfiguration.ErrNotFound):
		writeProblem(response, requestID, http.StatusNotFound,
			devopsv1.ErrorNotFound, "Not found", "the requested tenant resource does not exist", false)
	case errors.Is(err, pipelineconfiguration.ErrAlreadyExists):
		writeProblem(response, requestID, http.StatusConflict,
			devopsv1.ErrorConflict, "Already exists", "the DevOps resource already exists", false)
	case errors.Is(err, pipelineconfiguration.ErrIdempotencyConflict):
		writeProblem(response, requestID, http.StatusConflict,
			devopsv1.ErrorConflict, "Idempotency conflict", "Idempotency-Key was used for different content", false)
	case errors.Is(err, pipelineconfiguration.ErrResourceVersionConflict):
		writeProblem(response, requestID, http.StatusPreconditionFailed,
			devopsv1.ErrorPreconditionFailed, "Precondition failed", "If-Match does not identify the current resource version", false)
	case errors.Is(err, pipelineconfiguration.ErrNoDesiredChange):
		writeProblem(response, requestID, http.StatusConflict,
			devopsv1.ErrorConflict, "No desired change", "the submitted DevOps configuration is unchanged", false)
	case errors.Is(err, pipelineconfiguration.ErrPreconditionFailed):
		writeProblem(response, requestID, http.StatusPreconditionFailed,
			devopsv1.ErrorPreconditionFailed, "Precondition failed", "a referenced DevOps resource no longer satisfies this request", false)
	case errors.Is(err, runcontrol.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusUnprocessableEntity,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "request violates the PipelineRun control contract", false)
	case errors.Is(err, runcontrol.ErrNotFound):
		writeProblem(response, requestID, http.StatusNotFound,
			devopsv1.ErrorNotFound, "Not found", "the requested tenant PipelineRun does not exist", false)
	case errors.Is(err, runcontrol.ErrIdempotencyConflict):
		writeProblem(response, requestID, http.StatusConflict,
			devopsv1.ErrorConflict, "Idempotency conflict", "Idempotency-Key was used for a different PipelineRun command", false)
	case errors.Is(err, runcontrol.ErrResourceVersionConflict):
		writeProblem(response, requestID, http.StatusPreconditionFailed,
			devopsv1.ErrorPreconditionFailed, "Precondition failed", "If-Match does not identify the current PipelineRun version", false)
	case errors.Is(err, runcontrol.ErrNoDesiredChange):
		writeProblem(response, requestID, http.StatusConflict,
			devopsv1.ErrorConflict, "No desired change", "PipelineRun cancellation is already requested", false)
	case errors.Is(err, runcontrol.ErrTerminal):
		writeProblem(response, requestID, http.StatusConflict,
			devopsv1.ErrorConflict, "Terminal PipelineRun", "a terminal PipelineRun cannot be cancelled", false)
	case errors.Is(err, runcontrol.ErrNotTerminal):
		writeProblem(response, requestID, http.StatusConflict,
			devopsv1.ErrorConflict, "Nonterminal PipelineRun", "only a terminal PipelineRun can be replayed", false)
	case errors.Is(err, runcontrol.ErrQueueCapacityExceeded):
		response.Header().Set("Retry-After", "30")
		writeProblem(response, requestID, http.StatusTooManyRequests,
			devopsv1.ErrorResourceExhausted, "Queue capacity exhausted", "tenant queued-run capacity is exhausted", true)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, pipelineconfiguration.ErrRetryableTransaction),
		errors.Is(err, runcontrol.ErrRetryableTransaction):
		writeProblem(response, requestID, http.StatusServiceUnavailable,
			devopsv1.ErrorUnavailable, "DevOps unavailable", "the DevOps workflow is temporarily unavailable", true)
	default:
		writeProblem(response, requestID, http.StatusInternalServerError,
			devopsv1.ErrorInternal, "Internal error", "the DevOps request could not be completed", true)
	}
}

func methodNotAllowed(response http.ResponseWriter, request *http.Request, allow string) {
	response.Header().Set("Allow", allow)
	writeProblem(response, requestID(request), http.StatusMethodNotAllowed,
		devopsv1.ErrorMethodNotAllowed, "Method not allowed", "the HTTP method is not supported by this DevOps route", false)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeProblem(
	response http.ResponseWriter,
	requestID string,
	status int,
	code devopsv1.ErrorCode,
	title string,
	detail string,
	retryable bool,
) {
	problem := devopsv1.Problem{
		Type:  "https://errors.matrix.xiak.com/devops/" + strings.ToLower(strings.ReplaceAll(string(code), "_", "-")),
		Title: title, Status: status, Code: code, Detail: detail,
		TraceID: requestID, Retryable: retryable,
	}
	if devopsv1.ValidateProblem(problem) != nil {
		problem = devopsv1.Problem{
			Type: "https://errors.matrix.xiak.com/devops/internal", Title: "Internal error",
			Status: http.StatusInternalServerError, Code: devopsv1.ErrorInternal,
			Detail: "the error response could not be normalized", TraceID: "request-unavailable",
		}
		status = http.StatusInternalServerError
	}
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(problem)
}

func requestID(request *http.Request) string {
	value, _ := request.Context().Value(requestIDContextKey{}).(string)
	if value == "" {
		return "request-unavailable"
	}
	return value
}

func resourceVersionETag(value uint64) string {
	if value == 0 || value > devopsv1.MaximumContractInteger {
		return ""
	}
	return quotedETag(strconv.FormatUint(value, 10))
}

func quotedETag(value string) string {
	if value == "" || strings.ContainsAny(value, "\"\r\n") {
		return ""
	}
	return `"` + value + `"`
}

func newRequestID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	return "request-" + hex.EncodeToString(raw[:]), nil
}
