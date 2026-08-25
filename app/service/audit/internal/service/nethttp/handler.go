// Package nethttp exposes the strict Phase 1 Audit HTTP boundary on the Go
// standard library stack.
package nethttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/audit/internal/usecase/auditlog"
)

type Workflow interface {
	Readiness(context.Context) (auditv1.Readiness, error)
	Ingest(context.Context, iamv1.Secret, auditv1.Event) (auditv1.IngestionResult, error)
	QueryRecords(
		context.Context,
		iamv1.Secret,
		string,
		auditv1.QueryRecordsRequest,
	) (auditv1.RecordPage, error)
	VerifyChain(
		context.Context,
		iamv1.Secret,
		string,
		auditv1.VerifyChainRequest,
	) (auditv1.ChainVerification, error)
}

type Config struct {
	NewRequestID func() (string, error)
}

type handler struct {
	workflow Workflow
	config   Config
	routes   *http.ServeMux
}

type requestIDContextKey struct{}

func NewHandler(workflow Workflow, config Config) (http.Handler, error) {
	if workflow == nil {
		return nil, errors.New("Audit HTTP workflow is required")
	}
	if config.NewRequestID == nil {
		config.NewRequestID = newRequestID
	}
	value := &handler{workflow: workflow, config: config}
	routes := http.NewServeMux()
	routes.HandleFunc("/ready", value.ready)
	routes.HandleFunc("/v1/events", value.ingest)
	routes.HandleFunc("/v1/records:query", value.queryRecords)
	routes.HandleFunc("/v1/integrity:verify", value.verifyChain)
	routes.HandleFunc("/", value.notFound)
	value.routes = routes
	return value, nil
}

func (value *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID, err := value.config.NewRequestID()
	if err != nil || auditv1.ValidateID("requestId", requestID) != nil {
		writeProblem(
			response,
			"request-unavailable",
			http.StatusServiceUnavailable,
			"audit.unavailable",
			"Audit unavailable",
		)
		return
	}
	response.Header().Set("Matrix-Request-ID", requestID)
	request = request.WithContext(context.WithValue(request.Context(), requestIDContextKey{}, requestID))
	value.routes.ServeHTTP(response, request)
}

func (value *handler) ready(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	readiness, err := value.workflow.Readiness(request.Context())
	if err != nil || readiness.State != auditv1.ReadinessReady {
		value.writeError(response, request, auditlog.ErrUnavailable)
		return
	}
	writeJSON(response, http.StatusOK, readiness)
}

func (value *handler) ingest(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	event, ok := decodeJSON[auditv1.Event](response, request)
	if !ok {
		return
	}
	result, err := value.workflow.Ingest(request.Context(), credential, event)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	status := http.StatusCreated
	if result.Outcome == auditv1.IngestionDuplicate {
		status = http.StatusOK
	} else if result.Outcome != auditv1.IngestionAccepted {
		value.writeError(response, request, auditlog.ErrUnavailable)
		return
	}
	writeJSON(response, status, result)
}

func (value *handler) queryRecords(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[auditv1.QueryRecordsRequest](response, request)
	if !ok {
		return
	}
	page, err := value.workflow.QueryRecords(
		request.Context(),
		credential,
		requestID(request),
		body,
	)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, page)
}

func (value *handler) verifyChain(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[auditv1.VerifyChainRequest](response, request)
	if !ok {
		return
	}
	verification, err := value.workflow.VerifyChain(
		request.Context(),
		credential,
		requestID(request),
		body,
	)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, verification)
}

func (value *handler) notFound(response http.ResponseWriter, request *http.Request) {
	writeProblem(
		response,
		requestID(request),
		http.StatusNotFound,
		"audit.route.notfound",
		"Audit route not found",
	)
}

func (value *handler) requireMethod(
	response http.ResponseWriter,
	request *http.Request,
	method string,
) bool {
	if request.Method == method {
		return true
	}
	response.Header().Set("Allow", method)
	writeProblem(
		response,
		requestID(request),
		http.StatusMethodNotAllowed,
		"audit.method.invalid",
		"Audit method not allowed",
	)
	return false
}

func (value *handler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	requestID := requestID(request)
	switch {
	case errors.Is(err, auditlog.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusUnprocessableEntity, "audit.argument.invalid", "Audit argument invalid")
	case errors.Is(err, auditlog.ErrUnauthenticated):
		response.Header().Set("WWW-Authenticate", `Bearer realm="matrix-audit"`)
		writeProblem(response, requestID, http.StatusUnauthorized, "audit.authentication.failed", "Audit authentication failed")
	case errors.Is(err, auditlog.ErrForbidden):
		writeProblem(response, requestID, http.StatusForbidden, "audit.authorization.denied", "Audit authorization denied")
	case errors.Is(err, auditlog.ErrConflict):
		writeProblem(response, requestID, http.StatusConflict, "audit.state.conflict", "Audit state conflict")
	default:
		writeProblem(response, requestID, http.StatusServiceUnavailable, "audit.unavailable", "Audit unavailable")
	}
}

func decodeJSON[T any](response http.ResponseWriter, request *http.Request) (T, bool) {
	var zero T
	if request.Header.Get("Content-Encoding") != "" {
		writeProblem(response, requestID(request), http.StatusUnsupportedMediaType, "audit.encoding.unsupported", "Audit content encoding unsupported")
		return zero, false
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProblem(response, requestID(request), http.StatusUnsupportedMediaType, "audit.media.unsupported", "Audit media type unsupported")
		return zero, false
	}
	var body T
	if err := auditv1.DecodeRequest(request.Body, &body); err != nil {
		if errors.Is(err, contractjson.ErrDocumentTooLarge) {
			writeProblem(response, requestID(request), http.StatusRequestEntityTooLarge, "audit.body.toolarge", "Audit request body too large")
			return zero, false
		}
		writeProblem(response, requestID(request), http.StatusBadRequest, "audit.json.invalid", "Audit JSON invalid")
		return zero, false
	}
	return body, true
}

func bearerCredential(response http.ResponseWriter, request *http.Request) (iamv1.Secret, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		writeAuthenticationProblem(response, request)
		return iamv1.Secret{}, false
	}
	plaintext := strings.TrimPrefix(values[0], "Bearer ")
	if plaintext == "" || plaintext != strings.TrimSpace(plaintext) ||
		strings.ContainsAny(plaintext, " \t\r\n") {
		writeAuthenticationProblem(response, request)
		return iamv1.Secret{}, false
	}
	credential, err := iamv1.NewSecret(plaintext)
	if err != nil {
		writeAuthenticationProblem(response, request)
		return iamv1.Secret{}, false
	}
	return credential, true
}

func writeAuthenticationProblem(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("WWW-Authenticate", `Bearer realm="matrix-audit"`)
	writeProblem(
		response,
		requestID(request),
		http.StatusUnauthorized,
		"audit.authentication.failed",
		"Audit authentication failed",
	)
}

func rejectQueryAndBody(response http.ResponseWriter, request *http.Request) bool {
	if !rejectQuery(response, request) {
		return false
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		writeProblem(response, requestID(request), http.StatusBadRequest, "audit.body.unexpected", "Audit request body unexpected")
		return false
	}
	return true
}

func rejectQuery(response http.ResponseWriter, request *http.Request) bool {
	if request.URL.RawQuery == "" {
		return true
	}
	writeProblem(response, requestID(request), http.StatusBadRequest, "audit.query.unsupported", "Audit query unsupported")
	return false
}

func requestID(request *http.Request) string {
	value, _ := request.Context().Value(requestIDContextKey{}).(string)
	if value == "" {
		return "request-unavailable"
	}
	return value
}

func newRequestID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		clear(random)
		return "", err
	}
	result := "request-" + hex.EncodeToString(random)
	clear(random)
	return result, nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		writeProblem(response, "request-unavailable", http.StatusServiceUnavailable, "audit.unavailable", "Audit unavailable")
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func writeProblem(
	response http.ResponseWriter,
	requestID string,
	status int,
	code string,
	title string,
) {
	problem := auditv1.Problem{
		Type:      "https://matrix.xiak.com/problems/" + code,
		Title:     title,
		Status:    status,
		Code:      code,
		RequestID: requestID,
	}
	encoded, err := json.Marshal(problem)
	if err != nil {
		http.Error(response, "Audit unavailable", http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}
