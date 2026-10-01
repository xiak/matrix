// Package nethttp exposes the strict Phase 1 Audit HTTP boundary on the Go
// standard library stack.
package nethttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/audit/internal/usecase/auditlog"
	"github.com/xiak/matrix/app/service/internal/externalrequest"
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
	QueryRecordsAccessKey(context.Context, iamv1.AccessKeySignedRequest, string, auditv1.QueryRecordsRequest) (auditv1.RecordPage, error)
	QueryPlatformRecords(context.Context, iamv1.Secret, string, auditv1.QueryRecordsRequest) (auditv1.RecordPage, error)
	VerifyChain(
		context.Context,
		iamv1.Secret,
		string,
		auditv1.VerifyChainRequest,
	) (auditv1.ChainVerification, error)
	VerifyChainAccessKey(context.Context, iamv1.AccessKeySignedRequest, string, auditv1.VerifyChainRequest) (auditv1.ChainVerification, error)
	VerifyPlatformChain(context.Context, iamv1.Secret, string, auditv1.VerifyChainRequest) (auditv1.ChainVerification, error)
	VerifyInstallation(
		context.Context,
		iamv1.Secret,
		string,
		auditv1.VerifyInstallationRequest,
	) (auditv1.InstallationVerification, error)
}

type Config struct {
	NewRequestID     func() (string, error)
	NorthboundOrigin string
	InstallationID   string
}

type handler struct {
	workflow          Workflow
	config            Config
	routes            *http.ServeMux
	accessKeyBoundary *externalrequest.Boundary
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
	if config.NorthboundOrigin != "" || config.InstallationID != "" {
		boundary, err := externalrequest.NewBoundary(
			config.NorthboundOrigin, "/api/audit", config.InstallationID, iamv1.ProductAudit,
		)
		if err != nil {
			return nil, errors.New("Audit AccessKey northbound boundary is invalid")
		}
		value.accessKeyBoundary = boundary
	}
	routes := http.NewServeMux()
	routes.HandleFunc("/ready", value.ready)
	routes.HandleFunc("/v1/events", value.ingest)
	routes.HandleFunc("/v1/records:query", value.queryRecords)
	routes.HandleFunc("/v1/integrity:verify", value.verifyChain)
	routes.HandleFunc("/v1/platform/records:query", value.queryRecords)
	routes.HandleFunc("/v1/platform/integrity:verify", value.verifyChain)
	routes.HandleFunc("/v1/installation:verify", value.verifyInstallation)
	routes.HandleFunc("/", value.notFound)
	value.routes = routes
	return value, nil
}

func (value *handler) verifyInstallation(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	if len(request.Header.Values("Matrix-Subject-Credential")) != 0 {
		writeProblem(
			response,
			requestID(request),
			http.StatusBadRequest,
			"audit.header.unsupported",
			"Audit header unsupported",
		)
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[auditv1.VerifyInstallationRequest](response, request)
	if !ok {
		return
	}
	verification, err := value.workflow.VerifyInstallation(
		request.Context(), credential, requestID(request), body,
	)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	if auditv1.ValidateInstallationVerification(verification) != nil {
		value.writeError(response, request, auditlog.ErrUnavailable)
		return
	}
	writeJSON(response, http.StatusOK, verification)
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
	if externalrequest.IsAccessKeyAuthorization(request) {
		if !value.prepareAccessKeyRequest(response, request) {
			return
		}
	}
	value.routes.ServeHTTP(response, request)
}

type accessKeyContextKey struct{}

func (value *handler) prepareAccessKeyRequest(response http.ResponseWriter, request *http.Request) bool {
	accepted := value.accessKeyBoundary != nil && request.Method == http.MethodPost && request.URL != nil &&
		request.URL.RawQuery == "" && (request.URL.Path == "/v1/records:query" || request.URL.Path == "/v1/integrity:verify")
	if !accepted {
		writeAuthenticationProblem(response, request)
		return false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, auditv1.MaxRequestBytes+1))
	_ = request.Body.Close()
	if err != nil || int64(len(body)) > auditv1.MaxRequestBytes {
		clear(body)
		writeProblem(response, requestID(request), http.StatusBadRequest, "audit.json.invalid", "Audit JSON invalid")
		return false
	}
	signed, err := value.accessKeyBoundary.SignedRequest(request, body)
	if err != nil {
		clear(body)
		writeAuthenticationProblem(response, request)
		return false
	}
	request.Body = io.NopCloser(bytes.NewReader(bytes.Clone(body)))
	*request = *request.WithContext(context.WithValue(request.Context(), accessKeyContextKey{}, signed))
	clear(body)
	return true
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
	body, ok := decodeJSON[auditv1.QueryRecordsRequest](response, request)
	if !ok {
		return
	}
	query := value.workflow.QueryRecords
	if request.URL.Path == "/v1/platform/records:query" {
		query = value.workflow.QueryPlatformRecords
	}
	var page auditv1.RecordPage
	var err error
	if signed, present := request.Context().Value(accessKeyContextKey{}).(iamv1.AccessKeySignedRequest); present {
		page, err = value.workflow.QueryRecordsAccessKey(request.Context(), signed, requestID(request), body)
	} else {
		credential, credentialOK := bearerCredential(response, request)
		if !credentialOK {
			return
		}
		page, err = query(request.Context(), credential, requestID(request), body)
	}
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
	body, ok := decodeJSON[auditv1.VerifyChainRequest](response, request)
	if !ok {
		return
	}
	verify := value.workflow.VerifyChain
	if request.URL.Path == "/v1/platform/integrity:verify" {
		verify = value.workflow.VerifyPlatformChain
	}
	var verification auditv1.ChainVerification
	var err error
	if signed, present := request.Context().Value(accessKeyContextKey{}).(iamv1.AccessKeySignedRequest); present {
		verification, err = value.workflow.VerifyChainAccessKey(request.Context(), signed, requestID(request), body)
	} else {
		credential, credentialOK := bearerCredential(response, request)
		if !credentialOK {
			return
		}
		verification, err = verify(request.Context(), credential, requestID(request), body)
	}
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
