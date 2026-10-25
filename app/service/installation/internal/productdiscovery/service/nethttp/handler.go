package nethttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"

	installationv1 "github.com/xiak/matrix/api/installation/v1"
	"github.com/xiak/matrix/app/service/installation/internal/productdiscovery"
)

type Workflow interface {
	List(context.Context, string, string) (installationv1.InstalledProductList, error)
	Readiness(context.Context) installationv1.Readiness
}

type Config struct {
	NewRequestID func() (string, error)
}

type handler struct {
	workflow Workflow
	config   Config
}

var requestIDPattern = regexp.MustCompile(`^request-[0-9a-f]{32}$`)

func NewHandler(workflow Workflow, config Config) (http.Handler, error) {
	if workflow == nil {
		return nil, errors.New("product discovery workflow is required")
	}
	if config.NewRequestID == nil {
		config.NewRequestID = randomRequestID
	}
	value := &handler{workflow: workflow, config: config}
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", value.serveReadiness)
	mux.HandleFunc("/v1/installed-products", value.serveInstalledProducts)
	mux.HandleFunc("/", value.serveUnknown)
	return value.securityHeaders(mux), nil
}

func (value *handler) serveReadiness(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	if request.Method != http.MethodGet {
		writeProblem(response, requestID, http.StatusMethodNotAllowed,
			"installation.method.invalid", "Method not allowed")
		return
	}
	if !validEmptyRequest(request) {
		writeProblem(response, requestID, http.StatusBadRequest,
			"installation.request.invalid", "Readiness request is invalid")
		return
	}
	result := value.workflow.Readiness(request.Context())
	if installationv1.ValidateReadiness(result) != nil {
		writeProblem(response, requestID, http.StatusServiceUnavailable,
			"installation.unavailable", "Installation discovery is unavailable")
		return
	}
	status := http.StatusOK
	if result.State != installationv1.ReadinessReady {
		status = http.StatusServiceUnavailable
	}
	writeJSON(response, status, result)
}

func (value *handler) serveInstalledProducts(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	if request.Method != http.MethodGet {
		writeProblem(response, requestID, http.StatusMethodNotAllowed,
			"installation.method.invalid", "Method not allowed")
		return
	}
	if !validEmptyRequest(request) {
		writeProblem(response, requestID, http.StatusBadRequest,
			"installation.request.invalid", "Installed-product request is invalid")
		return
	}
	credential := request.Header.Get("Authorization")
	if credential == "" {
		writeProblem(response, requestID, http.StatusUnauthorized,
			"installation.authentication.failed", "Authentication failed")
		return
	}
	result, err := value.workflow.List(request.Context(), credential, requestID)
	if err != nil {
		value.writeWorkflowError(response, requestID, err)
		return
	}
	if installationv1.ValidateInstalledProductList(result) != nil {
		writeProblem(response, requestID, http.StatusServiceUnavailable,
			"installation.unavailable", "Installation discovery is unavailable")
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) serveUnknown(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	writeProblem(response, requestID, http.StatusNotFound,
		"installation.route.notfound", "Route not found")
}

func (value *handler) beginRequest(response http.ResponseWriter) (string, bool) {
	requestID, err := value.config.NewRequestID()
	if err != nil || !requestIDPattern.MatchString(requestID) {
		writeProblem(response, "request-unavailable", http.StatusServiceUnavailable,
			"installation.unavailable", "Installation discovery is unavailable")
		return "", false
	}
	response.Header().Set("Matrix-Request-ID", requestID)
	return requestID, true
}

func (value *handler) writeWorkflowError(
	response http.ResponseWriter,
	requestID string,
	err error,
) {
	switch {
	case errors.Is(err, productdiscovery.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusBadRequest,
			"installation.request.invalid", "Installed-product request is invalid")
	case errors.Is(err, productdiscovery.ErrUnauthenticated):
		writeProblem(response, requestID, http.StatusUnauthorized,
			"installation.authentication.failed", "Authentication failed")
	case errors.Is(err, productdiscovery.ErrPermissionDenied):
		writeProblem(response, requestID, http.StatusForbidden,
			"installation.authorization.denied", "Permission denied")
	default:
		writeProblem(response, requestID, http.StatusServiceUnavailable,
			"installation.unavailable", "Installation discovery is unavailable")
	}
}

func (value *handler) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		response.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(response, request)
	})
}

func validEmptyRequest(request *http.Request) bool {
	return request.URL.RawQuery == "" && request.ContentLength == 0 &&
		len(request.TransferEncoding) == 0 &&
		request.Header.Get("Content-Encoding") == ""
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
	code string,
	title string,
) {
	problem := installationv1.Problem{
		Type:      "https://errors.matrix.xiak.com/" + code,
		Title:     title,
		Status:    status,
		Code:      code,
		RequestID: requestID,
	}
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(problem)
}

func randomRequestID() (string, error) {
	var data [16]byte
	if _, err := io.ReadFull(rand.Reader, data[:]); err != nil {
		return "", err
	}
	return "request-" + hex.EncodeToString(data[:]), nil
}
