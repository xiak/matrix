package executorgatewayhttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/executorspoolfile"
)

const (
	executionsPath        = "/v1/executions"
	maximumSubmissionBody = int64(8+devopsbuildv1.MaximumDocumentBytes) +
		devopsv1.MaximumSourceArchiveBytes
)

type AdminSpool interface {
	Create(context.Context, io.Reader) (devopsbuildv1.Observation, error)
	Observe(context.Context, devopsbuildv1.Request) (devopsbuildv1.Observation, error)
	Cancel(context.Context, devopsbuildv1.Request) (devopsbuildv1.Observation, error)
}

type adminHandler struct {
	spool          AdminSpool
	clientIdentity *url.URL
}

func NewAdminHandler(spool AdminSpool, clientIdentity string) (http.Handler, error) {
	identity, err := parseSPIFFEIdentity(clientIdentity)
	if spool == nil || err != nil {
		return nil, errors.New("executor admin handler configuration is invalid")
	}
	return &adminHandler{spool: spool, clientIdentity: identity}, nil
}

func (handler *adminHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	secureResponse(response)
	if handler == nil || handler.spool == nil || request == nil ||
		exactPeerIdentity(request.TLS, handler.clientIdentity) != nil {
		writeEmpty(response, http.StatusUnauthorized)
		return
	}
	if requestHasExternalAuthority(request) {
		writeEmpty(response, http.StatusBadRequest)
		return
	}
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		writeEmpty(response, http.StatusMethodNotAllowed)
		return
	}
	if !hasSingleHeader(request, "Accept", devopsbuildv1.DocumentMediaType) {
		writeEmpty(response, http.StatusNotAcceptable)
		return
	}
	if request.URL.Path == executionsPath {
		handler.create(response, request)
		return
	}
	handler.control(response, request)
}

func (handler *adminHandler) create(
	response http.ResponseWriter,
	request *http.Request,
) {
	if !hasSingleHeader(request, "Content-Type", devopsbuildv1.FramedMediaType) ||
		request.ContentLength <= 8 || request.ContentLength > maximumSubmissionBody ||
		len(request.TransferEncoding) != 0 {
		writeEmpty(response, http.StatusBadRequest)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumSubmissionBody)
	observation, err := handler.spool.Create(request.Context(), request.Body)
	if err != nil {
		writeSpoolError(response, err)
		return
	}
	status := http.StatusAccepted
	if observation.State == devopsbuildv1.ExecutionTerminal ||
		observation.State == devopsbuildv1.ExecutionCancelled {
		status = http.StatusOK
	}
	writeObservation(response, observation, status)
}

func (handler *adminHandler) control(
	response http.ResponseWriter,
	request *http.Request,
) {
	prefix := executionsPath + "/"
	remainder := strings.TrimPrefix(request.URL.Path, prefix)
	parts := strings.Split(remainder, "/")
	if remainder == request.URL.Path || len(parts) != 2 ||
		devopsv1.ValidateDigest("executionId", parts[0]) != nil ||
		(parts[1] != "observe" && parts[1] != "cancel") {
		writeEmpty(response, http.StatusNotFound)
		return
	}
	content, ok := readDocumentRequest(response, request)
	if !ok {
		writeEmpty(response, http.StatusBadRequest)
		return
	}
	var err error
	action, buildRequest, err := devopsbuildv1.DecodeControl(content)
	wantAction := devopsbuildv1.ControlObserve
	if parts[1] == "cancel" {
		wantAction = devopsbuildv1.ControlCancel
	}
	executionID, executionErr := devopsbuildv1.ExecutionID(buildRequest)
	if err != nil || executionErr != nil || action != wantAction || executionID != parts[0] {
		writeEmpty(response, http.StatusBadRequest)
		return
	}
	var observation devopsbuildv1.Observation
	if action == devopsbuildv1.ControlObserve {
		observation, err = handler.spool.Observe(request.Context(), buildRequest)
	} else {
		observation, err = handler.spool.Cancel(request.Context(), buildRequest)
	}
	if err != nil {
		writeSpoolError(response, err)
		return
	}
	writeObservation(response, observation, http.StatusOK)
}

func writeObservation(
	response http.ResponseWriter,
	observation devopsbuildv1.Observation,
	status int,
) {
	// The spool validates the observation against its immutable request before
	// returning it. Marshaling this closed struct preserves the canonical wire
	// shape without exposing that request in the response.
	content, err := json.Marshal(observation)
	if err != nil || len(content) == 0 || len(content) > devopsbuildv1.MaximumDocumentBytes {
		writeEmpty(response, http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Content-Type", devopsbuildv1.DocumentMediaType)
	response.Header().Set("Content-Length", strconv.Itoa(len(content)))
	response.WriteHeader(status)
	_, _ = response.Write(content)
}

func writeSpoolError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, executorspoolfile.ErrInvalid):
		writeEmpty(response, http.StatusBadRequest)
	case errors.Is(err, executorspoolfile.ErrConflict):
		writeEmpty(response, http.StatusConflict)
	case errors.Is(err, executorspoolfile.ErrStaleAssignment):
		writeEmpty(response, http.StatusConflict)
	case errors.Is(err, executorspoolfile.ErrNotFound):
		writeEmpty(response, http.StatusNotFound)
	default:
		writeEmpty(response, http.StatusServiceUnavailable)
	}
}

func secureResponse(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeEmpty(response http.ResponseWriter, status int) {
	response.Header().Set("Content-Length", "0")
	response.WriteHeader(status)
}

func requestHasExternalAuthority(request *http.Request) bool {
	if request == nil || request.URL == nil || request.URL.Scheme != "" ||
		request.URL.Host != "" || request.URL.RawPath != "" ||
		request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.URL.Fragment != "" {
		return true
	}
	for _, name := range []string{
		"Authorization", "Cookie", "Forwarded", "Proxy-Authorization",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
	} {
		if len(request.Header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func hasSingleHeader(request *http.Request, name, value string) bool {
	values := request.Header.Values(name)
	return len(values) == 1 && values[0] == value
}
