package executorgatewayhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	runnerClaimsPath     = "/v1/runner/claims"
	runnerExecutionsPath = "/v1/runner/executions"
)

type RunnerSpool interface {
	Claim(
		context.Context,
		string,
		time.Time,
	) (devopsbuildv1.Assignment, io.ReadCloser, bool, error)
	Renew(
		context.Context,
		string,
		string,
		uint64,
		time.Time,
	) (devopsbuildv1.Renewal, error)
	Complete(
		context.Context,
		string,
		string,
		uint64,
		devopsbuildv1.Receipt,
		time.Time,
	) (devopsbuildv1.Observation, error)
	AppendLogs(
		context.Context,
		string,
		string,
		uint64,
		devopsbuildv1.LogBatch,
		time.Time,
	) error
	Request(context.Context, string) (devopsbuildv1.Request, error)
}

type runnerHandler struct {
	spool           RunnerSpool
	runnerNamespace *url.URL
	now             func() time.Time
}

func NewRunnerHandler(spool RunnerSpool, runnerNamespace string) (http.Handler, error) {
	namespace, err := parseSPIFFEIdentity(runnerNamespace)
	if spool == nil || err != nil {
		return nil, errors.New("executor runner handler configuration is invalid")
	}
	return &runnerHandler{
		spool: spool, runnerNamespace: namespace, now: time.Now,
	}, nil
}

func (handler *runnerHandler) ServeHTTP(
	response http.ResponseWriter,
	request *http.Request,
) {
	secureResponse(response)
	if handler == nil || handler.spool == nil || request == nil {
		writeEmpty(response, http.StatusUnauthorized)
		return
	}
	runnerID, err := runnerIDFromPeer(request.TLS, handler.runnerNamespace)
	if err != nil {
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
	if request.URL.Path == runnerClaimsPath {
		handler.claim(response, request, runnerID)
		return
	}
	handler.execution(response, request, runnerID)
}

func (handler *runnerHandler) claim(
	response http.ResponseWriter,
	request *http.Request,
	runnerID string,
) {
	if !hasSingleHeader(request, "Accept", devopsbuildv1.FramedMediaType) {
		writeEmpty(response, http.StatusNotAcceptable)
		return
	}
	content, ok := readDocumentRequest(response, request)
	if !ok || devopsbuildv1.DecodeClaim(content) != nil {
		writeEmpty(response, http.StatusBadRequest)
		return
	}
	assignment, archive, found, err := handler.spool.Claim(
		request.Context(), runnerID, canonicalGatewayTime(handler.now()),
	)
	if err != nil {
		if archive != nil {
			_ = archive.Close()
		}
		writeSpoolError(response, err)
		return
	}
	if !found {
		if archive != nil {
			_ = archive.Close()
			writeEmpty(response, http.StatusServiceUnavailable)
			return
		}
		writeEmpty(response, http.StatusNoContent)
		return
	}
	defer func() {
		if archive != nil {
			_ = archive.Close()
		}
	}()
	if devopsbuildv1.ValidateAssignment(assignment) != nil ||
		(assignment.Mode == devopsbuildv1.AssignmentExecute) != (archive != nil) {
		writeEmpty(response, http.StatusServiceUnavailable)
		return
	}
	metadata, err := devopsbuildv1.EncodeAssignment(assignment)
	if err != nil {
		writeEmpty(response, http.StatusServiceUnavailable)
		return
	}
	contentLength := int64(8 + len(metadata))
	if assignment.Mode == devopsbuildv1.AssignmentExecute {
		contentLength += assignment.Request.SourceArchiveBytes
	}
	if contentLength <= 8 || contentLength > maximumSubmissionBody {
		writeEmpty(response, http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Content-Type", devopsbuildv1.FramedMediaType)
	response.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	response.WriteHeader(http.StatusOK)
	_ = devopsbuildv1.WriteAssignment(response, assignment, archive)
}

func (handler *runnerHandler) execution(
	response http.ResponseWriter,
	request *http.Request,
	runnerID string,
) {
	prefix := runnerExecutionsPath + "/"
	remainder := strings.TrimPrefix(request.URL.Path, prefix)
	parts := strings.Split(remainder, "/")
	if remainder == request.URL.Path || len(parts) != 2 ||
		devopsv1.ValidateDigest("executionId", parts[0]) != nil ||
		(parts[1] != "renew" && parts[1] != "complete" && parts[1] != "logs") {
		writeEmpty(response, http.StatusNotFound)
		return
	}
	mediaType := devopsbuildv1.DocumentMediaType
	maximumBytes := int64(devopsbuildv1.MaximumDocumentBytes)
	if parts[1] == "logs" {
		mediaType = devopsbuildv1.LogDocumentMediaType
		maximumBytes = devopsbuildv1.MaximumLogDocumentBytes
	}
	if !hasSingleHeader(request, "Accept", mediaType) {
		writeEmpty(response, http.StatusNotAcceptable)
		return
	}
	content, ok := readSizedRequest(response, request, mediaType, maximumBytes)
	if !ok {
		writeEmpty(response, http.StatusBadRequest)
		return
	}
	buildRequest, err := handler.spool.Request(request.Context(), parts[0])
	if err != nil {
		writeSpoolError(response, err)
		return
	}
	if parts[1] == "renew" {
		handler.renew(response, request, runnerID, buildRequest, content)
		return
	}
	if parts[1] == "logs" {
		handler.logs(response, request, runnerID, buildRequest, parts[0], content)
		return
	}
	handler.complete(response, request, runnerID, buildRequest, content)
}

func (handler *runnerHandler) logs(
	response http.ResponseWriter,
	request *http.Request,
	runnerID string,
	buildRequest devopsbuildv1.Request,
	executionID string,
	content []byte,
) {
	appendRequest, err := devopsbuildv1.DecodeLogAppend(buildRequest, content)
	if err != nil || appendRequest.Batch.ExecutionID != executionID {
		writeEmpty(response, http.StatusBadRequest)
		return
	}
	if err := handler.spool.AppendLogs(
		request.Context(), runnerID, executionID,
		appendRequest.FencingToken, appendRequest.Batch,
		canonicalGatewayTime(handler.now()),
	); err != nil {
		writeSpoolError(response, err)
		return
	}
	writeEmpty(response, http.StatusNoContent)
}

func (handler *runnerHandler) renew(
	response http.ResponseWriter,
	request *http.Request,
	runnerID string,
	buildRequest devopsbuildv1.Request,
	content []byte,
) {
	renewalRequest, err := devopsbuildv1.DecodeRenewalRequest(content)
	executionID, executionErr := devopsbuildv1.ExecutionID(buildRequest)
	if err != nil || executionErr != nil || renewalRequest.ExecutionID != executionID {
		writeEmpty(response, http.StatusBadRequest)
		return
	}
	renewal, err := handler.spool.Renew(
		request.Context(), runnerID, renewalRequest.ExecutionID,
		renewalRequest.FencingToken, canonicalGatewayTime(handler.now()),
	)
	if err != nil {
		writeSpoolError(response, err)
		return
	}
	encoded, err := devopsbuildv1.EncodeRenewal(buildRequest, renewal)
	if err != nil {
		writeEmpty(response, http.StatusServiceUnavailable)
		return
	}
	writeDocument(response, encoded, http.StatusOK)
}

func (handler *runnerHandler) complete(
	response http.ResponseWriter,
	request *http.Request,
	runnerID string,
	buildRequest devopsbuildv1.Request,
	content []byte,
) {
	completion, err := devopsbuildv1.DecodeCompletion(buildRequest, content)
	if err != nil {
		writeEmpty(response, http.StatusBadRequest)
		return
	}
	_, err = handler.spool.Complete(
		request.Context(), runnerID, completion.ExecutionID,
		completion.FencingToken, completion.Receipt,
		canonicalGatewayTime(handler.now()),
	)
	if err != nil {
		writeSpoolError(response, err)
		return
	}
	writeEmpty(response, http.StatusNoContent)
}

func canonicalGatewayTime(now time.Time) time.Time {
	return now.UTC().Truncate(time.Microsecond)
}

func readDocumentRequest(
	response http.ResponseWriter,
	request *http.Request,
) ([]byte, bool) {
	return readSizedRequest(
		response, request, devopsbuildv1.DocumentMediaType,
		int64(devopsbuildv1.MaximumDocumentBytes),
	)
}

func readSizedRequest(
	response http.ResponseWriter,
	request *http.Request,
	contentType string,
	maximumBytes int64,
) ([]byte, bool) {
	if maximumBytes <= 0 ||
		!hasSingleHeader(request, "Content-Type", contentType) ||
		request.ContentLength <= 0 ||
		request.ContentLength > maximumBytes ||
		len(request.TransferEncoding) != 0 {
		return nil, false
	}
	request.Body = http.MaxBytesReader(
		response, request.Body, maximumBytes,
	)
	content, err := io.ReadAll(request.Body)
	if err != nil || int64(len(content)) != request.ContentLength {
		return nil, false
	}
	return content, true
}

func writeDocument(response http.ResponseWriter, content []byte, status int) {
	if len(content) == 0 || len(content) > devopsbuildv1.MaximumDocumentBytes {
		writeEmpty(response, http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Content-Type", devopsbuildv1.DocumentMediaType)
	response.Header().Set("Content-Length", strconv.Itoa(len(content)))
	response.WriteHeader(status)
	_, _ = response.Write(content)
}
