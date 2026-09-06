package nethttp

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/nodeenrollment"
)

const (
	nodeEnrollmentPublicOriginHeader    = "X-Matrix-Public-Origin"
	nodeEnrollmentObservedPeerHeader    = "X-Matrix-Observed-Peer"
	nodeEnrollmentTransportSchemeHeader = "X-Matrix-Transport-Scheme"
	maximumNodeEnrollmentExchangeBody   = int64(64 * 1024)
)

type EnrollmentWorkflow interface {
	Create(context.Context, nodeenrollment.CreateCommand) (nodeenrollment.CreateResult, error)
	Exchange(context.Context, nodeenrollment.ExchangeCommand) (nodeenrollment.ExchangeResult, error)
	Get(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.NodeEnrollment, error)
	List(context.Context, port.Authorization) (paasv1.NodeEnrollmentList, error)
	Revoke(context.Context, nodeenrollment.RevokeCommand) (nodeenrollment.RevokeResult, error)
	Regenerate(context.Context, nodeenrollment.RegenerateCommand) (nodeenrollment.CreateResult, error)
}

func (value *handler) exchangeNodeEnrollment(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" || len(request.Header.Values("Content-Encoding")) != 0 ||
		len(request.Header.Values("Authorization")) != 0 ||
		len(request.Header.Values("Matrix-Subject-Credential")) != 0 ||
		len(request.Header.Values("Idempotency-Key")) != 0 ||
		len(request.Header.Values("If-Match")) != 0 ||
		len(request.Header.Values("Cookie")) != 0 ||
		len(request.Header.Values(nodeEnrollmentPublicOriginHeader)) != 0 {
		writeNodeEnrollmentExchangeError(response, requestID, nodeenrollment.ErrInvalidArgument)
		return
	}
	observedPeer, err := nodeEnrollmentTransportPeer(request)
	if err != nil {
		writeNodeEnrollmentExchangeError(response, requestID, err)
		return
	}
	enrollmentID, ok := pathResourceID(response, request, "nodeEnrollmentId")
	if !ok {
		return
	}
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		writeProblem(response, requestID, http.StatusUnsupportedMediaType, paasv1.ErrorInvalidArgument, "Unsupported media type", "Content-Type must be application/json", false)
		return
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		writeProblem(response, requestID, http.StatusUnsupportedMediaType, paasv1.ErrorInvalidArgument, "Unsupported media type", "Content-Type must be application/json", false)
		return
	}
	// DecodeObject reads at most limit+1 bytes to distinguish an oversized
	// document. Give MaxBytesReader that same one-byte sentinel allowance while
	// keeping the accepted contract at exactly 64 KiB.
	request.Body = http.MaxBytesReader(response, request.Body, maximumNodeEnrollmentExchangeBody+1)
	var body paasv1.ExchangeNodeEnrollmentRequest
	if err = contractjson.DecodeObject(request.Body, maximumNodeEnrollmentExchangeBody, &body); err != nil {
		if errors.Is(err, contractjson.ErrDocumentTooLarge) {
			writeProblem(response, requestID, http.StatusRequestEntityTooLarge, paasv1.ErrorInvalidArgument, "Request too large", "node enrollment exchange body exceeds 64 KiB", false)
			return
		}
		writeNodeEnrollmentExchangeError(response, requestID, nodeenrollment.ErrInvalidArgument)
		return
	}
	if body.EnrollmentID != enrollmentID || paasv1.ValidateExchangeNodeEnrollmentRequest(body) != nil {
		writeNodeEnrollmentExchangeError(response, requestID, nodeenrollment.ErrInvalidArgument)
		return
	}
	result, err := value.enrollment.Exchange(request.Context(), nodeenrollment.ExchangeCommand{
		EnrollmentID: enrollmentID, ObservedPeerAddress: observedPeer, Request: body,
	})
	if err != nil {
		writeNodeEnrollmentExchangeError(response, requestID, err)
		return
	}
	if paasv1.ValidateNodeEnrollment(result.Enrollment) != nil ||
		result.Enrollment.Metadata.ID != enrollmentID ||
		result.Enrollment.State != paasv1.NodeEnrollmentVerifying ||
		paasv1.ValidateNodeEnrollmentExchangeResponseForRequest(result.Response, body) != nil {
		writeNodeEnrollmentExchangeError(response, requestID, nodeenrollment.ErrUnavailable)
		return
	}
	response.Header().Set("ETag", resourceVersionETag(result.Enrollment.Metadata.ResourceVersion))
	writeJSON(response, http.StatusOK, result.Response)
}

func nodeEnrollmentTransportPeer(request *http.Request) (string, error) {
	if request == nil {
		return "", nodeenrollment.ErrInvalidArgument
	}
	schemes := request.Header.Values(nodeEnrollmentTransportSchemeHeader)
	peers := request.Header.Values(nodeEnrollmentObservedPeerHeader)
	if len(schemes) != 1 || schemes[0] != "https" || len(peers) != 1 ||
		peers[0] == "" || strings.TrimSpace(peers[0]) != peers[0] || strings.Contains(peers[0], ",") {
		return "", nodeenrollment.ErrInvalidArgument
	}
	peer, err := netip.ParseAddr(peers[0])
	if err != nil || peer.Is4In6() || !peer.IsPrivate() || peer.IsLoopback() ||
		peer.IsUnspecified() || peer.IsMulticast() || peer.IsLinkLocalUnicast() ||
		peer.String() != peers[0] {
		return "", nodeenrollment.ErrInvalidArgument
	}
	return peer.String(), nil
}

func writeNodeEnrollmentExchangeError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, nodeenrollment.ErrCredentialRejected):
		writeProblem(response, requestID, http.StatusUnauthorized, paasv1.ErrorUnauthenticated, "Unauthenticated", "node enrollment credential is invalid", false)
	case errors.Is(err, nodeenrollment.ErrNotFound):
		writeProblem(response, requestID, http.StatusNotFound, paasv1.ErrorNotFound, "Not found", "node enrollment does not exist", false)
	case errors.Is(err, nodeenrollment.ErrExpired), errors.Is(err, nodeenrollment.ErrRevoked), errors.Is(err, nodeenrollment.ErrCredentialConsumed):
		writeProblem(response, requestID, http.StatusGone, paasv1.ErrorConflict, "Enrollment unavailable", "node enrollment can no longer be exchanged", false)
	case errors.Is(err, nodeenrollment.ErrConflict), errors.Is(err, nodeenrollment.ErrInvalidTransition), errors.Is(err, nodeenrollment.ErrRuntimeUnsupported):
		writeProblem(response, requestID, http.StatusConflict, paasv1.ErrorConflict, "Enrollment conflict", "node enrollment conflicts with current installation authority", false)
	case errors.Is(err, nodeenrollment.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusBadRequest, paasv1.ErrorInvalidArgument, "Invalid argument", "node enrollment exchange request is invalid", false)
	case errors.Is(err, nodeenrollment.ErrUnavailable), errors.Is(err, nodeenrollment.ErrRetryableTransaction):
		writeProblem(response, requestID, http.StatusServiceUnavailable, paasv1.ErrorInternal, "Enrollment unavailable", "node enrollment exchange is temporarily unavailable", true)
	case errors.Is(err, context.DeadlineExceeded):
		writeProblem(response, requestID, http.StatusGatewayTimeout, paasv1.ErrorDeadlineExceeded, "Deadline exceeded", "node enrollment exchange deadline was exceeded", true)
	default:
		writeProblem(response, requestID, http.StatusInternalServerError, paasv1.ErrorInternal, "Internal error", "node enrollment exchange could not be completed", true)
	}
}

func (value *handler) createNodeEnrollment(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginExecutionRequest(response, request, true)
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.CreateNodeEnrollmentRequest](
		value,
		response,
		request,
		requestID,
	)
	if !ok {
		return
	}
	if paasv1.ValidateCreateNodeEnrollmentRequest(body) != nil {
		writeWorkflowError(response, requestID, nodeenrollment.ErrInvalidArgument)
		return
	}
	controlPlaneBaseURL, err := nodeEnrollmentControlPlaneBaseURL(request)
	if err != nil {
		writeWorkflowError(response, requestID, nodeenrollment.ErrInvalidArgument)
		return
	}
	authorization, ok := value.authorizeRequest(
		response,
		request,
		requestID,
		port.AuthorizeNodeEnrollmentCreate,
		"NodeEnrollment",
		"collection",
	)
	if !ok {
		return
	}
	result, err := value.enrollment.Create(request.Context(), nodeenrollment.CreateCommand{
		Authorization:       authorization,
		Request:             body,
		IdempotencyKey:      request.Header.Get("Idempotency-Key"),
		ControlPlaneBaseURL: controlPlaneBaseURL,
	})
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	if paasv1.ValidateCreateNodeEnrollmentResponse(result.Response) != nil ||
		paasv1.ValidateOperation(result.Operation) != nil {
		writeWorkflowError(response, requestID, nodeenrollment.ErrUnavailable)
		return
	}
	writeNodeEnrollmentCreation(response, result)
}

func (value *handler) getNodeEnrollment(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginExecutionRequest(response, request, false)
	if !ok {
		return
	}
	id, ok := pathResourceID(response, request, "nodeEnrollmentId")
	if !ok {
		return
	}
	authorization, ok := value.authorizeRequest(
		response,
		request,
		requestID,
		port.AuthorizeNodeEnrollmentRead,
		"NodeEnrollment",
		id,
	)
	if !ok {
		return
	}
	enrollment, err := value.enrollment.Get(request.Context(), authorization, id)
	etag := ""
	if err == nil {
		etag = resourceVersionETag(enrollment.Metadata.ResourceVersion)
	}
	writeResource(response, requestID, enrollment, etag, err)
}

func (value *handler) listNodeEnrollments(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginExecutionRequest(response, request, false)
	if !ok {
		return
	}
	authorization, ok := value.authorizeRequest(
		response,
		request,
		requestID,
		port.AuthorizeNodeEnrollmentRead,
		"NodeEnrollment",
		"collection",
	)
	if !ok {
		return
	}
	enrollments, err := value.enrollment.List(request.Context(), authorization)
	writeResource(response, requestID, enrollments, "", err)
}

func (value *handler) revokeNodeEnrollment(response http.ResponseWriter, request *http.Request) {
	id, ok := pathResourceID(response, request, "nodeEnrollmentId")
	if !ok {
		return
	}
	requestID, ok := value.beginExecutionRequest(response, request, true)
	if !ok {
		return
	}
	if request.ContentLength != 0 || len(request.TransferEncoding) > 0 {
		writeWorkflowError(response, requestID, nodeenrollment.ErrInvalidArgument)
		return
	}
	expected, ok := parseIfMatch(response, request, requestID)
	if !ok {
		return
	}
	authorization, ok := value.authorizeRequest(
		response,
		request,
		requestID,
		port.AuthorizeNodeEnrollmentRevoke,
		"NodeEnrollment",
		id,
	)
	if !ok {
		return
	}
	result, err := value.enrollment.Revoke(request.Context(), nodeenrollment.RevokeCommand{
		Authorization: authorization, EnrollmentID: id,
		ExpectedResourceVersion: expected,
		IdempotencyKey:          request.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	if paasv1.ValidateNodeEnrollment(result.Enrollment) != nil ||
		result.Enrollment.Metadata.ID != id || result.Enrollment.State != paasv1.NodeEnrollmentRevoked {
		writeWorkflowError(response, requestID, nodeenrollment.ErrUnavailable)
		return
	}
	response.Header().Set("ETag", resourceVersionETag(result.Enrollment.Metadata.ResourceVersion))
	writeJSON(response, http.StatusOK, result.Enrollment)
}

func (value *handler) regenerateNodeEnrollment(response http.ResponseWriter, request *http.Request) {
	id, ok := pathResourceID(response, request, "nodeEnrollmentId")
	if !ok {
		return
	}
	requestID, ok := value.beginExecutionRequest(response, request, true)
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.RegenerateNodeEnrollmentRequest](
		value,
		response,
		request,
		requestID,
	)
	if !ok {
		return
	}
	if paasv1.ValidateRegenerateNodeEnrollmentRequest(body) != nil {
		writeWorkflowError(response, requestID, nodeenrollment.ErrInvalidArgument)
		return
	}
	controlPlaneBaseURL, err := nodeEnrollmentControlPlaneBaseURL(request)
	if err != nil {
		writeWorkflowError(response, requestID, nodeenrollment.ErrInvalidArgument)
		return
	}
	expected, ok := parseIfMatch(response, request, requestID)
	if !ok {
		return
	}
	authorization, ok := value.authorizeRequest(
		response,
		request,
		requestID,
		port.AuthorizeNodeEnrollmentRegenerate,
		"NodeEnrollment",
		id,
	)
	if !ok {
		return
	}
	result, err := value.enrollment.Regenerate(request.Context(), nodeenrollment.RegenerateCommand{
		Authorization: authorization, EnrollmentID: id,
		ExpectedResourceVersion: expected,
		IdempotencyKey:          request.Header.Get("Idempotency-Key"),
		Request:                 body,
		ControlPlaneBaseURL:     controlPlaneBaseURL,
	})
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	if paasv1.ValidateCreateNodeEnrollmentResponse(result.Response) != nil ||
		paasv1.ValidateOperation(result.Operation) != nil ||
		result.Response.Enrollment.Metadata.ID == id {
		writeWorkflowError(response, requestID, nodeenrollment.ErrUnavailable)
		return
	}
	writeNodeEnrollmentCreation(response, result)
}

func writeNodeEnrollmentCreation(response http.ResponseWriter, result nodeenrollment.CreateResult) {
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	enrollment := result.Response.Enrollment
	response.Header().Set("Location", "/v1/node-enrollments/"+string(enrollment.Metadata.ID))
	response.Header().Set("Operation-Location", "/v1/platform/operations/"+string(result.Operation.ID))
	response.Header().Set("ETag", resourceVersionETag(enrollment.Metadata.ResourceVersion))
	writeJSON(response, status, result.Response)
}

func nodeEnrollmentControlPlaneBaseURL(request *http.Request) (string, error) {
	if request == nil {
		return "", nodeenrollment.ErrInvalidArgument
	}
	values := request.Header.Values(nodeEnrollmentPublicOriginHeader)
	if len(values) != 1 || len(values[0]) > 2048 || values[0] == "" ||
		strings.TrimSpace(values[0]) != values[0] || strings.Contains(values[0], ",") {
		return "", nodeenrollment.ErrInvalidArgument
	}
	origin, err := url.Parse(values[0])
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil ||
		origin.Opaque != "" || origin.Path != "" || origin.RawPath != "" || origin.RawQuery != "" ||
		origin.ForceQuery || origin.Fragment != "" {
		return "", nodeenrollment.ErrInvalidArgument
	}
	baseURL := origin.String() + "/api/paas/v1"
	if nodeenrollment.ValidateControlPlaneBaseURL(baseURL) != nil {
		return "", nodeenrollment.ErrInvalidArgument
	}
	return baseURL, nil
}
