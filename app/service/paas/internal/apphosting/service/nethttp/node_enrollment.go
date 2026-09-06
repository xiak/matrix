package nethttp

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/nodeenrollment"
)

const nodeEnrollmentPublicOriginHeader = "X-Matrix-Public-Origin"

type EnrollmentWorkflow interface {
	Create(context.Context, nodeenrollment.CreateCommand) (nodeenrollment.CreateResult, error)
	Get(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.NodeEnrollment, error)
	List(context.Context, port.Authorization) (paasv1.NodeEnrollmentList, error)
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
