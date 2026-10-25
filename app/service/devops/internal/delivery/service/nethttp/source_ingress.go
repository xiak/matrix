package nethttp

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceingress"
)

var forbiddenSourceIngressHeaders = []string{
	"Authorization",
	"Idempotency-Key",
	"If-Match",
	"Matrix-Correlation-ID",
	"Matrix-Organization-ID",
	"Matrix-Subject-Credential",
	"Matrix-Tenant-ID",
	"X-Organization-ID",
	"X-Tenant-ID",
	"traceparent",
}

func (value *handler) sourceWebhook(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(response, request, http.MethodPost)
		return
	}
	if request.URL.RawQuery != "" {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "query parameters are not accepted", false)
		return
	}
	for _, name := range forbiddenSourceIngressHeaders {
		if len(request.Header.Values(name)) != 0 {
			writeProblem(response, requestID(request), http.StatusBadRequest,
				devopsv1.ErrorInvalidArgument, "Invalid argument", "caller authority and workflow headers are not accepted", false)
			return
		}
	}
	tenantID := devopsv1.TenantID(request.PathValue("tenantId"))
	scope := devopsv1.ResourceScope{TenantID: tenantID}
	if devopsv1.ValidateResourceScope(scope) != nil {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "tenantId is invalid", false)
		return
	}
	connectionID, ok := pathID(response, request, "sourceConnectionId")
	if !ok {
		return
	}
	if !acceptSourceMediaType(response, request) {
		return
	}
	providerEvent, ok := exactHeader(response, request, "X-Gitea-Event")
	if !ok {
		return
	}
	deliveryID, ok := exactHeader(response, request, "X-Gitea-Delivery")
	if !ok {
		return
	}
	signature, ok := exactHeader(response, request, "X-Gitea-Signature")
	if !ok {
		return
	}
	if request.ContentLength > sourceingress.MaximumWebhookBodyBytes {
		writeProblem(response, requestID(request), http.StatusRequestEntityTooLarge,
			devopsv1.ErrorPayloadTooLarge, "Payload too large", "webhook body exceeds the fixed limit", false)
		return
	}
	reader := http.MaxBytesReader(response, request.Body, sourceingress.MaximumWebhookBodyBytes)
	body, err := io.ReadAll(reader)
	if err != nil {
		var maximumError *http.MaxBytesError
		if errors.As(err, &maximumError) {
			writeProblem(response, requestID(request), http.StatusRequestEntityTooLarge,
				devopsv1.ErrorPayloadTooLarge, "Payload too large", "webhook body exceeds the fixed limit", false)
		} else {
			writeProblem(response, requestID(request), http.StatusBadRequest,
				devopsv1.ErrorInvalidArgument, "Invalid argument", "webhook body could not be read", false)
		}
		return
	}
	defer clear(body)
	if len(body) == 0 {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "webhook body is empty", false)
		return
	}
	result, err := value.ingress.Receive(request.Context(), sourceingress.Command{
		Scope: scope, SourceConnectionID: connectionID, ProviderEvent: providerEvent,
		DeliveryID: deliveryID, Signature: signature, Body: body,
		RequestID: requestID(request), CorrelationID: requestID(request),
	})
	if err != nil {
		writeSourceIngressError(response, requestID(request), err)
		return
	}
	if runadmission.ValidateAdmission(result.Admission) != nil {
		writeProblem(response, requestID(request), http.StatusInternalServerError,
			devopsv1.ErrorInternal, "Internal error", "source admission response could not be normalized", true)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func acceptSourceMediaType(response http.ResponseWriter, request *http.Request) bool {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || len(request.Header.Values("Content-Encoding")) != 0 {
		writeProblem(response, requestID(request), http.StatusUnsupportedMediaType,
			devopsv1.ErrorUnsupportedMediaType, "Unsupported media type", "webhook must use unencoded application/json", false)
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		writeProblem(response, requestID(request), http.StatusUnsupportedMediaType,
			devopsv1.ErrorUnsupportedMediaType, "Unsupported media type", "webhook must use application/json", false)
		return false
	}
	return true
}

func exactHeader(response http.ResponseWriter, request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	if len(values) != 1 || values[0] == "" || len(values[0]) > 256 {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "one bounded "+name+" header is required", false)
		return "", false
	}
	return values[0], true
}

func writeSourceIngressError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, sourceingress.ErrUnauthenticated):
		writeProblem(response, requestID, http.StatusUnauthorized,
			devopsv1.ErrorUnauthenticated, "Unauthenticated", "webhook authentication failed", false)
	case errors.Is(err, sourceingress.ErrInvalidArgument),
		errors.Is(err, sourceingress.ErrUnsupportedEvent),
		errors.Is(err, runadmission.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusUnprocessableEntity,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "webhook violates the source protocol", false)
	case errors.Is(err, sourceingress.ErrPrecondition),
		errors.Is(err, runadmission.ErrPreconditionFailed):
		writeProblem(response, requestID, http.StatusPreconditionFailed,
			devopsv1.ErrorPreconditionFailed, "Precondition failed", "source configuration is not ready", true)
	case errors.Is(err, runadmission.ErrReplayConflict):
		writeProblem(response, requestID, http.StatusConflict,
			devopsv1.ErrorConflict, "Delivery conflict", "delivery identity was reused for changed content", false)
	case errors.Is(err, runadmission.ErrQueueCapacityExceeded):
		response.Header().Set("Retry-After", "30")
		writeProblem(response, requestID, http.StatusTooManyRequests,
			devopsv1.ErrorResourceExhausted, "Queue capacity exhausted", "tenant queued-run capacity is exhausted", true)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, sourceingress.ErrUnavailable),
		errors.Is(err, runadmission.ErrRetryableTransaction):
		writeProblem(response, requestID, http.StatusServiceUnavailable,
			devopsv1.ErrorUnavailable, "DevOps unavailable", "source admission is temporarily unavailable", true)
	default:
		writeProblem(response, requestID, http.StatusInternalServerError,
			devopsv1.ErrorInternal, "Internal error", "source admission could not be completed", true)
	}
}
