package nethttp

import (
	"context"
	"net/http"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
)

type ExecutionWorkflow interface {
	CreatePool(context.Context, executionadmission.CreatePoolCommand) (paasv1.ExecutionPool, paasv1.Operation, bool, error)
	RegisterTarget(context.Context, executionadmission.RegisterTargetCommand) (paasv1.ExecutionTarget, paasv1.Operation, bool, error)
	GetPool(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.ExecutionPool, error)
	GetTarget(context.Context, port.Authorization, paasv1.ResourceID) (paasv1.ExecutionTarget, error)
	ListTargets(context.Context, port.Authorization) (paasv1.ExecutionTargetList, error)
	GetOperation(context.Context, port.Authorization, paasv1.OperationID) (paasv1.Operation, error)
}

func (value *handler) createExecutionPool(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginExecutionRequest(response, request, true)
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.CreateExecutionPoolRequest](value, response, request, requestID)
	if !ok {
		return
	}
	if paasv1.ValidateCreateExecutionPoolRequest(body) != nil {
		writeWorkflowError(response, requestID, executionadmission.ErrInvalidArgument)
		return
	}
	authorization, ok := value.authorizeRequest(response, request, requestID, port.AuthorizeExecutionPoolCreate, "ExecutionPool", body.ID)
	if !ok {
		return
	}
	pool, operation, replayed, err := value.execution.CreatePool(request.Context(), executionadmission.CreatePoolCommand{Authorization: authorization, Request: body, IdempotencyKey: request.Header.Get("Idempotency-Key")})
	value.writeCreation(response, requestID, replayed, pool.Metadata.ResourceVersion, "/v1/execution-pools/"+string(body.ID), operation, err)
}

func (value *handler) registerExecutionTarget(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginExecutionRequest(response, request, true)
	if !ok {
		return
	}
	body, ok := decodeJSON[paasv1.RegisterExecutionTargetRequest](value, response, request, requestID)
	if !ok {
		return
	}
	if paasv1.ValidateRegisterExecutionTargetRequest(body) != nil {
		writeWorkflowError(response, requestID, executionadmission.ErrInvalidArgument)
		return
	}
	authorization, ok := value.authorizeRequest(response, request, requestID, port.AuthorizeExecutionTargetRegister, "ExecutionTarget", body.ID)
	if !ok {
		return
	}
	target, operation, replayed, err := value.execution.RegisterTarget(request.Context(), executionadmission.RegisterTargetCommand{Authorization: authorization, Request: body, IdempotencyKey: request.Header.Get("Idempotency-Key")})
	value.writeCreation(response, requestID, replayed, target.Metadata.ResourceVersion, "/v1/execution-targets/"+string(body.ID), operation, err)
}

func (value *handler) getExecutionPool(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginExecutionRequest(response, request, false)
	if !ok {
		return
	}
	id, ok := pathResourceID(response, request, "executionPoolId")
	if !ok {
		return
	}
	authorization, ok := value.authorizeRequest(response, request, requestID, port.AuthorizeExecutionPoolRead, "ExecutionPool", id)
	if !ok {
		return
	}
	pool, err := value.execution.GetPool(request.Context(), authorization, id)
	writeResource(response, requestID, pool, "", err)
}

func (value *handler) getExecutionTarget(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginExecutionRequest(response, request, false)
	if !ok {
		return
	}
	id, ok := pathResourceID(response, request, "executionTargetId")
	if !ok {
		return
	}
	authorization, ok := value.authorizeRequest(response, request, requestID, port.AuthorizeExecutionTargetRead, "ExecutionTarget", id)
	if !ok {
		return
	}
	target, err := value.execution.GetTarget(request.Context(), authorization, id)
	writeResource(response, requestID, target, "", err)
}

func (value *handler) listExecutionTargets(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginExecutionRequest(response, request, false)
	if !ok {
		return
	}
	authorization, ok := value.authorizeRequest(
		response,
		request,
		requestID,
		port.AuthorizeExecutionTargetRead,
		"ExecutionTarget",
		"collection",
	)
	if !ok {
		return
	}
	targets, err := value.execution.ListTargets(request.Context(), authorization)
	writeResource(response, requestID, targets, "", err)
}

func (value *handler) getPlatformOperation(response http.ResponseWriter, request *http.Request) {
	requestID, ok := value.beginExecutionRequest(response, request, false)
	if !ok {
		return
	}
	id, ok := pathOperationID(response, request, "operationId")
	if !ok {
		return
	}
	authorization, ok := value.authorizeRequest(response, request, requestID, port.AuthorizePlatformOperationRead, "Operation", paasv1.ResourceID(id))
	if !ok {
		return
	}
	operation, err := value.execution.GetOperation(request.Context(), authorization, id)
	writeResource(response, requestID, operation, "", err)
}

func (value *handler) beginExecutionRequest(response http.ResponseWriter, request *http.Request, mutation bool) (string, bool) {
	requestID, ok := value.beginRequest(response)
	if !ok {
		return "", false
	}
	if request.URL.RawQuery != "" || (!mutation && (request.ContentLength > 0 || len(request.TransferEncoding) > 0)) {
		writeWorkflowError(response, requestID, executionadmission.ErrInvalidArgument)
		return "", false
	}
	if mutation {
		request.Body = http.MaxBytesReader(response, request.Body, 64*1024)
	}
	return requestID, true
}
