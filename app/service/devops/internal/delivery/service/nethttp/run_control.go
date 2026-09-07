package nethttp

import (
	"net/http"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runcontrol"
)

func (value *handler) pipelineRun(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodGet, false) {
		return
	}
	id, ok := pathID(response, request, "runId")
	if !ok {
		return
	}
	authorization, ok := value.authorize(
		response, request, iamv1.ActionDevOpsRunRead, iamv1.ResourcePipelineRun, id,
	)
	if !ok {
		return
	}
	run, err := value.runControl.Get(request.Context(), runcontrol.GetQuery{
		Authorization: authorization, RunID: id,
	})
	writeResource(
		response, request, run.Status.ResourceVersion, run,
		devopsv1.ValidatePipelineRun, err,
	)
}

func (value *handler) pipelineRunCancellation(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodPost, false) {
		return
	}
	id, ok := pathID(response, request, "runId")
	if !ok {
		return
	}
	version, ok := ifMatch(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	authorization, ok := value.authorize(
		response, request, iamv1.ActionDevOpsRunCancel, iamv1.ResourcePipelineRun, id,
	)
	if !ok {
		return
	}
	result, err := value.runControl.Cancel(request.Context(), runcontrol.CancelCommand{
		Authorization: authorization, RunID: id,
		ExpectedResourceVersion: version, IdempotencyKey: key,
	})
	writeMutation(
		response, request, http.StatusOK, "", result.Value.Status.ResourceVersion,
		result.Value, devopsv1.ValidatePipelineRun, err,
	)
}
