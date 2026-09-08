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
	id, ok := pipelineRunPathID(response, request)
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
	id, ok := pipelineRunPathID(response, request)
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

func (value *handler) pipelineRunReplay(response http.ResponseWriter, request *http.Request) {
	if !value.acceptEnvelope(response, request, http.MethodPost, false) {
		return
	}
	id, ok := pipelineRunPathID(response, request)
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
		response, request, iamv1.ActionDevOpsRunReplay, iamv1.ResourcePipelineRun, id,
	)
	if !ok {
		return
	}
	result, err := value.runControl.Replay(request.Context(), runcontrol.ReplayCommand{
		Authorization: authorization, SourceRunID: id,
		ExpectedResourceVersion: version, IdempotencyKey: key,
	})
	location := ""
	if err == nil {
		location = "/v1/runs/" + string(result.Value.ID)
	}
	writeMutation(
		response, request, http.StatusCreated, location, result.Value.Status.ResourceVersion,
		result.Value, devopsv1.ValidatePipelineRun, err,
	)
}

func pipelineRunPathID(
	response http.ResponseWriter,
	request *http.Request,
) (devopsv1.ResourceID, bool) {
	id := devopsv1.ResourceID(request.PathValue("runId"))
	if devopsv1.ValidatePipelineRunID("runId", id) != nil {
		writeProblem(response, requestID(request), http.StatusBadRequest,
			devopsv1.ErrorInvalidArgument, "Invalid argument", "runId is invalid", false)
		return "", false
	}
	return id, true
}
