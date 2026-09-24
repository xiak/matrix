package nethttp

import (
	"net/http"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

// Every operation is held by the actual login bearer. A StepUp ID is metadata,
// not a second authentication carrier or authority to select another subject.
func (value *handler) startStepUp(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.StartStepUpRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.StartStepUp(request.Context(), credential, body)
	if err == nil {
		err = iamv1.ValidateStepUp(result)
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) stepUpByRequest(response http.ResponseWriter, request *http.Request) {
	id, ok := commandPathID(response, request, "/v1/auth/step-up/by-request/", "", "requestId")
	if !ok || !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.StepUpByRequest(request.Context(), credential, id)
	if err == nil {
		err = iamv1.ValidateStepUp(result)
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) verifyStepUp(response http.ResponseWriter, request *http.Request) {
	id, ok := commandPathID(response, request, "/v1/auth/step-up/", ":verify", "stepUpId")
	if !ok || !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.VerifyStepUpRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.VerifyStepUp(request.Context(), credential, id, body)
	if err == nil {
		err = iamv1.ValidateStepUp(result)
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) regenerateRecoveryCodes(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.RegenerateRecoveryCodesRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.RegenerateRecoveryCodes(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	encoded, err := iamv1.EncodeRegenerateRecoveryCodesResponse(result)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	defer clear(encoded)
	writeEncodedJSON(response, http.StatusOK, encoded)
}

func (value *handler) recoveryCodeRegenerationByRequest(response http.ResponseWriter, request *http.Request) {
	id, ok := commandPathID(response, request, "/v1/auth/recovery-codes/regenerations/by-request/", "", "requestId")
	if !ok || !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.RecoveryCodeRegenerationByRequest(request.Context(), credential, id)
	if err == nil {
		err = iamv1.ValidateRecoveryCodeRegeneration(result)
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}
