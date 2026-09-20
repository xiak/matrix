package nethttp

import (
	"net/http"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func (value *handler) authenticatorState(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.AuthenticatorState(request.Context(), credential)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) startTOTPEnrollment(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.StartTOTPEnrollmentRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.StartTOTPEnrollment(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	encoded, err := iamv1.EncodeStartTOTPEnrollmentResponse(result)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	defer clear(encoded)
	writeEncodedJSON(response, http.StatusOK, encoded)
}

func (value *handler) totpEnrollmentByRequest(response http.ResponseWriter, request *http.Request) {
	id, ok := commandPathID(response, request, "/v1/auth/totp/enrollments/by-request/", "", "requestId")
	if !ok || !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.TOTPEnrollmentByRequest(request.Context(), credential, id)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) totpEnrollment(response http.ResponseWriter, request *http.Request) {
	const prefix = "/v1/auth/totp/enrollments/"
	if !rejectQuery(response, request) {
		return
	}
	if strings.HasSuffix(request.URL.Path, ":confirm") {
		id, ok := commandPathID(response, request, prefix, ":confirm", "enrollmentId")
		if !ok || !value.requireMethod(response, request, http.MethodPost) {
			return
		}
		credential, ok := bearerCredential(response, request)
		if !ok {
			return
		}
		body, ok := decodeJSON[iamv1.ConfirmTOTPEnrollmentRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.ConfirmTOTPEnrollment(request.Context(), credential, id, body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		encoded, err := iamv1.EncodeConfirmTOTPEnrollmentResponse(result)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		defer clear(encoded)
		writeEncodedJSON(response, http.StatusOK, encoded)
		return
	}
	id, ok := commandPathID(response, request, prefix, "", "enrollmentId")
	if !ok || !rejectQueryAndBody(response, request) {
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodDelete {
		response.Header().Set("Allow", "GET, DELETE")
		writeProblem(response, requestID(request), http.StatusMethodNotAllowed, "iam.method.invalid", "IAM method not allowed")
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	var result iamv1.TOTPEnrollment
	var err error
	if request.Method == http.MethodDelete {
		result, err = value.workflow.CancelTOTPEnrollment(request.Context(), credential, id)
	} else {
		result, err = value.workflow.TOTPEnrollment(request.Context(), credential, id)
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}
