package nethttp

import (
	"net/http"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

// The existing challenge router enforces one secret carrier and POST-only
// access. Authentication and the current stage are rechecked by the use case.
func (value *handler) challengeTOTPEnrollment(response http.ResponseWriter, request *http.Request, id, suffix string) {
	var encoded []byte
	var err error
	switch suffix {
	case ":enrollment-state":
		body, ok := decodeJSON[iamv1.InspectEnrollmentChallengeRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.InspectEnrollmentChallenge(request.Context(), id, body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		if iamv1.ValidateEnrollmentChallengeState(result) != nil || result.Challenge.ID != id {
			value.writeError(response, request, identityaccess.ErrUnavailable)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	case ":enroll":
		body, ok := decodeJSON[iamv1.StartChallengeTOTPEnrollmentRequest](value, response, request)
		if !ok {
			return
		}
		var result iamv1.StartTOTPEnrollmentResponse
		result, err = value.workflow.StartChallengeTOTPEnrollment(request.Context(), id, body)
		if err == nil {
			if result.Enrollment.RequestID != body.RequestID {
				err = identityaccess.ErrUnavailable
			} else {
				encoded, err = iamv1.EncodeStartTOTPEnrollmentResponse(result)
			}
		}
	case ":confirm-enrollment":
		body, ok := decodeJSON[iamv1.VerifyAuthenticationChallengeRequest](value, response, request)
		if !ok {
			return
		}
		var result iamv1.ConfirmTOTPEnrollmentResponse
		result, err = value.workflow.ConfirmChallengeTOTPEnrollment(request.Context(), id, body)
		if err == nil {
			encoded, err = iamv1.EncodeConfirmTOTPEnrollmentResponse(result)
		}
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	defer clear(encoded)
	writeEncodedJSON(response, http.StatusOK, encoded)
}

// The shared challenge router already rejects a bearer, query parameters and
// every method except POST. No caller-supplied tenant/user selector is read.
func (value *handler) authenticatorRecovery(response http.ResponseWriter, request *http.Request, id, suffix string) {
	var encoded []byte
	var err error
	switch suffix {
	case ":recover":
		body, ok := decodeJSON[iamv1.StartAuthenticatorRecoveryRequest](value, response, request)
		if !ok {
			return
		}
		var result iamv1.StartAuthenticatorRecoveryResponse
		result, err = value.workflow.StartAuthenticatorRecovery(request.Context(), id, body)
		if err == nil {
			encoded, err = iamv1.EncodeStartAuthenticatorRecoveryResponse(result)
		}
	case ":confirm-recovery":
		body, ok := decodeJSON[iamv1.VerifyAuthenticationChallengeRequest](value, response, request)
		if !ok {
			return
		}
		var result iamv1.ConfirmAuthenticatorRecoveryResponse
		result, err = value.workflow.ConfirmAuthenticatorRecovery(request.Context(), id, body)
		if err == nil {
			encoded, err = iamv1.EncodeConfirmAuthenticatorRecoveryResponse(result)
		}
	case ":recovery-result":
		body, ok := decodeJSON[iamv1.InspectAuthenticatorRecoveryRequest](value, response, request)
		if !ok {
			return
		}
		result, failure := value.workflow.InspectAuthenticatorRecovery(request.Context(), id, body)
		if failure != nil {
			value.writeError(response, request, failure)
			return
		}
		if failure = iamv1.ValidateAuthenticatorRecovery(result); failure != nil {
			value.writeError(response, request, failure)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	defer clear(encoded)
	writeEncodedJSON(response, http.StatusOK, encoded)
}

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
