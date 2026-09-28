package nethttp

import (
	"net/http"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

// Only called by the restricted challenge router, after its method, query
// and second-carrier checks. The nested ID never selects an account or user.
func (value *handler) enrollmentNotificationVerification(response http.ResponseWriter, request *http.Request) {
	const challengePrefix = "/v1/auth/challenges/"
	const collection = "notification-contact/verifications"
	id, tail, _ := strings.Cut(strings.TrimPrefix(request.URL.Path, challengePrefix), "/")
	if iamv1.ValidateID("challengeId", id) != nil {
		writeProblem(response, requestID(request), http.StatusNotFound, "iam.route.notfound", "IAM route not found")
		return
	}
	var result iamv1.NotificationContactVerification
	var err error
	if tail == collection {
		body, ok := decodeJSON[iamv1.StartChallengeNotificationContactVerificationRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.StartChallengeNotificationVerification(request.Context(), id, body)
		if err == nil && (result.RequestID != body.RequestID || result.Email != body.Email) {
			err = identityaccess.ErrUnavailable
		}
	} else {
		verificationID, ok := commandPathID(response, request, challengePrefix+id+"/"+collection+"/", ":confirm", "verificationId")
		if !ok {
			return
		}
		body, ok := decodeJSON[iamv1.ConfirmChallengeNotificationContactVerificationRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.ConfirmChallengeNotificationContact(request.Context(), id, verificationID, body)
		if err == nil && (result.ID != verificationID || result.State != "VERIFIED") {
			err = identityaccess.ErrUnavailable
		}
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	if iamv1.ValidateNotificationContactVerification(result) != nil {
		value.writeError(response, request, identityaccess.ErrUnavailable)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) notificationContact(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.NotificationContact(request.Context(), credential)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) startNotificationVerification(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.StartNotificationContactVerificationRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.StartNotificationVerification(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) notificationVerification(response http.ResponseWriter, request *http.Request) {
	const prefix = "/v1/auth/notification-contact/verifications/"
	if !rejectQuery(response, request) {
		return
	}
	if strings.HasSuffix(request.URL.Path, ":confirm") {
		id, ok := commandPathID(response, request, prefix, ":confirm", "verificationId")
		if !ok || !value.requireMethod(response, request, http.MethodPost) {
			return
		}
		credential, ok := bearerCredential(response, request)
		if !ok {
			return
		}
		body, ok := decodeJSON[iamv1.ConfirmNotificationContactVerificationRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.ConfirmNotificationContact(request.Context(), credential, id, body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	id, ok := commandPathID(response, request, prefix, "", "verificationId")
	if !ok || !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.NotificationVerification(request.Context(), credential, id)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}
