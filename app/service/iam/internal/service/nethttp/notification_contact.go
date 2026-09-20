package nethttp

import (
	"net/http"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

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
