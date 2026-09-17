package nethttp

import (
	"net/http"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *handler) accessKeys(response http.ResponseWriter, request *http.Request, parts []string) {
	if len(parts) < 2 || len(parts) > 3 || iamv1.ValidateID("userId", parts[0]) != nil {
		value.notFound(response, request)
		return
	}
	if !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	user := iamv1.PrincipalID(parts[0])
	if len(parts) == 2 {
		switch request.Method {
		case http.MethodGet:
			if !rejectQueryAndBody(response, request) {
				return
			}
			result, err := value.workflow.ListAccessKeys(request.Context(), credential, user, requestID(request))
			if err != nil {
				value.writeError(response, request, err)
				return
			}
			if iamv1.ValidateAccessKeyList(result) != nil {
				value.writeError(response, request, identityaccess.ErrUnavailable)
				return
			}
			writeJSON(response, http.StatusOK, result)
		case http.MethodPost:
			body, ok := decodeJSON[iamv1.CreateAccessKeyRequest](value, response, request)
			if !ok {
				return
			}
			if iamv1.ValidateCreateAccessKeyRequest(body) != nil {
				value.writeError(response, request, identityaccess.ErrInvalidArgument)
				return
			}
			result, err := value.workflow.CreateAccessKey(request.Context(), credential, user, body)
			if err != nil {
				value.writeError(response, request, err)
				return
			}
			encoded, err := iamv1.EncodeCreateAccessKeyResponse(result)
			if err != nil {
				value.writeError(response, request, identityaccess.ErrUnavailable)
				return
			}
			defer clear(encoded)
			status := http.StatusCreated
			if result.Outcome == "EQUAL_REPLAY" {
				status = http.StatusOK
			}
			writeEncodedJSON(response, status, encoded)
		default:
			response.Header().Set("Allow", "GET, POST")
			writeProblem(response, requestID(request), http.StatusMethodNotAllowed, "iam.method.invalid", "IAM method not allowed")
		}
		return
	}
	id, command := parts[2], ""
	if request.Method == http.MethodPost {
		for _, suffix := range []string{":set-status", ":delete"} {
			if strings.HasSuffix(id, suffix) {
				id, command = strings.TrimSuffix(id, suffix), suffix
				break
			}
		}
		if command == "" {
			value.notFound(response, request)
			return
		}
	} else if !value.requireMethod(response, request, http.MethodGet) {
		return
	}
	if iamv1.ValidateID("accessKeyId", id) != nil {
		value.notFound(response, request)
		return
	}
	key := iamv1.AccessKeyID(id)
	var result any
	var err error
	switch command {
	case "":
		if !rejectQueryAndBody(response, request) {
			return
		}
		var found iamv1.AccessKeyAccess
		found, err = value.workflow.GetAccessKey(request.Context(), credential, user, key, requestID(request))
		if err == nil && iamv1.ValidateAccessKeyAccess(found) != nil {
			err = identityaccess.ErrUnavailable
		}
		result = found
	case ":set-status":
		body, ok := decodeJSON[iamv1.SetAccessKeyStatusRequest](value, response, request)
		if !ok {
			return
		}
		if iamv1.ValidateSetAccessKeyStatusRequest(body) != nil {
			value.writeError(response, request, identityaccess.ErrInvalidArgument)
			return
		}
		var changed iamv1.SetAccessKeyStatusResponse
		changed, err = value.workflow.SetAccessKeyStatus(request.Context(), credential, user, key, body)
		if err == nil && iamv1.ValidateSetAccessKeyStatusResponse(changed) != nil {
			err = identityaccess.ErrUnavailable
		}
		result = changed
	case ":delete":
		body, ok := decodeJSON[iamv1.DeleteAccessKeyRequest](value, response, request)
		if !ok {
			return
		}
		if iamv1.ValidateDeleteAccessKeyRequest(body) != nil {
			value.writeError(response, request, identityaccess.ErrInvalidArgument)
			return
		}
		var deleted iamv1.DeleteAccessKeyResponse
		deleted, err = value.workflow.DeleteAccessKey(request.Context(), credential, user, key, body)
		if err == nil && iamv1.ValidateDeleteAccessKeyResponse(deleted) != nil {
			err = identityaccess.ErrUnavailable
		}
		result = deleted
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}
