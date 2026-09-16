package nethttp

import (
	"net/http"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *handler) logoutRoleSession(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.LogoutRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.LogoutRoleSession(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) currentRoleSession(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.CurrentRoleSession(request.Context(), credential)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) roles(response http.ResponseWriter, request *http.Request) {
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	if request.Method == http.MethodGet {
		after, ok := accountPage(response, request)
		if !ok {
			return
		}
		result, err := value.workflow.ListRoles(request.Context(), credential, after, requestID(request))
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	body, ok := decodeJSON[iamv1.CreateRoleRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.CreateRole(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (value *handler) role(response http.ResponseWriter, request *http.Request) {
	path, found := strings.CutPrefix(request.URL.Path, "/v1/roles/")
	parts := strings.Split(path, "/")
	if !found || len(parts) > 3 {
		value.notFound(response, request)
		return
	}
	id := parts[0]
	assume := len(parts) == 1 && strings.HasSuffix(id, ":assume")
	if assume {
		id = strings.TrimSuffix(id, ":assume")
	}
	status := len(parts) == 1 && strings.HasSuffix(id, ":set-status")
	if status {
		id = strings.TrimSuffix(id, ":set-status")
	}
	if iamv1.ValidateID("roleId", id) != nil {
		value.notFound(response, request)
		return
	}
	roleID := iamv1.RoleID(id)
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	if assume {
		if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
			return
		}
		body, ok := decodeJSON[iamv1.AssumeRoleRequest](value, response, request)
		if !ok {
			return
		}
		if iamv1.ValidateAssumeRoleRequest(body) != nil {
			value.writeError(response, request, identityaccess.ErrInvalidArgument)
			return
		}
		result, err := value.workflow.AssumeRole(request.Context(), credential, roleID, body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		encoded, err := iamv1.EncodeAssumeRoleResponse(result)
		if err != nil {
			value.writeError(response, request, identityaccess.ErrUnavailable)
			return
		}
		defer clear(encoded)
		writeEncodedJSON(response, http.StatusOK, encoded)
		return
	}
	if len(parts) >= 2 && parts[1] == "trust-versions" {
		if !value.requireMethod(response, request, http.MethodGet) {
			return
		}
		if len(parts) == 2 {
			after, ok := accountPage(response, request)
			if !ok {
				return
			}
			result, err := value.workflow.ListRoleTrustVersions(request.Context(), credential, roleID, after, requestID(request))
			if err != nil {
				value.writeError(response, request, err)
				return
			}
			writeJSON(response, http.StatusOK, result)
			return
		}
		if iamv1.ValidateID("trustVersionId", parts[2]) != nil {
			value.notFound(response, request)
			return
		}
		if !rejectQueryAndBody(response, request) {
			return
		}
		result, err := value.workflow.GetRoleTrustVersion(request.Context(), credential, roleID, iamv1.RoleTrustVersionID(parts[2]), requestID(request))
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if len(parts) == 2 && parts[1] == "permission-boundary" {
		value.rolePermissionBoundary(response, request, credential, roleID)
		return
	}
	if len(parts) == 2 && parts[1] == "trust-policy" {
		if !value.requireMethod(response, request, http.MethodPut) || !rejectQuery(response, request) {
			return
		}
		body, ok := decodeJSON[iamv1.SetRoleTrustPolicyRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.SetRoleTrustPolicy(request.Context(), credential, roleID, body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if len(parts) != 1 {
		value.notFound(response, request)
		return
	}
	if !rejectQuery(response, request) {
		return
	}
	if status {
		if !value.requireMethod(response, request, http.MethodPost) {
			return
		}
		body, ok := decodeJSON[iamv1.SetRoleStatusRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.SetRoleStatus(request.Context(), credential, roleID, body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	switch request.Method {
	case http.MethodGet:
		if !rejectQueryAndBody(response, request) {
			return
		}
		result, err := value.workflow.GetRole(request.Context(), credential, roleID, requestID(request))
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
	case http.MethodPatch:
		body, ok := decodeJSON[iamv1.UpdateRoleRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.UpdateRole(request.Context(), credential, roleID, body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
	case http.MethodDelete:
		body, ok := decodeJSON[iamv1.DeleteRoleRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.DeleteRole(request.Context(), credential, roleID, body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
	default:
		response.Header().Set("Allow", "GET, PATCH, DELETE")
		writeProblem(response, requestID(request), http.StatusMethodNotAllowed, "iam.method.invalid", "IAM method not allowed")
	}
}

func (value *handler) roleSessionByRequest(response http.ResponseWriter, request *http.Request) {
	id := strings.TrimPrefix(request.URL.Path, "/v1/auth/role-sessions/by-request/")
	revoke := strings.HasSuffix(id, ":revoke")
	if revoke {
		id = strings.TrimSuffix(id, ":revoke")
	}
	if iamv1.ValidateID("requestId", id) != nil {
		value.notFound(response, request)
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	if revoke {
		if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
			return
		}
		body, ok := decodeJSON[iamv1.RevokeRoleSessionRequest](value, response, request)
		if !ok {
			return
		}
		if iamv1.ValidateID("requestId", body.RequestID) != nil {
			value.writeError(response, request, identityaccess.ErrInvalidArgument)
			return
		}
		result, err := value.workflow.RevokeRoleSessionByRequest(request.Context(), credential, id, body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	result, found, err := value.workflow.GetRoleSessionByRequest(request.Context(), credential, id)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	if !found {
		value.notFound(response, request)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) rolePermissionBoundary(response http.ResponseWriter, request *http.Request, credential iamv1.Secret, id iamv1.RoleID) {
	if !rejectQuery(response, request) {
		return
	}
	var result iamv1.RolePermissionBoundary
	var err error
	switch request.Method {
	case http.MethodGet:
		if !rejectQueryAndBody(response, request) {
			return
		}
		result, err = value.workflow.GetRolePermissionBoundary(request.Context(), credential, id, requestID(request))
	case http.MethodPut:
		body, ok := decodeJSON[iamv1.SetRolePermissionBoundaryRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.SetRolePermissionBoundary(request.Context(), credential, id, body)
	case http.MethodDelete:
		body, ok := decodeJSON[iamv1.RemoveRolePermissionBoundaryRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.RemoveRolePermissionBoundary(request.Context(), credential, id, body)
	default:
		response.Header().Set("Allow", "GET, PUT, DELETE")
		writeProblem(response, requestID(request), http.StatusMethodNotAllowed, "iam.method.invalid", "IAM method not allowed")
		return
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}
