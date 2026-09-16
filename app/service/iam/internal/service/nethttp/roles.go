package nethttp

import (
	"net/http"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

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
