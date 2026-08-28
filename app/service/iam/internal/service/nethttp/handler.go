// Package nethttp exposes the strict Phase 1 IAM HTTP boundary on the Go
// standard library stack.
package nethttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

type Workflow interface {
	CurrentIdentity(context.Context, iamv1.Secret) (iamv1.CurrentIdentity, error)
	ListPrincipals(context.Context, iamv1.Secret, string, string) (iamv1.PrincipalList, error)
	ListAccounts(context.Context, iamv1.Secret, string, string) (iamv1.OrganizationAccountList, error)
	ReadOrganization(context.Context, iamv1.Secret, iamv1.OrganizationID, string) (iamv1.OrganizationAccount, error)
	SetOrganizationStatus(context.Context, iamv1.Secret, iamv1.OrganizationID, iamv1.SetOrganizationStatusRequest) (iamv1.OrganizationAccount, error)
	RecoverOrganizationAdministrator(context.Context, iamv1.Secret, iamv1.OrganizationID, iamv1.RecoverOrganizationAdministratorRequest) (iamv1.OrganizationAccount, error)
	CreateOrganization(context.Context, iamv1.Secret, iamv1.CreateOrganizationRequest) (iamv1.OrganizationAccount, error)
	SetAccountAlias(context.Context, iamv1.Secret, iamv1.SetAccountAliasRequest) (iamv1.OrganizationAccount, error)
	SetPrincipalStatus(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.SetPrincipalStatusRequest) (iamv1.Principal, error)
	ResetUserPassword(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.ResetUserPasswordRequest) (iamv1.Principal, error)
	Readiness(context.Context) (iamv1.Readiness, error)
	BootstrapStatus(context.Context, iamv1.Secret) (iamv1.BootstrapStatus, error)
	ServiceIdentity(context.Context, iamv1.Secret) (iamv1.ServiceIdentity, error)
	ResolveAuditProducer(context.Context, iamv1.Secret, iamv1.ResolveAuditProducerRequest) (iamv1.AuditProducerAuthorization, error)
	Login(context.Context, iamv1.LoginRequest) (iamv1.LoginResponse, error)
	Logout(context.Context, iamv1.Secret, iamv1.LogoutRequest) (iamv1.LogoutResponse, error)
	ChangePassword(context.Context, iamv1.Secret, iamv1.ChangePasswordRequest) (iamv1.ChangePasswordResponse, error)
	CreateUser(context.Context, iamv1.Secret, iamv1.CreateUserRequest) (iamv1.Principal, error)
	PutRoleBinding(context.Context, iamv1.Secret, iamv1.PutRoleBindingRequest) (iamv1.RoleBinding, error)
	RevokeRoleBinding(
		context.Context,
		iamv1.Secret,
		iamv1.RoleBindingID,
		iamv1.RevokeRoleBindingRequest,
	) (iamv1.Revocation, error)
	RevokeSession(
		context.Context,
		iamv1.Secret,
		iamv1.SessionID,
		iamv1.RevokeSessionRequest,
	) (iamv1.Revocation, error)
	Authorize(
		context.Context,
		iamv1.Secret,
		iamv1.Secret,
		iamv1.AuthorizationRequest,
	) (iamv1.AuthorizationDecision, error)
	VerifyInstallation(
		context.Context,
		iamv1.Secret,
		iamv1.AuthorizationRequest,
	) (iamv1.AuthorizationDecision, error)
}

type Config struct {
	NewRequestID func() (string, error)
}

type handler struct {
	workflow Workflow
	config   Config
	routes   *http.ServeMux
}

type requestIDContextKey struct{}

func NewHandler(workflow Workflow, config Config) (http.Handler, error) {
	if workflow == nil {
		return nil, errors.New("IAM HTTP workflow is required")
	}
	if config.NewRequestID == nil {
		config.NewRequestID = newRequestID
	}
	value := &handler{workflow: workflow, config: config}
	routes := http.NewServeMux()
	routes.HandleFunc("/ready", value.ready)
	routes.HandleFunc("/v1/bootstrap/status", value.bootstrapStatus)
	routes.HandleFunc("/v1/service-identity", value.serviceIdentity)
	routes.HandleFunc("/v1/audit-producer:resolve", value.resolveAuditProducer)
	routes.HandleFunc("/v1/auth/login", value.login)
	routes.HandleFunc("/v1/auth/me", value.currentIdentity)
	routes.HandleFunc("/v1/organizations", value.organizations)
	routes.HandleFunc("/v1/organizations/", value.organization)
	routes.HandleFunc("/v1/organization:alias", value.setAccountAlias)
	routes.HandleFunc("/v1/auth/logout", value.logout)
	routes.HandleFunc("/v1/auth/password", value.changePassword)
	routes.HandleFunc("/v1/authorize", value.authorize)
	routes.HandleFunc("/v1/installation:verify", value.verifyInstallation)
	routes.HandleFunc("/v1/principals", value.createUser)
	routes.HandleFunc("/v1/principals/", value.changeSubaccount)
	routes.HandleFunc("/v1/role-bindings", value.putRoleBinding)
	routes.HandleFunc("/v1/role-bindings/", value.revokeRoleBinding)
	routes.HandleFunc("/v1/sessions/", value.revokeSession)
	routes.HandleFunc("/", value.notFound)
	value.routes = routes
	return value, nil
}

func (value *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID, err := value.config.NewRequestID()
	if err != nil || iamv1.ValidateID("requestId", requestID) != nil {
		writeProblem(response, "request-unavailable", http.StatusServiceUnavailable, "iam.unavailable", "IAM unavailable")
		return
	}
	response.Header().Set("Matrix-Request-ID", requestID)
	request = request.WithContext(context.WithValue(request.Context(), requestIDContextKey{}, requestID))
	value.routes.ServeHTTP(response, request)
}

func (value *handler) ready(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	readiness, err := value.workflow.Readiness(request.Context())
	if err != nil || readiness.State != iamv1.ReadinessReady {
		value.writeError(response, request, identityaccess.ErrUnavailable)
		return
	}
	writeJSON(response, http.StatusOK, readiness)
}

func (value *handler) bootstrapStatus(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	status, err := value.workflow.BootstrapStatus(request.Context(), credential)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (value *handler) serviceIdentity(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	identity, err := value.workflow.ServiceIdentity(request.Context(), credential)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, identity)
}

func (value *handler) resolveAuditProducer(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	if len(request.Header.Values("Matrix-Subject-Credential")) != 0 {
		writeProblem(response, requestID(request), http.StatusBadRequest, "iam.header.unsupported", "IAM header unsupported")
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.ResolveAuditProducerRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.ResolveAuditProducer(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) login(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	body, ok := decodeJSON[iamv1.LoginRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.Login(request.Context(), body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	encoded, err := iamv1.EncodeLoginResponse(result)
	if err != nil {
		value.writeError(response, request, identityaccess.ErrUnavailable)
		return
	}
	writeEncodedJSON(response, http.StatusOK, encoded)
}

func (value *handler) logout(response http.ResponseWriter, request *http.Request) {
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
	result, err := value.workflow.Logout(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) changePassword(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.ChangePasswordRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.ChangePassword(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) createUser(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		value.listPrincipals(response, request)
		return
	}
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.CreateUserRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.CreateUser(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (value *handler) putRoleBinding(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.PutRoleBindingRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.PutRoleBinding(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) revokeRoleBinding(response http.ResponseWriter, request *http.Request) {
	id, ok := commandPathID(response, request, "/v1/role-bindings/", ":revoke", "roleBindingId")
	if !ok || !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.RevokeRoleBindingRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.RevokeRoleBinding(
		request.Context(), credential, iamv1.RoleBindingID(id), body,
	)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) revokeSession(response http.ResponseWriter, request *http.Request) {
	id, ok := commandPathID(response, request, "/v1/sessions/", ":revoke", "sessionId")
	if !ok || !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.RevokeSessionRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.RevokeSession(
		request.Context(), credential, iamv1.SessionID(id), body,
	)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) authorize(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	serviceCredential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	subjectCredential, ok := subjectBearer(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.AuthorizationRequest](value, response, request)
	if !ok {
		return
	}
	decision, err := value.workflow.Authorize(
		request.Context(),
		serviceCredential,
		subjectCredential,
		body,
	)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, decision)
}

func (value *handler) verifyInstallation(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	if len(request.Header.Values("Matrix-Subject-Credential")) != 0 {
		writeProblem(
			response,
			requestID(request),
			http.StatusBadRequest,
			"iam.header.unsupported",
			"IAM header unsupported",
		)
		return
	}
	serviceCredential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.AuthorizationRequest](value, response, request)
	if !ok {
		return
	}
	decision, err := value.workflow.VerifyInstallation(
		request.Context(), serviceCredential, body,
	)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, decision)
}

func (value *handler) currentIdentity(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.CurrentIdentity(request.Context(), credential)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func accountPage(response http.ResponseWriter, request *http.Request) (string, bool) {
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(request.URL.RawQuery) > 512 || len(query) > 1 || request.ContentLength != 0 || len(request.TransferEncoding) > 0 {
		writeProblem(response, requestID(request), http.StatusBadRequest, "iam.query.unsupported", "IAM page request invalid")
		return "", false
	}
	if len(query) == 0 {
		return "", true
	}
	values, ok := query["after"]
	if !ok || len(values) != 1 || iamv1.ValidateID("after", values[0]) != nil {
		writeProblem(response, requestID(request), http.StatusBadRequest, "iam.query.unsupported", "IAM page request invalid")
		return "", false
	}
	return values[0], true
}

func (value *handler) listPrincipals(response http.ResponseWriter, request *http.Request) {
	after, ok := accountPage(response, request)
	if !ok {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.ListPrincipals(request.Context(), credential, after, requestID(request))
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) organizations(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		after, ok := accountPage(response, request)
		if !ok {
			return
		}
		credential, ok := bearerCredential(response, request)
		if !ok {
			return
		}
		result, err := value.workflow.ListAccounts(request.Context(), credential, after, requestID(request))
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
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.CreateOrganizationRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.CreateOrganization(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (value *handler) setAccountAlias(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.SetAccountAliasRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.SetAccountAlias(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) organization(response http.ResponseWriter, request *http.Request) {
	suffix := ""
	if request.Method != http.MethodGet {
		if !value.requireMethod(response, request, http.MethodPost) {
			return
		}
		suffix = ":set-status"
		if strings.HasSuffix(request.URL.Path, ":recover-administrator") {
			suffix = ":recover-administrator"
		}
	}
	id, ok := commandPathID(response, request, "/v1/organizations/", suffix, "organizationId")
	if !ok || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	var result iamv1.OrganizationAccount
	var err error
	switch suffix {
	case "":
		if !rejectQueryAndBody(response, request) {
			return
		}
		result, err = value.workflow.ReadOrganization(request.Context(), credential, iamv1.OrganizationID(id), requestID(request))
	case ":set-status":
		body, ok := decodeJSON[iamv1.SetOrganizationStatusRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.SetOrganizationStatus(request.Context(), credential, iamv1.OrganizationID(id), body)
	case ":recover-administrator":
		body, ok := decodeJSON[iamv1.RecoverOrganizationAdministratorRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.RecoverOrganizationAdministrator(request.Context(), credential, iamv1.OrganizationID(id), body)
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) changeSubaccount(response http.ResponseWriter, request *http.Request) {
	suffix := ":set-status"
	reset := strings.HasSuffix(request.URL.Path, ":reset-password")
	if reset {
		suffix = ":reset-password"
	}
	id, ok := commandPathID(response, request, "/v1/principals/", suffix, "principalId")
	if !ok || !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	var result iamv1.Principal
	var err error
	if reset {
		body, ok := decodeJSON[iamv1.ResetUserPasswordRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.ResetUserPassword(request.Context(), credential, iamv1.PrincipalID(id), body)
	} else {
		body, ok := decodeJSON[iamv1.SetPrincipalStatusRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.SetPrincipalStatus(request.Context(), credential, iamv1.PrincipalID(id), body)
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) notFound(response http.ResponseWriter, request *http.Request) {
	writeProblem(response, requestID(request), http.StatusNotFound, "iam.route.notfound", "IAM route not found")
}

func (value *handler) requireMethod(
	response http.ResponseWriter,
	request *http.Request,
	method string,
) bool {
	if request.Method == method {
		return true
	}
	response.Header().Set("Allow", method)
	writeProblem(response, requestID(request), http.StatusMethodNotAllowed, "iam.method.invalid", "IAM method not allowed")
	return false
}

func (value *handler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	requestID := requestID(request)
	switch {
	case errors.Is(err, identityaccess.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusUnprocessableEntity, "iam.argument.invalid", "IAM argument invalid")
	case errors.Is(err, identityaccess.ErrUnauthenticated):
		response.Header().Set("WWW-Authenticate", `Bearer realm="matrix-iam"`)
		writeProblem(response, requestID, http.StatusUnauthorized, "iam.authentication.failed", "IAM authentication failed")
	case errors.Is(err, identityaccess.ErrForbidden):
		writeProblem(response, requestID, http.StatusForbidden, "iam.authorization.denied", "IAM authorization denied")
	case errors.Is(err, identityaccess.ErrConflict):
		writeProblem(response, requestID, http.StatusConflict, "iam.state.conflict", "IAM state conflict")
	default:
		writeProblem(response, requestID, http.StatusServiceUnavailable, "iam.unavailable", "IAM unavailable")
	}
}

func decodeJSON[T any](
	value *handler,
	response http.ResponseWriter,
	request *http.Request,
) (T, bool) {
	var zero T
	if request.Header.Get("Content-Encoding") != "" {
		writeProblem(response, requestID(request), http.StatusUnsupportedMediaType, "iam.encoding.unsupported", "IAM content encoding unsupported")
		return zero, false
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProblem(response, requestID(request), http.StatusUnsupportedMediaType, "iam.media.unsupported", "IAM media type unsupported")
		return zero, false
	}
	var body T
	if err := iamv1.DecodeRequest(request.Body, &body); err != nil {
		if errors.Is(err, contractjson.ErrDocumentTooLarge) {
			writeProblem(response, requestID(request), http.StatusRequestEntityTooLarge, "iam.body.toolarge", "IAM request body too large")
			return zero, false
		}
		writeProblem(response, requestID(request), http.StatusBadRequest, "iam.json.invalid", "IAM JSON invalid")
		return zero, false
	}
	return body, true
}

func bearerCredential(response http.ResponseWriter, request *http.Request) (iamv1.Secret, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		writeAuthenticationProblem(response, request)
		return iamv1.Secret{}, false
	}
	plaintext := strings.TrimPrefix(values[0], "Bearer ")
	if plaintext == "" || plaintext != strings.TrimSpace(plaintext) || strings.ContainsAny(plaintext, " \t\r\n") {
		writeAuthenticationProblem(response, request)
		return iamv1.Secret{}, false
	}
	credential, err := iamv1.NewSecret(plaintext)
	if err != nil {
		writeAuthenticationProblem(response, request)
		return iamv1.Secret{}, false
	}
	return credential, true
}

func commandPathID(
	response http.ResponseWriter,
	request *http.Request,
	prefix string,
	suffix string,
	name string,
) (string, bool) {
	id, found := strings.CutPrefix(request.URL.Path, prefix)
	if !found {
		writeProblem(response, requestID(request), http.StatusNotFound, "iam.route.notfound", "IAM route not found")
		return "", false
	}
	id, found = strings.CutSuffix(id, suffix)
	if !found || strings.Contains(id, "/") || iamv1.ValidateID(name, id) != nil {
		writeProblem(response, requestID(request), http.StatusNotFound, "iam.route.notfound", "IAM route not found")
		return "", false
	}
	return id, true
}

func subjectBearer(response http.ResponseWriter, request *http.Request) (iamv1.Secret, bool) {
	values := request.Header.Values("Matrix-Subject-Credential")
	if len(values) != 1 || values[0] == "" || values[0] != strings.TrimSpace(values[0]) ||
		strings.ContainsAny(values[0], " \t\r\n") {
		writeAuthenticationProblem(response, request)
		return iamv1.Secret{}, false
	}
	credential, err := iamv1.NewSecret(values[0])
	if err != nil {
		writeAuthenticationProblem(response, request)
		return iamv1.Secret{}, false
	}
	return credential, true
}

func writeAuthenticationProblem(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("WWW-Authenticate", `Bearer realm="matrix-iam"`)
	writeProblem(response, requestID(request), http.StatusUnauthorized, "iam.authentication.failed", "IAM authentication failed")
}

func rejectQueryAndBody(response http.ResponseWriter, request *http.Request) bool {
	if !rejectQuery(response, request) {
		return false
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) > 0 {
		writeProblem(response, requestID(request), http.StatusBadRequest, "iam.body.unexpected", "IAM request body unexpected")
		return false
	}
	return true
}

func rejectQuery(response http.ResponseWriter, request *http.Request) bool {
	if request.URL.RawQuery == "" {
		return true
	}
	writeProblem(response, requestID(request), http.StatusBadRequest, "iam.query.unsupported", "IAM query unsupported")
	return false
}

func requestID(request *http.Request) string {
	value, _ := request.Context().Value(requestIDContextKey{}).(string)
	if value == "" {
		return "request-unavailable"
	}
	return value
}

func newRequestID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		clear(random)
		return "", err
	}
	result := "request-" + hex.EncodeToString(random)
	clear(random)
	return result, nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		writeProblem(response, "request-unavailable", http.StatusServiceUnavailable, "iam.unavailable", "IAM unavailable")
		return
	}
	writeEncodedJSON(response, status, encoded)
}

func writeEncodedJSON(response http.ResponseWriter, status int, encoded []byte) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func writeProblem(
	response http.ResponseWriter,
	requestID string,
	status int,
	code string,
	title string,
) {
	problem := iamv1.Problem{
		Type:      "https://matrix.xiak.com/problems/" + code,
		Title:     title,
		Status:    status,
		Code:      code,
		RequestID: requestID,
	}
	encoded, err := json.Marshal(problem)
	if err != nil {
		http.Error(response, "IAM unavailable", http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}
