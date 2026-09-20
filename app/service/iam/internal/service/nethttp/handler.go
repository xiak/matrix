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
	ListAccessKeys(context.Context, iamv1.Secret, iamv1.PrincipalID, string) (iamv1.AccessKeyList, error)
	GetAccessKey(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.AccessKeyID, string) (iamv1.AccessKeyAccess, error)
	CreateAccessKey(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.CreateAccessKeyRequest) (iamv1.CreateAccessKeyResponse, error)
	SetAccessKeyStatus(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.AccessKeyID, iamv1.SetAccessKeyStatusRequest) (iamv1.SetAccessKeyStatusResponse, error)
	DeleteAccessKey(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.AccessKeyID, iamv1.DeleteAccessKeyRequest) (iamv1.DeleteAccessKeyResponse, error)
	CurrentIdentity(context.Context, iamv1.Secret) (iamv1.CurrentIdentity, error)
	ListUsers(context.Context, iamv1.Secret, string, string) (iamv1.UserList, error)
	GetUser(context.Context, iamv1.Secret, iamv1.PrincipalID, string) (iamv1.UserAccess, error)
	GetUserPermissionBoundary(context.Context, iamv1.Secret, iamv1.PrincipalID, string) (iamv1.UserPermissionBoundary, error)
	SetUserPermissionBoundary(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.SetUserPermissionBoundaryRequest) (iamv1.UserPermissionBoundary, error)
	RemoveUserPermissionBoundary(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.RemoveUserPermissionBoundaryRequest) (iamv1.UserPermissionBoundary, error)
	ListGroups(context.Context, iamv1.Secret, string, string) (iamv1.GroupList, error)
	GetGroup(context.Context, iamv1.Secret, iamv1.GroupID, string) (iamv1.GroupAccess, error)
	ListRoles(context.Context, iamv1.Secret, string, string) (iamv1.RoleList, error)
	GetRole(context.Context, iamv1.Secret, iamv1.RoleID, string) (iamv1.RoleAccess, error)
	AssumeRole(context.Context, iamv1.Secret, iamv1.RoleID, iamv1.AssumeRoleRequest) (iamv1.AssumeRoleResponse, error)
	CurrentRoleIdentity(context.Context, iamv1.Secret) (iamv1.CurrentRoleIdentity, error)
	ListAssumableRoles(context.Context, iamv1.Secret, string) (iamv1.AssumableRoleList, error)
	LogoutRoleSession(context.Context, iamv1.Secret, iamv1.LogoutRequest) (iamv1.RoleSession, error)
	GetRoleSessionByRequest(context.Context, iamv1.Secret, string) (iamv1.RoleSession, bool, error)
	RevokeRoleSessionByRequest(context.Context, iamv1.Secret, string, iamv1.RevokeRoleSessionRequest) (iamv1.RoleSession, error)
	ListRoleSessions(context.Context, iamv1.Secret, iamv1.RoleID, iamv1.RoleSessionFilter, string, string) (iamv1.RoleSessionList, error)
	GetRoleSession(context.Context, iamv1.Secret, iamv1.RoleID, iamv1.RoleSessionID, string) (iamv1.RoleSessionAccess, error)
	RevokeRoleSession(context.Context, iamv1.Secret, iamv1.RoleID, iamv1.RoleSessionID, iamv1.RevokeRoleSessionRequest) (iamv1.RevokeRoleSessionResponse, error)
	GetRolePermissionBoundary(context.Context, iamv1.Secret, iamv1.RoleID, string) (iamv1.RolePermissionBoundary, error)
	SetRolePermissionBoundary(context.Context, iamv1.Secret, iamv1.RoleID, iamv1.SetRolePermissionBoundaryRequest) (iamv1.RolePermissionBoundary, error)
	RemoveRolePermissionBoundary(context.Context, iamv1.Secret, iamv1.RoleID, iamv1.RemoveRolePermissionBoundaryRequest) (iamv1.RolePermissionBoundary, error)
	CreateRole(context.Context, iamv1.Secret, iamv1.CreateRoleRequest) (iamv1.Role, error)
	UpdateRole(context.Context, iamv1.Secret, iamv1.RoleID, iamv1.UpdateRoleRequest) (iamv1.Role, error)
	SetRoleStatus(context.Context, iamv1.Secret, iamv1.RoleID, iamv1.SetRoleStatusRequest) (iamv1.Role, error)
	SetRoleTrustPolicy(context.Context, iamv1.Secret, iamv1.RoleID, iamv1.SetRoleTrustPolicyRequest) (iamv1.Role, error)
	DeleteRole(context.Context, iamv1.Secret, iamv1.RoleID, iamv1.DeleteRoleRequest) (iamv1.RoleDeletion, error)
	ListRoleTrustVersions(context.Context, iamv1.Secret, iamv1.RoleID, string, string) (iamv1.RoleTrustVersionList, error)
	GetRoleTrustVersion(context.Context, iamv1.Secret, iamv1.RoleID, iamv1.RoleTrustVersionID, string) (iamv1.RoleTrustVersion, error)
	CreateGroup(context.Context, iamv1.Secret, iamv1.CreateGroupRequest) (iamv1.Group, error)
	UpdateGroup(context.Context, iamv1.Secret, iamv1.GroupID, iamv1.UpdateGroupRequest) (iamv1.Group, error)
	DeleteGroup(context.Context, iamv1.Secret, iamv1.GroupID, iamv1.DeleteGroupRequest) (iamv1.GroupDeletion, error)
	ListGroupMemberships(context.Context, iamv1.Secret, iamv1.GroupID, string, string) (iamv1.GroupMembershipList, error)
	CreateGroupMembership(context.Context, iamv1.Secret, iamv1.GroupID, iamv1.CreateGroupMembershipRequest) (iamv1.GroupMembership, error)
	RemoveGroupMembership(context.Context, iamv1.Secret, iamv1.GroupID, iamv1.GroupMembershipID, iamv1.RemoveGroupMembershipRequest) (iamv1.GroupMembership, error)
	ListPolicies(context.Context, iamv1.Secret, bool, string) (iamv1.PolicyList, error)
	ListAuthorizationProfiles(context.Context, iamv1.Secret, string) (iamv1.AuthorizationProfileList, error)
	GetPolicy(context.Context, iamv1.Secret, iamv1.PolicyID, string) (iamv1.PolicyDetail, error)
	CreatePolicy(context.Context, iamv1.Secret, iamv1.CreatePolicyRequest) (iamv1.PolicyDetail, error)
	ListPolicyVersions(context.Context, iamv1.Secret, iamv1.PolicyID, string) (iamv1.PolicyVersionList, error)
	GetPolicyVersion(context.Context, iamv1.Secret, iamv1.PolicyID, iamv1.PolicyVersionID, string) (iamv1.PolicyVersionDetail, error)
	CreatePolicyVersion(context.Context, iamv1.Secret, iamv1.PolicyID, iamv1.CreatePolicyVersionRequest) (iamv1.PolicyVersionDetail, error)
	DeletePolicyVersion(context.Context, iamv1.Secret, iamv1.PolicyID, iamv1.PolicyVersionID, iamv1.DeletePolicyVersionRequest) (iamv1.PolicyDetail, error)
	SetDefaultPolicyVersion(context.Context, iamv1.Secret, iamv1.PolicyID, iamv1.SetDefaultPolicyVersionRequest) (iamv1.PolicyDetail, error)
	UpdatePolicy(context.Context, iamv1.Secret, iamv1.PolicyID, iamv1.UpdatePolicyRequest) (iamv1.PolicyDetail, error)
	DeletePolicy(context.Context, iamv1.Secret, iamv1.PolicyID, iamv1.DeletePolicyRequest) (iamv1.Policy, error)
	ListAccounts(context.Context, iamv1.Secret, string, string) (iamv1.AccountList, error)
	GetAccount(context.Context, iamv1.Secret, iamv1.AccountID, string) (iamv1.AccountAccess, error)
	SetAccountStatus(context.Context, iamv1.Secret, iamv1.AccountID, iamv1.SetAccountStatusRequest) (iamv1.Account, error)
	RecoverRootCredentials(context.Context, iamv1.Secret, iamv1.AccountID, iamv1.RecoverRootCredentialsRequest) (iamv1.Account, error)
	CreateAccount(context.Context, iamv1.Secret, iamv1.CreateAccountRequest) (iamv1.Account, error)
	SetAccountAlias(context.Context, iamv1.Secret, iamv1.SetAccountAliasRequest) (iamv1.Account, error)
	UpdateUser(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.UpdateUserRequest) (iamv1.User, error)
	DeleteUser(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.DeleteUserRequest) (iamv1.UserDeletion, error)
	SetUserStatus(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.SetUserStatusRequest) (iamv1.User, error)
	ResetUserPassword(context.Context, iamv1.Secret, iamv1.PrincipalID, iamv1.ResetUserPasswordRequest) (iamv1.User, error)
	Readiness(context.Context) (iamv1.Readiness, error)
	BootstrapStatus(context.Context, iamv1.Secret) (iamv1.BootstrapStatus, error)
	ServiceIdentity(context.Context, iamv1.Secret) (iamv1.ServiceIdentity, error)
	ResolveAuditProducer(context.Context, iamv1.Secret, iamv1.ResolveAuditProducerRequest) (iamv1.AuditProducerAuthorization, error)
	Login(context.Context, iamv1.LoginRequest) (iamv1.LoginResponse, error)
	VerifyAuthenticationChallenge(context.Context, string, iamv1.VerifyAuthenticationChallengeRequest) (iamv1.LoginResponse, error)
	ChangeChallengePassword(context.Context, string, iamv1.ChallengePasswordChangeRequest) (iamv1.ChallengePasswordChangeResponse, error)
	StartAuthenticatorRecovery(context.Context, string, iamv1.StartAuthenticatorRecoveryRequest) (iamv1.StartAuthenticatorRecoveryResponse, error)
	ConfirmAuthenticatorRecovery(context.Context, string, iamv1.VerifyAuthenticationChallengeRequest) (iamv1.ConfirmAuthenticatorRecoveryResponse, error)
	InspectAuthenticatorRecovery(context.Context, string, iamv1.InspectAuthenticatorRecoveryRequest) (iamv1.AuthenticatorRecovery, error)
	AuthenticatorState(context.Context, iamv1.Secret) (iamv1.AuthenticatorState, error)
	StartTOTPEnrollment(context.Context, iamv1.Secret, iamv1.StartTOTPEnrollmentRequest) (iamv1.StartTOTPEnrollmentResponse, error)
	TOTPEnrollment(context.Context, iamv1.Secret, string) (iamv1.TOTPEnrollment, error)
	TOTPEnrollmentByRequest(context.Context, iamv1.Secret, string) (iamv1.TOTPEnrollment, error)
	CancelTOTPEnrollment(context.Context, iamv1.Secret, string) (iamv1.TOTPEnrollment, error)
	ConfirmTOTPEnrollment(context.Context, iamv1.Secret, string, iamv1.ConfirmTOTPEnrollmentRequest) (iamv1.ConfirmTOTPEnrollmentResponse, error)
	Logout(context.Context, iamv1.Secret, iamv1.LogoutRequest) (iamv1.LogoutResponse, error)
	ListOwnSessions(context.Context, iamv1.Secret, string) (iamv1.SessionList, error)
	RevokeOwnSession(context.Context, iamv1.Secret, iamv1.SessionID, iamv1.RevokeSessionRequest) (iamv1.RevokeOwnSessionResponse, error)
	RevokeOtherSessions(context.Context, iamv1.Secret, iamv1.RevokeSessionRequest) (iamv1.RevokeOtherSessionsResponse, error)
	ChangePassword(context.Context, iamv1.Secret, iamv1.ChangePasswordRequest) (iamv1.ChangePasswordResponse, error)
	NotificationContact(context.Context, iamv1.Secret) (iamv1.NotificationContact, error)
	NotificationVerification(context.Context, iamv1.Secret, string) (iamv1.NotificationContactVerification, error)
	StartNotificationVerification(context.Context, iamv1.Secret, iamv1.StartNotificationContactVerificationRequest) (iamv1.NotificationContactVerification, error)
	ConfirmNotificationContact(context.Context, iamv1.Secret, string, iamv1.ConfirmNotificationContactVerificationRequest) (iamv1.NotificationContactVerification, error)
	CreateUser(context.Context, iamv1.Secret, iamv1.CreateUserRequest) (iamv1.User, error)
	CreatePolicyAttachment(context.Context, iamv1.Secret, iamv1.CreatePolicyAttachmentRequest) (iamv1.PolicyAttachment, error)
	RevokePolicyAttachment(
		context.Context,
		iamv1.Secret,
		iamv1.PolicyAttachmentID,
		iamv1.RevokePolicyAttachmentRequest,
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
	AuthorizeAccessKey(context.Context, iamv1.Secret, iamv1.AccessKeyAuthorizationRequest) (iamv1.AccessKeyAuthorization, error)
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
	routes.HandleFunc("/v1/auth/challenges/", value.authenticationChallenge)
	routes.HandleFunc("/v1/auth/authenticators", value.authenticatorState)
	routes.HandleFunc("/v1/auth/totp/enrollments", value.startTOTPEnrollment)
	routes.HandleFunc("/v1/auth/totp/enrollments/by-request/", value.totpEnrollmentByRequest)
	routes.HandleFunc("/v1/auth/totp/enrollments/", value.totpEnrollment)
	routes.HandleFunc("/v1/auth/me", value.currentIdentity)
	routes.HandleFunc("/v1/policies", value.policies)
	routes.HandleFunc("/v1/authorization-profiles", value.authorizationProfiles)
	routes.HandleFunc("/v1/policies/", value.policy)
	routes.HandleFunc("/v1/platform-policies", value.listPolicies)
	routes.HandleFunc("/v1/accounts", value.accounts)
	routes.HandleFunc("/v1/accounts/", value.account)
	routes.HandleFunc("/v1/account:alias", value.setAccountAlias)
	routes.HandleFunc("/v1/auth/logout", value.logout)
	routes.HandleFunc("/v1/auth/sessions", value.listOwnSessions)
	routes.HandleFunc("/v1/auth/sessions:revoke-others", value.revokeOtherSessions)
	routes.HandleFunc("/v1/auth/sessions/", value.revokeOwnSession)
	routes.HandleFunc("/v1/auth/password", value.changePassword)
	routes.HandleFunc("/v1/auth/notification-contact", value.notificationContact)
	routes.HandleFunc("/v1/auth/notification-contact/verifications", value.startNotificationVerification)
	routes.HandleFunc("/v1/auth/notification-contact/verifications/", value.notificationVerification)
	routes.HandleFunc("/v1/authorize", value.authorize)
	routes.HandleFunc("/v1/authorize:access-key", value.authorizeAccessKey)
	routes.HandleFunc("/v1/installation:verify", value.verifyInstallation)
	routes.HandleFunc("/v1/users", value.users)
	routes.HandleFunc("/v1/users/", value.user)
	routes.HandleFunc("/v1/groups", value.groups)
	routes.HandleFunc("/v1/groups/", value.group)
	routes.HandleFunc("/v1/roles", value.roles)
	routes.HandleFunc("/v1/roles/", value.role)
	routes.HandleFunc("/v1/auth/role-sessions/by-request/", value.roleSessionByRequest)
	routes.HandleFunc("/v1/auth/role-session", value.currentRoleIdentity)
	routes.HandleFunc("/v1/auth/assumable-roles", value.assumableRoles)
	routes.HandleFunc("/v1/auth/role-session:logout", value.logoutRoleSession)
	routes.HandleFunc("/v1/policy-attachments", value.createPolicyAttachment)
	routes.HandleFunc("/v1/policy-attachments/", value.revokePolicyAttachment)
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

func (value *handler) policies(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		value.listPolicies(response, request)
		return
	}
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.CreatePolicyRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.CreatePolicy(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (value *handler) policy(response http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/v1/policies/")
	if strings.HasSuffix(path, ":set-default-version") || strings.Contains(path, "/") {
		value.policyVersion(response, request, path)
		return
	}
	if request.Method == http.MethodDelete {
		if !rejectQuery(response, request) {
			return
		}
		if iamv1.ValidateID("policyId", path) != nil {
			value.notFound(response, request)
			return
		}
		credential, ok := bearerCredential(response, request)
		if !ok {
			return
		}
		body, ok := decodeJSON[iamv1.DeletePolicyRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.DeletePolicy(request.Context(), credential, iamv1.PolicyID(path), body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if request.Method == http.MethodPatch {
		if !rejectQuery(response, request) {
			return
		}
		if iamv1.ValidateID("policyId", path) != nil {
			value.notFound(response, request)
			return
		}
		credential, ok := bearerCredential(response, request)
		if !ok {
			return
		}
		body, ok := decodeJSON[iamv1.UpdatePolicyRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.UpdatePolicy(request.Context(), credential, iamv1.PolicyID(path), body)
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
	id := strings.TrimPrefix(request.URL.Path, "/v1/policies/")
	if iamv1.ValidateID("policyId", id) != nil {
		value.notFound(response, request)
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.GetPolicy(request.Context(), credential, iamv1.PolicyID(id), requestID(request))
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) policyVersion(response http.ResponseWriter, request *http.Request, path string) {
	parts := strings.Split(path, "/")
	id := parts[0]
	setDefault := len(parts) == 1 && strings.HasSuffix(id, ":set-default-version")
	if setDefault {
		id = strings.TrimSuffix(id, ":set-default-version")
	}
	collection := len(parts) == 2 && parts[1] == "versions"
	item := len(parts) == 3 && parts[1] == "versions" && iamv1.ValidateID("versionId", parts[2]) == nil
	if iamv1.ValidateID("policyId", id) != nil || (!setDefault && !collection && !item) {
		value.notFound(response, request)
		return
	}
	method := http.MethodGet
	if setDefault || (collection && request.Method == http.MethodPost) {
		method = http.MethodPost
	}
	if item && request.Method == http.MethodDelete {
		method = http.MethodDelete
	}
	if !value.requireMethod(response, request, method) || !rejectQuery(response, request) {
		return
	}
	if method == http.MethodGet && !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	var result any
	var err error
	status := http.StatusOK
	switch {
	case item && method == http.MethodDelete:
		body, ok := decodeJSON[iamv1.DeletePolicyVersionRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.DeletePolicyVersion(request.Context(), credential, iamv1.PolicyID(id), iamv1.PolicyVersionID(parts[2]), body)
	case setDefault:
		body, ok := decodeJSON[iamv1.SetDefaultPolicyVersionRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.SetDefaultPolicyVersion(request.Context(), credential, iamv1.PolicyID(id), body)
	case collection && method == http.MethodPost:
		body, ok := decodeJSON[iamv1.CreatePolicyVersionRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.CreatePolicyVersion(request.Context(), credential, iamv1.PolicyID(id), body)
		status = http.StatusCreated
	case collection:
		result, err = value.workflow.ListPolicyVersions(request.Context(), credential, iamv1.PolicyID(id), requestID(request))
	case item:
		result, err = value.workflow.GetPolicyVersion(request.Context(), credential, iamv1.PolicyID(id), iamv1.PolicyVersionID(parts[2]), requestID(request))
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, status, result)
}

func (value *handler) authorizationProfiles(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.ListAuthorizationProfiles(request.Context(), credential, requestID(request))
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	if iamv1.ValidateAuthorizationProfileList(result) != nil {
		value.writeError(response, request, identityaccess.ErrUnavailable)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) listPolicies(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodGet) || !rejectQueryAndBody(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.ListPolicies(request.Context(), credential, request.URL.Path == "/v1/platform-policies", requestID(request))
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
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

func (value *handler) authenticationChallenge(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	suffix := ":verify"
	for _, candidate := range []string{":password", ":recover", ":confirm-recovery", ":recovery-result"} {
		if strings.HasSuffix(request.URL.Path, candidate) {
			suffix = candidate
			break
		}
	}
	id, ok := commandPathID(response, request, "/v1/auth/challenges/", suffix, "challengeId")
	if !ok {
		return
	}
	// This ceremony authenticates its own secret; a bearer cannot select a
	// second identity, and a challenge cannot enter the generic authenticator.
	if len(request.Header.Values("Authorization")) != 0 {
		writeProblem(response, requestID(request), http.StatusBadRequest, "iam.header.unsupported", "IAM header unsupported")
		return
	}
	if suffix == ":password" {
		body, ok := decodeJSON[iamv1.ChallengePasswordChangeRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.ChangeChallengePassword(request.Context(), id, body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		if iamv1.ValidateChallengePasswordChangeResponse(result) != nil {
			value.writeError(response, request, identityaccess.ErrUnavailable)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if suffix == ":recover" || suffix == ":confirm-recovery" || suffix == ":recovery-result" {
		value.authenticatorRecovery(response, request, id, suffix)
		return
	}
	body, ok := decodeJSON[iamv1.VerifyAuthenticationChallengeRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.VerifyAuthenticationChallenge(request.Context(), id, body)
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

func (value *handler) users(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		value.listUsers(response, request)
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

func (value *handler) groups(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		after, ok := directoryPage(response, request, iamv1.ValidatePageCursor)
		if !ok {
			return
		}
		credential, ok := bearerCredential(response, request)
		if !ok {
			return
		}
		result, err := value.workflow.ListGroups(request.Context(), credential, after, requestID(request))
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
	body, ok := decodeJSON[iamv1.CreateGroupRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.CreateGroup(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (value *handler) createPolicyAttachment(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.CreatePolicyAttachmentRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.CreatePolicyAttachment(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) revokePolicyAttachment(response http.ResponseWriter, request *http.Request) {
	id, ok := commandPathID(response, request, "/v1/policy-attachments/", ":revoke", "attachmentId")
	if !ok || !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	body, ok := decodeJSON[iamv1.RevokePolicyAttachmentRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.RevokePolicyAttachment(
		request.Context(), credential, iamv1.PolicyAttachmentID(id), body,
	)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) listOwnSessions(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodGet) {
		return
	}
	after, ok := directoryPage(response, request, iamv1.ValidatePageCursor)
	if !ok {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.ListOwnSessions(request.Context(), credential, after)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) revokeOtherSessions(response http.ResponseWriter, request *http.Request) {
	if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
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
	result, err := value.workflow.RevokeOtherSessions(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) revokeOwnSession(response http.ResponseWriter, request *http.Request) {
	id, ok := commandPathID(response, request, "/v1/auth/sessions/", ":revoke", "sessionId")
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
	result, err := value.workflow.RevokeOwnSession(request.Context(), credential, iamv1.SessionID(id), body)
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

func (value *handler) authorizeAccessKey(response http.ResponseWriter, request *http.Request) {
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
	if len(request.Header.Values("Content-Encoding")) != 0 || len(request.Header.Values("Content-Type")) != 1 || request.Header.Get("Content-Type") != "application/json" {
		writeProblem(response, requestID(request), http.StatusUnsupportedMediaType, "iam.media.unsupported", "IAM media type unsupported")
		return
	}
	body, err := iamv1.DecodeAccessKeyAuthorizationRequest(request.Body)
	if err != nil {
		writeProblem(response, requestID(request), http.StatusBadRequest, "iam.json.invalid", "IAM JSON invalid")
		return
	}
	result, err := value.workflow.AuthorizeAccessKey(request.Context(), credential, body)
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
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

func directoryPage(response http.ResponseWriter, request *http.Request, validateCursor func(string) error) (string, bool) {
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(request.URL.RawQuery) > 512 || len(query) > 1 || request.ContentLength != 0 || len(request.TransferEncoding) > 0 {
		writeProblem(response, requestID(request), http.StatusBadRequest, "iam.query.unsupported", "IAM page request invalid")
		return "", false
	}
	if len(query) == 0 {
		return "", true
	}
	values, ok := query["after"]
	if !ok || len(values) != 1 || validateCursor(values[0]) != nil {
		writeProblem(response, requestID(request), http.StatusBadRequest, "iam.query.unsupported", "IAM page request invalid")
		return "", false
	}
	return values[0], true
}

func (value *handler) listUsers(response http.ResponseWriter, request *http.Request) {
	after, ok := directoryPage(response, request, iamv1.ValidatePageCursor)
	if !ok {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	result, err := value.workflow.ListUsers(request.Context(), credential, after, requestID(request))
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) accounts(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		after, ok := directoryPage(response, request, iamv1.ValidatePageCursor)
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
	body, ok := decodeJSON[iamv1.CreateAccountRequest](value, response, request)
	if !ok {
		return
	}
	result, err := value.workflow.CreateAccount(request.Context(), credential, body)
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

func (value *handler) account(response http.ResponseWriter, request *http.Request) {
	suffix := ""
	if request.Method != http.MethodGet {
		if !value.requireMethod(response, request, http.MethodPost) {
			return
		}
		suffix = ":set-status"
		if strings.HasSuffix(request.URL.Path, ":recover-root-credentials") {
			suffix = ":recover-root-credentials"
		}
	}
	id, ok := commandPathID(response, request, "/v1/accounts/", suffix, "accountId")
	if !ok || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	var result any
	var err error
	switch suffix {
	case "":
		if !rejectQueryAndBody(response, request) {
			return
		}
		result, err = value.workflow.GetAccount(request.Context(), credential, iamv1.AccountID(id), requestID(request))
	case ":set-status":
		body, ok := decodeJSON[iamv1.SetAccountStatusRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.SetAccountStatus(request.Context(), credential, iamv1.AccountID(id), body)
	case ":recover-root-credentials":
		body, ok := decodeJSON[iamv1.RecoverRootCredentialsRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.RecoverRootCredentials(request.Context(), credential, iamv1.AccountID(id), body)
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) user(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/users/"), "/")
	if len(parts) >= 2 && parts[1] == "access-keys" {
		value.accessKeys(response, request, parts)
		return
	}
	if strings.HasSuffix(request.URL.Path, "/permission-boundary") {
		value.userPermissionBoundary(response, request)
		return
	}
	suffix := ""
	if request.Method == http.MethodPost {
		for _, candidate := range []string{":update", ":delete", ":set-status", ":reset-password"} {
			if strings.HasSuffix(request.URL.Path, candidate) {
				suffix = candidate
				break
			}
		}
		if suffix == "" {
			value.notFound(response, request)
			return
		}
	} else if request.Method != http.MethodGet {
		response.Header().Set("Allow", "GET, POST")
		writeProblem(response, requestID(request), http.StatusMethodNotAllowed, "iam.method.invalid", "IAM method not allowed")
		return
	}
	id, ok := commandPathID(response, request, "/v1/users/", suffix, "userId")
	if !ok || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	var result any
	var err error
	switch suffix {
	case "":
		if !rejectQueryAndBody(response, request) {
			return
		}
		result, err = value.workflow.GetUser(request.Context(), credential, iamv1.PrincipalID(id), requestID(request))
	case ":update":
		body, ok := decodeJSON[iamv1.UpdateUserRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.UpdateUser(request.Context(), credential, iamv1.PrincipalID(id), body)
	case ":delete":
		body, ok := decodeJSON[iamv1.DeleteUserRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.DeleteUser(request.Context(), credential, iamv1.PrincipalID(id), body)
	case ":reset-password":
		body, ok := decodeJSON[iamv1.ResetUserPasswordRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.ResetUserPassword(request.Context(), credential, iamv1.PrincipalID(id), body)
	case ":set-status":
		body, ok := decodeJSON[iamv1.SetUserStatusRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.SetUserStatus(request.Context(), credential, iamv1.PrincipalID(id), body)
	}
	if err != nil {
		value.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) userPermissionBoundary(response http.ResponseWriter, request *http.Request) {
	id, ok := commandPathID(response, request, "/v1/users/", "/permission-boundary", "userId")
	if !ok || !rejectQuery(response, request) {
		return
	}
	credential, ok := bearerCredential(response, request)
	if !ok {
		return
	}
	var result iamv1.UserPermissionBoundary
	var err error
	switch request.Method {
	case http.MethodGet:
		if !rejectQueryAndBody(response, request) {
			return
		}
		result, err = value.workflow.GetUserPermissionBoundary(request.Context(), credential, iamv1.PrincipalID(id), requestID(request))
	case http.MethodPut:
		body, ok := decodeJSON[iamv1.SetUserPermissionBoundaryRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.SetUserPermissionBoundary(request.Context(), credential, iamv1.PrincipalID(id), body)
	case http.MethodDelete:
		body, ok := decodeJSON[iamv1.RemoveUserPermissionBoundaryRequest](value, response, request)
		if !ok {
			return
		}
		result, err = value.workflow.RemoveUserPermissionBoundary(request.Context(), credential, iamv1.PrincipalID(id), body)
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

func (value *handler) group(response http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/v1/groups/")
	if path == request.URL.Path || path == "" || strings.Contains(path, "//") {
		value.notFound(response, request)
		return
	}
	parts := strings.Split(path, "/")
	groupPart := parts[0]
	if len(parts) == 1 {
		suffix := ""
		if request.Method != http.MethodGet {
			if !value.requireMethod(response, request, http.MethodPost) {
				return
			}
			if strings.HasSuffix(groupPart, ":update") {
				suffix = ":update"
			}
			if strings.HasSuffix(groupPart, ":delete") {
				suffix = ":delete"
			}
			if suffix == "" {
				value.notFound(response, request)
				return
			}
		}
		id := strings.TrimSuffix(groupPart, suffix)
		if iamv1.ValidateID("groupId", id) != nil {
			value.notFound(response, request)
			return
		}
		credential, ok := bearerCredential(response, request)
		if !ok {
			return
		}
		if suffix == "" {
			if !rejectQueryAndBody(response, request) {
				return
			}
			result, err := value.workflow.GetGroup(request.Context(), credential, iamv1.GroupID(id), requestID(request))
			if err != nil {
				value.writeError(response, request, err)
				return
			}
			writeJSON(response, http.StatusOK, result)
			return
		}
		if !rejectQuery(response, request) {
			return
		}
		if suffix == ":update" {
			body, ok := decodeJSON[iamv1.UpdateGroupRequest](value, response, request)
			if !ok {
				return
			}
			result, err := value.workflow.UpdateGroup(request.Context(), credential, iamv1.GroupID(id), body)
			if err != nil {
				value.writeError(response, request, err)
				return
			}
			writeJSON(response, http.StatusOK, result)
			return
		}
		body, ok := decodeJSON[iamv1.DeleteGroupRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.DeleteGroup(request.Context(), credential, iamv1.GroupID(id), body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if len(parts) == 2 && parts[1] == "memberships" {
		if iamv1.ValidateID("groupId", groupPart) != nil {
			value.notFound(response, request)
			return
		}
		credential, ok := bearerCredential(response, request)
		if !ok {
			return
		}
		if request.Method == http.MethodGet {
			after, ok := directoryPage(response, request, iamv1.ValidatePageCursor)
			if !ok {
				return
			}
			result, err := value.workflow.ListGroupMemberships(request.Context(), credential, iamv1.GroupID(groupPart), after, requestID(request))
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
		body, ok := decodeJSON[iamv1.CreateGroupMembershipRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.CreateGroupMembership(request.Context(), credential, iamv1.GroupID(groupPart), body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if len(parts) == 3 && parts[1] == "memberships" && strings.HasSuffix(parts[2], ":remove") {
		membershipID := strings.TrimSuffix(parts[2], ":remove")
		if iamv1.ValidateID("groupId", groupPart) != nil || iamv1.ValidateID("membershipId", membershipID) != nil {
			value.notFound(response, request)
			return
		}
		if !value.requireMethod(response, request, http.MethodPost) || !rejectQuery(response, request) {
			return
		}
		credential, ok := bearerCredential(response, request)
		if !ok {
			return
		}
		body, ok := decodeJSON[iamv1.RemoveGroupMembershipRequest](value, response, request)
		if !ok {
			return
		}
		result, err := value.workflow.RemoveGroupMembership(request.Context(), credential, iamv1.GroupID(groupPart), iamv1.GroupMembershipID(membershipID), body)
		if err != nil {
			value.writeError(response, request, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	value.notFound(response, request)
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
	case errors.Is(err, identityaccess.ErrAuthenticatorRecoveryNotFound):
		writeProblem(response, requestID, http.StatusNotFound, "iam.authenticator-recovery.not-found", "Authenticator recovery not found")
	case errors.Is(err, identityaccess.ErrTOTPEnrollmentNotFound):
		writeProblem(response, requestID, http.StatusNotFound, "iam.totp.enrollment.not-found", "TOTP enrollment not found")
	case errors.Is(err, identityaccess.ErrVerificationRejected):
		writeProblem(response, requestID, http.StatusUnprocessableEntity, "iam.verification.rejected", "IAM verification rejected")
	case errors.Is(err, identityaccess.ErrOverloaded):
		response.Header().Set("Retry-After", "1")
		writeProblem(response, requestID, http.StatusTooManyRequests, "iam.authentication.busy", "IAM authentication busy")
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
