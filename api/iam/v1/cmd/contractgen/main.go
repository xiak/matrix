// Command contractgen deterministically generates the committed IAM OpenAPI
// 3.1 document from executable Go contracts and explicit semantic overlays.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/api/internal/openapi31"
)

type object = openapi31.Object

var output = flag.String("output", "openapi.json", "generated OpenAPI output path")

func main() {
	flag.Parse()
	encoded, err := json.MarshalIndent(buildDocument(), "", "  ")
	if err != nil {
		fatalf("encode IAM OpenAPI: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		fatalf("write %s: %v", *output, err)
	}
}

func buildDocument() object {
	return openapi31.Build(openapi31.Options{
		Title:    "Matrix IAM v1 contracts",
		Version:  "0.1.0",
		Security: []any{object{"UserSession": []string{}}},
		Paths:    buildPaths(),
		SecuritySchemes: object{
			"UserSession": object{
				"type": "http", "scheme": "bearer",
				"description": "Opaque IAM user session credential.",
			},
			"ServiceCredential": object{
				"type": "http", "scheme": "bearer",
				"description": "Opaque IAM service credential bound to the calling service.",
			},
			"SubjectCredential": object{
				"type": "apiKey", "in": "header", "name": "Matrix-Subject-Credential",
				"description": "Transient opaque user session evaluated for this authorization call.",
			},
		},
		Responses: object{
			"ProblemResponse": object{
				"description": "Normalized RFC 9457-style IAM problem.",
				"content": object{
					"application/problem+json": object{"schema": openapi31.Ref("Problem")},
				},
			},
		},
		Scalars:       scalarSchemas(),
		Enums:         enumSchemas(),
		Structs:       structContracts(),
		FieldOverlay:  fieldOverlay,
		SchemaOverlay: applySemanticOverlays,
	})
}

func buildPaths() object {
	return object{
		"/v1/roles": object{
			"get":  readOperation("listRoles", "List current-account roles and exact resource capabilities", "RoleList", nil, accountPageParameters()),
			"post": mutationOperation("createRole", "Create a customer role without credentials or permission attachments", "CreateRoleRequest", "Role", "201", nil, nil),
		},
		"/v1/roles/{roleId}": object{
			"get":    readOperation("getRole", "Read role metadata, current trust and tenant policy attachments", "RoleAccess", nil, []any{openapi31.PathIDParameter("roleId")}),
			"patch":  mutationOperation("updateRole", "Replace editable role metadata at the expected revision", "UpdateRoleRequest", "Role", "200", nil, []any{openapi31.PathIDParameter("roleId")}),
			"delete": mutationOperation("deleteRole", "Tombstone a role and revoke its active attachments", "DeleteRoleRequest", "RoleDeletion", "200", nil, []any{openapi31.PathIDParameter("roleId")}),
		},
		"/v1/roles/{roleId}:set-status":   object{"post": mutationOperation("setRoleStatus", "Set role availability without stopping tenant workloads", "SetRoleStatusRequest", "Role", "200", nil, []any{openapi31.PathIDParameter("roleId")})},
		"/v1/roles/{roleId}/trust-policy": object{"put": mutationOperation("setRoleTrustPolicy", "Publish and select one immutable trust version", "SetRoleTrustPolicyRequest", "Role", "200", nil, []any{openapi31.PathIDParameter("roleId")})},
		"/v1/roles/{roleId}/permission-boundary": object{
			"get":    readOperation("getRolePermissionBoundary", "Read the role's required permission ceiling; null closes role assumption", "RolePermissionBoundary", nil, []any{openapi31.PathIDParameter("roleId")}),
			"put":    mutationOperation("setRolePermissionBoundary", "Set the role ceiling without granting permissions", "SetRolePermissionBoundaryRequest", "RolePermissionBoundary", "200", nil, []any{openapi31.PathIDParameter("roleId")}),
			"delete": mutationOperation("removeRolePermissionBoundary", "Remove the role ceiling and close assumption", "RemoveRolePermissionBoundaryRequest", "RolePermissionBoundary", "200", nil, []any{openapi31.PathIDParameter("roleId")}),
		},
		"/v1/roles/{roleId}:assume": object{
			"post": mutationOperation("assumeRole", "Issue an account-local role credential once; equal replay never returns a secret", "AssumeRoleRequest", "AssumeRoleResponse", "200", nil, []any{openapi31.PathIDParameter("roleId")}),
		},
		"/v1/roles/{roleId}/sessions": object{
			"get": readOperation("listRoleSessions", "List a bounded role-session history window; lifecycle is not current business eligibility", "RoleSessionList", nil,
				append(append([]any{openapi31.PathIDParameter("roleId")}, accountPageParameters()...),
					object{"name": "sourceUserId", "in": "query", "required": false, "schema": openapi31.Ref("ID")},
					object{"name": "sessionId", "in": "query", "required": false, "schema": openapi31.Ref("ID")},
					object{"name": "lifecycle", "in": "query", "required": false, "schema": object{"type": "string", "enum": []string{"ALL", "UNREVOKED", "EXPIRED", "REVOKED"}, "default": "UNREVOKED"}})),
		},
		"/v1/roles/{roleId}/sessions/{sessionId}": object{
			"get": readOperation("getRoleSession", "Read one precisely scoped non-secret session observation, including terminal history", "RoleSessionAccess", nil,
				[]any{openapi31.PathIDParameter("roleId"), openapi31.PathIDParameter("sessionId")}),
		},
		"/v1/roles/{roleId}/sessions/{sessionId}:revoke": object{
			"post": mutationOperation("revokeRoleSession", "Explicitly revoke one session using current USER authority; equal replay returns the original terminal record", "RevokeRoleSessionRequest", "RevokeRoleSessionResponse", "200", nil,
				[]any{openapi31.PathIDParameter("roleId"), openapi31.PathIDParameter("sessionId")}),
		},
		"/v1/auth/role-sessions/by-request/{requestId}": object{
			"get": readOperation("getRoleSessionByRequest", "Read only the authenticated source user's non-secret issuance result", "RoleSession", nil, []any{openapi31.PathIDParameter("requestId")}),
		},
		"/v1/auth/role-session": object{
			"get": readOperation("currentRoleIdentity", "Resolve the current role bearer and bound minimal display context; cached display is never authority", "CurrentRoleIdentity", nil, nil),
		},
		"/v1/auth/assumable-roles": object{
			"get": readOperation("listAssumableRoles", "Discover only currently assumable roles for the authenticated USER; bounded sparse pages may be empty with a continuation", "AssumableRoleList", nil,
				[]any{object{"name": "after", "in": "query", "required": false, "schema": roleDiscoveryCursorSchema(), "description": "Confidential self-discovery continuation. Pass nextAfter unchanged, including after an empty page; no account/user/session selectors."}}),
		},
		"/v1/auth/role-session:logout": object{
			"post": mutationOperation("logoutRoleSession", "Revoke only the possessed role credential, including after loss of business eligibility; no login session is issued", "LogoutRequest", "RoleSession", "200", nil, nil),
		},
		"/v1/auth/role-sessions/by-request/{requestId}:revoke": object{
			"post": mutationOperation("revokeRoleSessionByRequest", "Revoke the source user's original issuance without requiring current assume authority", "RevokeRoleSessionRequest", "RoleSession", "200", nil, []any{openapi31.PathIDParameter("requestId")}),
		},
		"/v1/roles/{roleId}/trust-versions":             object{"get": readOperation("listRoleTrustVersions", "List this role's immutable trust versions", "RoleTrustVersionList", nil, append([]any{openapi31.PathIDParameter("roleId")}, accountPageParameters()...))},
		"/v1/roles/{roleId}/trust-versions/{versionId}": object{"get": readOperation("getRoleTrustVersion", "Read an exact version in this role", "RoleTrustVersion", nil, []any{openapi31.PathIDParameter("roleId"), openapi31.PathIDParameter("versionId")})},
		"/ready": object{"get": readOperation(
			"getIAMReadiness", "Get IAM readiness", "Readiness", []any{}, nil,
		)},
		"/v1/bootstrap/status": object{"get": readOperation(
			"getBootstrapStatus", "Get bootstrap status", "BootstrapStatus",
			[]any{object{"ServiceCredential": []string{}}}, nil,
		)},
		"/v1/service-identity": object{"get": readOperation(
			"getServiceIdentity", "Get the identity bound to the current service credential", "ServiceIdentity",
			[]any{object{"ServiceCredential": []string{}}}, nil,
		)},
		"/v1/audit-producer:resolve": object{"post": mutationOperation(
			"resolveAuditProducer", "Prove one Audit event against committed IAM authority", "ResolveAuditProducerRequest", "AuditProducerAuthorization", "200",
			[]any{object{"ServiceCredential": []string{}}}, nil,
		)},
		"/v1/auth/login": object{"post": mutationOperation(
			"login", "Verify a password and issue either a login session or a restricted authentication challenge", "LoginRequest", "LoginResponse", "200", []any{}, nil,
		)},
		"/v1/auth/challenges/{challengeId}:verify": object{"post": mutationOperation(
			"verifyAuthenticationChallenge", "Consume the current login challenge and a fresh TOTP; its secret is not a bearer or permission", "VerifyAuthenticationChallengeRequest", "LoginResponse", "200", []any{}, []any{openapi31.PathIDParameter("challengeId")},
		)},
		"/v1/auth/challenges/{challengeId}:password": object{"post": mutationOperation(
			"changeChallengePassword", "Consume only a password-and-TOTP authenticated forced-change challenge; revoke all old sessions and challenges, then require a fresh login", "ChallengePasswordChangeRequest", "ChallengePasswordChangeResponse", "200", []any{}, []any{openapi31.PathIDParameter("challengeId")},
		)},
		"/v1/auth/challenges/{challengeId}:recover": object{"post": mutationOperation(
			"startAuthenticatorRecovery", "Consume one original recovery code under a current password-authenticated LOGIN challenge; revoke the lost factor and old sessions, issue only one-time rebinding material", "StartAuthenticatorRecoveryRequest", "StartAuthenticatorRecoveryResponse", "200", []any{}, []any{openapi31.PathIDParameter("challengeId")},
		)},
		"/v1/auth/challenges/{challengeId}:confirm-recovery": object{"post": mutationOperation(
			"confirmAuthenticatorRecovery", "Consume only a RECOVERY/ENROLLMENT challenge and new-factor TOTP; replace the entire recovery-code batch and require a fresh login", "VerifyAuthenticationChallengeRequest", "ConfirmAuthenticatorRecoveryResponse", "200", []any{}, []any{openapi31.PathIDParameter("challengeId")},
		)},
		"/v1/auth/challenges/{challengeId}:recovery-result": object{"post": mutationOperation(
			"inspectAuthenticatorRecovery", "Read only same-user recovery metadata using a fresh current LOGIN challenge; no secret replay or automatic new intent", "InspectAuthenticatorRecoveryRequest", "AuthenticatorRecovery", "200", []any{}, []any{openapi31.PathIDParameter("challengeId")},
		)},
		"/v1/auth/authenticators":   object{"get": readOperation("getAuthenticatorState", "Read this actual login USER's persisted factor state; no inferred settings or permissions", "AuthenticatorState", nil, nil)},
		"/v1/auth/totp/enrollments": object{"post": mutationOperation("startTOTPEnrollment", "Reauthenticate the current password and start first TOTP enrollment; only APPLIED discloses provisioning", "StartTOTPEnrollmentRequest", "StartTOTPEnrollmentResponse", "200", nil, nil)},
		"/v1/auth/totp/enrollments/{enrollmentId}": object{
			"get":    readOperation("getTOTPEnrollment", "Read original enrollment metadata, never its seed or recovery codes", "TOTPEnrollment", nil, []any{openapi31.PathIDParameter("enrollmentId")}),
			"delete": readOperation("cancelTOTPEnrollment", "Irreversibly cancel a pending enrollment, never an already confirmed binding; no body", "TOTPEnrollment", nil, []any{openapi31.PathIDParameter("enrollmentId")}),
		},
		"/v1/auth/totp/enrollments/by-request/{requestId}": object{"get": readOperation("getTOTPEnrollmentByRequest", "Find original same-USER metadata after a lost response; NOT_FOUND is not evidence of rollback", "TOTPEnrollment", nil, []any{openapi31.PathIDParameter("requestId")})},
		"/v1/auth/totp/enrollments/{enrollmentId}:confirm": object{"post": mutationOperation("confirmTOTPEnrollment", "Commit binding, OTP consumption, recovery batch, notice and session revocation; return codes once then reauthenticate", "ConfirmTOTPEnrollmentRequest", "ConfirmTOTPEnrollmentResponse", "200", nil, []any{openapi31.PathIDParameter("enrollmentId")})},
		"/v1/auth/step-up":                                             object{"post": mutationOperation("startStepUp", "Bind a purpose-limited operation proof to the current nonforced PASSWORD_TOTP Session and original command; no new credential", "StartStepUpRequest", "StepUp", "200", nil, nil)},
		"/v1/auth/step-up/by-request/{requestId}":                      object{"get": readOperation("getStepUpByRequest", "Read original proof metadata with the same current Session; not an authorization or a rollback guarantee", "StepUp", nil, []any{openapi31.PathIDParameter("requestId")})},
		"/v1/auth/step-up/{stepUpId}:verify":                           object{"post": mutationOperation("verifyStepUp", "Reauthenticate password and unused TOTP under shared budgets; keep the original absolute expiry and Session facts; repeated proof submission conflicts", "VerifyStepUpRequest", "StepUp", "200", nil, []any{openapi31.PathIDParameter("stepUpId")})},
		"/v1/auth/recovery-codes:regenerate":                           object{"post": mutationOperation("regenerateRecoveryCodes", "Consume the exact proved command and replace only its recovery-code batch; APPLIED discloses codes once, EQUAL_REPLAY returns metadata only", "RegenerateRecoveryCodesRequest", "RegenerateRecoveryCodesResponse", "200", nil, nil)},
		"/v1/auth/recovery-codes/regenerations/by-request/{requestId}": object{"get": readOperation("getRecoveryCodeRegenerationByRequest", "Read original same-USER completion using a current normal Session; never replay recovery codes", "RecoveryCodeRegeneration", nil, []any{openapi31.PathIDParameter("requestId")})},
		"/v1/auth/me":                object{"get": readOperation("getCurrentIdentity", "Get the current account and identity", "CurrentIdentity", nil, nil)},
		"/v1/authorization-profiles": object{"get": readOperation("listAuthorizationProfiles", "Read complete current product declarations under current account policy-list permission; metadata is not a permit or registration capability. Maximum complete response 64 KiB.", "AuthorizationProfileList", nil, nil)},
		"/v1/policies": object{
			"get":  readOperation("listPolicies", "Read the complete bounded current account policy metadata directory", "PolicyList", nil, nil),
			"post": mutationOperation("createPolicy", "Create an account-owned policy and its initial immutable version without attaching it", "CreatePolicyRequest", "PolicyDetail", "201", nil, nil),
		},
		"/v1/policies/{policyId}": object{
			"get":    readOperation("getPolicy", "Read the current tenant policy and default content", "PolicyDetail", nil, []any{openapi31.PathIDParameter("policyId")}),
			"patch":  mutationOperation("updatePolicy", "Rename a customer policy without changing its content or authority", "UpdatePolicyRequest", "PolicyDetail", "200", nil, []any{openapi31.PathIDParameter("policyId")}),
			"delete": mutationOperation("deletePolicy", "Retire an unreferenced customer policy while preserving immutable history", "DeletePolicyRequest", "Policy", "200", nil, []any{openapi31.PathIDParameter("policyId")}),
		},
		"/v1/policies/{policyId}/versions": object{
			"get":  readOperation("listPolicyVersions", "Read the bounded customer policy version inventory", "PolicyVersionList", nil, []any{openapi31.PathIDParameter("policyId")}),
			"post": mutationOperation("createPolicyVersion", "Create immutable content without changing the default policy version", "CreatePolicyVersionRequest", "PolicyVersionDetail", "201", nil, []any{openapi31.PathIDParameter("policyId")}),
		},
		"/v1/policies/{policyId}/versions/{versionId}": object{
			"get":    readOperation("getPolicyVersion", "Read one immutable customer policy version", "PolicyVersionDetail", nil, []any{openapi31.PathIDParameter("policyId"), openapi31.PathIDParameter("versionId")}),
			"delete": mutationOperation("deletePolicyVersion", "Retire a nondefault version without erasing historical content", "DeletePolicyVersionRequest", "PolicyDetail", "200", nil, []any{openapi31.PathIDParameter("policyId"), openapi31.PathIDParameter("versionId")}),
		},
		"/v1/policies/{policyId}:set-default-version": object{"post": mutationOperation("setDefaultPolicyVersion", "Atomically select an existing default version using the current policy revision", "SetDefaultPolicyVersionRequest", "PolicyDetail", "200", nil, []any{openapi31.PathIDParameter("policyId")})},
		"/v1/platform-policies":                       object{"get": readOperation("listPlatformPolicies", "Read the separately authorized sealed installation policy metadata directory", "PolicyList", nil, nil)},
		"/v1/accounts": object{
			"get":  readOperation("listAccounts", "List accounts as a platform operator", "AccountList", nil, accountPageParameters()),
			"post": mutationOperation("createAccount", "Create an account and its immutable root identity", "CreateAccountRequest", "Account", "201", nil, nil),
		},
		"/v1/accounts/{accountId}":                          object{"get": readOperation("getAccount", "Read account metadata and management capabilities as a platform operator", "AccountAccess", nil, []any{openapi31.PathIDParameter("accountId")})},
		"/v1/accounts/{accountId}:set-status":               object{"post": mutationOperation("setAccountStatus", "Suspend or restore account access without stopping workloads", "SetAccountStatusRequest", "Account", "200", nil, []any{openapi31.PathIDParameter("accountId")})},
		"/v1/accounts/{accountId}:recover-root-credentials": object{"post": mutationOperation("recoverRootCredentials", "Recover the account's immutable root identity without transferring ownership", "RecoverRootCredentialsRequest", "Account", "200", nil, []any{openapi31.PathIDParameter("accountId")})},
		"/v1/account:alias":                                 object{"post": mutationOperation("setAccountAlias", "Set the current account login alias", "SetAccountAliasRequest", "Account", "200", nil, nil)},
		"/v1/users/{userId}":                                object{"get": readOperation("getUser", "Read one manageable account user and target capabilities", "UserAccess", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/users/{userId}/access-keys": object{
			"get":  readOperation("listAccessKeys", "Read the complete, at most two undeleted keys of one user", "AccessKeyList", nil, []any{openapi31.PathIDParameter("userId")}),
			"post": mutationOperation("createAccessKey", "Create one user key; only the first successful response carries its secret", "CreateAccessKeyRequest", "CreateAccessKeyResponse", "201", nil, []any{openapi31.PathIDParameter("userId")}),
		},
		"/v1/users/{userId}/access-keys/{accessKeyId}": object{
			"get": readOperation("getAccessKey", "Read nonsecret user key metadata and current operation hints", "AccessKeyAccess", nil, []any{openapi31.PathIDParameter("userId"), openapi31.PathIDParameter("accessKeyId")}),
		},
		"/v1/users/{userId}/access-keys/{accessKeyId}:set-status": object{
			"post": mutationOperation("setAccessKeyStatus", "Explicitly disable or enable one key at its exact version", "SetAccessKeyStatusRequest", "SetAccessKeyStatusResponse", "200", nil, []any{openapi31.PathIDParameter("userId"), openapi31.PathIDParameter("accessKeyId")}),
		},
		"/v1/users/{userId}/access-keys/{accessKeyId}:delete": object{
			"post": mutationOperation("deleteAccessKey", "Irreversibly delete a disabled key without exporting material", "DeleteAccessKeyRequest", "DeleteAccessKeyResponse", "200", nil, []any{openapi31.PathIDParameter("userId"), openapi31.PathIDParameter("accessKeyId")}),
		},
		"/v1/users/{userId}/permission-boundary": object{
			"get":    readOperation("getUserPermissionBoundary", "Read the current user permission limit, not a grant", "UserPermissionBoundary", nil, []any{openapi31.PathIDParameter("userId")}),
			"put":    mutationOperation("setUserPermissionBoundary", "Root sets or replaces the tenant user permission limit", "SetUserPermissionBoundaryRequest", "UserPermissionBoundary", "200", nil, []any{openapi31.PathIDParameter("userId")}),
			"delete": mutationOperation("removeUserPermissionBoundary", "Root explicitly removes the tenant user permission limit", "RemoveUserPermissionBoundaryRequest", "UserPermissionBoundary", "200", nil, []any{openapi31.PathIDParameter("userId")}),
		},
		"/v1/users/{userId}:update":                                            object{"post": mutationOperation("updateUser", "Update an account user's display profile", "UpdateUserRequest", "User", "200", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/users/{userId}:delete":                                            object{"post": mutationOperation("deleteUser", "Irreversibly tombstone a disabled account user", "DeleteUserRequest", "UserDeletion", "200", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/users/{userId}:set-status":                                        object{"post": mutationOperation("setUserStatus", "Disable or enable an account user", "SetUserStatusRequest", "User", "200", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/users/{userId}:reset-password":                                    object{"post": mutationOperation("resetUserPassword", "Reset an account user password and revoke its sessions", "ResetUserPasswordRequest", "User", "200", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/auth/notification-contact":                                        object{"get": readOperation("getNotificationContact", "Read only this login USER's security contact; not an authentication or recovery identity", "NotificationContact", nil, nil)},
		"/v1/auth/notification-contact/verifications":                          object{"post": mutationOperation("startNotificationVerification", "Reauthenticate the current password to verify the first notification address; no replacement or selectors", "StartNotificationContactVerificationRequest", "NotificationContactVerification", "200", nil, nil)},
		"/v1/auth/notification-contact/verifications/{verificationId}":         object{"get": readOperation("getNotificationVerification", "Read the original verification from its actual starting login session; never consumes a code", "NotificationContactVerification", nil, []any{openapi31.PathIDParameter("verificationId")})},
		"/v1/auth/notification-contact/verifications/{verificationId}:confirm": object{"post": mutationOperation("confirmNotificationContact", "Consume the original address-possession code once; a repeated confirmation conflicts; query lost completions with GET", "ConfirmNotificationContactVerificationRequest", "NotificationContactVerification", "200", nil, []any{openapi31.PathIDParameter("verificationId")})},
		"/v1/auth/logout": object{"post": mutationOperation(
			"logout", "Revoke the current session", "LogoutRequest", "LogoutResponse", "200", nil, nil,
		)},
		"/v1/auth/sessions": object{"get": readOperation("listOwnSessions", "Observe only the current user's valid login sessions; not devices or online activity", "SessionList", nil,
			[]any{object{"name": "after", "in": "query", "required": false, "schema": pageCursorSchema(), "description": "Pass nextCursor unchanged. Bound to this actual login session, credential generation and installation; no account/user/current-session selectors."}})},
		"/v1/auth/sessions/{sessionId}:revoke": object{"post": mutationOperation("revokeOwnSession", "End another login session of the current user; the current session must use logout", "RevokeSessionRequest", "RevokeOwnSessionResponse", "200", nil,
			[]any{openapi31.PathIDParameter("sessionId")})},
		"/v1/auth/sessions:revoke-others": object{"post": mutationOperation("revokeOtherSessions", "Atomically end the current user's other login sessions; exact replay preserves later logins", "RevokeSessionRequest", "RevokeOtherSessionsResponse", "200", nil, nil)},
		"/v1/auth/password": object{"post": mutationOperation(
			"changePassword", "Change the current user password", "ChangePasswordRequest", "ChangePasswordResponse", "200", nil, nil,
		)},
		"/v1/users": object{"get": readOperation("listUsers", "List manageable users and their bounded direct policy attachments in the current account", "UserList", nil, accountPageParameters()), "post": mutationOperation(
			"createUser", "Create an account user", "CreateUserRequest", "User", "201", nil, nil,
		)},
		"/v1/groups": object{"get": readOperation("listGroups", "List groups and their bounded direct policy attachments in the current account", "GroupList", nil, accountPageParameters()), "post": mutationOperation(
			"createGroup", "Create an account group", "CreateGroupRequest", "Group", "201", nil, nil,
		)},
		"/v1/groups/{groupId}":        object{"get": readOperation("getGroup", "Read one group and its target capabilities", "GroupAccess", nil, []any{openapi31.PathIDParameter("groupId")})},
		"/v1/groups/{groupId}:update": object{"post": mutationOperation("updateGroup", "Update a group name and description", "UpdateGroupRequest", "Group", "200", nil, []any{openapi31.PathIDParameter("groupId")})},
		"/v1/groups/{groupId}:delete": object{"post": mutationOperation("deleteGroup", "Tombstone a group and close its active relationships", "DeleteGroupRequest", "GroupDeletion", "200", nil, []any{openapi31.PathIDParameter("groupId")})},
		"/v1/groups/{groupId}/memberships": object{
			"get":  readOperation("listGroupMemberships", "List current user memberships in a group", "GroupMembershipList", nil, append([]any{openapi31.PathIDParameter("groupId")}, accountPageParameters()...)),
			"post": mutationOperation("createGroupMembership", "Add one user to a group", "CreateGroupMembershipRequest", "GroupMembership", "200", nil, []any{openapi31.PathIDParameter("groupId")}),
		},
		"/v1/groups/{groupId}/memberships/{membershipId}:remove": object{"post": mutationOperation(
			"removeGroupMembership", "Remove one exact user membership from a group", "RemoveGroupMembershipRequest", "GroupMembership", "200", nil,
			[]any{openapi31.PathIDParameter("groupId"), openapi31.PathIDParameter("membershipId")},
		)},
		"/v1/policy-attachments": object{"post": mutationOperation(
			"createPolicyAttachment", "Create a direct user or group policy attachment", "CreatePolicyAttachmentRequest", "PolicyAttachment", "200", nil, nil,
		)},
		"/v1/policy-attachments/{attachmentId}:revoke": object{"post": mutationOperation(
			"revokePolicyAttachment", "Revoke a policy attachment", "RevokePolicyAttachmentRequest", "Revocation", "200", nil,
			[]any{openapi31.PathIDParameter("attachmentId")},
		)},
		"/v1/sessions/{sessionId}:revoke": object{"post": mutationOperation(
			"revokeSession", "Revoke an account session", "RevokeSessionRequest", "Revocation", "200", nil,
			[]any{openapi31.PathIDParameter("sessionId")},
		)},
		"/v1/authorize": object{"post": mutationOperation(
			"authorize", "Authorize a transient subject for one action", "AuthorizationRequest", "AuthorizationDecision", "200",
			[]any{object{"ServiceCredential": []string{}, "SubjectCredential": []string{}}}, nil,
		)},
		"/v1/authorize:access-key": object{"post": mutationOperation(
			"authorizeAccessKey", "Verify one signed product request and atomically record its decision and permanent nonce consumption", "AccessKeyAuthorizationRequest", "AccessKeyAuthorization", "200",
			[]any{object{"ServiceCredential": []string{}}}, nil,
		)},
		"/v1/installation:verify": object{"post": mutationOperation(
			"verifyInstallation", "Authorize the credential-bound installation verifier", "AuthorizationRequest", "AuthorizationDecision", "200",
			[]any{object{"ServiceCredential": []string{}}}, nil,
		)},
	}
}

func accountPageParameters() []any {
	return []any{object{"name": "after", "in": "query", "required": false, "schema": pageCursorSchema(), "description": "Opaque signed continuation bound to the current account, session, query and authority revision. Pass nextAfter unchanged; raw resource IDs are not accepted."}}
}

func pageCursorSchema() object {
	return object{"type": "string", "pattern": `^ic1\.[A-Za-z0-9_-]+$`, "not": object{"pattern": `[^A-Za-z0-9._-]`}, "minLength": 5, "maxLength": iamv1.MaxPageCursorBytes}
}

func roleDiscoveryCursorSchema() object {
	return object{"type": "string", "pattern": `^ir1\.[A-Za-z0-9_-]+$`, "not": object{"pattern": `[^A-Za-z0-9._-]`}, "minLength": 5, "maxLength": iamv1.MaxPageCursorBytes}
}

func mutationOperation(
	operationID, summary, requestSchema, responseSchema, status string,
	security []any,
	parameters []any,
) object {
	responses := openapi31.ProblemResponses("400", "401", "403", "409", "413", "415", "422", "500", "503")
	responses[status] = openapi31.JSONResponse("Command completed.", responseSchema)
	if operationID == "login" || operationID == "changePassword" || operationID == "startTOTPEnrollment" || operationID == "changeChallengePassword" || operationID == "verifyStepUp" {
		responses["429"] = object{
			"description": "This IAM instance's bounded password-work capacity is occupied; this discloses no user-specific attempt budget.",
			"headers":     object{"Retry-After": object{"schema": object{"type": "string", "const": "1"}}},
			"content":     object{"application/problem+json": object{"schema": openapi31.Ref("Problem")}},
		}
	}
	if operationID == "createAccessKey" {
		responses["200"] = openapi31.JSONResponse("Original nonsecret completion; no secret is reissued.", responseSchema)
	}
	if operationID == "verifyStepUp" || operationID == "regenerateRecoveryCodes" {
		responses["404"] = openapi31.ProblemResponses("404")["404"]
	}
	operation := object{
		"operationId": operationID,
		"summary":     summary,
		"requestBody": openapi31.JSONRequestBody(requestSchema),
		"responses":   responses,
	}
	if security != nil {
		operation["security"] = security
	}
	if len(parameters) > 0 {
		operation["parameters"] = parameters
	}
	return operation
}

func readOperation(
	operationID, summary, responseSchema string,
	security []any,
	parameters []any,
) object {
	responses := openapi31.ProblemResponses("401", "403", "500", "503")
	if operationID == "getRoleSessionByRequest" {
		responses["404"] = object{"$ref": "#/components/responses/ProblemResponse", "description": "No committed issuance found for this source user and request. This does not authorize a new intent."}
	}
	switch operationID {
	case "getAuthenticatorState", "getTOTPEnrollment", "getTOTPEnrollmentByRequest", "cancelTOTPEnrollment", "getStepUpByRequest", "getRecoveryCodeRegenerationByRequest":
		responses["400"] = object{"$ref": "#/components/responses/ProblemResponse", "description": "Invalid path, query or unexpected body; no identity selector is accepted."}
	}
	if operationID == "getStepUpByRequest" || operationID == "getRecoveryCodeRegenerationByRequest" {
		responses["404"] = object{"$ref": "#/components/responses/ProblemResponse", "description": "No original same-USER metadata observed; not evidence that an uncertain command rolled back, and not permission to create a replacement intent."}
	}
	switch operationID {
	case "getTOTPEnrollment", "getTOTPEnrollmentByRequest", "cancelTOTPEnrollment":
		responses["404"] = object{"$ref": "#/components/responses/ProblemResponse", "description": "No enrollment metadata found for this authenticated USER and original reference; not evidence that an uncertain command rolled back."}
	}
	if operationID == "cancelTOTPEnrollment" {
		responses["409"] = object{"$ref": "#/components/responses/ProblemResponse", "description": "The enrollment is already confirmed and cannot be cancelled."}
	}
	responses["200"] = openapi31.JSONResponse("Current authority state.", responseSchema)
	operation := object{
		"operationId": operationID,
		"summary":     summary,
		"responses":   responses,
	}
	if security != nil {
		operation["security"] = security
	}
	if len(parameters) > 0 {
		operation["parameters"] = parameters
	}
	return operation
}

func scalarSchemas() object {
	id := object{
		"type": "string", "minLength": 1, "maxLength": 128,
		"pattern": `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`,
	}
	result := object{
		"Event": object{"$ref": "../../audit/v1/openapi.json#/components/schemas/Event"},
		"Timestamp": object{
			"type": "string", "format": "date-time",
			"pattern": `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$`,
		},
		"ID": id,
		"Secret": object{
			"type": "string", "minLength": 1, "maxLength": 16384,
			"x-matrix-sensitive": true,
		},
	}
	for _, name := range []string{
		"AccountID", "PrincipalID", "GroupID", "GroupMembershipID", "RoleBindingID", "RoleID", "RoleTrustVersionID", "RoleSessionID", "SessionID", "DecisionID",
		"PolicyID", "PolicyVersionID", "PolicyAttachmentID", "AccessKeyID",
	} {
		result[name] = object{"allOf": []any{openapi31.Ref("ID")}}
	}
	result["ProductID"] = object{"type": "string", "pattern": `^[a-z][a-z0-9_-]{0,63}$`, "minLength": 1, "maxLength": 64}
	return result
}

func enumSchemas() map[string][]string {
	return map[string][]string{
		"RoleStatus":                   {string(iamv1.RoleActive), string(iamv1.RoleDisabled)},
		"AccessKeyStatus":              {string(iamv1.AccessKeyEnabled), string(iamv1.AccessKeyDisabled)},
		"RoleManagement":               {string(iamv1.RoleCustomerManaged)},
		"AccountStatus":                {string(iamv1.AccountActive), string(iamv1.AccountDisabled)},
		"PrincipalType":                {string(iamv1.PrincipalUser), string(iamv1.PrincipalServiceAccount)},
		"SubjectType":                  {string(iamv1.SubjectUser), string(iamv1.SubjectServiceAccount), string(iamv1.SubjectRole)},
		"UserAuthenticationMethod":     {string(iamv1.UserAuthenticationLoginSession), string(iamv1.UserAuthenticationAccessKey)},
		"PrincipalStatus":              {string(iamv1.PrincipalActive), string(iamv1.PrincipalDisabled)},
		"SessionStatus":                {string(iamv1.SessionActive), string(iamv1.SessionRevoked), string(iamv1.SessionExpired)},
		"RoleSessionLifecycle":         {string(iamv1.RoleSessionUnrevoked), string(iamv1.RoleSessionExpired), string(iamv1.RoleSessionRevoked)},
		"AuthorityScope":               {string(iamv1.AuthorityScopeTenant), string(iamv1.AuthorityScopeInstallation), string(iamv1.AuthorityScopeInstallationProbe)},
		"AuthorizationResourceMode":    {string(iamv1.AuthorizationResourceInstance), string(iamv1.AuthorizationResourceCollection)},
		"AuthorizationCollectionUsage": {string(iamv1.AuthorizationCollectionList), string(iamv1.AuthorizationCollectionCreate)},
		"IdentityKind":                 {string(iamv1.IdentityRoot), string(iamv1.IdentityUser)},
		"CapabilityRestriction":        openapi31.StringValues(iamv1.AllCapabilityRestrictions()),
		"PolicyAttachmentTargetKind":   {string(iamv1.PolicyTargetUser), string(iamv1.PolicyTargetService), string(iamv1.PolicyTargetGroup), string(iamv1.PolicyTargetRole)},
		"PolicyGrantSourceKind":        {string(iamv1.PolicyGrantDirect), string(iamv1.PolicyGrantGroup)},
		"PolicyManagement":             {string(iamv1.PolicySystemManaged), string(iamv1.PolicyCustomerManaged)},
		"PolicyStatus":                 {string(iamv1.PolicyActive), string(iamv1.PolicyRetired)},
		"PolicyEffect":                 {string(iamv1.PolicyAllow), string(iamv1.PolicyDeny)},
		"ConditionKey":                 {string(iamv1.ConditionIAMCurrentTime), string(iamv1.ConditionIAMAccountID), string(iamv1.ConditionIAMPrincipalID)},
		"PolicyConditionOperator":      {string(iamv1.PolicyDateGreaterThanEquals), string(iamv1.PolicyDateLessThan), string(iamv1.PolicyStringEquals), string(iamv1.PolicyStringNotEquals)},
		"PolicyResourceMatch":          {string(iamv1.PolicyResourceExact), string(iamv1.PolicyResourceAnyInAuthority), string(iamv1.PolicyResourcePrefixInAuthority)},
		"Action":                       openapi31.StringValues(iamv1.AllActions()),
		"ResourceKind": {
			string(iamv1.ResourceAccount), string(iamv1.ResourceUser), string(iamv1.ResourceAccessKey),
			string(iamv1.ResourcePolicy), string(iamv1.ResourceRole), string(iamv1.ResourceRoleSession),
			string(iamv1.ResourceOrganization), string(iamv1.ResourcePrincipal), string(iamv1.ResourceGroup), string(iamv1.ResourceGroupMembership), string(iamv1.ResourceRoleBinding), string(iamv1.ResourcePolicyAttachment),
			string(iamv1.ResourceSession), string(iamv1.ResourceApplication), string(iamv1.ResourceConfiguration),
			string(iamv1.ResourceConfigurationRevision), string(iamv1.ResourceApplicationRevision),
			string(iamv1.ResourceDeployment), string(iamv1.ResourceOperation),
			string(iamv1.ResourceServiceOffering), string(iamv1.ResourceRegion),
			string(iamv1.ResourceQuotaEntitlement), string(iamv1.ResourceServiceInstallation),
			string(iamv1.ResourceAuditRecord),
			string(iamv1.ResourceAuditChain), string(iamv1.ResourceInstallation),
			string(iamv1.ResourceExecutionPool), string(iamv1.ResourceExecutionTarget), string(iamv1.ResourceNodeEnrollment),
		},
		"DecisionReason": {string(iamv1.DecisionAllowed), string(iamv1.DecisionDenied)},
		"BootstrapState": {string(iamv1.BootstrapUninitialized), string(iamv1.BootstrapReady)},
		"ServicePurpose": openapi31.StringValues(iamv1.AllServicePurposes()),
		"ReadinessState": {string(iamv1.ReadinessReady), string(iamv1.ReadinessNotReady)},
		"LoginOutcome":   {string(iamv1.LoginAuthenticated), string(iamv1.LoginChallengeRequired)},
	}
}

func structContracts() map[string]reflect.Type {
	return map[string]reflect.Type{
		"Subject":                                       openapi31.StructType[iamv1.Subject](),
		"RoleSessionReference":                          openapi31.StructType[iamv1.RoleSessionReference](),
		"ResourceReference":                             openapi31.StructType[iamv1.ResourceReference](),
		"AuthorizationProfileReference":                 openapi31.StructType[iamv1.AuthorizationProfileReference](),
		"AuthorizationProfileList":                      openapi31.StructType[iamv1.AuthorizationProfileList](),
		"AuthorizationProfileEntry":                     openapi31.StructType[iamv1.AuthorizationProfileEntry](),
		"AuthorizationProfile":                          openapi31.StructType[iamv1.AuthorizationProfile](),
		"AuthorizationProfileAction":                    openapi31.StructType[iamv1.AuthorizationProfileAction](),
		"AuthorizationResourceShape":                    openapi31.StructType[iamv1.AuthorizationResourceShape](),
		"AuthorizationProfileCondition":                 openapi31.StructType[iamv1.AuthorizationProfileCondition](),
		"PolicyAttachment":                              openapi31.StructType[iamv1.PolicyAttachment](),
		"PolicyGrantSource":                             openapi31.StructType[iamv1.PolicyGrantSource](),
		"Policy":                                        openapi31.StructType[iamv1.Policy](),
		"PolicyDocument":                                openapi31.StructType[iamv1.PolicyDocument](),
		"PolicyStatement":                               openapi31.StructType[iamv1.PolicyStatement](),
		"PolicyCondition":                               openapi31.StructType[iamv1.PolicyCondition](),
		"PolicyResourceSelector":                        openapi31.StructType[iamv1.PolicyResourceSelector](),
		"PolicyVersion":                                 openapi31.StructType[iamv1.PolicyVersion](),
		"PolicyCompilation":                             openapi31.StructType[iamv1.PolicyCompilation](),
		"PolicyResolvedStatement":                       openapi31.StructType[iamv1.PolicyResolvedStatement](),
		"PolicyVersionReference":                        openapi31.StructType[iamv1.PolicyVersionReference](),
		"UserPermissionBoundary":                        openapi31.StructType[iamv1.UserPermissionBoundary](),
		"SetUserPermissionBoundaryRequest":              openapi31.StructType[iamv1.SetUserPermissionBoundaryRequest](),
		"RemoveUserPermissionBoundaryRequest":           openapi31.StructType[iamv1.RemoveUserPermissionBoundaryRequest](),
		"PolicyDetail":                                  openapi31.StructType[iamv1.PolicyDetail](),
		"CreatePolicyRequest":                           openapi31.StructType[iamv1.CreatePolicyRequest](),
		"PolicyVersionDetail":                           openapi31.StructType[iamv1.PolicyVersionDetail](),
		"PolicyVersionList":                             openapi31.StructType[iamv1.PolicyVersionList](),
		"CreatePolicyVersionRequest":                    openapi31.StructType[iamv1.CreatePolicyVersionRequest](),
		"SetDefaultPolicyVersionRequest":                openapi31.StructType[iamv1.SetDefaultPolicyVersionRequest](),
		"UpdatePolicyRequest":                           openapi31.StructType[iamv1.UpdatePolicyRequest](),
		"DeletePolicyRequest":                           openapi31.StructType[iamv1.DeletePolicyRequest](),
		"DeletePolicyVersionRequest":                    openapi31.StructType[iamv1.DeletePolicyVersionRequest](),
		"PolicyAttachmentTarget":                        openapi31.StructType[iamv1.PolicyAttachmentTarget](),
		"CreatePolicyAttachmentRequest":                 openapi31.StructType[iamv1.CreatePolicyAttachmentRequest](),
		"RevokePolicyAttachmentRequest":                 openapi31.StructType[iamv1.RevokePolicyAttachmentRequest](),
		"Session":                                       openapi31.StructType[iamv1.Session](),
		"SessionList":                                   openapi31.StructType[iamv1.SessionList](),
		"RevokeOwnSessionResponse":                      openapi31.StructType[iamv1.RevokeOwnSessionResponse](),
		"RevokeOtherSessionsResponse":                   openapi31.StructType[iamv1.RevokeOtherSessionsResponse](),
		"InitialOrganization":                           openapi31.StructType[iamv1.InitialOrganization](),
		"InitialAdministrator":                          openapi31.StructType[iamv1.InitialAdministrator](),
		"BootstrapServiceCredential":                    openapi31.StructType[iamv1.BootstrapServiceCredential](),
		"BootstrapDocument":                             openapi31.StructType[iamv1.BootstrapDocument](),
		"BootstrapStatus":                               openapi31.StructType[iamv1.BootstrapStatus](),
		"ServiceIdentity":                               openapi31.StructType[iamv1.ServiceIdentity](),
		"ResolveAuditProducerRequest":                   openapi31.StructType[iamv1.ResolveAuditProducerRequest](),
		"AuditProducerAuthorization":                    openapi31.StructType[iamv1.AuditProducerAuthorization](),
		"LoginRequest":                                  openapi31.StructType[iamv1.LoginRequest](),
		"VerifyAuthenticationChallengeRequest":          openapi31.StructType[iamv1.VerifyAuthenticationChallengeRequest](),
		"ChallengePasswordChangeRequest":                openapi31.StructType[iamv1.ChallengePasswordChangeRequest](),
		"ChallengePasswordChangeResponse":               openapi31.StructType[iamv1.ChallengePasswordChangeResponse](),
		"LoginResponse":                                 openapi31.StructType[iamv1.LoginResponse](),
		"AuthenticationChallenge":                       openapi31.StructType[iamv1.AuthenticationChallenge](),
		"AccountMFASettings":                            openapi31.StructType[iamv1.AccountMFASettings](),
		"AccountSecuritySettings":                       openapi31.StructType[iamv1.AccountSecuritySettings](),
		"SecuritySettingsUpdateIntent":                  openapi31.StructType[iamv1.SecuritySettingsUpdateIntent](),
		"UpdateAccountSecuritySettingsRequest":          openapi31.StructType[iamv1.UpdateAccountSecuritySettingsRequest](),
		"AccountSecuritySettingsChange":                 openapi31.StructType[iamv1.AccountSecuritySettingsChange](),
		"UpdateAccountSecuritySettingsResponse":         openapi31.StructType[iamv1.UpdateAccountSecuritySettingsResponse](),
		"AuthenticatorState":                            openapi31.StructType[iamv1.AuthenticatorState](),
		"TOTPEnrollment":                                openapi31.StructType[iamv1.TOTPEnrollment](),
		"TOTPProvisioning":                              openapi31.StructType[iamv1.TOTPProvisioning](),
		"StartTOTPEnrollmentRequest":                    openapi31.StructType[iamv1.StartTOTPEnrollmentRequest](),
		"StartTOTPEnrollmentResponse":                   openapi31.StructType[iamv1.StartTOTPEnrollmentResponse](),
		"ConfirmTOTPEnrollmentRequest":                  openapi31.StructType[iamv1.ConfirmTOTPEnrollmentRequest](),
		"ConfirmTOTPEnrollmentResponse":                 openapi31.StructType[iamv1.ConfirmTOTPEnrollmentResponse](),
		"AuthenticatorRecovery":                         openapi31.StructType[iamv1.AuthenticatorRecovery](),
		"StartAuthenticatorRecoveryRequest":             openapi31.StructType[iamv1.StartAuthenticatorRecoveryRequest](),
		"StartAuthenticatorRecoveryResponse":            openapi31.StructType[iamv1.StartAuthenticatorRecoveryResponse](),
		"InspectAuthenticatorRecoveryRequest":           openapi31.StructType[iamv1.InspectAuthenticatorRecoveryRequest](),
		"ConfirmAuthenticatorRecoveryResponse":          openapi31.StructType[iamv1.ConfirmAuthenticatorRecoveryResponse](),
		"StepUp":                                        openapi31.StructType[iamv1.StepUp](),
		"StartStepUpRequest":                            openapi31.StructType[iamv1.StartStepUpRequest](),
		"VerifyStepUpRequest":                           openapi31.StructType[iamv1.VerifyStepUpRequest](),
		"RegenerateRecoveryCodesRequest":                openapi31.StructType[iamv1.RegenerateRecoveryCodesRequest](),
		"RecoveryCodeRegeneration":                      openapi31.StructType[iamv1.RecoveryCodeRegeneration](),
		"RegenerateRecoveryCodesResponse":               openapi31.StructType[iamv1.RegenerateRecoveryCodesResponse](),
		"LogoutRequest":                                 openapi31.StructType[iamv1.LogoutRequest](),
		"LogoutResponse":                                openapi31.StructType[iamv1.LogoutResponse](),
		"ChangePasswordRequest":                         openapi31.StructType[iamv1.ChangePasswordRequest](),
		"ChangePasswordResponse":                        openapi31.StructType[iamv1.ChangePasswordResponse](),
		"NotificationContact":                           openapi31.StructType[iamv1.NotificationContact](),
		"NotificationContactVerification":               openapi31.StructType[iamv1.NotificationContactVerification](),
		"NotificationDeliveryObservation":               openapi31.StructType[iamv1.NotificationDeliveryObservation](),
		"StartNotificationContactVerificationRequest":   openapi31.StructType[iamv1.StartNotificationContactVerificationRequest](),
		"ConfirmNotificationContactVerificationRequest": openapi31.StructType[iamv1.ConfirmNotificationContactVerificationRequest](),
		"CreateUserRequest":                             openapi31.StructType[iamv1.CreateUserRequest](),
		"AccessKey":                                     openapi31.StructType[iamv1.AccessKey](),
		"AccessKeyAccess":                               openapi31.StructType[iamv1.AccessKeyAccess](),
		"AccessKeyList":                                 openapi31.StructType[iamv1.AccessKeyList](),
		"CreateAccessKeyRequest":                        openapi31.StructType[iamv1.CreateAccessKeyRequest](),
		"CreateAccessKeyResponse":                       openapi31.StructType[iamv1.CreateAccessKeyResponse](),
		"SetAccessKeyStatusRequest":                     openapi31.StructType[iamv1.SetAccessKeyStatusRequest](),
		"SetAccessKeyStatusResponse":                    openapi31.StructType[iamv1.SetAccessKeyStatusResponse](),
		"DeleteAccessKeyRequest":                        openapi31.StructType[iamv1.DeleteAccessKeyRequest](),
		"AccessKeyDeletion":                             openapi31.StructType[iamv1.AccessKeyDeletion](),
		"DeleteAccessKeyResponse":                       openapi31.StructType[iamv1.DeleteAccessKeyResponse](),
		"RootIdentity":                                  openapi31.StructType[iamv1.RootIdentity](),
		"Account":                                       openapi31.StructType[iamv1.Account](),
		"User":                                          openapi31.StructType[iamv1.User](),
		"Group":                                         openapi31.StructType[iamv1.Group](),
		"GroupMembership":                               openapi31.StructType[iamv1.GroupMembership](),
		"TrustPolicyDocument":                           openapi31.StructType[iamv1.TrustPolicyDocument](),
		"TrustPolicyStatement":                          openapi31.StructType[iamv1.TrustPolicyStatement](),
		"TrustPrincipal":                                openapi31.StructType[iamv1.TrustPrincipal](),
		"RoleTrustVersion":                              openapi31.StructType[iamv1.RoleTrustVersion](),
		"Role":                                          openapi31.StructType[iamv1.Role](),
		"RoleTag":                                       openapi31.StructType[iamv1.RoleTag](),
		"RoleListing":                                   openapi31.StructType[iamv1.RoleListing](),
		"RoleList":                                      openapi31.StructType[iamv1.RoleList](),
		"RoleAccess":                                    openapi31.StructType[iamv1.RoleAccess](),
		"RolePermissionBoundary":                        openapi31.StructType[iamv1.RolePermissionBoundary](),
		"SetRolePermissionBoundaryRequest":              openapi31.StructType[iamv1.SetRolePermissionBoundaryRequest](),
		"RemoveRolePermissionBoundaryRequest":           openapi31.StructType[iamv1.RemoveRolePermissionBoundaryRequest](),
		"RoleTrustVersionList":                          openapi31.StructType[iamv1.RoleTrustVersionList](),
		"CreateRoleRequest":                             openapi31.StructType[iamv1.CreateRoleRequest](),
		"AssumeRoleRequest":                             openapi31.StructType[iamv1.AssumeRoleRequest](),
		"AssumeRoleResponse":                            openapi31.StructType[iamv1.AssumeRoleResponse](),
		"RoleSession":                                   openapi31.StructType[iamv1.RoleSession](),
		"RoleSessionListing":                            openapi31.StructType[iamv1.RoleSessionListing](),
		"RoleSessionList":                               openapi31.StructType[iamv1.RoleSessionList](),
		"RoleSessionAccess":                             openapi31.StructType[iamv1.RoleSessionAccess](),
		"RevokeRoleSessionResponse":                     openapi31.StructType[iamv1.RevokeRoleSessionResponse](),
		"CurrentRoleIdentity":                           openapi31.StructType[iamv1.CurrentRoleIdentity](),
		"RoleAccountDisplay":                            openapi31.StructType[iamv1.RoleAccountDisplay](),
		"RoleDisplay":                                   openapi31.StructType[iamv1.RoleDisplay](),
		"RoleSourceUserDisplay":                         openapi31.StructType[iamv1.RoleSourceUserDisplay](),
		"AssumableRole":                                 openapi31.StructType[iamv1.AssumableRole](),
		"AssumableRoleList":                             openapi31.StructType[iamv1.AssumableRoleList](),
		"RevokeRoleSessionRequest":                      openapi31.StructType[iamv1.RevokeRoleSessionRequest](),
		"UpdateRoleRequest":                             openapi31.StructType[iamv1.UpdateRoleRequest](),
		"SetRoleStatusRequest":                          openapi31.StructType[iamv1.SetRoleStatusRequest](),
		"SetRoleTrustPolicyRequest":                     openapi31.StructType[iamv1.SetRoleTrustPolicyRequest](),
		"DeleteRoleRequest":                             openapi31.StructType[iamv1.DeleteRoleRequest](),
		"RoleDeletion":                                  openapi31.StructType[iamv1.RoleDeletion](),
		"ActionCapability":                              openapi31.StructType[iamv1.ActionCapability](),
		"CurrentIdentity":                               openapi31.StructType[iamv1.CurrentIdentity](),
		"PolicyList":                                    openapi31.StructType[iamv1.PolicyList](),
		"UserAccess":                                    openapi31.StructType[iamv1.UserAccess](),
		"UserList":                                      openapi31.StructType[iamv1.UserList](),
		"GroupAccess":                                   openapi31.StructType[iamv1.GroupAccess](),
		"GroupList":                                     openapi31.StructType[iamv1.GroupList](),
		"GroupMembershipAccess":                         openapi31.StructType[iamv1.GroupMembershipAccess](),
		"GroupMembershipList":                           openapi31.StructType[iamv1.GroupMembershipList](),
		"AccountAccess":                                 openapi31.StructType[iamv1.AccountAccess](),
		"AccountList":                                   openapi31.StructType[iamv1.AccountList](),
		"CreateAccountRequest":                          openapi31.StructType[iamv1.CreateAccountRequest](),
		"SetAccountAliasRequest":                        openapi31.StructType[iamv1.SetAccountAliasRequest](),
		"SetUserStatusRequest":                          openapi31.StructType[iamv1.SetUserStatusRequest](),
		"UpdateUserRequest":                             openapi31.StructType[iamv1.UpdateUserRequest](),
		"DeleteUserRequest":                             openapi31.StructType[iamv1.DeleteUserRequest](),
		"UserDeletion":                                  openapi31.StructType[iamv1.UserDeletion](),
		"CreateGroupRequest":                            openapi31.StructType[iamv1.CreateGroupRequest](),
		"UpdateGroupRequest":                            openapi31.StructType[iamv1.UpdateGroupRequest](),
		"DeleteGroupRequest":                            openapi31.StructType[iamv1.DeleteGroupRequest](),
		"GroupDeletion":                                 openapi31.StructType[iamv1.GroupDeletion](),
		"CreateGroupMembershipRequest":                  openapi31.StructType[iamv1.CreateGroupMembershipRequest](),
		"RemoveGroupMembershipRequest":                  openapi31.StructType[iamv1.RemoveGroupMembershipRequest](),
		"SetAccountStatusRequest":                       openapi31.StructType[iamv1.SetAccountStatusRequest](),
		"RecoverRootCredentialsRequest":                 openapi31.StructType[iamv1.RecoverRootCredentialsRequest](),
		"ResetUserPasswordRequest":                      openapi31.StructType[iamv1.ResetUserPasswordRequest](),
		"RevokeSessionRequest":                          openapi31.StructType[iamv1.RevokeSessionRequest](),
		"Revocation":                                    openapi31.StructType[iamv1.Revocation](),
		"AuthorizationRequest":                          openapi31.StructType[iamv1.AuthorizationRequest](),
		"AuthorizationDecision":                         openapi31.StructType[iamv1.AuthorizationDecision](),
		"AccessKeyAuthorization":                        openapi31.StructType[iamv1.AccessKeyAuthorization](),
		"AccessKeyHTTPRequest":                          openapi31.StructType[iamv1.AccessKeyHTTPRequest](),
		"Readiness":                                     openapi31.StructType[iamv1.Readiness](),
		"Problem":                                       openapi31.StructType[iamv1.Problem](),
	}
}

func fieldOverlay(owner string, field reflect.StructField, jsonName string, base object) object {
	if jsonName == "expectedResourceVersion" && (owner == "SecuritySettingsUpdateIntent" || owner == "UpdateAccountSecuritySettingsRequest" || owner == "AccountSecuritySettingsChange") {
		return object{"type": "integer", "minimum": 1, "maximum": uint64(9007199254740990)}
	}
	if jsonName == "factorRevision" || jsonName == "expectedFactorRevision" {
		if owner == "StepUp" || owner == "StartStepUpRequest" || owner == "RegenerateRecoveryCodesRequest" || owner == "RecoveryCodeRegeneration" {
			return object{"type": "integer", "minimum": 2, "maximum": uint64(9007199254740991)}
		}
		maximum := uint64(9007199254740990)
		if owner == "AuthenticatorState" {
			maximum++
		}
		return object{"type": "integer", "minimum": 1, "maximum": maximum}
	}
	if owner == "AuthenticatorState" && jsonName == "enrollmentState" {
		return object{"enum": []string{"NEVER_BOUND", "BOUND", "RECOVERY_REQUIRED"}}
	}
	if owner == "TOTPEnrollment" && jsonName == "state" {
		return object{"enum": []string{"PENDING", "CONFIRMED", "CANCELLED", "EXPIRED"}}
	}
	if owner == "AuthenticatorRecovery" && jsonName == "state" {
		return object{"enum": []string{"STARTED", "COMPLETED", "SUPERSEDED", "EXPIRED"}}
	}
	if (owner == "StepUp" || owner == "StartStepUpRequest") && jsonName == "operation" {
		return object{"const": string(iamv1.StepUpRegenerateRecoveryCodes)}
	}
	if owner == "StepUp" && jsonName == "state" {
		return object{"enum": []string{"PENDING", "PROVED", "CONSUMED", "EXPIRED"}}
	}
	if (owner == "StartTOTPEnrollmentResponse" || owner == "RegenerateRecoveryCodesResponse" || owner == "UpdateAccountSecuritySettingsResponse") && jsonName == "outcome" {
		return object{"enum": []string{"APPLIED", "EQUAL_REPLAY"}}
	}
	if owner == "ConfirmTOTPEnrollmentResponse" || owner == "ConfirmAuthenticatorRecoveryResponse" || owner == "RegenerateRecoveryCodesResponse" {
		if jsonName == "nextStep" {
			return object{"const": "REAUTHENTICATE"}
		}
		if jsonName == "recoveryCodes" {
			return object{"type": "array", "minItems": 10, "maxItems": 10, "uniqueItems": true, "items": object{"type": "string", "minLength": 1, "readOnly": true}}
		}
	}
	if owner == "AuthenticationChallenge" {
		switch jsonName {
		case "purpose":
			return object{"enum": []string{"LOGIN", "RECOVERY"}}
		case "nextStep":
			return object{"enum": []string{"TOTP", "PASSWORD_CHANGE", "RECOVER", "ENROLLMENT"}}
		}
	}
	if owner == "ChallengePasswordChangeResponse" && jsonName == "nextStep" {
		return object{"const": "REAUTHENTICATE"}
	}
	if (owner == "NotificationContact" || owner == "NotificationContactVerification" || owner == "StartNotificationContactVerificationRequest") && jsonName == "email" {
		return object{"type": "string", "minLength": 3, "maxLength": 254, "description": "One ASCII dot-atom address and canonical lower-case DNS domain. No display name, address list, literal IP, SMTPUTF8 or normalization of local-part case. Authoritative syntax validation applies."}
	}
	if owner == "NotificationContact" {
		switch jsonName {
		case "state":
			return object{"type": "string", "enum": []string{"NONE", "VERIFIED"}}
		case "resourceVersion":
			return object{"type": "integer", "minimum": 0, "maximum": 9007199254740991}
		case "pendingVerificationId":
			return openapi31.Ref("ID")
		}
	}
	if owner == "NotificationContactVerification" && jsonName == "state" {
		return object{"type": "string", "enum": []string{"PENDING", "VERIFIED", "CANCELLED", "EXPIRED"}}
	}
	if owner == "ConfirmNotificationContactVerificationRequest" && jsonName == "code" {
		return object{"type": "string", "pattern": "^[0-9]{8}$", "minLength": 8, "maxLength": 8, "writeOnly": true}
	}
	if owner == "NotificationDeliveryObservation" {
		switch jsonName {
		case "state":
			return object{"type": "string", "enum": []string{"PENDING", "IN_FLIGHT", "RETRY_WAIT", "ACCEPTED", "FAILED", "EXPIRED"}}
		case "attempts":
			return object{"type": "integer", "minimum": 0, "maximum": 5}
		case "lastOutcome":
			return object{"type": "string", "enum": []string{"ACCEPTED", "REJECTED", "UNKNOWN", "UNAVAILABLE"}}
		case "lastSmtpCode":
			return object{"type": "integer", "anyOf": []any{object{"const": 250}, object{"minimum": 400, "maximum": 599}}}
		}
	}
	if owner == "AccessKeyHTTPRequest" {
		switch jsonName {
		case "method":
			base = object{"type": "string", "enum": []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}}
		case "scheme":
			base = object{"type": "string", "enum": []string{"http", "https"}}
		case "authority":
			base = object{"type": "string", "minLength": 1, "maxLength": 255, "description": "Exact canonical lower-case HTTP authority; IAM additionally validates DNS/IP and port encoding."}
		case "escapedPath":
			base = object{"type": "string", "minLength": 1, "maxLength": 2048, "pattern": "^/", "description": "Canonical RFC3986 escaped path; ambiguous or aliased encodings are rejected, not normalized."}
		case "rawQuery":
			base = object{"type": "string", "maxLength": 4096, "description": "At most 64 canonical name=value items ordered by encoded name, preserving repeated-name value order."}
		case "contentType":
			base = object{"type": "string", "enum": []string{"", "application/json"}}
		case "idempotencyKey", "ifMatch":
			base = object{"type": "string", "maxLength": 128, "pattern": "^[ -~]*$", "description": "Exact covered header, including empty; leading/trailing whitespace is invalid."}
		case "bodyDigest":
			base = object{"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
		}
	}
	if owner == "AccessKeyAuthorization" && jsonName == "signedRequestDigest" {
		base = object{"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
	}
	if owner == "CreateAccessKeyResponse" || owner == "SetAccessKeyStatusResponse" || owner == "DeleteAccessKeyResponse" {
		if jsonName == "outcome" {
			base = object{"type": "string", "enum": []string{"APPLIED", "EQUAL_REPLAY"}}
		}
		if jsonName == "key" {
			base["properties"] = object{"resourceVersion": object{"minimum": 2}}
			if owner == "CreateAccessKeyResponse" {
				base["properties"] = object{"resourceVersion": object{"const": 1}, "status": object{"const": string(iamv1.AccessKeyEnabled)}}
			}
		}
	}
	if (owner == "AccessKeyList" || owner == "AccessKeyAccess") && jsonName == "capabilities" {
		base["minItems"], base["maxItems"] = 3, 3
		base["uniqueItems"] = true
		if owner == "AccessKeyList" {
			base["minItems"], base["maxItems"] = 1, 1
			base["items"] = object{"allOf": []any{openapi31.Ref("ActionCapability"), object{"properties": object{
				"action":   object{"const": string(iamv1.ActionIAMAccessKeyCreate)},
				"resource": object{"properties": object{"kind": object{"const": string(iamv1.ResourceUser)}}},
			}}}}
		} else {
			var actions []any
			for _, action := range []iamv1.Action{iamv1.ActionIAMAccessKeyRead, iamv1.ActionIAMAccessKeySetStatus, iamv1.ActionIAMAccessKeyDelete} {
				actions = append(actions, object{"contains": object{"properties": object{
					"action":   object{"const": string(action)},
					"resource": object{"properties": object{"kind": object{"const": string(iamv1.ResourceAccessKey)}}},
				}}, "minContains": 1, "maxContains": 1})
			}
			base["allOf"] = actions
		}
	}
	if owner == "AccessKeyList" && jsonName == "items" {
		base["maxItems"], base["uniqueItems"] = iamv1.MaxUserAccessKeys, true
	}
	if owner == "AssumeRoleRequest" {
		switch jsonName {
		case "durationSeconds":
			base = object{"type": "integer", "minimum": iamv1.MinRoleSessionDurationSeconds, "maximum": iamv1.MaxRoleSessionDurationSeconds,
				"default": iamv1.DefaultRoleSessionDurationSeconds}
		case "sessionPolicy":
			base = openapi31.Ref("PolicyDocument")
			base["type"] = "object"
			base["properties"] = object{"scope": object{"const": string(iamv1.AuthorityScopeTenant)}}
		}
	}
	if owner == "Role" || owner == "CreateRoleRequest" || owner == "UpdateRoleRequest" || owner == "RoleDeletion" || owner == "RoleDisplay" || owner == "AssumableRole" {
		switch jsonName {
		case "name":
			base["minLength"], base["maxLength"] = 1, 64
		case "description":
			base["maxLength"] = 512
		case "tags":
			base["maxItems"], base["uniqueItems"] = 50, true
			base["description"] = "Literal metadata only. UTF-8 limits, unique keys and the 4096-byte aggregate name/description/tag budget require authoritative validation."
		case "maxSessionDurationSeconds":
			base = object{"type": "integer", "minimum": iamv1.MinRoleSessionDurationSeconds, "maximum": iamv1.MaxRoleSessionDurationSeconds}
			if owner == "CreateRoleRequest" {
				base["default"] = iamv1.DefaultRoleSessionDurationSeconds
			}
		}
	}
	if owner == "AssumableRole" {
		switch jsonName {
		case "status":
			base = object{"const": string(iamv1.RoleActive)}
		case "capability":
			base["properties"] = object{"action": object{"const": string(iamv1.ActionIAMRoleAssume)},
				"resource":  object{"properties": object{"kind": object{"const": string(iamv1.ResourceRole)}}},
				"available": object{"const": true}, "restrictionReason": false}
		}
	}
	if owner == "AssumableRoleList" && jsonName == "items" {
		base["maxItems"], base["uniqueItems"] = iamv1.RoleDiscoveryPageSize, true
		base["description"] = "Only eligible roles from a bounded candidate window. Empty items may still have nextAfter; no total-count or page-count semantics."
	}
	if owner == "RoleSessionList" && jsonName == "items" {
		base["maxItems"], base["uniqueItems"] = iamv1.DirectoryPageSize, true
		base["description"] = "One bounded candidate window; an empty filtered page may still have nextAfter. No total count."
	}
	if owner == "RoleSessionListing" && jsonName == "revokeCapability" {
		base["properties"] = object{"action": object{"const": string(iamv1.ActionIAMRoleSessionRevoke)},
			"resource": object{"properties": object{"kind": object{"const": string(iamv1.ResourceRoleSession)}}}}
	}
	if owner == "RevokeRoleSessionResponse" {
		if jsonName == "outcome" {
			base = object{"type": "string", "enum": []string{"APPLIED", "EQUAL_REPLAY"}}
		}
		if jsonName == "session" {
			base["properties"] = object{"status": object{"const": string(iamv1.SessionRevoked)}}
		}
	}
	if owner == "CurrentRoleIdentity" && jsonName == "session" {
		base["properties"] = object{"status": object{"const": string(iamv1.SessionActive)}, "revokedAt": false}
	}
	if owner == "RoleTag" {
		if jsonName == "key" {
			base["minLength"], base["maxLength"] = 1, 64
		}
		if jsonName == "value" {
			base["maxLength"] = 256
		}
	}
	if (owner == "RoleList" || owner == "RoleTrustVersionList") && jsonName == "items" {
		base["maxItems"] = iamv1.DirectoryPageSize
	}
	if (owner == "RoleListing" || owner == "RoleAccess") && jsonName == "capabilities" {
		base["minItems"], base["maxItems"] = 9, 9
		if owner == "RoleAccess" {
			// Nine role-management capabilities, one exact Assume capability,
			// and at most one revoke capability for each of 256 attachments.
			base["minItems"], base["maxItems"] = 10, 9+1+256
		}
	}
	if owner == "TrustPolicyDocument" {
		switch jsonName {
		case "languageVersion":
			base = object{"const": iamv1.TrustPolicyLanguageVersion}
		case "statements":
			base["maxItems"], base["uniqueItems"] = iamv1.MaxTrustPolicyStatements, true
			base["description"] = "Empty means no trusted carriers. SID uniqueness, total encoded byte budget and account membership require authoritative validation."
		}
	}
	if owner == "TrustPolicyStatement" {
		switch jsonName {
		case "sid":
			base = openapi31.Ref("ID")
		case "principals":
			base["minItems"], base["maxItems"], base["uniqueItems"] = 1, iamv1.MaxTrustStatementPrincipals, true
		}
	}
	if owner == "TrustPrincipal" && jsonName == "type" {
		base = object{"const": string(iamv1.PrincipalUser)}
	}
	if owner == "AuthorizationProfileList" && jsonName == "items" {
		base["minItems"], base["maxItems"] = 1, iamv1.MaxAuthorizationProfileListItems
	}
	if owner == "AuthorizationProfile" {
		switch jsonName {
		case "callingService":
			base = object{"type": "string", "pattern": `^[A-Z][A-Z0-9_-]{0,63}$`, "maxLength": 64}
		case "actions":
			base["minItems"], base["maxItems"] = 1, iamv1.MaxAuthorizationProfileActions
		}
	}
	if owner == "AuthorizationProfileAction" {
		switch jsonName {
		case "action":
			base = object{"type": "string", "pattern": `^[a-z][a-z0-9_-]{0,63}(\.[a-z][a-z0-9_-]{0,63}){1,4}$`, "maxLength": 128}
		case "resourceKind", "resultResourceKind":
			base = object{"type": "string", "pattern": `^[A-Z][A-Z0-9_-]{0,63}$`, "maxLength": 64}
		case "resourceShapes":
			base["minItems"], base["maxItems"] = 1, 3
		case "subjectTypes":
			base["minItems"], base["maxItems"], base["uniqueItems"] = 1, 3, true
		case "userAuthenticationMethods":
			base["minItems"], base["maxItems"], base["uniqueItems"] = 1, 2, true
		case "conditions":
			base["maxItems"] = 3
			base = object{"anyOf": []any{object{"type": "null"}, base}}
		}
	}
	if (owner == "Policy" || owner == "CreatePolicyRequest" || owner == "UpdatePolicyRequest" || owner == "UpdateUserRequest" ||
		owner == "RoleAccountDisplay" || owner == "RoleSourceUserDisplay") && jsonName == "displayName" {
		base["minLength"], base["maxLength"] = 1, 128
	}
	if (owner == "Group" || owner == "GroupDeletion" || owner == "CreateGroupRequest" || owner == "UpdateGroupRequest") && jsonName == "name" {
		base["minLength"], base["maxLength"] = 1, 64
	}
	if (owner == "Group" || owner == "CreateGroupRequest" || owner == "UpdateGroupRequest") && jsonName == "description" {
		base["minLength"], base["maxLength"] = 0, 512
	}
	if jsonName == "contentDigest" {
		base = object{"type": "string", "pattern": `^sha256:[0-9a-f]{64}$`}
	}
	if jsonName == "loginName" || jsonName == "administratorLoginName" || jsonName == "rootLoginName" {
		base = object{"type": "string", "pattern": `^[a-z][a-z0-9._-]{2,63}$`, "minLength": 3, "maxLength": 64}
		if owner == "LoginRequest" {
			base = object{"type": "string", "pattern": `^[a-z][a-z0-9._-]{2,63}(@[A-Za-z0-9][A-Za-z0-9._:-]{0,127})?$`, "minLength": 3, "maxLength": 193}
		}
	}
	if jsonName == "alias" {
		base = object{"type": "string", "pattern": `^[a-z][a-z0-9-]{1,61}[a-z0-9]$`, "minLength": 3, "maxLength": 63}
	}
	if jsonName == "loginAlias" {
		base = object{"anyOf": []any{object{"type": "null"}, object{"type": "string", "pattern": `^[a-z][a-z0-9-]{1,61}[a-z0-9]$`, "minLength": 3, "maxLength": 63}}}
	}
	if jsonName == "nextAfter" || (owner == "SessionList" && jsonName == "nextCursor") {
		base = pageCursorSchema()
		if owner == "AssumableRoleList" {
			base = roleDiscoveryCursorSchema()
		}
	}
	if owner == "CreatePolicyAttachmentRequest" && jsonName == "target" {
		base = object{"allOf": []any{openapi31.Ref("PolicyAttachmentTarget"), object{"properties": object{"kind": object{"enum": []string{string(iamv1.PolicyTargetUser), string(iamv1.PolicyTargetGroup), string(iamv1.PolicyTargetRole)}}}}}}
	}
	if (owner == "UserList" || owner == "AccountList" || owner == "GroupList" || owner == "GroupMembershipList") && jsonName == "items" {
		base["maxItems"] = 100
	}
	if owner == "SessionList" && jsonName == "items" {
		base["maxItems"] = iamv1.DirectoryPageSize
		base["items"] = object{"allOf": []any{openapi31.Ref("Session"), object{"properties": object{
			"status": object{"const": string(iamv1.SessionActive)}, "revokedAt": false,
		}}}}
	}
	if (owner == "RevokeOwnSessionResponse" || owner == "RevokeOtherSessionsResponse") && jsonName == "outcome" {
		base = object{"type": "string", "enum": []string{"APPLIED", "EQUAL_REPLAY"}}
	}
	if owner == "RevokeOtherSessionsResponse" {
		if jsonName == "kind" {
			base = object{"const": "OtherSessionsRevocation"}
		}
		if jsonName == "revokedCount" {
			base = object{"type": "integer", "minimum": 0, "maximum": uint64(9007199254740991)}
		}
	}
	if owner == "PolicyList" && jsonName == "items" {
		base["maxItems"] = iamv1.MaxPolicyListItems
		base["items"] = object{"allOf": []any{base["items"], object{"properties": object{"status": object{"const": "ACTIVE"}}}}}
	}
	if owner == "CurrentIdentity" && jsonName == "policySources" {
		base["maxItems"] = 256
	}
	if (owner == "UserAccess" || owner == "GroupAccess" || owner == "RoleAccess") && jsonName == "policyAttachments" {
		base["maxItems"] = 256
		targetKind := string(iamv1.PolicyTargetUser)
		if owner == "GroupAccess" {
			targetKind = string(iamv1.PolicyTargetGroup)
		}
		if owner == "RoleAccess" {
			targetKind = string(iamv1.PolicyTargetRole)
		}
		base["items"] = object{"allOf": []any{openapi31.Ref("PolicyAttachment"), object{"properties": object{
			"revokedAt": false, "target": object{"properties": object{"kind": object{"const": targetKind}}},
		}}}}
	}
	if (owner == "CurrentIdentity" || owner == "UserAccess" || owner == "GroupAccess" || owner == "GroupMembershipAccess" || owner == "AccountAccess") && jsonName == "capabilities" {
		base["maxItems"] = map[string]int{"CurrentIdentity": 10, "UserAccess": 265, "GroupAccess": 262, "GroupMembershipAccess": 1, "AccountAccess": 2}[owner]
	}
	if field.Type.Name() == "Secret" {
		base["writeOnly"] = true
		if (owner == "LoginResponse" && (jsonName == "credential" || jsonName == "challengeCredential")) || (owner == "CreateAccessKeyResponse" && jsonName == "secret") || owner == "TOTPProvisioning" {
			delete(base, "writeOnly")
			base["readOnly"] = true
		}
	}
	if field.Type.Kind() == reflect.String &&
		(jsonName == "id" || strings.HasSuffix(jsonName, "Id")) {
		base = openapi31.Ref("ID")
	}
	if jsonName == "resourceVersion" || jsonName == "schemaVersion" || jsonName == "policyResourceVersion" || jsonName == "userResourceVersion" || jsonName == "accessKeyResourceVersion" || ((owner == "AuthorizationProfileReference" || owner == "AuthorizationProfile") && jsonName == "revision") {
		base["minimum"] = 1
		if owner == "AccessKeyDeletion" {
			base["minimum"] = 2
		}
		if jsonName == "accessKeyResourceVersion" {
			base["maximum"] = uint64(9007199254740990)
		}
	}
	if owner == "ChangePasswordRequest" && jsonName == "revokeOtherSessions" {
		base["default"] = true
		base["description"] = "Revoke other login sessions, preserving only the current bearer session after transactional revalidation. Omission defaults to true. Required password replacement always revokes other sessions; false can retain only already valid sessions of the same user."
	}
	return base
}

func applySemanticOverlays(schemas object) {
	schemas["AccountMFASettings"].(object)["description"] = "Explicit ordinary USER MFA requirement, not factor state, Session authentication facts or an exception for protected identities. Missing or null is invalid, never an inferred false."
	schemas["AccountSecuritySettings"].(object)["description"] = "Non-secret current-account configuration. Contract component only; this slice does not publish settings routes or permissions."
	schemas["SecuritySettingsUpdateIntent"].(object)["description"] = "Exact non-secret target for a future Session-held operation proof. Not a selector or permit; current StepUp operations do not yet accept it."
	schemas["UpdateAccountSecuritySettingsRequest"].(object)["description"] = "Replace the supported MFA configuration at one expected version using a proof held by the actual current Session. No identity selector, arbitrary patch or caller-controlled Session retention. Contract only; no runtime route in this slice."
	schemas["AccountSecuritySettingsChange"].(object)["description"] = "Immutable historical completion. Runtime validation additionally requires settings.resourceVersion == expectedResourceVersion + 1. settings.updatedAt is the original completion time, not observation time; requestId is not lookup authority."
	schemas["AccountSecuritySettingsChange"].(object)["properties"].(object)["callerSessionEnded"] = object{"type": "boolean", "description": "Whether this change ended its original calling Session. Never an instruction to end a later reader's current Session."}
	schemas["AccountSecuritySettingsChange"].(object)["allOf"] = []any{object{
		"if":   object{"properties": object{"callerSessionEnded": object{"const": true}}},
		"then": object{"properties": object{"settings": object{"properties": object{"mfa": object{"properties": object{"requiredForUsers": object{"const": true}}}}}}},
	}}
	schemas["UpdateAccountSecuritySettingsResponse"].(object)["description"] = "APPLIED and EQUAL_REPLAY carry the same original non-secret completion, not fresh authorization, current Session state or a credential."
	schemas["StepUp"].(object)["description"] = "Non-secret metadata bound to one operation and its original effective login Session. It is not a bearer, unlogged challenge or authorization permit. Runtime validation enforces the original 120-second lifetime and proof/consumption ordering; proving never extends expiry."
	schemas["StepUp"].(object)["oneOf"] = []any{
		object{"properties": object{"state": object{"const": "PENDING"}, "provedAt": false, "consumedAt": false}},
		object{"required": []string{"provedAt"}, "properties": object{"state": object{"const": "PROVED"}, "provedAt": object{"type": "string"}, "consumedAt": false}},
		object{"required": []string{"provedAt", "consumedAt"}, "properties": object{"state": object{"const": "CONSUMED"}, "provedAt": object{"type": "string"}, "consumedAt": object{"type": "string"}}},
		object{"properties": object{"state": object{"const": "EXPIRED"}, "provedAt": object{"type": "string"}, "consumedAt": false}},
	}
	schemas["RecoveryCodeRegeneration"].(object)["description"] = "Immutable non-secret observation of an original same-user recovery-code regeneration. It neither returns saved codes nor renews step-up authority."
	schemas["RegenerateRecoveryCodesResponse"].(object)["oneOf"] = []any{
		object{"required": []string{"recoveryCodes"}, "properties": object{"outcome": object{"const": "APPLIED"}, "recoveryCodes": object{"type": "array"}}},
		object{"properties": object{"outcome": object{"const": "EQUAL_REPLAY"}, "recoveryCodes": false}},
	}
	schemas["AuthenticationChallenge"].(object)["oneOf"] = []any{
		object{"properties": object{"purpose": object{"const": "LOGIN"}, "nextStep": object{"enum": []string{"TOTP", "PASSWORD_CHANGE", "RECOVER"}}}},
		object{"properties": object{"purpose": object{"const": "RECOVERY"}, "nextStep": object{"const": "ENROLLMENT"}}},
	}
	schemas["AuthenticatorRecovery"].(object)["description"] = "Non-secret observation of one purpose-limited recovery. Authoritative validation enforces at most five minutes and completion before expiry; metadata never conveys recovery authority."
	schemas["AuthenticatorRecovery"].(object)["oneOf"] = []any{
		object{"properties": object{"state": object{"const": "STARTED"}, "completedAt": false}},
		object{"required": []string{"completedAt"}, "properties": object{"state": object{"enum": []string{"COMPLETED", "SUPERSEDED", "EXPIRED"}}, "completedAt": object{"type": "string"}}},
	}
	schemas["StartAuthenticatorRecoveryResponse"].(object)["properties"].(object)["recovery"] = object{"allOf": []any{openapi31.Ref("AuthenticatorRecovery"), object{"properties": object{"state": object{"const": "STARTED"}}}}}
	schemas["StartAuthenticatorRecoveryResponse"].(object)["properties"].(object)["challenge"] = object{"allOf": []any{openapi31.Ref("AuthenticationChallenge"), object{"properties": object{"purpose": object{"const": "RECOVERY"}}}}}
	schemas["StartAuthenticatorRecoveryResponse"].(object)["description"] = "One-time recovery capability and provisioning. The challenge and recovery share the original absolute expiry. Never returned by inspection or a login response."
	schemas["ConfirmAuthenticatorRecoveryResponse"].(object)["properties"].(object)["recovery"] = object{"allOf": []any{openapi31.Ref("AuthenticatorRecovery"), object{"properties": object{"state": object{"const": "COMPLETED"}}}}}
	schemas["StartTOTPEnrollmentResponse"].(object)["oneOf"] = []any{
		object{"required": []string{"provisioning"}, "properties": object{"outcome": object{"const": "APPLIED"}, "provisioning": object{"type": "object"}, "enrollment": object{"properties": object{"state": object{"const": "PENDING"}}}}},
		object{"properties": object{"outcome": object{"const": "EQUAL_REPLAY"}, "provisioning": false}},
	}
	schemas["TOTPEnrollment"].(object)["oneOf"] = []any{
		object{"properties": object{"state": object{"const": "PENDING"}, "completedAt": false}},
		object{"required": []string{"completedAt"}, "properties": object{"state": object{"enum": []string{"CONFIRMED", "CANCELLED", "EXPIRED"}}, "completedAt": object{"type": "string"}}},
	}
	schemas["ConfirmTOTPEnrollmentResponse"].(object)["properties"].(object)["enrollment"] = object{"allOf": []any{openapi31.Ref("TOTPEnrollment"), object{"properties": object{"state": object{"const": "CONFIRMED"}}}}}
	schemas["AuthenticatorState"].(object)["oneOf"] = []any{
		object{"properties": object{"enrollmentState": object{"const": "NEVER_BOUND"}, "factorRevision": object{"const": 1}, "factorId": false}},
		object{"required": []string{"factorId"}, "properties": object{"enrollmentState": object{"const": "BOUND"}, "factorRevision": object{"minimum": 2}}},
		object{"properties": object{"enrollmentState": object{"const": "RECOVERY_REQUIRED"}}},
	}
	schemas["LoginResponse"].(object)["description"] = "Disjoint authentication result. A challenge is not a Session, bearer or authorization. Credential-bearing results require explicit encoding and no-store handling."
	schemas["LoginResponse"].(object)["oneOf"] = []any{
		object{"required": []string{"session", "credential", "mustChangePassword"}, "properties": object{
			"outcome":            object{"const": string(iamv1.LoginAuthenticated)},
			"session":            object{"type": "object", "properties": object{"status": object{"const": "ACTIVE"}, "revokedAt": false}},
			"mustChangePassword": object{"type": "boolean"}, "challenge": false, "challengeCredential": false,
		}},
		object{"required": []string{"challenge", "challengeCredential"}, "properties": object{
			"outcome": object{"const": string(iamv1.LoginChallengeRequired)}, "challenge": object{"type": "object", "properties": object{"purpose": object{"const": "LOGIN"}}},
			"session": false, "credential": false, "mustChangePassword": false,
		}},
	}
	schemas["NotificationContact"].(object)["oneOf"] = []any{
		object{"properties": object{"state": object{"const": "NONE"}, "resourceVersion": object{"const": 0}, "email": false, "verifiedAt": false}},
		object{"required": []string{"email", "verifiedAt"}, "properties": object{"state": object{"const": "VERIFIED"}, "resourceVersion": object{"minimum": 1}, "verifiedAt": object{"type": "string"}, "pendingVerificationId": false}},
	}
	schemas["NotificationContactVerification"].(object)["oneOf"] = []any{
		object{"properties": object{"state": object{"const": "PENDING"}, "completedAt": false}},
		object{"required": []string{"completedAt"}, "properties": object{"state": object{"enum": []string{"VERIFIED", "CANCELLED", "EXPIRED"}}, "completedAt": object{"type": "string"}}},
	}
	schemas["NotificationDeliveryObservation"].(object)["description"] = "Exact durable submission observation, never delivery/read proof. ACCEPTED requires lastOutcome ACCEPTED and exact SMTP 250. Retriable observations are UNKNOWN/UNAVAILABLE or 4xx; 5xx is terminal. Original intent, time and attempt progression are validated authoritatively."
	unobserved := object{"properties": object{"lastOutcome": false, "lastSmtpCode": false}}
	retryable := object{"required": []string{"lastOutcome"}, "oneOf": []any{
		object{"properties": object{"lastOutcome": object{"enum": []string{"UNKNOWN", "UNAVAILABLE"}}, "lastSmtpCode": false}},
		object{"required": []string{"lastSmtpCode"}, "properties": object{"lastOutcome": object{"const": "REJECTED"}, "lastSmtpCode": object{"minimum": 400, "maximum": 499}}},
	}}
	deliveryState := func(state string, minimum, maximum int) object {
		return object{"properties": object{"state": object{"const": state}, "attempts": object{"minimum": minimum, "maximum": maximum}}}
	}
	schemas["NotificationDeliveryObservation"].(object)["oneOf"] = []any{
		object{"allOf": []any{deliveryState("PENDING", 0, 0), unobserved}},
		object{"allOf": []any{deliveryState("IN_FLIGHT", 1, 1), unobserved}},
		object{"allOf": []any{deliveryState("IN_FLIGHT", 2, 5), retryable}},
		object{"allOf": []any{deliveryState("RETRY_WAIT", 1, 4), retryable}},
		object{"allOf": []any{deliveryState("ACCEPTED", 1, 5), object{"required": []string{"lastOutcome", "lastSmtpCode"},
			"properties": object{"lastOutcome": object{"const": "ACCEPTED"}, "lastSmtpCode": object{"const": 250}}}}},
		object{"allOf": []any{deliveryState("FAILED", 1, 5), object{"required": []string{"lastOutcome", "lastSmtpCode"},
			"properties": object{"lastOutcome": object{"const": "REJECTED"}, "lastSmtpCode": object{"minimum": 500, "maximum": 599}}}}},
		object{"allOf": []any{deliveryState("FAILED", 5, 5), retryable}},
		object{"allOf": []any{deliveryState("EXPIRED", 0, 0), unobserved}},
		object{"allOf": []any{deliveryState("EXPIRED", 1, 4), retryable}},
	}
	// The signed wire uses its explicit codec, not reflection of secret-bearing
	// implementation values. This schema is never a second transport encoder.
	schemas["AccessKeySignedRequest"] = object{"type": "object", "additionalProperties": false, "writeOnly": true,
		"required": []string{"apiVersion", "kind", "http", "authorization"}, "properties": object{
			"apiVersion": object{"const": iamv1.APIVersion}, "kind": object{"const": "AccessKeySignedRequest"},
			"http": openapi31.Ref("AccessKeyHTTPRequest"),
			"authorization": object{"type": "string", "writeOnly": true, "maxLength": iamv1.MaxAccessKeyAuthorizationBytes,
				"pattern": "^Matrix-HMAC-SHA256-V1 KeyId=[A-Za-z0-9][A-Za-z0-9._:-]{0,127},Installation=[A-Za-z0-9][A-Za-z0-9._:-]{0,127},Audience=[a-z][a-z0-9_-]{0,63},SignedAt=[1-9][0-9]{0,11},Nonce=[A-Za-z0-9_-]{21}[AQgw],Signature=[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"}}}
	schemas["AccessKeyAuthorizationRequest"] = object{"type": "object", "additionalProperties": false,
		"required": []string{"authorization", "signedRequest"}, "properties": object{
			"authorization": openapi31.Ref("AuthorizationRequest"), "signedRequest": openapi31.Ref("AccessKeySignedRequest")},
		"description": "Service-bound internal request only. No subject/account selector. The actual PEP binds HTTP data and audience; IAM verifies the MAC and database-time window. Duplicate nonce conflicts, never replays a permit."}
	schemas["AccessKeyAuthorization"].(object)["allOf"] = []any{object{
		"if": object{"properties": object{"decision": object{"properties": object{"allowed": object{"const": true}}}}},
		"then": object{"properties": object{"decision": object{"properties": object{"installationId": false, "subject": object{
			"required": []string{"accessKeyId"}, "properties": object{"type": object{"const": "USER"}}}}}}},
	}}
	schemas["AccessKeyHTTPRequest"].(object)["allOf"] = []any{object{
		"if":   object{"properties": object{"contentType": object{"const": ""}}},
		"then": object{"properties": object{"bodyDigest": object{"const": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}},
		"else": object{"properties": object{"bodyDigest": object{"not": object{"const": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}}},
	}}
	applyPolicyLanguageOverlays(schemas)
	applyAuthorizationProfileOverlays(schemas)
	// Immutable response content checks syntax, not today's action catalog.
	// Publication keeps the current declaration overlays above. This is an
	// inline projection of the same language, not another policy model.
	cloneSchema := func(value any) object {
		encoded, err := json.Marshal(value)
		if err != nil {
			panic(err)
		}
		var copied object
		if err := json.Unmarshal(encoded, &copied); err != nil {
			panic(err)
		}
		return copied
	}
	versionDocument := cloneSchema(schemas["PolicyDocument"])
	versionStatement := cloneSchema(schemas["PolicyStatement"])
	versionSelector := cloneSchema(schemas["PolicyResourceSelector"])
	delete(versionDocument, "allOf")
	delete(versionStatement, "allOf")
	versionSelector["properties"].(map[string]any)["kind"] = object{"type": "string", "maxLength": 64, "pattern": `^[A-Z][A-Z0-9_-]*$`}
	exactPolicyAction := object{"type": "string", "maxLength": 128, "pattern": `^[a-z][a-z0-9_-]{0,63}(\.[a-z][a-z0-9_-]{0,63}){1,4}$`}
	versionStatement["properties"].(map[string]any)["actions"].(map[string]any)["items"] = object{"anyOf": []any{exactPolicyAction,
		object{"type": "string", "maxLength": 128, "pattern": `^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_-]{0,63}\.\*$`}}}
	versionStatement["properties"].(map[string]any)["resources"].(map[string]any)["items"] = versionSelector
	versionDocument["properties"].(map[string]any)["statements"].(map[string]any)["items"] = versionStatement
	versionDocument["allOf"] = []any{object{
		"if": object{"properties": object{"scope": object{"not": object{"const": "TENANT"}}}},
		"then": object{"properties": object{"statements": object{"items": object{"properties": object{
			"actions":   object{"items": exactPolicyAction},
			"resources": object{"items": object{"properties": object{"match": object{"enum": []string{"EXACT", "ANY_IN_AUTHORITY"}}}}},
		}}}}},
	}}
	schemas["PolicyVersion"].(object)["properties"].(object)["document"] = versionDocument
	boundary := schemas["UserPermissionBoundary"].(object)
	boundary["required"] = []string{"apiVersion", "kind", "accountId", "userId", "resourceVersion", "policy"}
	boundary["properties"].(object)["policy"] = object{"anyOf": []any{object{"type": "null"}, openapi31.Ref("PolicyVersionReference")}}
	roleBoundary := schemas["RolePermissionBoundary"].(object)
	roleBoundary["required"] = []string{"apiVersion", "kind", "accountId", "roleId", "resourceVersion", "policy"}
	roleBoundary["properties"].(object)["policy"] = object{"anyOf": []any{object{"type": "null"}, openapi31.Ref("PolicyVersionReference")},
		"description": "Null closes role assumption; it never means an unlimited ceiling."}
	roleResponse := schemas["AssumeRoleResponse"].(object)
	keyResponse := schemas["CreateAccessKeyResponse"].(object)
	keyResponse["required"] = []string{"outcome", "key"}
	keyResponse["oneOf"] = []any{
		object{"required": []string{"secret"}, "properties": object{"outcome": object{"const": "APPLIED"}}},
		object{"properties": object{"outcome": object{"const": "EQUAL_REPLAY"}, "secret": false}},
	}
	schemas["AccessKey"].(object)["allOf"] = []any{object{
		"if":   object{"properties": object{"resourceVersion": object{"const": 1}}},
		"then": object{"properties": object{"status": object{"const": string(iamv1.AccessKeyEnabled)}}},
	}}
	schemas["Subject"].(object)["oneOf"] = []any{
		object{"required": []string{"roleSession"}, "properties": object{"type": object{"const": "ROLE"}, "accessKeyId": false}},
		object{"properties": object{"type": object{"const": "USER"}, "roleSession": false}},
		object{"properties": object{"type": object{"const": "SERVICE_ACCOUNT"}, "roleSession": false, "accessKeyId": false}},
	}
	roleResponse["required"] = []string{"outcome", "session"}
	roleResponse["oneOf"] = []any{
		object{"required": []string{"credential"}, "properties": object{"outcome": object{"const": "APPLIED"}, "session": object{"properties": object{"status": object{"const": "ACTIVE"}}}}},
		object{"properties": object{"outcome": object{"const": "EQUAL_REPLAY"}, "credential": false}},
	}
	schemas["RoleSession"].(object)["oneOf"] = []any{
		object{"properties": object{"status": object{"const": "ACTIVE"}, "revokedAt": false}},
		object{"required": []string{"revokedAt"}, "properties": object{"status": object{"const": "REVOKED"}}},
	}
	schemas["RoleSessionListing"].(object)["oneOf"] = []any{
		object{"properties": object{"lifecycle": object{"const": "UNREVOKED"}, "session": object{"properties": object{"status": object{"const": "ACTIVE"}}}}},
		object{"properties": object{"lifecycle": object{"const": "EXPIRED"}, "session": object{"properties": object{"status": object{"const": "ACTIVE"}}}, "revokeCapability": object{"properties": object{"available": object{"const": false}}}}},
		object{"properties": object{"lifecycle": object{"const": "REVOKED"}, "session": object{"properties": object{"status": object{"const": "REVOKED"}}}, "revokeCapability": object{"properties": object{"available": object{"const": false}}}}},
	}
	schemas["PolicyVersion"].(object)["oneOf"] = []any{
		object{"properties": object{"contractVersion": object{"const": iamv1.PolicyVersionLegacyContract}, "compilation": false,
			"document": object{"properties": object{"statements": object{"items": object{"properties": object{"actions": object{"items": exactPolicyAction}}}}}}}},
		object{"required": []string{"compilation"}, "properties": object{"contractVersion": object{"const": iamv1.PolicyVersionCompiledContract}}},
	}
	compiled := schemas["PolicyCompilation"].(object)["properties"].(object)
	compiled["compilationVersion"] = object{"const": iamv1.PolicyCompilationVersion}
	compiled["profiles"] = object{"type": "array", "minItems": 1, "maxItems": iamv1.MaxPolicyCompilationProfiles, "uniqueItems": true, "items": openapi31.Ref("AuthorizationProfileReference")}
	compiled["resolvedStatements"] = object{"type": "array", "minItems": 1, "maxItems": iamv1.MaxPolicyStatements, "uniqueItems": true, "items": openapi31.Ref("PolicyResolvedStatement")}
	resolved := schemas["PolicyResolvedStatement"].(object)["properties"].(object)
	resolved["sid"] = openapi31.Ref("ID")
	resolved["actions"] = object{"type": "array", "minItems": 1, "maxItems": iamv1.MaxStatementActions, "uniqueItems": true,
		"items": object{"type": "string", "minLength": 1, "maxLength": 128, "pattern": `^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*){1,4}$`}}
	schemas["Policy"].(object)["oneOf"] = []any{
		object{"properties": object{"management": object{"const": "SYSTEM"}, "accountId": false,
			"id": object{"pattern": `^system\..+`}}},
		object{"required": []string{"accountId"}, "properties": object{"management": object{"const": "CUSTOMER"},
			"scope": object{"const": "TENANT"}, "id": object{"not": object{"pattern": `^system\.`}}}},
	}
	schemas["PolicyList"].(object)["oneOf"] = []any{
		object{"properties": object{"scope": object{"const": "TENANT"}, "installationId": false,
			"items": object{"items": object{"properties": object{"scope": object{"const": "TENANT"}}}}}},
		object{"required": []string{"installationId"}, "properties": object{"scope": object{"const": "INSTALLATION"},
			"items": object{"items": object{"properties": object{"scope": object{"const": "INSTALLATION"}}}}}},
	}
	schemas["ActionCapability"].(object)["oneOf"] = []any{
		object{"properties": object{"available": object{"const": true}, "restrictionReason": false}},
		object{"required": []string{"restrictionReason"}, "properties": object{"available": object{"const": false}}},
	}
	schemas["PolicyAttachment"].(object)["oneOf"] = []any{
		object{"properties": object{"scope": object{"const": "TENANT"}, "installationId": false}},
		object{"required": []string{"installationId"}, "properties": object{"scope": object{"const": "INSTALLATION"},
			"target": object{"properties": object{"kind": object{"const": "USER"}}}}},
		object{"required": []string{"installationId"}, "properties": object{"scope": object{"const": "INSTALLATION_PROBE"},
			"target": object{"properties": object{"kind": object{"const": "SERVICE_ACCOUNT"}}}}},
	}
	schemas["PolicyGrantSource"].(object)["oneOf"] = []any{
		object{
			"properties": object{
				"kind":       object{"const": string(iamv1.PolicyGrantDirect)},
				"membership": false,
				"attachment": object{"properties": object{"target": object{"properties": object{"kind": object{"const": string(iamv1.PolicyTargetUser)}}}}},
			},
		},
		object{
			"required": []string{"membership"},
			"properties": object{
				"kind": object{"const": string(iamv1.PolicyGrantGroup)},
				"attachment": object{"properties": object{
					"scope":  object{"const": string(iamv1.AuthorityScopeTenant)},
					"target": object{"properties": object{"kind": object{"const": string(iamv1.PolicyTargetGroup)}}},
				}},
				"membership": object{"properties": object{"removedAt": false, "removedBy": false}},
			},
		},
	}
	schemas["GroupMembership"].(object)["oneOf"] = []any{
		object{"properties": object{"removedAt": false, "removedBy": false, "resourceVersion": object{"const": 1}}},
		object{"required": []string{"removedAt", "removedBy"}, "properties": object{"resourceVersion": object{"minimum": 2}}},
	}
	schemas["AuditProducerAuthorization"].(object)["oneOf"] = []any{
		object{"required": []string{"tenantId"}, "properties": object{"installationId": false}},
		object{"required": []string{"installationId"}, "properties": object{"tenantId": false}},
	}
	kinds := map[string]string{
		"AccountSecuritySettings": "AccountSecuritySettings", "AccountSecuritySettingsChange": "AccountSecuritySettingsChange",
		"NotificationContact": "NotificationContact", "NotificationContactVerification": "NotificationContactVerification",
		"AccessKey": "AccessKey", "AccessKeyList": "AccessKeyList", "AccessKeyDeletion": "AccessKeyDeletion",
		"CurrentRoleIdentity": "CurrentRoleIdentity", "AssumableRoleList": "AssumableRoleList",
		"RoleSession":     "RoleSession",
		"RoleSessionList": "RoleSessionList", "RoleSessionAccess": "RoleSessionAccess",
		"Role": "Role", "RoleList": "RoleList", "RoleDeletion": "RoleDeletion", "RoleTrustVersion": "RoleTrustVersion", "RoleTrustVersionList": "RoleTrustVersionList",
		"AuthorizationProfileList": "AuthorizationProfileList", "AuthorizationProfile": "AuthorizationProfile",
		"UserPermissionBoundary": "UserPermissionBoundary",
		"RolePermissionBoundary": "RolePermissionBoundary",
		"Policy":                 "Policy",
		"PolicyList":             "PolicyList",
		"CurrentIdentity":        "CurrentIdentity", "UserList": "UserList", "GroupList": "GroupList", "GroupMembershipList": "GroupMembershipList", "AccountList": "AccountList",
		"Account": "Account", "User": "User", "Group": "Group", "GroupMembership": "GroupMembership", "GroupDeletion": "GroupDeletion",
		"PolicyAttachment": "PolicyAttachment",
		"Session":          "Session", "BootstrapDocument": "IAMBootstrap", "BootstrapStatus": "BootstrapStatus",
		"ServiceIdentity":            "ServiceIdentity",
		"AuditProducerAuthorization": "AuditProducerAuthorization",
		"Revocation":                 "Revocation", "AuthorizationDecision": "AuthorizationDecision",
		"Readiness": "Readiness",
	}
	for owner, kind := range kinds {
		properties := schemas[owner].(object)["properties"].(object)
		if value, exists := properties["apiVersion"]; exists {
			_ = value
			properties["apiVersion"] = object{"const": iamv1.APIVersion}
		}
		if _, exists := properties["kind"]; exists {
			properties["kind"] = object{"const": kind}
		}
	}

	bootstrap := schemas["BootstrapDocument"].(object)
	bootstrapProperties := bootstrap["properties"].(object)
	servicePurposes := iamv1.AllServicePurposes()
	prefixItems := make([]any, len(servicePurposes))
	for index, purpose := range servicePurposes {
		prefixItems[index] = object{
			"allOf": []any{
				openapi31.Ref("BootstrapServiceCredential"),
				object{"properties": object{"purpose": object{"const": string(purpose)}}},
			},
		}
	}
	bootstrapProperties["services"] = object{
		"type": "array", "prefixItems": prefixItems, "items": false,
		"minItems": len(servicePurposes), "maxItems": len(servicePurposes),
	}

	schemas["AuditProducerAuthorization"].(object)["properties"].(object)["producer"] = object{
		"allOf": []any{openapi31.Ref("ServiceIdentity"), object{"properties": object{
			"purpose": object{"enum": []string{"IAM", "PAAS", "AUDIT"}},
		}}},
	}
	bootstrapStatus := schemas["BootstrapStatus"].(object)
	bootstrapStatus["allOf"] = []any{
		object{
			"if": object{"properties": object{"state": object{"const": string(iamv1.BootstrapUninitialized)}}, "required": []string{"state"}},
			"then": object{"properties": object{
				"installationId": false, "organizationId": false, "contentDigest": false, "appliedAt": false,
			}},
		},
		object{
			"if":   object{"properties": object{"state": object{"const": string(iamv1.BootstrapReady)}}, "required": []string{"state"}},
			"then": object{"required": []string{"installationId", "organizationId", "contentDigest", "appliedAt"}},
		},
	}

	decision := schemas["AuthorizationDecision"].(object)
	decision["required"] = append(decision["required"].([]string), "profile", "resourceMode", "correlationId")
	decision["properties"].(object)["profile"] = openapi31.Ref("AuthorizationProfileReference")
	decisionRules := []any{
		object{
			"if": object{"properties": object{"allowed": object{"const": true}}, "required": []string{"allowed"}},
			"then": object{
				"required":   []string{"subject"},
				"properties": object{"reason": object{"const": string(iamv1.DecisionAllowed)}},
			},
		},
		object{
			"if": object{"properties": object{"allowed": object{"const": false}}, "required": []string{"allowed"}},
			"then": object{"properties": object{
				"reason": object{"const": string(iamv1.DecisionDenied)}, "tenantId": false, "installationId": false, "subject": false,
			}},
		},
	}
	var platformActions []string
	for _, definition := range iamv1.AllActionDefinitions() {
		if definition.AuthorityScope == iamv1.AuthorityScopeInstallation {
			platformActions = append(platformActions, string(definition.Action))
		}
	}
	decisionRules = append(decisionRules, object{
		"if": object{"properties": object{"allowed": object{"const": true}}, "required": []string{"allowed"}},
		"then": object{
			"if": object{"properties": object{"action": object{"enum": platformActions}}, "required": []string{"action"}},
			"then": object{"required": []string{"installationId"}, "properties": object{
				"tenantId": false, "subject": object{"properties": object{"type": object{"const": string(iamv1.PrincipalUser)}, "accessKeyId": false}},
			}},
			"else": object{"required": []string{"tenantId"}, "properties": object{"installationId": false}},
		},
	})
	decision["allOf"] = append(decisionRules, authorizationTargetRules(true)...)
	schemas["AuthorizationRequest"].(object)["allOf"] = authorizationTargetRules(false)

	session := schemas["Session"].(object)
	session["allOf"] = []any{
		object{
			"if":   object{"properties": object{"status": object{"const": string(iamv1.SessionRevoked)}}, "required": []string{"status"}},
			"then": object{"required": []string{"revokedAt"}},
			"else": object{"properties": object{"revokedAt": false}},
		},
	}
}

func applyAuthorizationProfileOverlays(schemas object) {
	shape := schemas["AuthorizationResourceShape"].(object)
	shape["oneOf"] = []any{
		object{"properties": object{"mode": object{"const": "INSTANCE"}, "collectionUsage": false}},
		object{"required": []string{"collectionUsage"}, "properties": object{"mode": object{"const": "COLLECTION"}, "prefixAllowed": object{"const": false}}},
	}
	conditions := map[iamv1.ConditionKey]iamv1.AuthorizationProfileCondition{}
	for _, profile := range iamv1.AllAuthorizationProfiles() {
		for _, action := range profile.Actions {
			for _, condition := range action.Conditions {
				conditions[condition.Key] = condition
			}
		}
	}
	keys := make([]iamv1.ConditionKey, 0, len(conditions))
	for key := range conditions {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	conditionRules := []any{}
	for _, key := range keys {
		condition := conditions[key]
		conditionRules = append(conditionRules, object{"properties": object{"key": object{"const": key}, "valueType": object{"const": condition.ValueType}, "source": object{"const": condition.Source}}})
	}
	schemas["AuthorizationProfileCondition"].(object)["oneOf"] = conditionRules
	actionRules := []any{
		object{"if": object{"properties": object{"scope": object{"not": object{"const": "TENANT"}}}},
			"then": object{"properties": object{"conditions": object{"anyOf": []any{object{"type": "null"}, object{"type": "array", "maxItems": 0}}},
				"resourceShapes": object{"items": object{"properties": object{"prefixAllowed": object{"const": false}}}}}}},
		object{"if": object{"required": []string{"userAuthenticationMethods"}},
			"then": object{"anyOf": []any{
				object{"required": []string{"subjectTypes"}, "properties": object{"subjectTypes": object{"contains": object{"const": string(iamv1.SubjectUser)}}}},
				object{"not": object{"required": []string{"subjectTypes"}}, "properties": object{"scope": object{"not": object{"const": string(iamv1.AuthorityScopeInstallationProbe)}}}},
			}}},
	}
	for _, usage := range []string{"COLLECTION_LIST", "COLLECTION_CREATE"} {
		then := object{"properties": object{"resultResourceKind": false}}
		if usage == "COLLECTION_CREATE" {
			then = object{"required": []string{"resultResourceKind"}}
		}
		actionRules = append(actionRules, object{
			"if":   object{"properties": object{"resourceShapes": object{"contains": object{"required": []string{"collectionUsage"}, "properties": object{"collectionUsage": object{"const": usage}}}}}},
			"then": then,
		})
	}
	schemas["AuthorizationProfileAction"].(object)["allOf"] = actionRules
}

func authorizationTargetRules(includeSubject bool) []any {
	var rules []any
	for _, profile := range iamv1.AllAuthorizationProfiles() {
		_, digest, err := iamv1.CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			panic(err)
		}
		for _, action := range profile.Actions {
			var shapes []any
			for _, shape := range action.ResourceShapes {
				properties := object{"resourceMode": object{"const": string(shape.Mode)}, "collectionUsage": false}
				required := []string{"resourceMode"}
				if shape.Mode == iamv1.AuthorizationResourceCollection {
					properties["collectionUsage"] = object{"const": string(shape.CollectionUsage)}
					properties["resource"] = object{"properties": object{"id": object{"const": "collection"}}}
					required = append(required, "collectionUsage")
				}
				shapes = append(shapes, object{"properties": properties, "required": required})
			}
			properties := object{
				"profile":  object{"const": object{"product": string(profile.Product), "revision": profile.Revision, "contentDigest": digest}},
				"resource": object{"properties": object{"kind": object{"const": string(action.ResourceKind)}}},
			}
			if includeSubject {
				var subjects []string
				for _, subject := range []iamv1.SubjectType{iamv1.SubjectUser, iamv1.SubjectServiceAccount, iamv1.SubjectRole} {
					if iamv1.CheckAuthorizationProfileSubject(profile, iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}, action.Action, subject) == nil {
						subjects = append(subjects, string(subject))
					}
				}
				subjectProperties := object{"type": object{"enum": subjects}}
				subjectSchema := object{"properties": subjectProperties}
				reference := iamv1.AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}
				keyAllowed := action.Scope == iamv1.AuthorityScopeTenant && iamv1.CheckAuthorizationProfileUserAuthentication(profile, reference, action.Action, iamv1.UserAuthenticationAccessKey) == nil
				if !keyAllowed {
					subjectProperties["accessKeyId"] = false
				} else if iamv1.CheckAuthorizationProfileUserAuthentication(profile, reference, action.Action, iamv1.UserAuthenticationLoginSession) != nil {
					subjectSchema["if"] = object{"properties": object{"type": object{"const": string(iamv1.SubjectUser)}}}
					subjectSchema["then"] = object{"required": []string{"accessKeyId"}}
				}
				properties["subject"] = subjectSchema
			}
			rules = append(rules, object{
				"if":   object{"properties": object{"action": object{"const": string(action.Action)}}, "required": []string{"action"}},
				"then": object{"properties": properties, "oneOf": shapes},
			})
		}
	}
	return rules
}

func applyPolicyLanguageOverlays(schemas object) {
	families := iamv1.PolicyActionFamilies()
	patterns := make([]iamv1.Action, 0, len(families))
	for pattern := range families {
		patterns = append(patterns, pattern)
	}
	slices.Sort(patterns)
	selectors := make(map[iamv1.Action][]string)
	allSelectors := []string{}
	for _, definition := range iamv1.AllActionDefinitions() {
		selectors[definition.Action] = []string{string(definition.Action)}
		allSelectors = append(allSelectors, string(definition.Action))
	}
	for _, pattern := range patterns {
		allSelectors = append(allSelectors, string(pattern))
		for _, action := range families[pattern] {
			selectors[action] = append(selectors[action], string(pattern))
		}
	}
	document := schemas["PolicyDocument"].(object)
	documentProperties := document["properties"].(object)
	documentProperties["languageVersion"] = object{"const": iamv1.PolicyLanguageVersion}
	documentProperties["statements"].(object)["minItems"] = 1
	documentProperties["statements"].(object)["maxItems"] = iamv1.MaxPolicyStatements
	statement := schemas["PolicyStatement"].(object)
	statementProperties := statement["properties"].(object)
	statementProperties["actions"].(object)["items"] = object{"enum": allSelectors}
	statementProperties["sid"] = openapi31.Ref("ID")
	statementProperties["conditions"].(object)["minItems"] = 1
	statementProperties["conditions"].(object)["maxItems"] = iamv1.MaxStatementConditions
	statementProperties["conditions"].(object)["uniqueItems"] = true
	var uniqueConditions []any
	for _, key := range []iamv1.ConditionKey{iamv1.ConditionIAMCurrentTime, iamv1.ConditionIAMAccountID, iamv1.ConditionIAMPrincipalID} {
		operators := []iamv1.PolicyConditionOperator{iamv1.PolicyStringEquals, iamv1.PolicyStringNotEquals}
		if key == iamv1.ConditionIAMCurrentTime {
			operators = []iamv1.PolicyConditionOperator{iamv1.PolicyDateGreaterThanEquals, iamv1.PolicyDateLessThan}
		}
		for _, operator := range operators {
			uniqueConditions = append(uniqueConditions, object{
				"contains":    object{"required": []string{"key", "operator"}, "properties": object{"key": object{"const": string(key)}, "operator": object{"const": string(operator)}}},
				"minContains": 0, "maxContains": 1,
			})
		}
	}
	statementProperties["conditions"].(object)["allOf"] = uniqueConditions
	condition := schemas["PolicyCondition"].(object)
	condition["properties"].(object)["values"] = object{
		"type": "array", "minItems": 1, "maxItems": iamv1.MaxStringConditionValues, "uniqueItems": true,
		"items": object{"type": "string", "maxLength": 128},
	}
	condition["oneOf"] = []any{
		object{"properties": object{
			"key":      object{"const": string(iamv1.ConditionIAMCurrentTime)},
			"operator": object{"enum": []string{string(iamv1.PolicyDateGreaterThanEquals), string(iamv1.PolicyDateLessThan)}},
			"values": object{"maxItems": 1, "items": object{"type": "string", "format": "date-time", "maxLength": 27,
				"pattern": `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{0,5}[1-9])?Z$`}},
		}},
		object{"properties": object{
			"key":      object{"enum": []string{string(iamv1.ConditionIAMAccountID), string(iamv1.ConditionIAMPrincipalID)}},
			"operator": object{"enum": []string{string(iamv1.PolicyStringEquals), string(iamv1.PolicyStringNotEquals)}},
			"values":   object{"items": openapi31.Ref("ID")},
		}},
	}
	for field, maximum := range map[string]int{"actions": iamv1.MaxStatementActions, "resources": iamv1.MaxStatementResources} {
		items := statementProperties[field].(object)
		items["minItems"], items["maxItems"], items["uniqueItems"] = 1, maximum, true
	}
	schemas["PolicyResourceSelector"].(object)["oneOf"] = []any{
		object{"required": []string{"id"}, "properties": object{"match": object{"enum": []string{string(iamv1.PolicyResourceExact), string(iamv1.PolicyResourcePrefixInAuthority)}}}},
		object{"properties": object{"match": object{"const": string(iamv1.PolicyResourceAnyInAuthority)}, "id": false}},
	}
	var scopeRules []any
	for _, scope := range []iamv1.AuthorityScope{iamv1.AuthorityScopeTenant, iamv1.AuthorityScopeInstallation, iamv1.AuthorityScopeInstallationProbe} {
		actions := []string{}
		for _, definition := range iamv1.AllActionDefinitions() {
			if definition.AuthorityScope == scope {
				actions = append(actions, selectors[definition.Action]...)
			}
		}
		slices.Sort(actions)
		actions = slices.Compact(actions)
		properties := object{"actions": object{"items": object{"enum": actions}}}
		if scope != iamv1.AuthorityScopeTenant {
			properties["resources"] = object{"items": object{"properties": object{"match": object{"enum": []string{string(iamv1.PolicyResourceExact), string(iamv1.PolicyResourceAnyInAuthority)}}}}}
		}
		scopeRules = append(scopeRules, object{
			"if":   object{"properties": object{"scope": object{"const": string(scope)}}},
			"then": object{"properties": object{"statements": object{"items": object{"properties": properties}}}},
		})
	}
	document["allOf"] = scopeRules
	var actionRules []any
	seenKinds := map[iamv1.ResourceKind]bool{}
	for _, definition := range iamv1.AllActionDefinitions() {
		actionRules = append(actionRules, object{
			"if":   object{"properties": object{"actions": object{"contains": object{"enum": selectors[definition.Action]}}}},
			"then": object{"properties": object{"resources": object{"contains": object{"properties": object{"kind": object{"const": string(definition.ResourceKind)}}}}}},
		})
		if _, supported := iamv1.LookupActionConditionDefinition(definition.Action, iamv1.ConditionIAMCurrentTime); !supported {
			actionRules = append(actionRules, object{
				"if":   object{"properties": object{"actions": object{"contains": object{"enum": selectors[definition.Action]}}}},
				"then": object{"properties": object{"conditions": false}},
			})
		}
		if seenKinds[definition.ResourceKind] {
			continue
		}
		seenKinds[definition.ResourceKind] = true
		actions := []string{}
		prefixUnsupported := []string{}
		for _, candidate := range iamv1.AllActionDefinitions() {
			if candidate.ResourceKind == definition.ResourceKind {
				actions = append(actions, selectors[candidate.Action]...)
				if !candidate.ResourcePrefixAllowed {
					prefixUnsupported = append(prefixUnsupported, selectors[candidate.Action]...)
				}
			}
		}
		slices.Sort(actions)
		actions = slices.Compact(actions)
		slices.Sort(prefixUnsupported)
		prefixUnsupported = slices.Compact(prefixUnsupported)
		if len(prefixUnsupported) != 0 {
			actionRules = append(actionRules, object{
				"if": object{"properties": object{"resources": object{"contains": object{"properties": object{
					"kind": object{"const": string(definition.ResourceKind)}, "match": object{"const": string(iamv1.PolicyResourcePrefixInAuthority)},
				}}}}},
				"then": object{"properties": object{"actions": object{"not": object{"contains": object{"enum": prefixUnsupported}}}}},
			})
		}
		actionRules = append(actionRules, object{
			"if":   object{"properties": object{"resources": object{"contains": object{"properties": object{"kind": object{"const": string(definition.ResourceKind)}}}}}},
			"then": object{"properties": object{"actions": object{"contains": object{"enum": actions}}}},
		})
	}
	// Retired/unknown resource kinds cannot enter a live permission document.
	kinds := []string{}
	for _, definition := range iamv1.AllActionDefinitions() {
		if seenKinds[definition.ResourceKind] {
			kinds = append(kinds, string(definition.ResourceKind))
			delete(seenKinds, definition.ResourceKind)
		}
	}
	schemas["PolicyResourceSelector"].(object)["properties"].(object)["kind"] = object{"enum": kinds}
	statement["allOf"] = actionRules
	schemas["CreatePolicyRequest"].(object)["allOf"] = []any{object{"properties": object{"document": object{"properties": object{"scope": object{"const": "TENANT"}}}}}}
	schemas["PolicyDetail"].(object)["allOf"] = []any{object{"properties": object{
		"policy":  object{"properties": object{"scope": object{"const": "TENANT"}, "status": object{"const": "ACTIVE"}}},
		"version": object{"properties": object{"document": object{"properties": object{"scope": object{"const": "TENANT"}}}}},
	}}}
	for _, name := range []string{"CreatePolicyVersionRequest", "SetDefaultPolicyVersionRequest", "UpdatePolicyRequest", "DeletePolicyRequest", "DeletePolicyVersionRequest", "SetUserPermissionBoundaryRequest", "RemoveUserPermissionBoundaryRequest", "SetRolePermissionBoundaryRequest", "RemoveRolePermissionBoundaryRequest"} {
		schemas[name].(object)["properties"].(object)["resourceVersion"].(object)["maximum"] = 9007199254740990
	}
	schemas["CreatePolicyVersionRequest"].(object)["allOf"] = schemas["CreatePolicyRequest"].(object)["allOf"]
	customerPolicy := object{"properties": object{"scope": object{"const": "TENANT"}, "status": object{"const": "ACTIVE"}, "management": object{"const": "CUSTOMER"}}}
	tenantVersion := object{"properties": object{"document": object{"properties": object{"scope": object{"const": "TENANT"}}}}}
	schemas["PolicyVersionDetail"].(object)["allOf"] = []any{object{"properties": object{"policy": customerPolicy, "version": tenantVersion}}}
	schemas["PolicyVersionList"].(object)["allOf"] = []any{object{"properties": object{"policy": customerPolicy, "items": object{"minItems": 1, "maxItems": iamv1.MaxPolicyVersions, "items": tenantVersion}}}}
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
