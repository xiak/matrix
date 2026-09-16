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
			"login", "Log in with a password", "LoginRequest", "LoginResponse", "200", []any{}, nil,
		)},
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
		"/v1/users/{userId}/permission-boundary": object{
			"get":    readOperation("getUserPermissionBoundary", "Read the current user permission limit, not a grant", "UserPermissionBoundary", nil, []any{openapi31.PathIDParameter("userId")}),
			"put":    mutationOperation("setUserPermissionBoundary", "Root sets or replaces the tenant user permission limit", "SetUserPermissionBoundaryRequest", "UserPermissionBoundary", "200", nil, []any{openapi31.PathIDParameter("userId")}),
			"delete": mutationOperation("removeUserPermissionBoundary", "Root explicitly removes the tenant user permission limit", "RemoveUserPermissionBoundaryRequest", "UserPermissionBoundary", "200", nil, []any{openapi31.PathIDParameter("userId")}),
		},
		"/v1/users/{userId}:update":         object{"post": mutationOperation("updateUser", "Update an account user's display profile", "UpdateUserRequest", "User", "200", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/users/{userId}:delete":         object{"post": mutationOperation("deleteUser", "Irreversibly tombstone a disabled account user", "DeleteUserRequest", "UserDeletion", "200", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/users/{userId}:set-status":     object{"post": mutationOperation("setUserStatus", "Disable or enable an account user", "SetUserStatusRequest", "User", "200", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/users/{userId}:reset-password": object{"post": mutationOperation("resetUserPassword", "Reset an account user password and revoke its sessions", "ResetUserPasswordRequest", "User", "200", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/auth/logout": object{"post": mutationOperation(
			"logout", "Revoke the current session", "LogoutRequest", "LogoutResponse", "200", nil, nil,
		)},
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
		"PolicyID", "PolicyVersionID", "PolicyAttachmentID",
	} {
		result[name] = object{"allOf": []any{openapi31.Ref("ID")}}
	}
	result["ProductID"] = object{"type": "string", "pattern": `^[a-z][a-z0-9_-]{0,63}$`, "minLength": 1, "maxLength": 64}
	return result
}

func enumSchemas() map[string][]string {
	return map[string][]string{
		"RoleStatus":                   {string(iamv1.RoleActive), string(iamv1.RoleDisabled)},
		"RoleManagement":               {string(iamv1.RoleCustomerManaged)},
		"AccountStatus":                {string(iamv1.AccountActive), string(iamv1.AccountDisabled)},
		"PrincipalType":                {string(iamv1.PrincipalUser), string(iamv1.PrincipalServiceAccount)},
		"SubjectType":                  {string(iamv1.SubjectUser), string(iamv1.SubjectServiceAccount), string(iamv1.SubjectRole)},
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
			string(iamv1.ResourceAccount), string(iamv1.ResourceUser),
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
	}
}

func structContracts() map[string]reflect.Type {
	return map[string]reflect.Type{
		"Subject":                             openapi31.StructType[iamv1.Subject](),
		"RoleSessionReference":                openapi31.StructType[iamv1.RoleSessionReference](),
		"ResourceReference":                   openapi31.StructType[iamv1.ResourceReference](),
		"AuthorizationProfileReference":       openapi31.StructType[iamv1.AuthorizationProfileReference](),
		"AuthorizationProfileList":            openapi31.StructType[iamv1.AuthorizationProfileList](),
		"AuthorizationProfileEntry":           openapi31.StructType[iamv1.AuthorizationProfileEntry](),
		"AuthorizationProfile":                openapi31.StructType[iamv1.AuthorizationProfile](),
		"AuthorizationProfileAction":          openapi31.StructType[iamv1.AuthorizationProfileAction](),
		"AuthorizationResourceShape":          openapi31.StructType[iamv1.AuthorizationResourceShape](),
		"AuthorizationProfileCondition":       openapi31.StructType[iamv1.AuthorizationProfileCondition](),
		"PolicyAttachment":                    openapi31.StructType[iamv1.PolicyAttachment](),
		"PolicyGrantSource":                   openapi31.StructType[iamv1.PolicyGrantSource](),
		"Policy":                              openapi31.StructType[iamv1.Policy](),
		"PolicyDocument":                      openapi31.StructType[iamv1.PolicyDocument](),
		"PolicyStatement":                     openapi31.StructType[iamv1.PolicyStatement](),
		"PolicyCondition":                     openapi31.StructType[iamv1.PolicyCondition](),
		"PolicyResourceSelector":              openapi31.StructType[iamv1.PolicyResourceSelector](),
		"PolicyVersion":                       openapi31.StructType[iamv1.PolicyVersion](),
		"PolicyCompilation":                   openapi31.StructType[iamv1.PolicyCompilation](),
		"PolicyResolvedStatement":             openapi31.StructType[iamv1.PolicyResolvedStatement](),
		"PolicyVersionReference":              openapi31.StructType[iamv1.PolicyVersionReference](),
		"UserPermissionBoundary":              openapi31.StructType[iamv1.UserPermissionBoundary](),
		"SetUserPermissionBoundaryRequest":    openapi31.StructType[iamv1.SetUserPermissionBoundaryRequest](),
		"RemoveUserPermissionBoundaryRequest": openapi31.StructType[iamv1.RemoveUserPermissionBoundaryRequest](),
		"PolicyDetail":                        openapi31.StructType[iamv1.PolicyDetail](),
		"CreatePolicyRequest":                 openapi31.StructType[iamv1.CreatePolicyRequest](),
		"PolicyVersionDetail":                 openapi31.StructType[iamv1.PolicyVersionDetail](),
		"PolicyVersionList":                   openapi31.StructType[iamv1.PolicyVersionList](),
		"CreatePolicyVersionRequest":          openapi31.StructType[iamv1.CreatePolicyVersionRequest](),
		"SetDefaultPolicyVersionRequest":      openapi31.StructType[iamv1.SetDefaultPolicyVersionRequest](),
		"UpdatePolicyRequest":                 openapi31.StructType[iamv1.UpdatePolicyRequest](),
		"DeletePolicyRequest":                 openapi31.StructType[iamv1.DeletePolicyRequest](),
		"DeletePolicyVersionRequest":          openapi31.StructType[iamv1.DeletePolicyVersionRequest](),
		"PolicyAttachmentTarget":              openapi31.StructType[iamv1.PolicyAttachmentTarget](),
		"CreatePolicyAttachmentRequest":       openapi31.StructType[iamv1.CreatePolicyAttachmentRequest](),
		"RevokePolicyAttachmentRequest":       openapi31.StructType[iamv1.RevokePolicyAttachmentRequest](),
		"Session":                             openapi31.StructType[iamv1.Session](),
		"InitialOrganization":                 openapi31.StructType[iamv1.InitialOrganization](),
		"InitialAdministrator":                openapi31.StructType[iamv1.InitialAdministrator](),
		"BootstrapServiceCredential":          openapi31.StructType[iamv1.BootstrapServiceCredential](),
		"BootstrapDocument":                   openapi31.StructType[iamv1.BootstrapDocument](),
		"BootstrapStatus":                     openapi31.StructType[iamv1.BootstrapStatus](),
		"ServiceIdentity":                     openapi31.StructType[iamv1.ServiceIdentity](),
		"ResolveAuditProducerRequest":         openapi31.StructType[iamv1.ResolveAuditProducerRequest](),
		"AuditProducerAuthorization":          openapi31.StructType[iamv1.AuditProducerAuthorization](),
		"LoginRequest":                        openapi31.StructType[iamv1.LoginRequest](),
		"LoginResponse":                       openapi31.StructType[iamv1.LoginResponse](),
		"LogoutRequest":                       openapi31.StructType[iamv1.LogoutRequest](),
		"LogoutResponse":                      openapi31.StructType[iamv1.LogoutResponse](),
		"ChangePasswordRequest":               openapi31.StructType[iamv1.ChangePasswordRequest](),
		"ChangePasswordResponse":              openapi31.StructType[iamv1.ChangePasswordResponse](),
		"CreateUserRequest":                   openapi31.StructType[iamv1.CreateUserRequest](),
		"RootIdentity":                        openapi31.StructType[iamv1.RootIdentity](),
		"Account":                             openapi31.StructType[iamv1.Account](),
		"User":                                openapi31.StructType[iamv1.User](),
		"Group":                               openapi31.StructType[iamv1.Group](),
		"GroupMembership":                     openapi31.StructType[iamv1.GroupMembership](),
		"TrustPolicyDocument":                 openapi31.StructType[iamv1.TrustPolicyDocument](),
		"TrustPolicyStatement":                openapi31.StructType[iamv1.TrustPolicyStatement](),
		"TrustPrincipal":                      openapi31.StructType[iamv1.TrustPrincipal](),
		"RoleTrustVersion":                    openapi31.StructType[iamv1.RoleTrustVersion](),
		"Role":                                openapi31.StructType[iamv1.Role](),
		"RoleTag":                             openapi31.StructType[iamv1.RoleTag](),
		"RoleListing":                         openapi31.StructType[iamv1.RoleListing](),
		"RoleList":                            openapi31.StructType[iamv1.RoleList](),
		"RoleAccess":                          openapi31.StructType[iamv1.RoleAccess](),
		"RolePermissionBoundary":              openapi31.StructType[iamv1.RolePermissionBoundary](),
		"SetRolePermissionBoundaryRequest":    openapi31.StructType[iamv1.SetRolePermissionBoundaryRequest](),
		"RemoveRolePermissionBoundaryRequest": openapi31.StructType[iamv1.RemoveRolePermissionBoundaryRequest](),
		"RoleTrustVersionList":                openapi31.StructType[iamv1.RoleTrustVersionList](),
		"CreateRoleRequest":                   openapi31.StructType[iamv1.CreateRoleRequest](),
		"AssumeRoleRequest":                   openapi31.StructType[iamv1.AssumeRoleRequest](),
		"AssumeRoleResponse":                  openapi31.StructType[iamv1.AssumeRoleResponse](),
		"RoleSession":                         openapi31.StructType[iamv1.RoleSession](),
		"RoleSessionListing":                  openapi31.StructType[iamv1.RoleSessionListing](),
		"RoleSessionList":                     openapi31.StructType[iamv1.RoleSessionList](),
		"RoleSessionAccess":                   openapi31.StructType[iamv1.RoleSessionAccess](),
		"RevokeRoleSessionResponse":           openapi31.StructType[iamv1.RevokeRoleSessionResponse](),
		"CurrentRoleIdentity":                 openapi31.StructType[iamv1.CurrentRoleIdentity](),
		"RoleAccountDisplay":                  openapi31.StructType[iamv1.RoleAccountDisplay](),
		"RoleDisplay":                         openapi31.StructType[iamv1.RoleDisplay](),
		"RoleSourceUserDisplay":               openapi31.StructType[iamv1.RoleSourceUserDisplay](),
		"AssumableRole":                       openapi31.StructType[iamv1.AssumableRole](),
		"AssumableRoleList":                   openapi31.StructType[iamv1.AssumableRoleList](),
		"RevokeRoleSessionRequest":            openapi31.StructType[iamv1.RevokeRoleSessionRequest](),
		"UpdateRoleRequest":                   openapi31.StructType[iamv1.UpdateRoleRequest](),
		"SetRoleStatusRequest":                openapi31.StructType[iamv1.SetRoleStatusRequest](),
		"SetRoleTrustPolicyRequest":           openapi31.StructType[iamv1.SetRoleTrustPolicyRequest](),
		"DeleteRoleRequest":                   openapi31.StructType[iamv1.DeleteRoleRequest](),
		"RoleDeletion":                        openapi31.StructType[iamv1.RoleDeletion](),
		"ActionCapability":                    openapi31.StructType[iamv1.ActionCapability](),
		"CurrentIdentity":                     openapi31.StructType[iamv1.CurrentIdentity](),
		"PolicyList":                          openapi31.StructType[iamv1.PolicyList](),
		"UserAccess":                          openapi31.StructType[iamv1.UserAccess](),
		"UserList":                            openapi31.StructType[iamv1.UserList](),
		"GroupAccess":                         openapi31.StructType[iamv1.GroupAccess](),
		"GroupList":                           openapi31.StructType[iamv1.GroupList](),
		"GroupMembershipAccess":               openapi31.StructType[iamv1.GroupMembershipAccess](),
		"GroupMembershipList":                 openapi31.StructType[iamv1.GroupMembershipList](),
		"AccountAccess":                       openapi31.StructType[iamv1.AccountAccess](),
		"AccountList":                         openapi31.StructType[iamv1.AccountList](),
		"CreateAccountRequest":                openapi31.StructType[iamv1.CreateAccountRequest](),
		"SetAccountAliasRequest":              openapi31.StructType[iamv1.SetAccountAliasRequest](),
		"SetUserStatusRequest":                openapi31.StructType[iamv1.SetUserStatusRequest](),
		"UpdateUserRequest":                   openapi31.StructType[iamv1.UpdateUserRequest](),
		"DeleteUserRequest":                   openapi31.StructType[iamv1.DeleteUserRequest](),
		"UserDeletion":                        openapi31.StructType[iamv1.UserDeletion](),
		"CreateGroupRequest":                  openapi31.StructType[iamv1.CreateGroupRequest](),
		"UpdateGroupRequest":                  openapi31.StructType[iamv1.UpdateGroupRequest](),
		"DeleteGroupRequest":                  openapi31.StructType[iamv1.DeleteGroupRequest](),
		"GroupDeletion":                       openapi31.StructType[iamv1.GroupDeletion](),
		"CreateGroupMembershipRequest":        openapi31.StructType[iamv1.CreateGroupMembershipRequest](),
		"RemoveGroupMembershipRequest":        openapi31.StructType[iamv1.RemoveGroupMembershipRequest](),
		"SetAccountStatusRequest":             openapi31.StructType[iamv1.SetAccountStatusRequest](),
		"RecoverRootCredentialsRequest":       openapi31.StructType[iamv1.RecoverRootCredentialsRequest](),
		"ResetUserPasswordRequest":            openapi31.StructType[iamv1.ResetUserPasswordRequest](),
		"RevokeSessionRequest":                openapi31.StructType[iamv1.RevokeSessionRequest](),
		"Revocation":                          openapi31.StructType[iamv1.Revocation](),
		"AuthorizationRequest":                openapi31.StructType[iamv1.AuthorizationRequest](),
		"AuthorizationDecision":               openapi31.StructType[iamv1.AuthorizationDecision](),
		"Readiness":                           openapi31.StructType[iamv1.Readiness](),
		"Problem":                             openapi31.StructType[iamv1.Problem](),
	}
}

func fieldOverlay(owner string, field reflect.StructField, jsonName string, base object) object {
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
	if jsonName == "nextAfter" {
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
		if owner == "LoginResponse" && jsonName == "credential" {
			delete(base, "writeOnly")
			base["readOnly"] = true
		}
	}
	if field.Type.Kind() == reflect.String &&
		(jsonName == "id" || strings.HasSuffix(jsonName, "Id")) {
		base = openapi31.Ref("ID")
	}
	if jsonName == "resourceVersion" || jsonName == "schemaVersion" || jsonName == "policyResourceVersion" || ((owner == "AuthorizationProfileReference" || owner == "AuthorizationProfile") && jsonName == "revision") {
		base["minimum"] = 1
	}
	if owner == "ChangePasswordRequest" && jsonName == "revokeOtherSessions" {
		base["default"] = true
		base["description"] = "Revoke other login sessions, preserving only the current bearer session after transactional revalidation. Omission defaults to true. Required password replacement always revokes other sessions; false can retain only already valid sessions of the same user."
	}
	return base
}

func applySemanticOverlays(schemas object) {
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
	schemas["Subject"].(object)["oneOf"] = []any{
		object{"required": []string{"roleSession"}, "properties": object{"type": object{"const": "ROLE"}}},
		object{"properties": object{"type": object{"enum": []string{"USER", "SERVICE_ACCOUNT"}}, "roleSession": false}},
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
				"tenantId": false, "subject": object{"properties": object{"type": object{"const": string(iamv1.PrincipalUser)}}},
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
				properties["subject"] = object{"properties": object{"type": object{"enum": subjects}}}
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
