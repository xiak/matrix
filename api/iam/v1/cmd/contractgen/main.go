// Command contractgen deterministically generates the committed IAM OpenAPI
// 3.1 document from executable Go contracts and explicit semantic overlays.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
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
		"/v1/auth/me": object{"get": readOperation("getCurrentIdentity", "Get the current account and identity", "CurrentIdentity", nil, nil)},
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
		"/v1/users/{userId}:update":                         object{"post": mutationOperation("updateUser", "Update an account user's display profile", "UpdateUserRequest", "User", "200", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/users/{userId}:delete":                         object{"post": mutationOperation("deleteUser", "Irreversibly tombstone a disabled account user", "DeleteUserRequest", "UserDeletion", "200", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/users/{userId}:set-status":                     object{"post": mutationOperation("setUserStatus", "Disable or enable an account user", "SetUserStatusRequest", "User", "200", nil, []any{openapi31.PathIDParameter("userId")})},
		"/v1/users/{userId}:reset-password":                 object{"post": mutationOperation("resetUserPassword", "Reset an account user password and revoke its sessions", "ResetUserPasswordRequest", "User", "200", nil, []any{openapi31.PathIDParameter("userId")})},
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
		"AccountID", "PrincipalID", "GroupID", "GroupMembershipID", "RoleBindingID", "SessionID", "DecisionID",
		"PolicyID", "PolicyVersionID", "PolicyAttachmentID",
	} {
		result[name] = object{"allOf": []any{openapi31.Ref("ID")}}
	}
	return result
}

func enumSchemas() map[string][]string {
	return map[string][]string{
		"AccountStatus":              {string(iamv1.AccountActive), string(iamv1.AccountDisabled)},
		"PrincipalType":              {string(iamv1.PrincipalUser), string(iamv1.PrincipalServiceAccount)},
		"PrincipalStatus":            {string(iamv1.PrincipalActive), string(iamv1.PrincipalDisabled)},
		"SessionStatus":              {string(iamv1.SessionActive), string(iamv1.SessionRevoked), string(iamv1.SessionExpired)},
		"AuthorityScope":             {string(iamv1.AuthorityScopeTenant), string(iamv1.AuthorityScopeInstallation), string(iamv1.AuthorityScopeInstallationProbe)},
		"IdentityKind":               {string(iamv1.IdentityRoot), string(iamv1.IdentityUser)},
		"CapabilityRestriction":      openapi31.StringValues(iamv1.AllCapabilityRestrictions()),
		"PolicyAttachmentTargetKind": {string(iamv1.PolicyTargetUser), string(iamv1.PolicyTargetService), string(iamv1.PolicyTargetGroup), string(iamv1.PolicyTargetRole)},
		"PolicyGrantSourceKind":      {string(iamv1.PolicyGrantDirect), string(iamv1.PolicyGrantGroup)},
		"PolicyManagement":           {string(iamv1.PolicySystemManaged), string(iamv1.PolicyCustomerManaged)},
		"PolicyStatus":               {string(iamv1.PolicyActive), string(iamv1.PolicyRetired)},
		"PolicyEffect":               {string(iamv1.PolicyAllow), string(iamv1.PolicyDeny)},
		"ConditionKey":               {string(iamv1.ConditionIAMCurrentTime), string(iamv1.ConditionIAMAccountID), string(iamv1.ConditionIAMPrincipalID)},
		"PolicyConditionOperator":    {string(iamv1.PolicyDateGreaterThanEquals), string(iamv1.PolicyDateLessThan), string(iamv1.PolicyStringEquals), string(iamv1.PolicyStringNotEquals)},
		"PolicyResourceMatch":        {string(iamv1.PolicyResourceExact), string(iamv1.PolicyResourceAnyInAuthority), string(iamv1.PolicyResourcePrefixInAuthority)},
		"Action":                     openapi31.StringValues(iamv1.AllActions()),
		"ResourceKind": {
			string(iamv1.ResourceAccount), string(iamv1.ResourceUser),
			string(iamv1.ResourcePolicy),
			string(iamv1.ResourceOrganization), string(iamv1.ResourcePrincipal), string(iamv1.ResourceGroup), string(iamv1.ResourceGroupMembership), string(iamv1.ResourceRoleBinding), string(iamv1.ResourcePolicyAttachment),
			string(iamv1.ResourceSession), string(iamv1.ResourceApplication), string(iamv1.ResourceConfiguration),
			string(iamv1.ResourceConfigurationRevision), string(iamv1.ResourceApplicationRevision),
			string(iamv1.ResourceDeployment), string(iamv1.ResourceOperation),
			string(iamv1.ResourceServiceOffering), string(iamv1.ResourceRegion),
			string(iamv1.ResourceQuotaEntitlement), string(iamv1.ResourceServiceInstallation),
			string(iamv1.ResourceAuditRecord),
			string(iamv1.ResourceAuditChain), string(iamv1.ResourceInstallation),
			string(iamv1.ResourceExecutionPool), string(iamv1.ResourceExecutionTarget),
		},
		"DecisionReason": {string(iamv1.DecisionAllowed), string(iamv1.DecisionDenied)},
		"BootstrapState": {string(iamv1.BootstrapUninitialized), string(iamv1.BootstrapReady)},
		"ServicePurpose": openapi31.StringValues(iamv1.AllServicePurposes()),
		"ReadinessState": {string(iamv1.ReadinessReady), string(iamv1.ReadinessNotReady)},
	}
}

func structContracts() map[string]reflect.Type {
	return map[string]reflect.Type{
		"Subject":                        openapi31.StructType[iamv1.Subject](),
		"ResourceReference":              openapi31.StructType[iamv1.ResourceReference](),
		"PolicyAttachment":               openapi31.StructType[iamv1.PolicyAttachment](),
		"PolicyGrantSource":              openapi31.StructType[iamv1.PolicyGrantSource](),
		"Policy":                         openapi31.StructType[iamv1.Policy](),
		"PolicyDocument":                 openapi31.StructType[iamv1.PolicyDocument](),
		"PolicyStatement":                openapi31.StructType[iamv1.PolicyStatement](),
		"PolicyCondition":                openapi31.StructType[iamv1.PolicyCondition](),
		"PolicyResourceSelector":         openapi31.StructType[iamv1.PolicyResourceSelector](),
		"PolicyVersion":                  openapi31.StructType[iamv1.PolicyVersion](),
		"PolicyDetail":                   openapi31.StructType[iamv1.PolicyDetail](),
		"CreatePolicyRequest":            openapi31.StructType[iamv1.CreatePolicyRequest](),
		"PolicyVersionDetail":            openapi31.StructType[iamv1.PolicyVersionDetail](),
		"PolicyVersionList":              openapi31.StructType[iamv1.PolicyVersionList](),
		"CreatePolicyVersionRequest":     openapi31.StructType[iamv1.CreatePolicyVersionRequest](),
		"SetDefaultPolicyVersionRequest": openapi31.StructType[iamv1.SetDefaultPolicyVersionRequest](),
		"UpdatePolicyRequest":            openapi31.StructType[iamv1.UpdatePolicyRequest](),
		"DeletePolicyRequest":            openapi31.StructType[iamv1.DeletePolicyRequest](),
		"DeletePolicyVersionRequest":     openapi31.StructType[iamv1.DeletePolicyVersionRequest](),
		"PolicyAttachmentTarget":         openapi31.StructType[iamv1.PolicyAttachmentTarget](),
		"CreatePolicyAttachmentRequest":  openapi31.StructType[iamv1.CreatePolicyAttachmentRequest](),
		"RevokePolicyAttachmentRequest":  openapi31.StructType[iamv1.RevokePolicyAttachmentRequest](),
		"Session":                        openapi31.StructType[iamv1.Session](),
		"InitialOrganization":            openapi31.StructType[iamv1.InitialOrganization](),
		"InitialAdministrator":           openapi31.StructType[iamv1.InitialAdministrator](),
		"BootstrapServiceCredential":     openapi31.StructType[iamv1.BootstrapServiceCredential](),
		"BootstrapDocument":              openapi31.StructType[iamv1.BootstrapDocument](),
		"BootstrapStatus":                openapi31.StructType[iamv1.BootstrapStatus](),
		"ServiceIdentity":                openapi31.StructType[iamv1.ServiceIdentity](),
		"ResolveAuditProducerRequest":    openapi31.StructType[iamv1.ResolveAuditProducerRequest](),
		"AuditProducerAuthorization":     openapi31.StructType[iamv1.AuditProducerAuthorization](),
		"LoginRequest":                   openapi31.StructType[iamv1.LoginRequest](),
		"LoginResponse":                  openapi31.StructType[iamv1.LoginResponse](),
		"LogoutRequest":                  openapi31.StructType[iamv1.LogoutRequest](),
		"LogoutResponse":                 openapi31.StructType[iamv1.LogoutResponse](),
		"ChangePasswordRequest":          openapi31.StructType[iamv1.ChangePasswordRequest](),
		"ChangePasswordResponse":         openapi31.StructType[iamv1.ChangePasswordResponse](),
		"CreateUserRequest":              openapi31.StructType[iamv1.CreateUserRequest](),
		"RootIdentity":                   openapi31.StructType[iamv1.RootIdentity](),
		"Account":                        openapi31.StructType[iamv1.Account](),
		"User":                           openapi31.StructType[iamv1.User](),
		"Group":                          openapi31.StructType[iamv1.Group](),
		"GroupMembership":                openapi31.StructType[iamv1.GroupMembership](),
		"ActionCapability":               openapi31.StructType[iamv1.ActionCapability](),
		"CurrentIdentity":                openapi31.StructType[iamv1.CurrentIdentity](),
		"PolicyList":                     openapi31.StructType[iamv1.PolicyList](),
		"UserAccess":                     openapi31.StructType[iamv1.UserAccess](),
		"UserList":                       openapi31.StructType[iamv1.UserList](),
		"GroupAccess":                    openapi31.StructType[iamv1.GroupAccess](),
		"GroupList":                      openapi31.StructType[iamv1.GroupList](),
		"GroupMembershipAccess":          openapi31.StructType[iamv1.GroupMembershipAccess](),
		"GroupMembershipList":            openapi31.StructType[iamv1.GroupMembershipList](),
		"AccountAccess":                  openapi31.StructType[iamv1.AccountAccess](),
		"AccountList":                    openapi31.StructType[iamv1.AccountList](),
		"CreateAccountRequest":           openapi31.StructType[iamv1.CreateAccountRequest](),
		"SetAccountAliasRequest":         openapi31.StructType[iamv1.SetAccountAliasRequest](),
		"SetUserStatusRequest":           openapi31.StructType[iamv1.SetUserStatusRequest](),
		"UpdateUserRequest":              openapi31.StructType[iamv1.UpdateUserRequest](),
		"DeleteUserRequest":              openapi31.StructType[iamv1.DeleteUserRequest](),
		"UserDeletion":                   openapi31.StructType[iamv1.UserDeletion](),
		"CreateGroupRequest":             openapi31.StructType[iamv1.CreateGroupRequest](),
		"UpdateGroupRequest":             openapi31.StructType[iamv1.UpdateGroupRequest](),
		"DeleteGroupRequest":             openapi31.StructType[iamv1.DeleteGroupRequest](),
		"GroupDeletion":                  openapi31.StructType[iamv1.GroupDeletion](),
		"CreateGroupMembershipRequest":   openapi31.StructType[iamv1.CreateGroupMembershipRequest](),
		"RemoveGroupMembershipRequest":   openapi31.StructType[iamv1.RemoveGroupMembershipRequest](),
		"SetAccountStatusRequest":        openapi31.StructType[iamv1.SetAccountStatusRequest](),
		"RecoverRootCredentialsRequest":  openapi31.StructType[iamv1.RecoverRootCredentialsRequest](),
		"ResetUserPasswordRequest":       openapi31.StructType[iamv1.ResetUserPasswordRequest](),
		"RevokeSessionRequest":           openapi31.StructType[iamv1.RevokeSessionRequest](),
		"Revocation":                     openapi31.StructType[iamv1.Revocation](),
		"AuthorizationRequest":           openapi31.StructType[iamv1.AuthorizationRequest](),
		"AuthorizationDecision":          openapi31.StructType[iamv1.AuthorizationDecision](),
		"Readiness":                      openapi31.StructType[iamv1.Readiness](),
		"Problem":                        openapi31.StructType[iamv1.Problem](),
	}
}

func fieldOverlay(owner string, field reflect.StructField, jsonName string, base object) object {
	if (owner == "Policy" || owner == "CreatePolicyRequest" || owner == "UpdatePolicyRequest" || owner == "UpdateUserRequest") && jsonName == "displayName" {
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
	}
	if owner == "CreatePolicyAttachmentRequest" && jsonName == "target" {
		base = object{"allOf": []any{openapi31.Ref("PolicyAttachmentTarget"), object{"properties": object{"kind": object{"enum": []string{string(iamv1.PolicyTargetUser), string(iamv1.PolicyTargetGroup)}}}}}}
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
	if (owner == "UserAccess" || owner == "GroupAccess") && jsonName == "policyAttachments" {
		base["maxItems"] = 256
		targetKind := string(iamv1.PolicyTargetUser)
		if owner == "GroupAccess" {
			targetKind = string(iamv1.PolicyTargetGroup)
		}
		base["items"] = object{"allOf": []any{openapi31.Ref("PolicyAttachment"), object{"properties": object{
			"revokedAt": false, "target": object{"properties": object{"kind": object{"const": targetKind}}},
		}}}}
	}
	if (owner == "CurrentIdentity" || owner == "UserAccess" || owner == "GroupAccess" || owner == "GroupMembershipAccess" || owner == "AccountAccess") && jsonName == "capabilities" {
		base["maxItems"] = map[string]int{"CurrentIdentity": 8, "UserAccess": 263, "GroupAccess": 262, "GroupMembershipAccess": 1, "AccountAccess": 2}[owner]
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
	if jsonName == "resourceVersion" || jsonName == "schemaVersion" || jsonName == "policyResourceVersion" {
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
		"Policy":          "Policy",
		"PolicyList":      "PolicyList",
		"CurrentIdentity": "CurrentIdentity", "UserList": "UserList", "GroupList": "GroupList", "GroupMembershipList": "GroupMembershipList", "AccountList": "AccountList",
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
	var recordedActions []string
	for _, definition := range iamv1.AllRecordedActionDefinitions() {
		recordedActions = append(recordedActions, string(definition.Action))
	}
	// The shared Action enum remains current-only. Historical vocabulary is
	// accepted only in immutable decision responses, never in requests/policies.
	decision["properties"].(object)["action"] = object{"type": "string", "enum": recordedActions}
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
	for _, definition := range iamv1.AllRecordedActionDefinitions() {
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
	decision["allOf"] = append(decisionRules, actionResourceRules(iamv1.AllRecordedActionDefinitions())...)
	schemas["AuthorizationRequest"].(object)["allOf"] = actionResourceRules(iamv1.AllActionDefinitions())

	session := schemas["Session"].(object)
	session["allOf"] = []any{
		object{
			"if":   object{"properties": object{"status": object{"const": string(iamv1.SessionRevoked)}}, "required": []string{"status"}},
			"then": object{"required": []string{"revokedAt"}},
			"else": object{"properties": object{"revokedAt": false}},
		},
	}
}

func actionResourceRules(definitions []iamv1.ActionDefinition) []any {
	rules := make([]any, 0, len(definitions))
	for _, definition := range definitions {
		rules = append(rules, object{
			"if": object{
				"properties": object{"action": object{"const": string(definition.Action)}},
				"required":   []string{"action"},
			},
			"then": object{
				"properties": object{
					"resource": object{
						"properties": object{"kind": object{"const": string(definition.ResourceKind)}},
						"required":   []string{"kind"},
					},
				},
			},
		})
	}
	return rules
}

func applyPolicyLanguageOverlays(schemas object) {
	document := schemas["PolicyDocument"].(object)
	documentProperties := document["properties"].(object)
	documentProperties["languageVersion"] = object{"const": iamv1.PolicyLanguageVersion}
	documentProperties["statements"].(object)["minItems"] = 1
	documentProperties["statements"].(object)["maxItems"] = iamv1.MaxPolicyStatements
	statement := schemas["PolicyStatement"].(object)
	statementProperties := statement["properties"].(object)
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
				actions = append(actions, string(definition.Action))
			}
		}
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
			"if":   object{"properties": object{"actions": object{"contains": object{"const": string(definition.Action)}}}},
			"then": object{"properties": object{"resources": object{"contains": object{"properties": object{"kind": object{"const": string(definition.ResourceKind)}}}}}},
		})
		if _, supported := iamv1.LookupActionConditionDefinition(definition.Action, iamv1.ConditionIAMCurrentTime); !supported {
			actionRules = append(actionRules, object{
				"if":   object{"properties": object{"actions": object{"contains": object{"const": string(definition.Action)}}}},
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
				actions = append(actions, string(candidate.Action))
				if !candidate.ResourcePrefixAllowed {
					prefixUnsupported = append(prefixUnsupported, string(candidate.Action))
				}
			}
		}
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
	for _, name := range []string{"CreatePolicyVersionRequest", "SetDefaultPolicyVersionRequest", "UpdatePolicyRequest", "DeletePolicyRequest", "DeletePolicyVersionRequest"} {
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
