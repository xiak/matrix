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
		"/v1/auth/me":           object{"get": readOperation("getCurrentIdentity", "Get the current account and identity", "CurrentIdentity", nil, nil)},
		"/v1/policies":          object{"get": readOperation("listPolicies", "Read the complete bounded current account policy metadata directory", "PolicyList", nil, nil)},
		"/v1/platform-policies": object{"get": readOperation("listPlatformPolicies", "Read the separately authorized sealed installation policy metadata directory", "PolicyList", nil, nil)},
		"/v1/accounts": object{
			"get":  readOperation("listAccounts", "List accounts as a platform operator", "AccountList", nil, accountPageParameters()),
			"post": mutationOperation("createAccount", "Create an account and its immutable root identity", "CreateAccountRequest", "Account", "201", nil, nil),
		},
		"/v1/accounts/{accountId}":                          object{"get": readOperation("getAccount", "Read account metadata as a platform operator", "Account", nil, []any{openapi31.PathIDParameter("accountId")})},
		"/v1/accounts/{accountId}:set-status":               object{"post": mutationOperation("setAccountStatus", "Suspend or restore account access without stopping workloads", "SetAccountStatusRequest", "Account", "200", nil, []any{openapi31.PathIDParameter("accountId")})},
		"/v1/accounts/{accountId}:recover-root-credentials": object{"post": mutationOperation("recoverRootCredentials", "Recover the account's immutable root identity without transferring ownership", "RecoverRootCredentialsRequest", "Account", "200", nil, []any{openapi31.PathIDParameter("accountId")})},
		"/v1/account:alias":                                 object{"post": mutationOperation("setAccountAlias", "Set the current account login alias", "SetAccountAliasRequest", "Account", "200", nil, nil)},
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
		"/v1/policy-attachments": object{"post": mutationOperation(
			"createPolicyAttachment", "Create a direct user policy attachment", "CreatePolicyAttachmentRequest", "PolicyAttachment", "200", nil, nil,
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
	return []any{object{"name": "after", "in": "query", "required": false, "schema": openapi31.Ref("ID"), "description": "Exclusive user or account ID boundary within the authorized directory."}}
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
		"AccountID", "PrincipalID", "RoleBindingID", "SessionID", "DecisionID",
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
		"PolicyAttachmentTargetKind": {string(iamv1.PolicyTargetUser), string(iamv1.PolicyTargetService), string(iamv1.PolicyTargetGroup), string(iamv1.PolicyTargetRole)},
		"PolicyManagement":           {string(iamv1.PolicySystemManaged), string(iamv1.PolicyCustomerManaged)},
		"PolicyStatus":               {string(iamv1.PolicyActive), string(iamv1.PolicyRetired)},
		"Action":                     openapi31.StringValues(iamv1.AllActions()),
		"ResourceKind": {
			string(iamv1.ResourceAccount), string(iamv1.ResourceUser),
			string(iamv1.ResourceOrganization), string(iamv1.ResourcePrincipal), string(iamv1.ResourceRoleBinding), string(iamv1.ResourcePolicyAttachment),
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
		"Subject":                       openapi31.StructType[iamv1.Subject](),
		"ResourceReference":             openapi31.StructType[iamv1.ResourceReference](),
		"PolicyAttachment":              openapi31.StructType[iamv1.PolicyAttachment](),
		"Policy":                        openapi31.StructType[iamv1.Policy](),
		"PolicyAttachmentTarget":        openapi31.StructType[iamv1.PolicyAttachmentTarget](),
		"CreatePolicyAttachmentRequest": openapi31.StructType[iamv1.CreatePolicyAttachmentRequest](),
		"RevokePolicyAttachmentRequest": openapi31.StructType[iamv1.RevokePolicyAttachmentRequest](),
		"Session":                       openapi31.StructType[iamv1.Session](),
		"InitialOrganization":           openapi31.StructType[iamv1.InitialOrganization](),
		"InitialAdministrator":          openapi31.StructType[iamv1.InitialAdministrator](),
		"BootstrapServiceCredential":    openapi31.StructType[iamv1.BootstrapServiceCredential](),
		"BootstrapDocument":             openapi31.StructType[iamv1.BootstrapDocument](),
		"BootstrapStatus":               openapi31.StructType[iamv1.BootstrapStatus](),
		"ServiceIdentity":               openapi31.StructType[iamv1.ServiceIdentity](),
		"ResolveAuditProducerRequest":   openapi31.StructType[iamv1.ResolveAuditProducerRequest](),
		"AuditProducerAuthorization":    openapi31.StructType[iamv1.AuditProducerAuthorization](),
		"LoginRequest":                  openapi31.StructType[iamv1.LoginRequest](),
		"LoginResponse":                 openapi31.StructType[iamv1.LoginResponse](),
		"LogoutRequest":                 openapi31.StructType[iamv1.LogoutRequest](),
		"LogoutResponse":                openapi31.StructType[iamv1.LogoutResponse](),
		"ChangePasswordRequest":         openapi31.StructType[iamv1.ChangePasswordRequest](),
		"ChangePasswordResponse":        openapi31.StructType[iamv1.ChangePasswordResponse](),
		"CreateUserRequest":             openapi31.StructType[iamv1.CreateUserRequest](),
		"RootIdentity":                  openapi31.StructType[iamv1.RootIdentity](),
		"Account":                       openapi31.StructType[iamv1.Account](),
		"User":                          openapi31.StructType[iamv1.User](),
		"CurrentIdentity":               openapi31.StructType[iamv1.CurrentIdentity](),
		"PolicyList":                    openapi31.StructType[iamv1.PolicyList](),
		"UserAccess":                    openapi31.StructType[iamv1.UserAccess](),
		"UserList":                      openapi31.StructType[iamv1.UserList](),
		"AccountList":                   openapi31.StructType[iamv1.AccountList](),
		"CreateAccountRequest":          openapi31.StructType[iamv1.CreateAccountRequest](),
		"SetAccountAliasRequest":        openapi31.StructType[iamv1.SetAccountAliasRequest](),
		"SetUserStatusRequest":          openapi31.StructType[iamv1.SetUserStatusRequest](),
		"SetAccountStatusRequest":       openapi31.StructType[iamv1.SetAccountStatusRequest](),
		"RecoverRootCredentialsRequest": openapi31.StructType[iamv1.RecoverRootCredentialsRequest](),
		"ResetUserPasswordRequest":      openapi31.StructType[iamv1.ResetUserPasswordRequest](),
		"RevokeSessionRequest":          openapi31.StructType[iamv1.RevokeSessionRequest](),
		"Revocation":                    openapi31.StructType[iamv1.Revocation](),
		"AuthorizationRequest":          openapi31.StructType[iamv1.AuthorizationRequest](),
		"AuthorizationDecision":         openapi31.StructType[iamv1.AuthorizationDecision](),
		"Readiness":                     openapi31.StructType[iamv1.Readiness](),
		"Problem":                       openapi31.StructType[iamv1.Problem](),
	}
}

func fieldOverlay(owner string, field reflect.StructField, jsonName string, base object) object {
	if owner == "Policy" && jsonName == "displayName" {
		base["minLength"], base["maxLength"] = 1, 128
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
		base = openapi31.Ref("ID")
	}
	if owner == "CreatePolicyAttachmentRequest" && jsonName == "target" {
		base = object{"allOf": []any{openapi31.Ref("PolicyAttachmentTarget"), object{"properties": object{"kind": object{"const": "USER"}}}}}
	}
	if (owner == "UserList" || owner == "AccountList") && jsonName == "items" {
		base["maxItems"] = 100
	}
	if owner == "PolicyList" && jsonName == "items" {
		base["maxItems"] = iamv1.MaxPolicyListItems
	}
	if (owner == "CurrentIdentity" || owner == "UserAccess") && jsonName == "policyAttachments" {
		base["maxItems"] = 256
		base["items"] = object{"allOf": []any{openapi31.Ref("PolicyAttachment"), object{"properties": object{
			"revokedAt": false, "target": object{"properties": object{"kind": object{"const": "USER"}}},
		}}}}
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
	schemas["CurrentIdentity"].(object)["allOf"] = []any{object{
		"if": object{"properties": object{"canCreateAccounts": object{"const": true}}, "required": []string{"canCreateAccounts"}},
		"then": object{"properties": object{
			"policyAttachments": object{"contains": object{"properties": object{"scope": object{"const": "INSTALLATION"}}, "required": []string{"scope"}}},
			"user":              object{"properties": object{"mustChangePassword": object{"const": false}}},
		}},
	}}
	schemas["PolicyAttachment"].(object)["oneOf"] = []any{
		object{"properties": object{"scope": object{"const": "TENANT"}, "installationId": false}},
		object{"required": []string{"installationId"}, "properties": object{"scope": object{"const": "INSTALLATION"},
			"target": object{"properties": object{"kind": object{"const": "USER"}}}}},
		object{"required": []string{"installationId"}, "properties": object{"scope": object{"const": "INSTALLATION_PROBE"},
			"target": object{"properties": object{"kind": object{"const": "SERVICE_ACCOUNT"}}}}},
	}
	schemas["AuditProducerAuthorization"].(object)["oneOf"] = []any{
		object{"required": []string{"tenantId"}, "properties": object{"installationId": false}},
		object{"required": []string{"installationId"}, "properties": object{"tenantId": false}},
	}
	kinds := map[string]string{
		"Policy":          "Policy",
		"PolicyList":      "PolicyList",
		"CurrentIdentity": "CurrentIdentity", "UserList": "UserList", "AccountList": "AccountList",
		"Account": "Account", "User": "User",
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

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
