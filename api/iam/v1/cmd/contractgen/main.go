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
		"/v1/auth/login": object{"post": mutationOperation(
			"login", "Log in with a password", "LoginRequest", "LoginResponse", "200", []any{}, nil,
		)},
		"/v1/auth/logout": object{"post": mutationOperation(
			"logout", "Revoke the current session", "LogoutRequest", "LogoutResponse", "200", nil, nil,
		)},
		"/v1/auth/password": object{"post": mutationOperation(
			"changePassword", "Change the current user password", "ChangePasswordRequest", "ChangePasswordResponse", "200", nil, nil,
		)},
		"/v1/principals": object{"post": mutationOperation(
			"createUser", "Create an organization user", "CreateUserRequest", "Principal", "201", nil, nil,
		)},
		"/v1/role-bindings": object{"post": mutationOperation(
			"putRoleBinding", "Put a built-in role binding", "PutRoleBindingRequest", "RoleBinding", "200", nil, nil,
		)},
		"/v1/role-bindings/{roleBindingId}:revoke": object{"post": mutationOperation(
			"revokeRoleBinding", "Revoke a role binding", "RevokeRoleBindingRequest", "Revocation", "200", nil,
			[]any{openapi31.PathIDParameter("roleBindingId")},
		)},
		"/v1/sessions/{sessionId}:revoke": object{"post": mutationOperation(
			"revokeSession", "Revoke an organization session", "RevokeSessionRequest", "Revocation", "200", nil,
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
		"OrganizationID", "PrincipalID", "RoleBindingID", "SessionID", "DecisionID",
	} {
		result[name] = object{"allOf": []any{openapi31.Ref("ID")}}
	}
	return result
}

func enumSchemas() map[string][]string {
	return map[string][]string{
		"OrganizationStatus": {string(iamv1.OrganizationActive), string(iamv1.OrganizationDisabled)},
		"PrincipalType":      {string(iamv1.PrincipalUser), string(iamv1.PrincipalServiceAccount)},
		"PrincipalStatus":    {string(iamv1.PrincipalActive), string(iamv1.PrincipalDisabled)},
		"SessionStatus":      {string(iamv1.SessionActive), string(iamv1.SessionRevoked), string(iamv1.SessionExpired)},
		"BuiltinRole":        openapi31.StringValues(iamv1.AllBuiltinRoles()),
		"Action":             openapi31.StringValues(iamv1.AllActions()),
		"ResourceKind": {
			string(iamv1.ResourceOrganization), string(iamv1.ResourcePrincipal), string(iamv1.ResourceRoleBinding),
			string(iamv1.ResourceSession), string(iamv1.ResourceApplication), string(iamv1.ResourceConfiguration),
			string(iamv1.ResourceConfigurationRevision), string(iamv1.ResourceApplicationRevision),
			string(iamv1.ResourceDeployment), string(iamv1.ResourceOperation),
			string(iamv1.ResourceServiceOffering), string(iamv1.ResourceRegion),
			string(iamv1.ResourceQuotaEntitlement), string(iamv1.ResourceServiceInstallation),
			string(iamv1.ResourceAuditRecord),
			string(iamv1.ResourceAuditChain), string(iamv1.ResourceInstallation),
		},
		"DecisionReason": {string(iamv1.DecisionAllowed), string(iamv1.DecisionDenied)},
		"BootstrapState": {string(iamv1.BootstrapUninitialized), string(iamv1.BootstrapReady)},
		"ServicePurpose": openapi31.StringValues(iamv1.AllServicePurposes()),
		"ReadinessState": {string(iamv1.ReadinessReady), string(iamv1.ReadinessNotReady)},
	}
}

func structContracts() map[string]reflect.Type {
	return map[string]reflect.Type{
		"Subject":                    openapi31.StructType[iamv1.Subject](),
		"ResourceReference":          openapi31.StructType[iamv1.ResourceReference](),
		"Organization":               openapi31.StructType[iamv1.Organization](),
		"Principal":                  openapi31.StructType[iamv1.Principal](),
		"RoleBinding":                openapi31.StructType[iamv1.RoleBinding](),
		"Session":                    openapi31.StructType[iamv1.Session](),
		"InitialOrganization":        openapi31.StructType[iamv1.InitialOrganization](),
		"InitialAdministrator":       openapi31.StructType[iamv1.InitialAdministrator](),
		"BootstrapServiceCredential": openapi31.StructType[iamv1.BootstrapServiceCredential](),
		"BootstrapDocument":          openapi31.StructType[iamv1.BootstrapDocument](),
		"BootstrapStatus":            openapi31.StructType[iamv1.BootstrapStatus](),
		"ServiceIdentity":            openapi31.StructType[iamv1.ServiceIdentity](),
		"LoginRequest":               openapi31.StructType[iamv1.LoginRequest](),
		"LoginResponse":              openapi31.StructType[iamv1.LoginResponse](),
		"LogoutRequest":              openapi31.StructType[iamv1.LogoutRequest](),
		"LogoutResponse":             openapi31.StructType[iamv1.LogoutResponse](),
		"ChangePasswordRequest":      openapi31.StructType[iamv1.ChangePasswordRequest](),
		"ChangePasswordResponse":     openapi31.StructType[iamv1.ChangePasswordResponse](),
		"CreateUserRequest":          openapi31.StructType[iamv1.CreateUserRequest](),
		"PutRoleBindingRequest":      openapi31.StructType[iamv1.PutRoleBindingRequest](),
		"RevokeRoleBindingRequest":   openapi31.StructType[iamv1.RevokeRoleBindingRequest](),
		"RevokeSessionRequest":       openapi31.StructType[iamv1.RevokeSessionRequest](),
		"Revocation":                 openapi31.StructType[iamv1.Revocation](),
		"AuthorizationRequest":       openapi31.StructType[iamv1.AuthorizationRequest](),
		"AuthorizationDecision":      openapi31.StructType[iamv1.AuthorizationDecision](),
		"Readiness":                  openapi31.StructType[iamv1.Readiness](),
		"Problem":                    openapi31.StructType[iamv1.Problem](),
	}
}

func fieldOverlay(owner string, field reflect.StructField, jsonName string, base object) object {
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
	if jsonName == "resourceVersion" || jsonName == "schemaVersion" {
		base["minimum"] = 1
	}
	return base
}

func applySemanticOverlays(schemas object) {
	kinds := map[string]string{
		"Organization": "Organization", "Principal": "Principal", "RoleBinding": "RoleBinding",
		"Session": "Session", "BootstrapDocument": "IAMBootstrap", "BootstrapStatus": "BootstrapStatus",
		"ServiceIdentity": "ServiceIdentity",
		"Revocation":      "Revocation", "AuthorizationDecision": "AuthorizationDecision",
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

	principal := schemas["Principal"].(object)
	principal["allOf"] = []any{
		object{
			"if":   object{"properties": object{"type": object{"const": string(iamv1.PrincipalUser)}}, "required": []string{"type"}},
			"then": object{"required": []string{"loginName"}},
		},
		object{
			"if":   object{"properties": object{"type": object{"const": string(iamv1.PrincipalServiceAccount)}}, "required": []string{"type"}},
			"then": object{"properties": object{"loginName": false, "mustChangePassword": false}},
		},
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
	decisionRules := []any{
		object{
			"if": object{"properties": object{"allowed": object{"const": true}}, "required": []string{"allowed"}},
			"then": object{
				"required":   []string{"tenantId", "subject"},
				"properties": object{"reason": object{"const": string(iamv1.DecisionAllowed)}},
			},
		},
		object{
			"if": object{"properties": object{"allowed": object{"const": false}}, "required": []string{"allowed"}},
			"then": object{"properties": object{
				"reason": object{"const": string(iamv1.DecisionDenied)}, "tenantId": false, "subject": false,
			}},
		},
	}
	decision["allOf"] = append(decisionRules, actionResourceRules()...)
	schemas["AuthorizationRequest"].(object)["allOf"] = actionResourceRules()

	session := schemas["Session"].(object)
	session["allOf"] = []any{
		object{
			"if":   object{"properties": object{"status": object{"const": string(iamv1.SessionRevoked)}}, "required": []string{"status"}},
			"then": object{"required": []string{"revokedAt"}},
			"else": object{"properties": object{"revokedAt": false}},
		},
	}
}

func actionResourceRules() []any {
	actions := iamv1.AllActions()
	rules := make([]any, 0, len(actions))
	for _, action := range actions {
		resourceKind, known := iamv1.ResourceKindForAction(action)
		if !known {
			panic("IAM action has no resource kind: " + string(action))
		}
		rules = append(rules, object{
			"if": object{
				"properties": object{"action": object{"const": string(action)}},
				"required":   []string{"action"},
			},
			"then": object{
				"properties": object{
					"resource": object{
						"properties": object{"kind": object{"const": string(resourceKind)}},
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
