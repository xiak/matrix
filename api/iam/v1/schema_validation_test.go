package iamv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

func TestEveryIAMOpenAPISchemaCompilesAsJSONSchema202012(t *testing.T) {
	document := loadIAMOpenAPI(t)
	for name := range iamOpenAPISchemas(t, document) {
		t.Run(name, func(t *testing.T) {
			_ = compileIAMOpenAPISchema(t, document, name)
		})
	}
}

func TestIAMSchemaAcceptsGoUTCSecondEncoding(t *testing.T) {
	value := Readiness{
		APIVersion: APIVersion, Kind: "Readiness", State: ReadinessReady,
		SchemaVersion: 1, CheckedAt: time.Date(2026, 8, 25, 1, 2, 3, 0, time.UTC),
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode readiness: %v", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode readiness: %v", err)
	}
	if err := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "Readiness").Validate(instance); err != nil {
		t.Fatalf("Go-encoded UTC second does not satisfy IAM schema: %v", err)
	}
}

func TestIAMPasswordChangePolicyHasNoCurrentSessionSelector(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "ChangePasswordRequest")
	for _, setting := range []any{nil, true, false} {
		instance := map[string]any{"currentPassword": "Current-Test-Password-49!", "newPassword": "Replacement-Test-Password-73!", "requestId": "request-password-policy"}
		if setting != nil {
			instance["revokeOtherSessions"] = setting
		}
		if err := schema.Validate(instance); err != nil {
			t.Fatalf("valid session policy rejected: %v", err)
		}
		encoded, _ := json.Marshal(instance)
		var request ChangePasswordRequest
		if DecodeRequest(bytes.NewReader(encoded), &request) != nil || ValidateChangePasswordRequest(request) != nil {
			t.Fatal("valid password policy failed strict request decoding")
		}
		if (setting == nil) != (request.RevokeOtherSessions == nil) ||
			setting != nil && *request.RevokeOtherSessions != setting.(bool) {
			t.Fatal("explicit false and omitted policy were not distinguished")
		}
		if _, err := json.Marshal(request); !errors.Is(err, ErrSecretSerialization) {
			t.Fatal("password policy serialized credential material")
		}
		for _, selector := range []string{"sessionId", "currentSessionId", "principalId", "tenantId"} {
			instance[selector] = "forged"
			encoded, _ := json.Marshal(instance)
			var attack ChangePasswordRequest
			if schema.Validate(instance) == nil || DecodeRequest(bytes.NewReader(encoded), &attack) == nil {
				t.Fatalf("password change accepted caller-selected %s", selector)
			}
			delete(instance, selector)
		}
		for _, invalid := range []any{"false", nil, 0} {
			instance["revokeOtherSessions"] = invalid
			encoded, _ = json.Marshal(instance)
			if schema.Validate(instance) == nil || DecodeRequest(bytes.NewReader(encoded), &request) == nil {
				t.Fatal("password change accepted a non-boolean session policy")
			}
		}
	}
}

func TestIAMTenantLifecycleRequestsBindVersionAndOriginalPrimary(t *testing.T) {
	document := loadIAMOpenAPI(t)
	status := map[string]any{"status": "DISABLED", "resourceVersion": float64(1), "requestId": "request-status"}
	recovery := map[string]any{"principalId": "primary-original", "initialPassword": "Recovery-Temporary-Password-79!", "resourceVersion": float64(1), "requestId": "request-recovery"}
	for name, instance := range map[string]map[string]any{"SetOrganizationStatusRequest": status, "RecoverOrganizationAdministratorRequest": recovery} {
		schema := compileIAMOpenAPISchema(t, document, name)
		if err := schema.Validate(instance); err != nil {
			t.Fatalf("valid %s: %v", name, err)
		}
		for _, selector := range []string{"tenantId", "installationId", "organizationId", "newPrimaryId", "role"} {
			instance[selector] = "forged"
			if schema.Validate(instance) == nil {
				t.Fatalf("%s accepted selector %s", name, selector)
			}
			delete(instance, selector)
		}
		instance["resourceVersion"] = float64(0)
		if schema.Validate(instance) == nil {
			t.Fatalf("%s accepted missing concurrency authority", name)
		}
		instance["resourceVersion"] = float64(1)
	}
	encoded, _ := json.Marshal(recovery)
	var request RecoverOrganizationAdministratorRequest
	if err := DecodeRequest(bytes.NewReader(encoded), &request); err != nil || ValidateRecoverOrganizationAdministratorRequest(request) != nil {
		t.Fatal("valid primary recovery request rejected")
	}
	if _, err := json.Marshal(request); !errors.Is(err, ErrSecretSerialization) {
		t.Fatal("primary recovery serialized its temporary credential")
	}
	request.PrincipalID = ""
	if ValidateRecoverOrganizationAdministratorRequest(request) == nil {
		t.Fatal("recovery accepted missing original principal")
	}
	delete(recovery, "principalId")
	if compileIAMOpenAPISchema(t, document, "RecoverOrganizationAdministratorRequest").Validate(recovery) == nil {
		t.Fatal("recovery schema accepted missing original principal")
	}
}

func TestIAMAccountSchemasPreserveQualifiedLoginAndExplicitGrant(t *testing.T) {
	document := loadIAMOpenAPI(t)
	loginSchema := compileIAMOpenAPISchema(t, document, "LoginRequest")
	login := loadIAMSchemaExample(t, "examples/login-request.json")
	for _, name := range []string{"developer@acme", "developer@10001", "admin"} {
		login["loginName"] = name
		if err := loginSchema.Validate(login); err != nil {
			t.Fatalf("qualified login %s: %v", name, err)
		}
	}
	login["loginName"] = "developer@acme@other"
	if loginSchema.Validate(login) == nil {
		t.Fatal("schema accepted an ambiguous login")
	}
	createSchema := compileIAMOpenAPISchema(t, document, "CreateUserRequest")
	create := loadIAMSchemaExample(t, "examples/create-user-request.json")
	if err := createSchema.Validate(create); err != nil {
		t.Fatalf("no initial role: %v", err)
	}
	create["initialRole"] = "PAAS_VIEWER"
	if err := createSchema.Validate(create); err != nil {
		t.Fatalf("explicit initial role: %v", err)
	}
	for _, role := range []BuiltinRole{RoleInstallationVerifier, RolePlatformOperator} {
		create["initialRole"] = string(role)
		if createSchema.Validate(create) == nil {
			t.Fatalf("member creation schema accepted privileged role %s", role)
		}
	}
	grantSchema := compileIAMOpenAPISchema(t, document, "PutRoleBindingRequest")
	grant := loadIAMSchemaExample(t, "examples/put-role-binding-request.json")
	grant["role"] = string(RolePlatformOperator)
	if err := grantSchema.Validate(grant); err != nil {
		t.Fatalf("explicit platform grant contract: %v", err)
	}
	aliasSchema := compileIAMOpenAPISchema(t, document, "SetAccountAliasRequest")
	alias := map[string]any{"alias": "acme", "resourceVersion": float64(1), "requestId": "request-alias"}
	if err := aliasSchema.Validate(alias); err != nil {
		t.Fatalf("alias request: %v", err)
	}
	alias["tenantId"] = "forged"
	if aliasSchema.Validate(alias) == nil {
		t.Fatal("alias schema accepted a tenant selector")
	}
}

func TestAuditProducerSchemaKeepsAppendAuthoritySeparate(t *testing.T) {
	document := loadIAMOpenAPI(t)
	requestSchema := compileIAMOpenAPISchema(t, document, "ResolveAuditProducerRequest")
	event := loadIAMSchemaExample(t, "../../audit/v1/examples/event-paas.json")
	request := map[string]any{"event": event}
	if err := requestSchema.Validate(request); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"organizationId", "tenantId", "installationId", "purpose", "principalId", "subject", "source"} {
		request[selector] = "forged"
		if requestSchema.Validate(request) == nil {
			t.Fatalf("producer request accepted %s", selector)
		}
		delete(request, selector)
	}
	schema := compileIAMOpenAPISchema(t, document, "AuditProducerAuthorization")
	producer := loadIAMSchemaExample(t, "examples/service-identity.json")
	var typedEvent auditv1.Event
	encodedEvent, _ := json.Marshal(event)
	if json.Unmarshal(encodedEvent, &typedEvent) != nil {
		t.Fatal("invalid Audit example")
	}
	_, digest, err := auditv1.CanonicalizeEvent(auditv1.SourcePaaS, typedEvent)
	if err != nil {
		t.Fatal(err)
	}
	response := map[string]any{"apiVersion": APIVersion, "kind": "AuditProducerAuthorization", "producer": producer, "tenantId": "organization-customer", "contentDigest": digest}
	for _, purpose := range []ServicePurpose{ServiceIAM, ServicePaaS, ServiceAudit} {
		producer["purpose"] = string(purpose)
		if err := schema.Validate(response); err != nil {
			t.Fatal(err)
		}
	}
	response["installationId"] = "installation-example"
	if schema.Validate(response) == nil {
		t.Fatal("mixed scope passed producer schema")
	}
	delete(response, "tenantId")
	if err := schema.Validate(response); err != nil {
		t.Fatal(err)
	}
	producer["purpose"] = string(ServiceInstallationVerifier)
	if schema.Validate(response) == nil {
		t.Fatal("verifier gained producer authority in the schema")
	}
	value := AuditProducerAuthorization{APIVersion: APIVersion, Kind: "AuditProducerAuthorization", TenantID: "organization-customer", ContentDigest: digest,
		Producer: ServiceIdentity{APIVersion: APIVersion, Kind: "ServiceIdentity", InstallationID: "installation-example", OrganizationID: "organization-platform", PrincipalID: "service-iam", Purpose: ServiceIAM}}
	if err := ValidateAuditProducerAuthorization(value); err != nil {
		t.Fatal(err)
	}
	value.Producer.Purpose = ServiceInstallationVerifier
	if ValidateAuditProducerAuthorization(value) == nil {
		t.Fatal("verifier gained producer authority in Go")
	}
}

func TestIAMExamplesValidateAgainstOpenAPISchemas(t *testing.T) {
	document := loadIAMOpenAPI(t)
	examples := map[string]string{
		"examples/organization.json":                   "Organization",
		"examples/principal.json":                      "Principal",
		"examples/role-binding.json":                   "RoleBinding",
		"examples/bootstrap-document.json":             "BootstrapDocument",
		"examples/bootstrap-status.json":               "BootstrapStatus",
		"examples/service-identity.json":               "ServiceIdentity",
		"examples/login-request.json":                  "LoginRequest",
		"examples/login-response.json":                 "LoginResponse",
		"examples/logout-request.json":                 "LogoutRequest",
		"examples/logout-response.json":                "LogoutResponse",
		"examples/change-password-request.json":        "ChangePasswordRequest",
		"examples/change-password-response.json":       "ChangePasswordResponse",
		"examples/create-user-request.json":            "CreateUserRequest",
		"examples/put-role-binding-request.json":       "PutRoleBindingRequest",
		"examples/revoke-role-binding-request.json":    "RevokeRoleBindingRequest",
		"examples/revoke-session-request.json":         "RevokeSessionRequest",
		"examples/revocation.json":                     "Revocation",
		"examples/authorization-request.json":          "AuthorizationRequest",
		"examples/authorization-decision-allowed.json": "AuthorizationDecision",
		"examples/authorization-decision-denied.json":  "AuthorizationDecision",
		"examples/readiness.json":                      "Readiness",
		"examples/problem.json":                        "Problem",
	}
	for path, schemaName := range examples {
		t.Run(path, func(t *testing.T) {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(source))
			if err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
			if err := compileIAMOpenAPISchema(t, document, schemaName).Validate(instance); err != nil {
				t.Fatalf("%s does not satisfy %s: %v", path, schemaName, err)
			}
		})
	}
}

func TestIAMOpenAPIEnforcesAuthorizationAndBootstrapSemantics(t *testing.T) {
	document := loadIAMOpenAPI(t)
	authorizationSchema := compileIAMOpenAPISchema(t, document, "AuthorizationRequest")
	request := loadIAMSchemaExample(t, "examples/authorization-request.json")
	request["resource"].(map[string]any)["kind"] = string(ResourceOrganization)
	if err := authorizationSchema.Validate(request); err == nil {
		t.Fatal("authorization action with the wrong resource kind must fail schema validation")
	}

	decisionSchema := compileIAMOpenAPISchema(t, document, "AuthorizationDecision")
	allowed := loadIAMSchemaExample(t, "examples/authorization-decision-allowed.json")
	delete(allowed, "tenantId")
	if err := decisionSchema.Validate(allowed); err == nil {
		t.Fatal("allowed decision without derived tenant must fail schema validation")
	}
	denied := loadIAMSchemaExample(t, "examples/authorization-decision-denied.json")
	denied["subject"] = map[string]any{"type": "USER", "id": "forged-subject"}
	if err := decisionSchema.Validate(denied); err == nil {
		t.Fatal("denied decision exposing subject data must fail schema validation")
	}
	platform := loadIAMSchemaExample(t, "examples/authorization-decision-allowed.json")
	delete(platform, "tenantId")
	platform["action"] = string(ActionPaaSExecutionTargetRegister)
	platform["resource"].(map[string]any)["kind"] = string(ResourceExecutionTarget)
	platform["installationId"] = "installation-example"
	if err := decisionSchema.Validate(platform); err != nil {
		t.Fatalf("installation-bound platform decision failed schema validation: %v", err)
	}
	platform["tenantId"] = "organization-example"
	if decisionSchema.Validate(platform) == nil {
		t.Fatal("mixed platform and tenant authority passed schema validation")
	}
	delete(platform, "tenantId")
	delete(platform, "installationId")
	if decisionSchema.Validate(platform) == nil {
		t.Fatal("platform decision without installation binding passed schema validation")
	}

	bootstrapSchema := compileIAMOpenAPISchema(t, document, "BootstrapDocument")
	bootstrap := loadIAMSchemaExample(t, "examples/bootstrap-document.json")
	services := bootstrap["services"].([]any)
	services[0], services[1] = services[1], services[0]
	if err := bootstrapSchema.Validate(bootstrap); err == nil {
		t.Fatal("bootstrap service credentials in a different order must fail schema validation")
	}
}
