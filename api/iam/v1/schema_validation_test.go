package iamv1

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
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
	create["initialRole"] = "INSTALLATION_VERIFIER"
	if createSchema.Validate(create) == nil {
		t.Fatal("schema accepted an internal verifier role")
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
	request := map[string]any{"organizationId": "organization-customer"}
	if err := requestSchema.Validate(request); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"purpose", "principalId", "subject", "source"} {
		request[selector] = "forged"
		if requestSchema.Validate(request) == nil {
			t.Fatalf("producer request accepted %s", selector)
		}
		delete(request, selector)
	}
	schema := compileIAMOpenAPISchema(t, document, "AuditProducerAuthorization")
	producer := loadIAMSchemaExample(t, "examples/service-identity.json")
	response := map[string]any{"apiVersion": APIVersion, "kind": "AuditProducerAuthorization", "producer": producer, "organizationId": "organization-customer"}
	for _, purpose := range []ServicePurpose{ServiceIAM, ServicePaaS, ServiceAudit} {
		producer["purpose"] = string(purpose)
		if err := schema.Validate(response); err != nil {
			t.Fatal(err)
		}
	}
	producer["purpose"] = string(ServiceInstallationVerifier)
	if schema.Validate(response) == nil {
		t.Fatal("verifier gained producer authority in the schema")
	}
	value := AuditProducerAuthorization{APIVersion: APIVersion, Kind: "AuditProducerAuthorization", OrganizationID: "organization-customer",
		Producer: ServiceIdentity{APIVersion: APIVersion, Kind: "ServiceIdentity", OrganizationID: "organization-platform", PrincipalID: "service-iam", Purpose: ServiceIAM}}
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

	bootstrapSchema := compileIAMOpenAPISchema(t, document, "BootstrapDocument")
	bootstrap := loadIAMSchemaExample(t, "examples/bootstrap-document.json")
	services := bootstrap["services"].([]any)
	services[0], services[1] = services[1], services[0]
	if err := bootstrapSchema.Validate(bootstrap); err == nil {
		t.Fatal("bootstrap service credentials in a different order must fail schema validation")
	}
}
