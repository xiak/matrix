package iamv1

import (
	"bytes"
	"os"
	"testing"

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

func TestIAMExamplesValidateAgainstOpenAPISchemas(t *testing.T) {
	document := loadIAMOpenAPI(t)
	examples := map[string]string{
		"examples/organization.json":                   "Organization",
		"examples/principal.json":                      "Principal",
		"examples/role-binding.json":                   "RoleBinding",
		"examples/bootstrap-document.json":             "BootstrapDocument",
		"examples/bootstrap-status.json":               "BootstrapStatus",
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
