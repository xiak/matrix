package iamv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/xiak/matrix/api/contractjson"
)

func TestIAMExamplesPassDomainValidation(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"organization", validIAMExample[Organization]("examples/organization.json", ValidateOrganization)},
		{"principal", validIAMExample[Principal]("examples/principal.json", ValidatePrincipal)},
		{"role binding", validIAMExample[RoleBinding]("examples/role-binding.json", ValidateRoleBinding)},
		{"bootstrap status", validIAMExample[BootstrapStatus]("examples/bootstrap-status.json", ValidateBootstrapStatus)},
		{"service identity", validIAMExample[ServiceIdentity]("examples/service-identity.json", ValidateServiceIdentity)},
		{"login request", validIAMExample[LoginRequest]("examples/login-request.json", ValidateLoginRequest)},
		{"login response", validIAMExample[LoginResponse]("examples/login-response.json", ValidateLoginResponse)},
		{"logout request", validIAMExample[LogoutRequest]("examples/logout-request.json", ValidateLogoutRequest)},
		{"logout response", validIAMExample[LogoutResponse]("examples/logout-response.json", ValidateLogoutResponse)},
		{"password request", validIAMExample[ChangePasswordRequest]("examples/change-password-request.json", ValidateChangePasswordRequest)},
		{"password response", validIAMExample[ChangePasswordResponse]("examples/change-password-response.json", ValidateChangePasswordResponse)},
		{"create user", validIAMExample[CreateUserRequest]("examples/create-user-request.json", ValidateCreateUserRequest)},
		{"put role binding", validIAMExample[PutRoleBindingRequest]("examples/put-role-binding-request.json", ValidatePutRoleBindingRequest)},
		{"revoke role binding", validIAMExample[RevokeRoleBindingRequest]("examples/revoke-role-binding-request.json", ValidateRevokeRoleBindingRequest)},
		{"revoke session", validIAMExample[RevokeSessionRequest]("examples/revoke-session-request.json", ValidateRevokeSessionRequest)},
		{"revocation", validIAMExample[Revocation]("examples/revocation.json", ValidateRevocation)},
		{"authorization request", validIAMExample[AuthorizationRequest]("examples/authorization-request.json", ValidateAuthorizationRequest)},
		{"allowed decision", validIAMExample[AuthorizationDecision]("examples/authorization-decision-allowed.json", ValidateAuthorizationDecision)},
		{"denied decision", validIAMExample[AuthorizationDecision]("examples/authorization-decision-denied.json", ValidateAuthorizationDecision)},
		{"readiness", validIAMExample[Readiness]("examples/readiness.json", ValidateReadiness)},
		{"problem", validIAMExample[Problem]("examples/problem.json", ValidateProblem)},
		{"bootstrap document", func(t *testing.T) {
			file, err := os.Open("examples/bootstrap-document.json")
			if err != nil {
				t.Fatalf("open bootstrap document: %v", err)
			}
			defer file.Close()
			if _, err := DecodeBootstrapDocument(file); err != nil {
				t.Fatalf("decode and validate bootstrap document: %v", err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func TestIAMAuthorizationInputCannotForgeAuthorityContext(t *testing.T) {
	valid := `{"action":"paas.deployment.create","resource":{"kind":"DEPLOYMENT","id":"deployment-example"},"requestId":"request-authorize","correlationId":"correlation-authorize"}`
	for name, forged := range map[string]string{
		"tenant":  strings.Replace(valid, `"action"`, `"tenantId":"organization-forged","action"`, 1),
		"subject": strings.Replace(valid, `"action"`, `"subject":{"type":"USER","id":"principal-forged"},"action"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var request AuthorizationRequest
			err := DecodeRequest(strings.NewReader(forged), &request)
			if !errors.Is(err, contractjson.ErrUnknownField) {
				t.Fatalf("forged %s context error = %v, want unknown field", name, err)
			}
		})
	}

	duplicate := strings.Replace(valid, `"kind":"DEPLOYMENT"`, `"kind":"DEPLOYMENT","kind":"DEPLOYMENT"`, 1)
	var request AuthorizationRequest
	if err := DecodeRequest(strings.NewReader(duplicate), &request); !errors.Is(err, contractjson.ErrDuplicateField) {
		t.Fatalf("duplicate nested authority field error = %v, want duplicate field", err)
	}
	if err := DecodeRequest(strings.NewReader(valid+` {}`), &request); !errors.Is(err, contractjson.ErrTrailingData) {
		t.Fatalf("trailing authority document error = %v, want trailing data", err)
	}
	oversized := `{"action":"paas.deployment.create","padding":"` +
		strings.Repeat("A", int(MaxRequestBytes)) + `"}`
	if err := DecodeRequest(strings.NewReader(oversized), &request); !errors.Is(err, contractjson.ErrDocumentTooLarge) {
		t.Fatalf("oversized authority document error = %v, want document too large", err)
	}
}

func TestIAMActionCatalogHasOneResourceKind(t *testing.T) {
	for _, action := range AllActions() {
		kind, known := ResourceKindForAction(action)
		if !known || kind == "" {
			t.Fatalf("action %q has no resource kind", action)
		}
		request := AuthorizationRequest{
			Action: action, Resource: ResourceReference{Kind: kind, ID: "resource-example"},
			RequestID: "request-example", CorrelationID: "correlation-example",
		}
		if err := ValidateAuthorizationRequest(request); err != nil {
			t.Fatalf("valid catalog entry %q/%q rejected: %v", action, kind, err)
		}
		request.Resource.Kind = ResourceKind("NOT_A_RESOURCE")
		if err := ValidateAuthorizationRequest(request); err == nil {
			t.Fatalf("action %q accepted an unbound resource kind", action)
		}
	}
	if _, known := ResourceKindForAction(Action("paas.unregistered.execute")); known {
		t.Fatal("unregistered action has a resource binding")
	}
}

func TestIAMCredentialsRequireExplicitEncoding(t *testing.T) {
	plaintext := "Example-Only-Secret-49!"
	secret, err := NewSecret(plaintext)
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	login := decodeIAMExample[LoginResponse](t, "examples/login-response.json")
	bootstrap := decodeIAMExample[BootstrapDocument](t, "examples/bootstrap-document.json")
	values := []any{
		secret,
		LoginRequest{LoginName: "admin", Password: secret, RequestID: "request-login"},
		login,
		bootstrap,
	}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if !errors.Is(err, ErrSecretSerialization) {
			t.Fatalf("json.Marshal(%T) error = %v, want forbidden credential serialization", value, err)
		}
		if bytes.Contains(encoded, []byte(plaintext)) {
			t.Fatalf("json.Marshal(%T) leaked credential material", value)
		}
	}
	if rendered := fmt.Sprintf("%s %#v", secret, secret); strings.Contains(rendered, plaintext) || !strings.Contains(rendered, "REDACTED") {
		t.Fatalf("formatted secret was not redacted: %q", rendered)
	}

	bootstrapJSON, err := EncodeBootstrapDocument(bootstrap)
	if err != nil {
		t.Fatalf("explicitly encode bootstrap document: %v", err)
	}
	decodedBootstrap, err := DecodeBootstrapDocument(bytes.NewReader(bootstrapJSON))
	if err != nil {
		t.Fatalf("decode explicitly encoded bootstrap document: %v", err)
	}
	if !bytes.Equal(decodedBootstrap.Administrator.Password.CopyBytes(), bootstrap.Administrator.Password.CopyBytes()) {
		t.Fatal("explicit bootstrap encoding changed administrator credential")
	}

	loginJSON, err := EncodeLoginResponse(login)
	if err != nil {
		t.Fatalf("explicitly encode login response: %v", err)
	}
	var decodedLogin LoginResponse
	if err := DecodeRequest(bytes.NewReader(loginJSON), &decodedLogin); err != nil {
		t.Fatalf("decode explicitly encoded login response: %v", err)
	}
	if !bytes.Equal(decodedLogin.Credential.CopyBytes(), login.Credential.CopyBytes()) {
		t.Fatal("explicit login response encoding changed session credential")
	}
	if decodedLogin.MustChangePassword != login.MustChangePassword {
		t.Fatal("explicit login response encoding changed the password-change requirement")
	}
}

func TestIAMLoginResponsePublishesPasswordChangeRequirement(t *testing.T) {
	document := loadIAMOpenAPI(t)
	login := mustIAMObject(t, iamOpenAPISchemas(t, document)["LoginResponse"], "login response schema")
	properties := mustIAMObject(t, login["properties"], "login response properties")
	if _, exists := properties["mustChangePassword"]; !exists {
		t.Fatal("login response does not publish the password-change requirement")
	}
	required, ok := login["required"].([]any)
	if !ok {
		t.Fatalf("login response required fields = %#v", login["required"])
	}
	found := false
	for _, field := range required {
		if field == "mustChangePassword" {
			found = true
		}
	}
	if !found {
		t.Fatal("login response password-change requirement is optional")
	}
}

func TestIAMOpenAPICredentialBoundaries(t *testing.T) {
	document := loadIAMOpenAPI(t)
	paths := mustIAMObject(t, document["paths"], "paths")
	authorizePath := mustIAMObject(t, paths["/v1/authorize"], "authorize path")
	authorize := mustIAMObject(t, authorizePath["post"], "authorize operation")
	security, ok := authorize["security"].([]any)
	if !ok || len(security) != 1 {
		t.Fatalf("authorize security = %#v, want one AND requirement", authorize["security"])
	}
	requirement := mustIAMObject(t, security[0], "authorize security requirement")
	if len(requirement) != 2 || requirement["ServiceCredential"] == nil || requirement["SubjectCredential"] == nil {
		t.Fatalf("authorize security = %#v, want service and subject credentials", requirement)
	}
	verificationPath := mustIAMObject(t, paths["/v1/installation:verify"], "installation verification path")
	verification := mustIAMObject(t, verificationPath["post"], "installation verification operation")
	verificationSecurity, ok := verification["security"].([]any)
	if !ok || len(verificationSecurity) != 1 {
		t.Fatalf("installation verification security = %#v, want one requirement", verification["security"])
	}
	verificationRequirement := mustIAMObject(
		t, verificationSecurity[0], "installation verification security requirement",
	)
	if len(verificationRequirement) != 1 || verificationRequirement["ServiceCredential"] == nil {
		t.Fatalf(
			"installation verification security = %#v, want only verifier service credential",
			verificationRequirement,
		)
	}

	identityPath := mustIAMObject(t, paths["/v1/service-identity"], "service identity path")
	identity := mustIAMObject(t, identityPath["get"], "service identity operation")
	identitySecurity, ok := identity["security"].([]any)
	if !ok || len(identitySecurity) != 1 {
		t.Fatalf("service identity security = %#v, want one requirement", identity["security"])
	}
	identityRequirement := mustIAMObject(t, identitySecurity[0], "service identity security requirement")
	if len(identityRequirement) != 1 || identityRequirement["ServiceCredential"] == nil {
		t.Fatalf("service identity security = %#v, want only current service credential", identityRequirement)
	}
	if _, exists := identity["requestBody"]; exists {
		t.Fatal("service identity endpoint accepts a request body selector")
	}
	if parameters, exists := identity["parameters"]; exists {
		t.Fatalf("service identity endpoint exposes selector parameters: %#v", parameters)
	}

	authorizationRequest := mustIAMObject(t, iamOpenAPISchemas(t, document)["AuthorizationRequest"], "authorization request schema")
	properties := mustIAMObject(t, authorizationRequest["properties"], "authorization request properties")
	for _, forbidden := range []string{"tenantId", "organizationId", "subject"} {
		if _, exists := properties[forbidden]; exists {
			t.Fatalf("authorization request exposes forged authority field %q", forbidden)
		}
	}
	assertNoAuthoritySelectorHeader(t, document)
}

func validIAMExample[T any](path string, validate func(T) error) func(*testing.T) {
	return func(t *testing.T) {
		value := decodeIAMExample[T](t, path)
		if err := validate(value); err != nil {
			t.Fatalf("validate %s: %v", path, err)
		}
	}
}

func mustIAMObject(t *testing.T, value any, name string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s contains %T, want object", name, value)
	}
	return object
}

func assertNoAuthoritySelectorHeader(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			assertNoAuthoritySelectorHeader(t, item)
		}
	case map[string]any:
		if typed["in"] == "header" {
			name, _ := typed["name"].(string)
			normalized := strings.ToLower(name)
			if strings.Contains(normalized, "tenant") || strings.Contains(normalized, "organization") ||
				(strings.Contains(normalized, "subject") && name != "Matrix-Subject-Credential") {
				t.Fatalf("OpenAPI exposes authority selector header %q", name)
			}
		}
		for _, child := range typed {
			assertNoAuthoritySelectorHeader(t, child)
		}
	}
}
