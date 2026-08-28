package iamv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

func TestLocalRecoveryCapabilityBindsOnePrivateIntent(t *testing.T) {
	secret := func(value string) Secret {
		t.Helper()
		result, err := NewSecret(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	scope := LocalCredentialRecoveryScope{
		InstallationID: "installation-local", BootstrapDigest: "sha256:" + strings.Repeat("a", 64),
		OrganizationID: "organization-original", PrincipalID: "principal-original",
	}
	local := LocalCredentialRecoveryAuthority{
		APIVersion: APIVersion, Kind: "LocalCredentialRecoveryAuthority", Purpose: LocalCredentialRecoveryPurpose,
		Scope: scope, CapabilityKey: secret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x39}, 32))),
	}
	request := LocalCredentialRecoveryRequest{
		APIVersion: APIVersion, Kind: "LocalCredentialRecoveryRequest", Purpose: LocalCredentialRecoveryPurpose,
		CommandID: "command-original", Scope: scope,
		Expected: LocalCredentialRecoveryExpected{OrganizationResourceVersion: 3, PrincipalResourceVersion: 7,
			CredentialGeneration: 4, PlatformBindingID: "binding-original", PlatformBindingResourceVersion: 1},
		NewPassword: secret("Recovery-Private-Password-123!"),
	}
	signed, err := SignLocalCredentialRecoveryRequest(local, request)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := VerifyLocalCredentialRecoveryRequest(local, signed)
	if err != nil || ValidateDigest("commitment", commitment) != nil {
		t.Fatalf("verify capability: %v", err)
	}
	repeated, err := SignLocalCredentialRecoveryRequest(local, request)
	if err != nil || !bytes.Equal(signed.Capability.CopyBytes(), repeated.Capability.CopyBytes()) {
		t.Fatal("same private intent did not reproduce its capability")
	}
	for name, change := range map[string]func(*LocalCredentialRecoveryRequest){
		"purpose":              func(v *LocalCredentialRecoveryRequest) { v.Purpose = "PLATFORM_ROLE_GRANT" },
		"command":              func(v *LocalCredentialRecoveryRequest) { v.CommandID = "command-other" },
		"installation":         func(v *LocalCredentialRecoveryRequest) { v.Scope.InstallationID = "installation-other" },
		"bootstrap":            func(v *LocalCredentialRecoveryRequest) { v.Scope.BootstrapDigest = "sha256:" + strings.Repeat("b", 64) },
		"tenant":               func(v *LocalCredentialRecoveryRequest) { v.Scope.OrganizationID = "organization-other" },
		"primary":              func(v *LocalCredentialRecoveryRequest) { v.Scope.PrincipalID = "principal-child" },
		"organization version": func(v *LocalCredentialRecoveryRequest) { v.Expected.OrganizationResourceVersion++ },
		"principal version":    func(v *LocalCredentialRecoveryRequest) { v.Expected.PrincipalResourceVersion++ },
		"generation":           func(v *LocalCredentialRecoveryRequest) { v.Expected.CredentialGeneration++ },
		"binding":              func(v *LocalCredentialRecoveryRequest) { v.Expected.PlatformBindingID = "binding-other" },
		"binding version":      func(v *LocalCredentialRecoveryRequest) { v.Expected.PlatformBindingResourceVersion++ },
		"password":             func(v *LocalCredentialRecoveryRequest) { v.NewPassword = secret("Different-Private-Password-123!") },
		"capability": func(v *LocalCredentialRecoveryRequest) {
			v.Capability = secret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)))
		},
		"missing capability":  func(v *LocalCredentialRecoveryRequest) { v.Capability = Secret{} },
		"overflow generation": func(v *LocalCredentialRecoveryRequest) { v.Expected.CredentialGeneration = 9007199254740991 },
	} {
		t.Run(name, func(t *testing.T) {
			forged := signed
			change(&forged)
			if _, err := VerifyLocalCredentialRecoveryRequest(local, forged); !errors.Is(err, ErrInvalidLocalCredentialRecovery) {
				t.Fatalf("substituted intent accepted: %v", err)
			}
		})
	}
	otherKey := local
	otherKey.CapabilityKey = secret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32)))
	if _, err := VerifyLocalCredentialRecoveryRequest(otherKey, signed); err == nil {
		t.Fatal("another installation authority key accepted")
	}
	for _, value := range []any{local, signed} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrSecretSerialization) {
			t.Fatalf("ordinary secret serialization error=%v", err)
		}
		formatted := fmt.Sprintf("%+v %#v", value, value)
		for _, sensitive := range []Secret{local.CapabilityKey, signed.NewPassword, signed.Capability} {
			if strings.Contains(formatted, string(sensitive.CopyBytes())) {
				t.Fatal("private material leaked through formatting")
			}
		}
	}
	encodedAuthority, err := EncodeLocalCredentialRecoveryAuthority(local)
	if err != nil {
		t.Fatal(err)
	}
	decodedAuthority, err := DecodeLocalCredentialRecoveryAuthority(bytes.NewReader(encodedAuthority))
	if err != nil || decodedAuthority.Scope != scope {
		t.Fatalf("authority private round trip: %v", err)
	}
	encoded, err := EncodeLocalCredentialRecoveryRequest(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeLocalCredentialRecoveryRequest(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyLocalCredentialRecoveryRequest(decodedAuthority, decoded); err != nil || got != commitment {
		t.Fatalf("private wire changed commitment: %v", err)
	}
	for _, forged := range []string{
		strings.Replace(string(encoded), `"commandId":`, `"commandId":"other","commandId":`, 1),
		strings.TrimSuffix(string(encoded), "}") + `,"databaseDsn":"attacker"}`,
		string(encoded) + `{}`,
		strings.Replace(string(encoded), `"newPassword":`, `"extra":true,"newPassword":`, 1),
	} {
		if _, err := DecodeLocalCredentialRecoveryRequest(strings.NewReader(forged)); err == nil {
			t.Fatal("ambiguous/unknown private request accepted")
		}
	}
}

func TestLocalRecoveryReceiptIsHistoricalNotFreshAuthority(t *testing.T) {
	scope := LocalCredentialRecoveryScope{InstallationID: "installation-original", BootstrapDigest: "sha256:" + strings.Repeat("a", 64), OrganizationID: "organization-original", PrincipalID: "principal-original"}
	expected := LocalCredentialRecoveryExpected{OrganizationResourceVersion: 1, PrincipalResourceVersion: 4, CredentialGeneration: 3, PlatformBindingID: "binding-original", PlatformBindingResourceVersion: 1}
	result := LocalCredentialRecoveryResult{APIVersion: APIVersion, Kind: "LocalCredentialRecoveryResult", State: "APPLIED", CommandID: "command-original",
		InputCommitment: "sha256:" + strings.Repeat("b", 64), Scope: scope, PreviousCredentialGeneration: 3, CredentialGeneration: 4,
		PrincipalResourceVersion: 5, RevokedSessions: 2, AuditEventID: "event-original", CompletedAt: time.Date(2026, 8, 28, 1, 2, 3, 0, time.UTC)}
	inspection := LocalCredentialRecoveryInspection{APIVersion: APIVersion, Kind: "LocalCredentialRecoveryInspection", Scope: scope, State: "COMPLETED",
		CommandID: result.CommandID, InputCommitment: result.InputCommitment, Expected: &expected, Result: &result}
	if err := ValidateLocalCredentialRecoveryInspection(inspection); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*LocalCredentialRecoveryInspection){
		"wrong command":             func(v *LocalCredentialRecoveryInspection) { v.CommandID = "other" },
		"wrong commitment":          func(v *LocalCredentialRecoveryInspection) { v.InputCommitment = "sha256:" + strings.Repeat("c", 64) },
		"scope":                     func(v *LocalCredentialRecoveryInspection) { v.Scope.PrincipalID = "another-primary" },
		"missing result":            func(v *LocalCredentialRecoveryInspection) { v.Result = nil },
		"missing original expected": func(v *LocalCredentialRecoveryInspection) { v.Expected = nil },
		"missing receipt cannot supply current state": func(v *LocalCredentialRecoveryInspection) { v.State = "NOT_FOUND"; v.Result = nil },
		"eligible cannot assert receipt":              func(v *LocalCredentialRecoveryInspection) { v.State = "ELIGIBLE" },
	} {
		t.Run(name, func(t *testing.T) {
			v := inspection
			mutate(&v)
			if ValidateLocalCredentialRecoveryInspection(v) == nil {
				t.Fatal("invalid historical completion accepted")
			}
		})
	}
	missing := inspection
	missing.State, missing.Expected, missing.Result = "NOT_FOUND", nil, nil
	if err := ValidateLocalCredentialRecoveryInspection(missing); err != nil {
		t.Fatal(err)
	}
	query := LocalCredentialRecoveryReceiptQuery{APIVersion: APIVersion, Kind: "LocalCredentialRecoveryReceiptQuery", CommandID: result.CommandID, InputCommitment: result.InputCommitment}
	if err := ValidateLocalCredentialRecoveryReceiptQuery(query); err != nil {
		t.Fatal(err)
	}
	forgedQuery := `{"apiVersion":"` + APIVersion + `","kind":"LocalCredentialRecoveryReceiptQuery","commandId":"command-original","inputCommitment":"` + result.InputCommitment + `","tenantId":"other"}`
	if DecodeRequest(strings.NewReader(forgedQuery), &query) == nil {
		t.Fatal("receipt query accepted a target selector")
	}
}

func TestPublicBootstrapDigestPreservesTheSealedPrivateBytes(t *testing.T) {
	document := decodeIAMExample[BootstrapDocument](t, "examples/bootstrap-document.json")
	encoded, err := EncodeBootstrapDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	got, err := BootstrapDigest(document)
	if err != nil || got != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatalf("bootstrap byte commitment changed: %v", err)
	}
	if _, err := json.Marshal(document); !errors.Is(err, ErrSecretSerialization) {
		t.Fatal("public digest exposed ordinary bootstrap serialization")
	}
}

func TestPlatformDecisionsCannotMasqueradeAsTenantAuthority(t *testing.T) {
	source, err := os.ReadFile("examples/authorization-decision-allowed.json")
	if err != nil {
		t.Fatal(err)
	}
	var valid AuthorizationDecision
	if err := json.Unmarshal(source, &valid); err != nil {
		t.Fatal(err)
	}
	valid.Action, valid.Resource.Kind = ActionPaaSExecutionTargetRegister, ResourceExecutionTarget
	valid.TenantID, valid.InstallationID = "", "installation-example"
	if err := ValidateAuthorizationDecision(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AuthorizationDecision){
		"missing installation": func(value *AuthorizationDecision) { value.InstallationID = "" },
		"mixed authorities":    func(value *AuthorizationDecision) { value.TenantID = "organization-example" },
		"tenant action": func(value *AuthorizationDecision) {
			value.Action, value.Resource.Kind = ActionPaaSApplicationRead, ResourceApplication
		},
		"denial leak": func(value *AuthorizationDecision) {
			value.Allowed, value.Reason, value.Subject = false, DecisionDenied, nil
		},
		"service authority": func(value *AuthorizationDecision) {
			subject := *value.Subject
			subject.Type = PrincipalServiceAccount
			value.Subject = &subject
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			if ValidateAuthorizationDecision(value) == nil {
				t.Fatal("invalid platform authority accepted")
			}
		})
	}
}

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

func TestQualifiedLoginIsAnAccountNamespaceNotAnEmail(t *testing.T) {
	for _, name := range []string{"admin", "developer@acme", "developer@123456789", "developer@tenant-prod", "developer@tenant.example", "dev.user@tenant:region-1"} {
		if err := ValidateLoginIdentifier(name); err != nil {
			t.Errorf("valid login %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"developer@", "@acme", "developer@@acme", "developer@acme@other", "developer@ acme", " developer@acme", "developer@acme ", "Dev@acme", "developer@主账号", "developer@acme/other"} {
		if ValidateLoginIdentifier(name) == nil {
			t.Errorf("invalid login %q accepted", name)
		}
	}
	for _, alias := range []string{"acme", "team-42", "a" + strings.Repeat("b", 61) + "9"} {
		if ValidateAccountAlias(alias) != nil {
			t.Errorf("valid alias %q rejected", alias)
		}
	}
	for _, alias := range []string{"", "ab", "Acme", "123", "team-", "-team", "team.example", "team_name", strings.Repeat("a", 64)} {
		if ValidateAccountAlias(alias) == nil {
			t.Errorf("invalid alias %q accepted", alias)
		}
	}
	create := decodeIAMExample[CreateUserRequest](t, "examples/create-user-request.json")
	create.LoginName = "developer@acme"
	if ValidateCreateUserRequest(create) == nil {
		t.Fatal("user creation accepted a qualified local username")
	}
	create.LoginName = "developer"
	if ValidateCreateUserRequest(create) != nil {
		t.Fatal("creation without an initial role must be accepted")
	}
	for _, role := range AllBuiltinRoles() {
		create.InitialRole = &role
		if (ValidateCreateUserRequest(create) == nil) != (role != RoleInstallationVerifier && role != RolePlatformOperator) {
			t.Errorf("initial role assignability is wrong for %s", role)
		}
	}
}

func TestAccountDirectoryContractsRejectCrossTenantAuthority(t *testing.T) {
	principal := decodeIAMExample[Principal](t, "examples/principal.json")
	binding := decodeIAMExample[RoleBinding](t, "examples/role-binding.json")
	binding.PrincipalID, binding.OrganizationID = principal.ID, principal.OrganizationID
	list := PrincipalList{APIVersion: APIVersion, Kind: "PrincipalList", Items: []PrincipalAccess{{Principal: principal, RoleBindings: []RoleBinding{binding}}}}
	if err := ValidatePrincipalList(list); err != nil {
		t.Fatalf("valid directory: %v", err)
	}
	list.Items[0].RoleBindings[0].OrganizationID = "organization-other"
	if ValidatePrincipalList(list) == nil {
		t.Fatal("directory accepted a cross-tenant role binding")
	}
	list.Items[0].RoleBindings = []RoleBinding{}
	list.NextAfter = "different-principal"
	if ValidatePrincipalList(list) == nil {
		t.Fatal("directory accepted an unrelated cursor")
	}
	list.NextAfter = ""
	list.Items = append(list.Items, list.Items[0])
	if ValidatePrincipalList(list) == nil {
		t.Fatal("directory accepted duplicate principals")
	}
	if ValidateSetAccountAliasRequest(SetAccountAliasRequest{Alias: "acme", RequestID: "request-alias"}) == nil {
		t.Fatal("alias mutation accepted no concurrency version")
	}
	if ValidateSetPrincipalStatusRequest(SetPrincipalStatusRequest{Status: "REMOVED", ResourceVersion: 1, RequestID: "request-status"}) == nil {
		t.Fatal("unsupported status accepted")
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
