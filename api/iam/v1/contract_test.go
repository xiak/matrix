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

var removedBuiltinRoleNames = []string{
	"ORGANIZATION_ADMIN",
	"PLATFORM_OPERATOR",
	"PAAS_DEVELOPER",
	"PAAS_VIEWER",
	"AUDIT_READER",
	"INSTALLATION_VERIFIER",
}

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
		AccountID: "organization-original", PrincipalID: "principal-original",
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
		"tenant":               func(v *LocalCredentialRecoveryRequest) { v.Scope.AccountID = "organization-other" },
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
	scope := LocalCredentialRecoveryScope{InstallationID: "installation-original", BootstrapDigest: "sha256:" + strings.Repeat("a", 64), AccountID: "organization-original", PrincipalID: "principal-original"}
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
		{"account", validIAMExample[Account]("examples/account.json", ValidateAccount)},
		{"user", validIAMExample[User]("examples/user.json", ValidateUser)},
		{"bootstrap status", validIAMExample[BootstrapStatus]("examples/bootstrap-status.json", ValidateBootstrapStatus)},
		{"service identity", validIAMExample[ServiceIdentity]("examples/service-identity.json", ValidateServiceIdentity)},
		{"login request", validIAMExample[LoginRequest]("examples/login-request.json", ValidateLoginRequest)},
		{"login response", validIAMExample[LoginResponse]("examples/login-response.json", ValidateLoginResponse)},
		{"logout request", validIAMExample[LogoutRequest]("examples/logout-request.json", ValidateLogoutRequest)},
		{"logout response", validIAMExample[LogoutResponse]("examples/logout-response.json", ValidateLogoutResponse)},
		{"password request", validIAMExample[ChangePasswordRequest]("examples/change-password-request.json", ValidateChangePasswordRequest)},
		{"password response", validIAMExample[ChangePasswordResponse]("examples/change-password-response.json", ValidateChangePasswordResponse)},
		{"create user", validIAMExample[CreateUserRequest]("examples/create-user-request.json", ValidateCreateUserRequest)},
		{"create policy attachment", validIAMExample[CreatePolicyAttachmentRequest]("examples/create-policy-attachment-request.json", ValidateCreatePolicyAttachmentRequest)},
		{"revoke policy attachment", validIAMExample[RevokePolicyAttachmentRequest]("examples/revoke-policy-attachment-request.json", ValidateRevokePolicyAttachmentRequest)},
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

func TestIAMActionDefinitionsDeclareProductServiceAndScope(t *testing.T) {
	// These cases pin security boundaries, including equal resource kinds in
	// different authority scopes and managedservice's PaaS caller.
	for _, want := range []ActionDefinition{
		{ActionIAMAccountCreate, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeInstallation},
		{ActionIAMAccountRootCredentialsRecover, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeInstallation},
		{ActionIAMUserCreate, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeTenant},
		{ActionIAMPolicyAttachmentCreate, ProductIAM, ServiceIAM, ResourceUser, AuthorityScopeTenant},
		{ActionIAMPolicyAttachmentRevoke, ProductIAM, ServiceIAM, ResourcePolicyAttachment, AuthorityScopeTenant},
		{ActionIAMPlatformPolicyAttachmentCreate, ProductIAM, ServiceIAM, ResourceUser, AuthorityScopeInstallation},
		{ActionIAMPlatformPolicyAttachmentRevoke, ProductIAM, ServiceIAM, ResourcePolicyAttachment, AuthorityScopeInstallation},
		{ActionIAMSessionRevoke, ProductIAM, ServiceIAM, ResourceSession, AuthorityScopeTenant},
		{ActionPaaSApplicationCreate, ProductPaaS, ServicePaaS, ResourceApplication, AuthorityScopeTenant},
		{ActionPaaSExecutionPoolCreate, ProductPaaS, ServicePaaS, ResourceExecutionPool, AuthorityScopeInstallation},
		{ActionPaaSExecutionTargetRegister, ProductPaaS, ServicePaaS, ResourceExecutionTarget, AuthorityScopeInstallation},
		{ActionPaaSOperationRead, ProductPaaS, ServicePaaS, ResourceOperation, AuthorityScopeTenant},
		{ActionPaaSPlatformOperationRead, ProductPaaS, ServicePaaS, ResourceOperation, AuthorityScopeInstallation},
		{ActionManagedServiceOfferingRead, ProductManagedService, ServicePaaS, ResourceServiceOffering, AuthorityScopeTenant},
		{ActionManagedServiceInstallationCreate, ProductManagedService, ServicePaaS, ResourceServiceInstallation, AuthorityScopeTenant},
		{ActionAuditRecordRead, ProductAudit, ServiceAudit, ResourceAuditRecord, AuthorityScopeTenant},
		{ActionAuditPlatformRecordRead, ProductAudit, ServiceAudit, ResourceAuditRecord, AuthorityScopeInstallation},
		{ActionAuditIntegrityVerify, ProductAudit, ServiceAudit, ResourceAuditChain, AuthorityScopeTenant},
		{ActionAuditPlatformIntegrityVerify, ProductAudit, ServiceAudit, ResourceAuditChain, AuthorityScopeInstallation},
		{ActionInstallationVerify, ProductInstallation, ServiceInstallationVerifier, ResourceInstallation, AuthorityScopeInstallationProbe},
	} {
		if got, known := LookupActionDefinition(want.Action); !known || got != want {
			t.Errorf("definition %s = %+v known=%v, want %+v", want.Action, got, known, want)
		}
	}

	callers := map[ProductID]ServicePurpose{
		ProductIAM: ServiceIAM, ProductPaaS: ServicePaaS, ProductManagedService: ServicePaaS,
		ProductAudit: ServiceAudit, ProductInstallation: ServiceInstallationVerifier,
	}
	seen := make(map[Action]bool)
	for _, definition := range AllActionDefinitions() {
		if seen[definition.Action] || definition.Action == "" {
			t.Fatalf("duplicate/empty action definition %q", definition.Action)
		}
		seen[definition.Action] = true
		if caller, known := callers[definition.Product]; !known || caller != definition.CallingService {
			t.Errorf("product caller changed: %+v", definition)
		}
		switch definition.AuthorityScope {
		case AuthorityScopeTenant, AuthorityScopeInstallation:
			if definition.Product == ProductInstallation {
				t.Fatal("installation verifier became a business authorization product")
			}
		case AuthorityScopeInstallationProbe:
			if definition.Action != ActionInstallationVerify || definition.CallingService != ServiceInstallationVerifier {
				t.Fatal("probe scope admitted an unrelated action or service")
			}
		default:
			t.Errorf("missing authority scope: %+v", definition)
		}
		kind, known := ResourceKindForAction(definition.Action)
		if !known || kind != definition.ResourceKind || IsPlatformAction(definition.Action) != (definition.AuthorityScope == AuthorityScopeInstallation) {
			t.Errorf("validators diverge from the definition: %+v", definition)
		}
	}
	actions := AllActions()
	if len(seen) != len(actions) {
		t.Fatal("action inventory and definitions diverge")
	}
	for _, action := range actions {
		if !seen[action] {
			t.Errorf("action %s lacks an explicit definition", action)
		}
	}
	for _, unknown := range []Action{"", "iam.principal.unknown", "paas.unregistered.execute", "installation.verify.other"} {
		if definition, known := LookupActionDefinition(unknown); known || definition != (ActionDefinition{}) || IsPlatformAction(unknown) {
			t.Errorf("unknown action obtained a definition/authority: %q", unknown)
		}
	}
}

func TestIAMCatalogReadsCannotModifyAuthority(t *testing.T) {
	want, known := LookupActionDefinition(ActionIAMAccountCreate)
	if !known {
		t.Fatal("account creation is not registered")
	}
	definitions := AllActionDefinitions()
	for index := range definitions {
		definitions[index] = ActionDefinition{Action: "paas.forged.execute", CallingService: ServicePaaS}
	}
	actions := AllActions()
	for index := range actions {
		actions[index] = "paas.forged.execute"
	}
	copy, _ := LookupActionDefinition(want.Action)
	copy.CallingService, copy.AuthorityScope = ServicePaaS, AuthorityScopeTenant
	if got, known := LookupActionDefinition(want.Action); !known || got != want {
		t.Fatal("caller mutation changed the authority catalog")
	}
	for _, definition := range AllActionDefinitions() {
		if definition.Action == "paas.forged.execute" {
			t.Fatal("definition slice exposed mutable catalog storage")
		}
	}
	for _, action := range AllActions() {
		if action == "paas.forged.execute" {
			t.Fatal("action slice exposed mutable catalog storage")
		}
	}
	for index := range AllRecordedActionDefinitions() {
		copy := AllRecordedActionDefinitions()
		copy[index] = ActionDefinition{Action: "iam.forged.execute"}
	}
	seen := map[Action]bool{}
	for _, definition := range AllRecordedActionDefinitions() {
		if definition.Action == "iam.forged.execute" || seen[definition.Action] {
			t.Fatal("historical catalog was mutable or ambiguous")
		}
		seen[definition.Action] = true
	}
}

func policyDocumentFixture() PolicyDocument {
	return PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant, Statements: []PolicyStatement{
		{SID: "read", Effect: PolicyAllow, Actions: []Action{ActionPaaSDeploymentRead, ActionPaaSApplicationRead}, Resources: []PolicyResourceSelector{
			{Kind: ResourceDeployment, Match: PolicyResourceExact, ID: "deployment-one"},
			{Kind: ResourceApplication, Match: PolicyResourceExact, ID: "application-one"},
		}},
		{SID: "create", Effect: PolicyDeny, Actions: []Action{ActionPaaSApplicationCreate}, Resources: []PolicyResourceSelector{
			{Kind: ResourceApplication, Match: PolicyResourceAnyInAuthority},
		}},
	}}
}

func TestPolicyIdentityStringConditionsAreBoundedSets(t *testing.T) {
	plain, _, err := CanonicalizePolicyDocument(policyDocumentFixture())
	if err != nil {
		t.Fatal(err)
	}
	withConditions := func(value string) string {
		return strings.Replace(plain, `"resources":`, `"conditions":`+value+`,"resources":`, 1)
	}
	valid := `[{"key":"iam.account-id","operator":"STRING_EQUALS","values":["account-b","account-a"]},{"key":"iam.principal-id","operator":"STRING_EQUALS","values":["principal-z","principal-a"]},{"key":"iam.principal-id","operator":"STRING_NOT_EQUALS","values":["principal-denied"]}]`
	document, err := DecodePolicyDocument(strings.NewReader(withConditions(valid)))
	if err != nil {
		t.Fatal("declared identity conditions rejected", err)
	}
	before, _ := json.Marshal(document)
	canonical, digest, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(document)
	if !bytes.Equal(before, after) {
		t.Fatal("string set normalization mutated caller input")
	}
	reordered, err := DecodePolicyDocument(strings.NewReader(withConditions(strings.ReplaceAll(strings.ReplaceAll(valid, `"account-b","account-a"`, `"account-a","account-b"`), `"principal-z","principal-a"`, `"principal-a","principal-z"`))))
	if err != nil {
		t.Fatal(err)
	}
	if other, otherDigest, err := CanonicalizePolicyDocument(reordered); err != nil || canonical != other || digest != otherDigest {
		t.Fatal("string set order changed canonical permission content")
	}
	tooMany := make([]string, 17)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("principal-%d", index)
	}
	tooManyJSON, _ := json.Marshal(tooMany)
	for _, invalid := range []string{
		strings.Replace(valid, "iam.account-id", "caller.account-id", 1),
		strings.Replace(valid, "iam.account-id", "iam.principal-id", 1),
		strings.Replace(valid, "STRING_NOT_EQUALS", "STRING_EQUALS", 1),
		strings.Replace(valid, "STRING_NOT_EQUALS", "DATE_LESS_THAN", 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":[]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":null`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":[1]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":[""]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":["principal-*"]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":[" principal-denied"]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":["principal-denied","principal-denied"]`, 1),
		strings.Replace(valid, `"values":["principal-denied"]`, `"values":`+string(tooManyJSON), 1),
		strings.Replace(valid, `"key":`, `"source":"CALLER","key":`, 1),
	} {
		if _, err := DecodePolicyDocument(strings.NewReader(withConditions(invalid))); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid identity condition admitted")
		}
	}
	for _, action := range AllActionDefinitions() {
		for _, key := range []ConditionKey{"iam.account-id", "iam.principal-id"} {
			definition, found := LookupActionConditionDefinition(action.Action, key)
			if found != (action.AuthorityScope == AuthorityScopeTenant) || found && (definition.Source != "IAM_AUTHENTICATED_IDENTITY" || definition.ValueType != "STRING") {
				t.Fatal("identity condition source crossed a scope")
			}
		}
	}
}

func TestPolicyTimeConditionsAreStrictAndPreserveUnconditionalContent(t *testing.T) {
	for _, action := range AllActionDefinitions() {
		definition, found := LookupActionConditionDefinition(action.Action, ConditionIAMCurrentTime)
		if found != (action.AuthorityScope == AuthorityScopeTenant) || (found && (definition.Source != ConditionIAMTransactionTime || definition.ValueType != ConditionTime)) {
			t.Fatal("time source declaration crossed a scope")
		}
		if _, found := LookupActionConditionDefinition(action.Action, "caller.time"); found {
			t.Fatal("unknown condition declared")
		}
	}
	if _, found := LookupActionConditionDefinition("unknown.action", ConditionIAMCurrentTime); found {
		t.Fatal("unknown action acquired time condition support")
	}
	original, digest, err := CanonicalizePolicyDocument(policyDocumentFixture())
	if err != nil {
		t.Fatal(err)
	}
	withConditions := func(conditions string) string {
		return strings.Replace(original, `"resources":`, `"conditions":`+conditions+`,"resources":`, 1)
	}
	valid := `[{"key":"iam.current-time","operator":"DATE_GREATER_THAN_EQUALS","values":["2026-09-14T00:00:00Z"]},{"key":"iam.current-time","operator":"DATE_LESS_THAN","values":["2026-09-15T00:00:00Z"]}]`
	document, err := DecodePolicyDocument(strings.NewReader(withConditions(valid)))
	if err != nil {
		t.Fatal("declared time window rejected", err)
	}
	before, _ := json.Marshal(document)
	encoded, _, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(document)
	if !bytes.Equal(before, after) {
		t.Fatal("condition canonicalization mutated caller input")
	}
	reversed := document
	reversed.Statements = append([]PolicyStatement(nil), document.Statements...)
	reversed.Statements[0].Conditions = append([]PolicyCondition(nil), document.Statements[0].Conditions...)
	reversed.Statements[0].Conditions[0], reversed.Statements[0].Conditions[1] = reversed.Statements[0].Conditions[1], reversed.Statements[0].Conditions[0]
	if normalized, _, err := CanonicalizePolicyDocument(reversed); err != nil || normalized != encoded {
		t.Fatal("condition AND order changed canonical authority")
	}
	roundTrip, err := DecodePolicyDocument(strings.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, err := CanonicalizePolicyDocument(roundTrip)
	if err != nil || canonical != encoded {
		t.Fatal("condition canonical round trip changed content")
	}
	for _, invalid := range []string{
		`null`, `[]`,
		strings.Replace(valid, "iam.current-time", "request.current-time", 1),
		strings.Replace(valid, "DATE_LESS_THAN", "DATE_NOT_EQUALS", 1),
		strings.Replace(valid, "2026-09-15T00:00:00Z", "2026-09-14T00:00:00Z", 1),
		strings.Replace(valid, "2026-09-15T00:00:00Z", "2026-09-13T00:00:00Z", 1),
		strings.Replace(valid, "2026-09-15T00:00:00Z", "2026-09-15T00:00:00+00:00", 1),
		strings.Replace(valid, "2026-09-15T00:00:00Z", "2026-09-15T00:00:00.0000001Z", 1),
		strings.Replace(valid, "2026-09-15T00:00:00Z", "2026-02-30T00:00:00Z", 1),
		strings.Replace(valid, `"values":["2026-09-14T00:00:00Z"]`, `"values":[]`, 1),
		strings.Replace(valid, `"values":["2026-09-14T00:00:00Z"]`, `"values":[123]`, 1),
		strings.Replace(valid, `"values":["2026-09-14T00:00:00Z"]`, `"values":["2026-09-14T00:00:00Z","2026-09-13T00:00:00Z"]`, 1),
		strings.Replace(valid, `"key":`, `"source":"CALLER","key":`, 1),
		strings.Replace(valid, "DATE_LESS_THAN", "DATE_GREATER_THAN_EQUALS", 1),
	} {
		if _, err := DecodePolicyDocument(strings.NewReader(withConditions(invalid))); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid time condition admitted")
		}
	}
	plain, err := DecodePolicyDocument(strings.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	retained, retainedDigest, err := CanonicalizePolicyDocument(plain)
	if err != nil || retained != original || retainedDigest != digest || strings.Contains(retained, "conditions") {
		t.Fatal("unconditional canonical content changed")
	}
}

func TestPolicyContentCanonicalizationIsStableAndDoesNotMutateTheDocument(t *testing.T) {
	document := policyDocumentFixture()
	before, _ := json.Marshal(document)
	encoded, digest, err := CanonicalizePolicyDocument(document)
	if err != nil || ValidateDigest("policy digest", digest) != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	after, _ := json.Marshal(document)
	if !bytes.Equal(before, after) {
		t.Fatal("canonicalization mutated caller-owned collections")
	}
	document.Statements[0], document.Statements[1] = document.Statements[1], document.Statements[0]
	document.Statements[1].Actions[0], document.Statements[1].Actions[1] = document.Statements[1].Actions[1], document.Statements[1].Actions[0]
	document.Statements[1].Resources[0], document.Statements[1].Resources[1] = document.Statements[1].Resources[1], document.Statements[1].Resources[0]
	if reordered, reorderedDigest, err := CanonicalizePolicyDocument(document); err != nil || reordered != encoded || reorderedDigest != digest {
		t.Fatalf("set ordering changed canonical policy content: %v", err)
	}
	decoded, err := DecodePolicyDocument(strings.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	version := PolicyVersion{PolicyID: "policy-example", ID: "version-first", Document: decoded, ContentDigest: digest}
	if ValidatePolicyVersion(version) != nil {
		t.Fatal("valid immutable version rejected")
	}
	version.Document.Statements[0].Effect = PolicyAllow
	if ValidatePolicyVersion(version) == nil {
		t.Fatal("changed policy content retained its old digest")
	}
	if _, changedDigest, err := CanonicalizePolicyDocument(version.Document); err != nil || changedDigest == digest {
		t.Fatal("effect change did not change the digest")
	}
}

func TestPolicyLanguageRejectsUnsupportedOrAmbiguousAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*PolicyDocument){
		"language":                   func(v *PolicyDocument) { v.LanguageVersion = "future" },
		"scope":                      func(v *PolicyDocument) { v.Scope = "ACCOUNT_FROM_REQUEST" },
		"empty statements":           func(v *PolicyDocument) { v.Statements = nil },
		"empty sid":                  func(v *PolicyDocument) { v.Statements[0].SID = "" },
		"duplicate sid":              func(v *PolicyDocument) { v.Statements[0].SID = v.Statements[1].SID },
		"unknown effect":             func(v *PolicyDocument) { v.Statements[0].Effect = "PERMIT" },
		"empty actions":              func(v *PolicyDocument) { v.Statements[0].Actions = nil },
		"unknown action":             func(v *PolicyDocument) { v.Statements[0].Actions[0] = "paas.*" },
		"duplicate action":           func(v *PolicyDocument) { v.Statements[0].Actions[0] = v.Statements[0].Actions[1] },
		"mixed scope":                func(v *PolicyDocument) { v.Statements[0].Actions[0] = ActionPaaSExecutionTargetRegister },
		"missing required resource":  func(v *PolicyDocument) { v.Statements[0].Resources = v.Statements[0].Resources[:1] },
		"extra resource kind":        func(v *PolicyDocument) { v.Statements[0].Resources[0].Kind = ResourcePrincipal },
		"unknown match":              func(v *PolicyDocument) { v.Statements[0].Resources[0].Match = "PREFIX" },
		"exact wildcard":             func(v *PolicyDocument) { v.Statements[0].Resources[0].ID = "*" },
		"missing exact id":           func(v *PolicyDocument) { v.Statements[0].Resources[0].ID = "" },
		"authority wildcard with id": func(v *PolicyDocument) { v.Statements[1].Resources[0].ID = "selected-by-caller" },
		"duplicate selector": func(v *PolicyDocument) {
			v.Statements[0].Resources = append(v.Statements[0].Resources, v.Statements[0].Resources[0])
		},
		"too many actions": func(v *PolicyDocument) { v.Statements[0].Actions = make([]Action, MaxStatementActions+1) },
		"too many resources": func(v *PolicyDocument) {
			v.Statements[0].Resources = make([]PolicyResourceSelector, MaxStatementResources+1)
		},
		"too many statements": func(v *PolicyDocument) { v.Statements = make([]PolicyStatement, MaxPolicyStatements+1) },
	} {
		t.Run(name, func(t *testing.T) {
			document := policyDocumentFixture()
			mutate(&document)
			if !errors.Is(ValidatePolicyDocument(document), ErrInvalidPolicy) {
				t.Fatal("invalid policy accepted")
			}
			if encoded, digest, err := CanonicalizePolicyDocument(document); !errors.Is(err, ErrInvalidPolicy) || encoded != "" || digest != "" {
				t.Fatal("invalid policy acquired canonical authority")
			}
		})
	}
	encoded, _, _ := CanonicalizePolicyDocument(policyDocumentFixture())
	for _, forged := range []string{
		strings.Replace(encoded, `"languageVersion":`, `"languageVersion":"future","languageVersion":`, 1),
		strings.Replace(encoded, `"effect":`, `"conditions":{"callerAdmin":true},"effect":`, 1),
		strings.Replace(encoded, `"kind":"APPLICATION"`, `"kind":"PRINCIPAL","kind":"APPLICATION"`, 1),
		strings.Replace(encoded, `"scope":`, `"tenantId":"other","scope":`, 1),
		strings.Replace(encoded, `"actions":[`, `"actions":[null,`, 1),
		strings.Replace(encoded, `"match":"ANY_IN_AUTHORITY"`, `"match":"ANY_IN_AUTHORITY","id":null`, 1),
		strings.Replace(encoded, `"match":"ANY_IN_AUTHORITY"`, `"match":"ANY_IN_AUTHORITY","id":""`, 1),
		encoded + `{}`,
		strings.Repeat(" ", int(MaxPolicyBytes)) + encoded,
	} {
		if _, err := DecodePolicyDocument(strings.NewReader(forged)); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("ambiguous/unsupported wire document accepted")
		}
	}
}

func TestPolicyDiagnosticsLocateRejectedAuthorityWithoutEchoingInput(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(*PolicyDocument)
		code    PolicyValidationCode
		pointer string
	}{
		{"language", func(v *PolicyDocument) { v.LanguageVersion = "untrusted-private-input" }, PolicyUnsupported, "/languageVersion"},
		{"scope", func(v *PolicyDocument) { v.Scope = "untrusted-private-input" }, PolicyInvalidValue, "/scope"},
		{"empty statements", func(v *PolicyDocument) { v.Statements = nil }, PolicyLimitExceeded, "/statements"},
		{"statement limit", func(v *PolicyDocument) { v.Statements = make([]PolicyStatement, MaxPolicyStatements+1) }, PolicyLimitExceeded, "/statements"},
		{"sid", func(v *PolicyDocument) { v.Statements[0].SID = "bad/input" }, PolicyInvalidValue, "/statements/0/sid"},
		{"duplicate sid", func(v *PolicyDocument) { v.Statements[1].SID = v.Statements[0].SID }, PolicyDuplicate, "/statements/1/sid"},
		{"effect", func(v *PolicyDocument) { v.Statements[0].Effect = "untrusted-private-input" }, PolicyInvalidValue, "/statements/0/effect"},
		{"empty actions", func(v *PolicyDocument) { v.Statements[0].Actions = nil }, PolicyLimitExceeded, "/statements/0/actions"},
		{"action limit", func(v *PolicyDocument) { v.Statements[0].Actions = make([]Action, MaxStatementActions+1) }, PolicyLimitExceeded, "/statements/0/actions"},
		{"empty resources", func(v *PolicyDocument) { v.Statements[0].Resources = nil }, PolicyLimitExceeded, "/statements/0/resources"},
		{"resource limit", func(v *PolicyDocument) {
			v.Statements[0].Resources = make([]PolicyResourceSelector, MaxStatementResources+1)
		}, PolicyLimitExceeded, "/statements/0/resources"},
		{"unknown action", func(v *PolicyDocument) { v.Statements[0].Actions[0] = "untrusted-private-input" }, PolicyUnsupported, "/statements/0/actions/0"},
		{"scope mismatch", func(v *PolicyDocument) { v.Statements[0].Actions[0] = ActionPaaSExecutionTargetRegister }, PolicyScopeMismatch, "/statements/0/actions/0"},
		{"duplicate action", func(v *PolicyDocument) { v.Statements[0].Actions[1] = v.Statements[0].Actions[0] }, PolicyDuplicate, "/statements/0/actions/1"},
		{"resource kind", func(v *PolicyDocument) { v.Statements[0].Resources[0].Kind = ResourceUser }, PolicyResourceMismatch, "/statements/0/resources/0/kind"},
		{"resource match", func(v *PolicyDocument) { v.Statements[0].Resources[0].Match = "untrusted-private-input" }, PolicyUnsupported, "/statements/0/resources/0/match"},
		{"resource id", func(v *PolicyDocument) { v.Statements[0].Resources[0].ID = "bad/input" }, PolicyInvalidValue, "/statements/0/resources/0/id"},
		{"authority id", func(v *PolicyDocument) { v.Statements[1].Resources[0].ID = "untrusted-private-input" }, PolicyInvalidValue, "/statements/1/resources/0/id"},
		{"duplicate resource", func(v *PolicyDocument) {
			v.Statements[0].Resources = append(v.Statements[0].Resources, v.Statements[0].Resources[0])
		}, PolicyDuplicate, "/statements/0/resources/2"},
		{"missing resource", func(v *PolicyDocument) { v.Statements[0].Resources = v.Statements[0].Resources[:1] }, PolicyResourceMismatch, "/statements/0/actions/1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := policyDocumentFixture()
			test.mutate(&document)
			before, _ := json.Marshal(document)
			for range 3 {
				canonical, digest, encodingError := CanonicalizePolicyDocument(document)
				if canonical != "" || digest != "" {
					t.Fatal("rejected document acquired canonical authority")
				}
				for _, err := range []error{ValidatePolicyDocument(document), encodingError} {
					var diagnostic *PolicyValidationError
					if !errors.Is(err, ErrInvalidPolicy) || !errors.As(err, &diagnostic) || diagnostic.Code != test.code || diagnostic.Pointer != test.pointer {
						t.Fatalf("unexpected safe diagnostic: %#v", diagnostic)
					}
					if err.Error() != ErrInvalidPolicy.Error() {
						t.Fatal("ordinary error exposed diagnostic or input")
					}
				}
			}
			after, _ := json.Marshal(document)
			if !bytes.Equal(before, after) {
				t.Fatal("analysis changed the submitted policy")
			}
		})
	}
}

func TestPolicyDecodeDiagnosticsPreserveStrictDocumentRejection(t *testing.T) {
	valid, _, err := CanonicalizePolicyDocument(policyDocumentFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{
		`null`, `[]`, `{"languageVersion":`, valid + `{}`,
		strings.Replace(valid, `"scope":`, `"scope":"TENANT","scope":`, 1),
		strings.Replace(valid, `"scope":`, `"private-input":"must-not-be-echoed","scope":`, 1),
		strings.Replace(valid, `"actions":[`, `"actions":[{},`, 1),
		strings.Replace(valid, `"match":"ANY_IN_AUTHORITY"`, `"match":"ANY_IN_AUTHORITY","id":null`, 1),
	} {
		_, err := DecodePolicyDocument(strings.NewReader(source))
		var diagnostic *PolicyValidationError
		if !errors.Is(err, ErrInvalidPolicy) || !errors.As(err, &diagnostic) || diagnostic.Code != PolicyInvalidDocument || diagnostic.Pointer != "" {
			t.Fatalf("ambiguous JSON was accepted or mislocated: %#v", diagnostic)
		}
		if err.Error() != ErrInvalidPolicy.Error() {
			t.Fatal("malformed JSON leaked native decoder details")
		}
	}
	_, err = DecodePolicyDocument(strings.NewReader(strings.Repeat(" ", int(MaxPolicyBytes)) + valid))
	var diagnostic *PolicyValidationError
	if !errors.As(err, &diagnostic) || diagnostic.Code != PolicyLimitExceeded || diagnostic.Pointer != "" {
		t.Fatal("raw input size limit did not produce a bounded root diagnostic")
	}
	large := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant}
	for i := range MaxPolicyStatements {
		statement := PolicyStatement{SID: fmt.Sprintf("statement-%d", i), Effect: PolicyAllow, Actions: []Action{ActionPaaSApplicationRead}}
		for j := range MaxStatementResources {
			statement.Resources = append(statement.Resources, PolicyResourceSelector{Kind: ResourceApplication, Match: PolicyResourceExact, ID: strings.Repeat("r", 120) + fmt.Sprintf("%03d", j)})
		}
		large.Statements = append(large.Statements, statement)
	}
	canonical, digest, encodingError := CanonicalizePolicyDocument(large)
	if canonical != "" || digest != "" {
		t.Fatal("oversized typed document acquired canonical authority")
	}
	for _, err := range []error{ValidatePolicyDocument(large), encodingError} {
		if !errors.As(err, &diagnostic) || diagnostic.Code != PolicyLimitExceeded || diagnostic.Pointer != "" {
			t.Fatal("typed document size limit did not produce a root diagnostic")
		}
	}
}

func FuzzPolicyDocumentCanonicalRoundTrip(f *testing.F) {
	valid, _, _ := CanonicalizePolicyDocument(policyDocumentFixture())
	f.Add(valid)
	timed := policyDocumentFixture()
	timed.Statements[0].Conditions = []PolicyCondition{{Key: ConditionIAMCurrentTime, Operator: PolicyDateLessThan, Values: []string{"2026-09-15T00:00:00Z"}}}
	timedCanonical, _, err := CanonicalizePolicyDocument(timed)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(timedCanonical)
	identity := policyDocumentFixture()
	identity.Statements[0].Conditions = []PolicyCondition{{Key: ConditionIAMPrincipalID, Operator: PolicyStringNotEquals, Values: []string{"user-z", "user-a"}}}
	identityCanonical, _, err := CanonicalizePolicyDocument(identity)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(identityCanonical)
	f.Add(`{"languageVersion":"1","scope":"TENANT","statements":[]}`)
	f.Add(`{"statements":null}`)
	f.Fuzz(func(t *testing.T, source string) {
		document, err := DecodePolicyDocument(strings.NewReader(source))
		if err != nil {
			var diagnostic *PolicyValidationError
			if !errors.Is(err, ErrInvalidPolicy) || !errors.As(err, &diagnostic) || err.Error() != ErrInvalidPolicy.Error() {
				t.Fatal("rejected input lacks a safe policy diagnostic")
			}
			return
		}
		canonical, digest, err := CanonicalizePolicyDocument(document)
		if err != nil {
			t.Fatal(err)
		}
		repeated, err := DecodePolicyDocument(strings.NewReader(canonical))
		if err != nil {
			t.Fatal(err)
		}
		if again, againDigest, err := CanonicalizePolicyDocument(repeated); err != nil || canonical != again || digest != againDigest {
			t.Fatal("accepted policy has unstable canonical content")
		}
	})
}

func TestPolicyMetadataAndAttachmentOwnershipContracts(t *testing.T) {
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	policy := Policy{APIVersion: APIVersion, Kind: "Policy", ID: "policy-example", Management: PolicyCustomerManaged,
		AccountID: "account-a", DisplayName: "Application reader", Scope: AuthorityScopeTenant, Status: PolicyActive,
		DefaultVersionID: "version-one", ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	attachment := PolicyAttachment{APIVersion: APIVersion, Kind: "PolicyAttachment", ID: "attachment-example", AccountID: "account-a",
		Target: PolicyAttachmentTarget{Kind: PolicyTargetUser, ID: "user-example"}, PolicyID: policy.ID,
		Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	if ValidatePolicy(policy) != nil || ValidatePolicyAttachment(attachment) != nil {
		t.Fatal("valid policy relationship rejected")
	}
	document := policyDocumentFixture()
	_, digest, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	detail := PolicyDetail{APIVersion: APIVersion, Kind: "PolicyDetail", Policy: policy,
		Version: PolicyVersion{PolicyID: policy.ID, ID: policy.DefaultVersionID, Document: document, ContentDigest: digest}}
	if ValidatePolicyDetail(detail) != nil {
		t.Fatal("valid policy detail rejected")
	}
	for name, mutate := range map[string]func(*PolicyDetail){
		"wrong version owner": func(v *PolicyDetail) { v.Version.PolicyID = "another-policy" },
		"wrong default":       func(v *PolicyDetail) { v.Policy.DefaultVersionID = "another-version" },
		"wrong digest":        func(v *PolicyDetail) { v.Version.ContentDigest = "sha256:" + strings.Repeat("0", 64) },
		"retired detail":      func(v *PolicyDetail) { v.Policy.Status = PolicyRetired },
		"unknown wrapper":     func(v *PolicyDetail) { v.Kind = "PolicyPermit" },
	} {
		t.Run(name, func(t *testing.T) {
			value := detail
			mutate(&value)
			if ValidatePolicyDetail(value) == nil {
				t.Fatal("inconsistent policy detail accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*Policy){
		"missing owner":             func(v *Policy) { v.AccountID = "" },
		"customer system namespace": func(v *Policy) { v.ID = SystemPolicyPlatformOperator },
		"customer platform scope":   func(v *Policy) { v.Scope = AuthorityScopeInstallation },
		"customer probe scope":      func(v *Policy) { v.Scope = AuthorityScopeInstallationProbe },
		"unknown manager":           func(v *Policy) { v.Management = "PUBLIC" },
		"unknown status":            func(v *Policy) { v.Status = "DELETED" },
		"no default":                func(v *Policy) { v.DefaultVersionID = "" },
		"zero revision":             func(v *Policy) { v.ResourceVersion = 0 },
		"invalid chronology":        func(v *Policy) { v.UpdatedAt = now.Add(-time.Second) },
		"unsafe display name":       func(v *Policy) { v.DisplayName = "reader\nowner" },
	} {
		t.Run(name, func(t *testing.T) {
			value := policy
			mutate(&value)
			if !errors.Is(ValidatePolicy(value), ErrInvalidPolicy) {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
	system := policy
	system.Management, system.ID, system.AccountID, system.Scope = PolicySystemManaged, SystemPolicyPlatformOperator, "", AuthorityScopeInstallation
	if ValidatePolicy(system) != nil {
		t.Fatal("system metadata rejected")
	}
	system.AccountID = "account-a"
	if ValidatePolicy(system) == nil {
		t.Fatal("system metadata accepted a customer owner")
	}
	for name, mutate := range map[string]func(*PolicyAttachment){
		"missing account":               func(v *PolicyAttachment) { v.AccountID = "" },
		"unknown target":                func(v *PolicyAttachment) { v.Target.Kind = "ROOT" },
		"missing target":                func(v *PolicyAttachment) { v.Target.ID = "" },
		"mixed scope":                   func(v *PolicyAttachment) { v.InstallationID = "installation-a" },
		"platform without installation": func(v *PolicyAttachment) { v.Scope = AuthorityScopeInstallation },
		"unknown scope":                 func(v *PolicyAttachment) { v.Scope = "GLOBAL" },
		"unversioned revocation":        func(v *PolicyAttachment) { v.RevokedAt = &now },
		"revocation time differs":       func(v *PolicyAttachment) { at := now.Add(time.Second); v.RevokedAt, v.ResourceVersion = &at, 2 },
	} {
		t.Run(name, func(t *testing.T) {
			value := attachment
			mutate(&value)
			if ValidatePolicyAttachment(value) == nil {
				t.Fatal("invalid attachment accepted")
			}
		})
	}
	for _, kind := range []PolicyAttachmentTargetKind{PolicyTargetUser, PolicyTargetService, PolicyTargetGroup, PolicyTargetRole} {
		value := attachment
		value.Target.Kind = kind
		if ValidatePolicyAttachment(value) != nil {
			t.Fatal("tenant target contract rejected")
		}
		value.Scope, value.InstallationID = AuthorityScopeInstallation, "installation-a"
		if (ValidatePolicyAttachment(value) == nil) != (kind == PolicyTargetUser) {
			t.Fatal("platform attachment must target a USER")
		}
		value.Scope = AuthorityScopeInstallationProbe
		if (ValidatePolicyAttachment(value) == nil) != (kind == PolicyTargetService) {
			t.Fatal("probe attachment must target a service")
		}
	}
	attachment.RevokedAt, attachment.ResourceVersion = &now, 2
	if ValidatePolicyAttachment(attachment) != nil {
		t.Fatal("immutable revoked relationship rejected")
	}
	policy.Status = PolicyRetired
	if ValidatePolicy(policy) != nil {
		t.Fatal("retired metadata rejected")
	}
	policyJSON, _ := json.Marshal(policy)
	attachmentJSON, _ := json.Marshal(attachment)
	if got, err := DecodePolicy(bytes.NewReader(policyJSON)); err != nil || got.ID != policy.ID {
		t.Fatal("metadata round trip failed")
	}
	if got, err := DecodePolicyAttachment(bytes.NewReader(attachmentJSON)); err != nil || got.RevokedAt == nil {
		t.Fatal("revocation round trip failed")
	}
	for _, prefix := range []string{`{"unknown":true,`, `{"id":"injected",`} {
		if _, err := DecodePolicy(strings.NewReader(prefix + string(policyJSON[1:]))); err == nil {
			t.Fatal("policy accepted unknown/duplicate input")
		}
		if _, err := DecodePolicyAttachment(strings.NewReader(prefix + string(attachmentJSON[1:]))); err == nil {
			t.Fatal("attachment accepted unknown/duplicate input")
		}
	}
}

func TestCurrentIdentityUsesOnlyItsLivePolicyGrantSources(t *testing.T) {
	now := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	blocked := func(action Action, kind ResourceKind, id string) ActionCapability {
		return ActionCapability{Action: action, Resource: ResourceReference{Kind: kind, ID: id}, RestrictionReason: CapabilityAuthorityRequired}
	}
	identity := CurrentIdentity{APIVersion: APIVersion, Kind: "CurrentIdentity",
		Account: Account{APIVersion: APIVersion, Kind: "Account", ID: "account-a", DisplayName: "Account A",
			Status: AccountActive, RootIdentity: RootIdentity{PrincipalID: "user-a", LoginName: "admin"},
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now},
		User: User{APIVersion: APIVersion, Kind: "User", ID: "user-a", AccountID: "account-a",
			LoginName: "admin", DisplayName: "Administrator", Status: PrincipalActive,
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now},
		IdentityKind: IdentityRoot,
		PolicySources: []PolicyGrantSource{{Kind: PolicyGrantDirect, Attachment: PolicyAttachment{
			APIVersion: APIVersion, Kind: "PolicyAttachment", ID: "attachment-a",
			AccountID: "account-a", Target: PolicyAttachmentTarget{Kind: PolicyTargetUser, ID: "user-a"},
			PolicyID: SystemPolicyAccountAdministrator, Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}}},
		Capabilities: []ActionCapability{
			blocked(ActionIAMAccountCreate, ResourceAccount, "accounts"),
			blocked(ActionIAMAccountRead, ResourceAccount, "accounts"),
			blocked(ActionIAMAccountAliasSet, ResourceAccount, "account-a"),
			blocked(ActionIAMUserList, ResourceAccount, "account-a"),
			blocked(ActionIAMUserCreate, ResourceAccount, "account-a"),
			blocked(ActionIAMPolicyList, ResourceAccount, "account-a"),
			blocked(ActionIAMGroupList, ResourceAccount, "account-a"),
			blocked(ActionIAMGroupCreate, ResourceAccount, "account-a"),
		}}
	if ValidateCurrentIdentity(identity) != nil {
		t.Fatal("current policy identity rejected")
	}
	for name, mutate := range map[string]func(*CurrentIdentity){
		"missing snapshot":     func(v *CurrentIdentity) { v.PolicySources = nil },
		"another account":      func(v *CurrentIdentity) { v.PolicySources[0].Attachment.AccountID = "account-b" },
		"another user":         func(v *CurrentIdentity) { v.PolicySources[0].Attachment.Target.ID = "user-b" },
		"service carrier":      func(v *CurrentIdentity) { v.PolicySources[0].Attachment.Target.Kind = PolicyTargetService },
		"duplicate attachment": func(v *CurrentIdentity) { v.PolicySources = append(v.PolicySources, v.PolicySources[0]) },
		"revoked attachment": func(v *CurrentIdentity) {
			v.PolicySources[0].Attachment.RevokedAt = &now
			v.PolicySources[0].Attachment.ResourceVersion = 2
		},
		"missing capability": func(v *CurrentIdentity) { v.Capabilities = v.Capabilities[1:] },
		"wrong capability target": func(v *CurrentIdentity) {
			v.Capabilities[0].Resource.ID = "account-a"
		},
		"available with restriction": func(v *CurrentIdentity) {
			v.Capabilities[0].Available = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := identity
			value.PolicySources = append([]PolicyGrantSource{}, identity.PolicySources...)
			value.Capabilities = append([]ActionCapability{}, identity.Capabilities...)
			mutate(&value)
			if ValidateCurrentIdentity(value) == nil {
				t.Fatal("invalid current attachment relationship accepted")
			}
		})
	}
	membership := GroupMembership{APIVersion: APIVersion, Kind: "GroupMembership", ID: "membership-a",
		AccountID: "account-a", GroupID: "group-a", UserID: "user-a", CreatedBy: "user-admin",
		ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	groupIdentity := identity
	groupIdentity.PolicySources = []PolicyGrantSource{{Kind: PolicyGrantGroup, Attachment: PolicyAttachment{
		APIVersion: APIVersion, Kind: "PolicyAttachment", ID: "attachment-group", AccountID: "account-a",
		Target: PolicyAttachmentTarget{Kind: PolicyTargetGroup, ID: "group-a"}, PolicyID: SystemPolicyPaaSViewer,
		Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}, Membership: &membership}}
	if ValidateCurrentIdentity(groupIdentity) == nil {
		t.Fatal("root identity accepted a group inheritance path")
	}
	groupIdentity.Account.RootIdentity = RootIdentity{PrincipalID: "root-user", LoginName: "owner"}
	groupIdentity.IdentityKind = IdentityUser
	if ValidateCurrentIdentity(groupIdentity) != nil {
		t.Fatal("current group policy source rejected")
	}
	wrongMembership := membership
	wrongMembership.UserID = "user-b"
	groupIdentity.PolicySources[0].Membership = &wrongMembership
	if ValidateCurrentIdentity(groupIdentity) == nil {
		t.Fatal("group source for another user accepted")
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if json.Unmarshal(encoded, &wire) != nil {
		t.Fatal("decode identity fixture")
	}
	wire["roles"] = json.RawMessage(`[]`)
	encoded, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CurrentIdentity
	if DecodeRequest(bytes.NewReader(encoded), &decoded) == nil {
		t.Fatal("old roles field remained as a parallel current identity contract")
	}
	delete(wire, "roles")
	wire["policyAttachments"] = json.RawMessage(`[]`)
	encoded, err = json.Marshal(wire)
	if err != nil || DecodeRequest(bytes.NewReader(encoded), &decoded) == nil {
		t.Fatal("old direct-only policy attachments remained as a parallel current identity contract")
	}
	delete(wire, "policyAttachments")
	wire["canCreateAccounts"] = json.RawMessage(`true`)
	encoded, err = json.Marshal(wire)
	if err != nil || DecodeRequest(bytes.NewReader(encoded), &decoded) == nil {
		t.Fatal("old account creation hint remained as a parallel capability contract")
	}
}

func TestGroupAccessRequiresExactRelationsAndCapabilities(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	group := Group{APIVersion: APIVersion, Kind: "Group", AccountID: "account-a", ID: "group-a", Name: "Operators",
		ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	attachment := PolicyAttachment{APIVersion: APIVersion, Kind: "PolicyAttachment", ID: "attachment-a", AccountID: group.AccountID,
		Target: PolicyAttachmentTarget{Kind: PolicyTargetGroup, ID: string(group.ID)}, PolicyID: SystemPolicyPaaSViewer,
		Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	access := GroupAccess{Group: group, PolicyAttachments: []PolicyAttachment{attachment}}
	for _, action := range []Action{ActionIAMGroupDelete, ActionIAMGroupMembershipCreate, ActionIAMGroupMembershipList,
		ActionIAMGroupPolicyAttachmentCreate, ActionIAMGroupRead, ActionIAMGroupUpdate} {
		access.Capabilities = append(access.Capabilities, ActionCapability{Action: action, Resource: ResourceReference{Kind: ResourceGroup, ID: string(group.ID)}, Available: true})
	}
	access.Capabilities = append(access.Capabilities, ActionCapability{Action: ActionIAMGroupPolicyAttachmentRevoke,
		Resource: ResourceReference{Kind: ResourcePolicyAttachment, ID: string(attachment.ID)}, RestrictionReason: CapabilityAuthorityRequired})
	if ValidateGroupAccess(access) != nil {
		t.Fatal("valid mixed available/unavailable group capabilities rejected")
	}
	for name, mutate := range map[string]func(*GroupAccess){
		"missing capability":          func(v *GroupAccess) { v.Capabilities = v.Capabilities[1:] },
		"duplicate capability":        func(v *GroupAccess) { v.Capabilities = append(v.Capabilities, v.Capabilities[0]) },
		"unrelated capability":        func(v *GroupAccess) { v.Capabilities[0].Action = ActionIAMUserDelete },
		"wrong target":                func(v *GroupAccess) { v.Capabilities[0].Resource.ID = "other-group" },
		"missing restriction":         func(v *GroupAccess) { v.Capabilities[len(v.Capabilities)-1].RestrictionReason = "" },
		"missing attachment snapshot": func(v *GroupAccess) { v.PolicyAttachments = nil },
		"foreign attachment":          func(v *GroupAccess) { v.PolicyAttachments[0].AccountID = "account-b" },
		"user attachment":             func(v *GroupAccess) { v.PolicyAttachments[0].Target.Kind = PolicyTargetUser },
		"different group":             func(v *GroupAccess) { v.PolicyAttachments[0].Target.ID = "group-b" },
		"revoked attachment": func(v *GroupAccess) {
			v.PolicyAttachments[0].RevokedAt = &now
			v.PolicyAttachments[0].ResourceVersion = 2
		},
		"platform attachment": func(v *GroupAccess) {
			v.PolicyAttachments[0].Scope = AuthorityScopeInstallation
			v.PolicyAttachments[0].InstallationID = "installation-a"
		},
		"invalid group revision": func(v *GroupAccess) { v.Group.ResourceVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			value := access
			value.PolicyAttachments = append([]PolicyAttachment{}, access.PolicyAttachments...)
			value.Capabilities = append([]ActionCapability{}, access.Capabilities...)
			mutate(&value)
			if ValidateGroupAccess(value) == nil {
				t.Fatal("invalid group authority projection accepted")
			}
		})
	}
	membership := GroupMembership{APIVersion: APIVersion, Kind: "GroupMembership", AccountID: group.AccountID,
		ID: "membership-a", GroupID: group.ID, UserID: "user-a", CreatedBy: "user-admin", ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	page := GroupMembershipList{APIVersion: APIVersion, Kind: "GroupMembershipList", AccountID: group.AccountID, GroupID: group.ID,
		Items: []GroupMembershipAccess{{Membership: membership, Capabilities: []ActionCapability{{Action: ActionIAMGroupMembershipRemove,
			Resource: ResourceReference{Kind: ResourceGroupMembership, ID: string(membership.ID)}, Available: true}}}}}
	if ValidateGroupMembershipList(page) != nil {
		t.Fatal("valid membership page rejected")
	}
	for name, mutate := range map[string]func(*GroupMembershipList){
		"foreign account": func(v *GroupMembershipList) { v.AccountID = "account-b" },
		"different group": func(v *GroupMembershipList) { v.GroupID = "group-b" },
		"removed relation": func(v *GroupMembershipList) {
			v.Items[0].Membership.RemovedAt = &now
			v.Items[0].Membership.ResourceVersion = 2
		},
		"wrong continuation": func(v *GroupMembershipList) { v.NextAfter = "membership-b" },
		"user as removal target": func(v *GroupMembershipList) {
			v.Items[0].Capabilities[0].Resource = ResourceReference{Kind: ResourceUser, ID: "user-a"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := page
			value.Items = append([]GroupMembershipAccess{}, page.Items...)
			value.Items[0].Capabilities = append([]ActionCapability{}, page.Items[0].Capabilities...)
			mutate(&value)
			if ValidateGroupMembershipList(value) == nil {
				t.Fatal("invalid membership page accepted")
			}
		})
	}
}

func TestPolicyCanonicalizationEnforcesByteBudgetForTypedInputs(t *testing.T) {
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant}
	for i := 0; i < MaxPolicyStatements; i++ {
		statement := PolicyStatement{SID: fmt.Sprintf("statement-%d", i), Effect: PolicyAllow, Actions: []Action{ActionPaaSApplicationRead}}
		for j := 0; j < MaxStatementResources; j++ {
			statement.Resources = append(statement.Resources, PolicyResourceSelector{Kind: ResourceApplication, Match: PolicyResourceExact, ID: fmt.Sprintf("application-%d", j)})
		}
		document.Statements = append(document.Statements, statement)
	}
	if validatePolicyStructure(document) != nil {
		t.Fatal("fixture must obey structural limits")
	}
	if !errors.Is(ValidatePolicyDocument(document), ErrInvalidPolicy) {
		t.Fatal("typed document bypassed byte budget")
	}
	if encoded, digest, err := CanonicalizePolicyDocument(document); !errors.Is(err, ErrInvalidPolicy) || encoded != "" || digest != "" {
		t.Fatal("oversized typed document acquired a digest")
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
		t.Fatal("creation without implicit authority must be accepted")
	}
	for _, role := range removedBuiltinRoleNames {
		encoded, err := json.Marshal(map[string]any{"loginName": "developer", "displayName": "Developer", "initialPassword": "Initial-Password-49!", "requestId": "initial-role-rejected", "initialRole": role})
		if err != nil {
			t.Fatal(err)
		}
		if DecodeRequest(bytes.NewReader(encoded), &create) == nil {
			t.Fatalf("removed initialRole field accepted %s", role)
		}
	}
}

func TestAccountDirectoryContractsRejectCrossTenantAuthority(t *testing.T) {
	user := decodeIAMExample[User](t, "examples/user.json")
	attachment := PolicyAttachment{APIVersion: APIVersion, Kind: "PolicyAttachment", ID: "attachment-directory",
		AccountID: user.AccountID, Target: PolicyAttachmentTarget{Kind: PolicyTargetUser, ID: string(user.ID)},
		PolicyID: SystemPolicyPaaSViewer, Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: user.CreatedAt, UpdatedAt: user.CreatedAt}
	blocked := func(action Action, kind ResourceKind, id string) ActionCapability {
		return ActionCapability{Action: action, Resource: ResourceReference{Kind: kind, ID: id}, RestrictionReason: CapabilityAuthorityRequired}
	}
	list := UserList{APIVersion: APIVersion, Kind: "UserList", Items: []UserAccess{{User: user, PolicyAttachments: []PolicyAttachment{attachment},
		Capabilities: []ActionCapability{
			blocked(ActionIAMUserRead, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserUpdate, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserDelete, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserSetStatus, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserPasswordReset, ResourceUser, string(user.ID)),
			blocked(ActionIAMPolicyAttachmentCreate, ResourceUser, string(user.ID)),
			blocked(ActionIAMPlatformPolicyAttachmentCreate, ResourceUser, string(user.ID)),
			blocked(ActionIAMPolicyAttachmentRevoke, ResourcePolicyAttachment, string(attachment.ID)),
		}}}}
	if err := ValidateUserList(list); err != nil {
		t.Fatalf("valid directory: %v", err)
	}
	for name, mutate := range map[string]func(*PolicyAttachment){
		"wrong subject": func(a *PolicyAttachment) { a.Target.ID = "other-user" },
		"wrong carrier": func(a *PolicyAttachment) { a.Target.Kind = PolicyTargetService },
		"revoked":       func(a *PolicyAttachment) { a.ResourceVersion = 2; a.RevokedAt = &a.UpdatedAt },
	} {
		t.Run(name, func(t *testing.T) {
			changed := attachment
			mutate(&changed)
			list.Items[0].PolicyAttachments = []PolicyAttachment{changed}
			if ValidateUserList(list) == nil {
				t.Fatal("invalid directory attachment accepted")
			}
		})
	}
	list.Items[0].PolicyAttachments = []PolicyAttachment{attachment, attachment}
	if ValidateUserList(list) == nil {
		t.Fatal("duplicate attachment accepted")
	}
	list.Items[0].PolicyAttachments[1].ID = "another-attachment"
	if ValidateUserList(list) == nil {
		t.Fatal("duplicate active policy accepted")
	}
	list.Items[0].PolicyAttachments = []PolicyAttachment{attachment}
	list.Items[0].PolicyAttachments[0].AccountID = "organization-other"
	if ValidateUserList(list) == nil {
		t.Fatal("directory accepted a cross-tenant policy attachment")
	}
	list.Items[0].PolicyAttachments = []PolicyAttachment{}
	list.NextAfter = "different-principal"
	if ValidateUserList(list) == nil {
		t.Fatal("directory accepted an unrelated cursor")
	}
	list.NextAfter = ""
	list.Items = append(list.Items, list.Items[0])
	if ValidateUserList(list) == nil {
		t.Fatal("directory accepted duplicate principals")
	}
	if ValidateSetAccountAliasRequest(SetAccountAliasRequest{Alias: "acme", RequestID: "request-alias"}) == nil {
		t.Fatal("alias mutation accepted no concurrency version")
	}
	if ValidateSetUserStatusRequest(SetUserStatusRequest{Status: "REMOVED", ResourceVersion: 1, RequestID: "request-status"}) == nil {
		t.Fatal("unsupported status accepted")
	}
}

func TestUserProfileAndDeletionContractsAreStrictAndNonSecret(t *testing.T) {
	update := UpdateUserRequest{DisplayName: "Renamed user", ResourceVersion: 7, RequestID: "request-user-update"}
	if ValidateUpdateUserRequest(update) != nil || ValidateDeleteUserRequest(DeleteUserRequest{ResourceVersion: 8, RequestID: "request-user-delete"}) != nil {
		t.Fatal("valid user lifecycle request rejected")
	}
	for _, invalid := range []UpdateUserRequest{
		{DisplayName: "", ResourceVersion: 7, RequestID: "request-user-update"},
		{DisplayName: " padded ", ResourceVersion: 7, RequestID: "request-user-update"},
		{DisplayName: "Renamed user", ResourceVersion: 0, RequestID: "request-user-update"},
	} {
		if ValidateUpdateUserRequest(invalid) == nil {
			t.Fatal("invalid user profile update accepted")
		}
	}
	for _, encoded := range []string{
		`{"displayName":"Renamed user","resourceVersion":7,"requestId":"request-user-update","loginName":"replacement"}`,
		`{"resourceVersion":8,"requestId":"request-user-delete","accountId":"forged"}`,
	} {
		var target any = &UpdateUserRequest{}
		if strings.Contains(encoded, "accountId") {
			target = &DeleteUserRequest{}
		}
		if DecodeRequest(strings.NewReader(encoded), target) == nil {
			t.Fatal("user lifecycle request accepted an authority or identity selector")
		}
	}
	deletedAt := time.Date(2026, 9, 11, 9, 10, 11, 123000, time.UTC)
	receipt := UserDeletion{APIVersion: APIVersion, Kind: "UserDeletion", AccountID: "account-a", ID: "user-a",
		LoginName: "member.a", ResourceVersion: 9, DeletedAt: deletedAt}
	if ValidateUserDeletion(receipt) != nil {
		t.Fatal("valid user deletion receipt rejected")
	}
	receipt.DeletedAt = time.Time{}
	if ValidateUserDeletion(receipt) == nil {
		t.Fatal("deletion receipt without an authoritative timestamp accepted")
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
