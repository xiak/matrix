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

func TestRetiredActionsAreHistoricalDecisionsNotRequestsOrPolicies(t *testing.T) {
	document := loadIAMOpenAPI(t)
	requestSchema := compileIAMOpenAPISchema(t, document, "AuthorizationRequest")
	decisionSchema := compileIAMOpenAPISchema(t, document, "AuthorizationDecision")
	instance := func(value any) any {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		result, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, test := range []struct {
		action  Action
		kind    ResourceKind
		scope   AuthorityScope
		current bool
	}{
		{ActionIAMRoleBindingPut, ResourcePrincipal, AuthorityScopeTenant, false},
		{ActionIAMRoleBindingRevoke, ResourceRoleBinding, AuthorityScopeTenant, false},
		{ActionIAMPlatformRoleBindingPut, ResourcePrincipal, AuthorityScopeInstallation, false},
		{ActionIAMPlatformRoleBindingRevoke, ResourceRoleBinding, AuthorityScopeInstallation, false},
		{ActionIAMPolicyAttachmentCreate, ResourceUser, AuthorityScopeTenant, true},
		{ActionIAMPolicyAttachmentRevoke, ResourcePolicyAttachment, AuthorityScopeTenant, true},
		{ActionIAMPlatformPolicyAttachmentCreate, ResourceUser, AuthorityScopeInstallation, true},
		{ActionIAMPlatformPolicyAttachmentRevoke, ResourcePolicyAttachment, AuthorityScopeInstallation, true},
	} {
		t.Run(string(test.action), func(t *testing.T) {
			request := AuthorizationRequest{Action: test.action, Resource: ResourceReference{Kind: test.kind, ID: "target-one"},
				RequestID: "request-one", CorrelationID: "correlation-one"}
			if (ValidateAuthorizationRequest(request) == nil) != test.current || (requestSchema.Validate(instance(request)) == nil) != test.current {
				t.Fatal("request schema/validator disagrees with current-only catalog")
			}
			if _, known := LookupActionDefinition(test.action); known != test.current {
				t.Fatal("retired action is callable")
			}
			policy := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: test.scope, Statements: []PolicyStatement{{
				SID: "one", Effect: PolicyAllow, Actions: []Action{test.action},
				Resources: []PolicyResourceSelector{{Kind: test.kind, Match: PolicyResourceAnyInAuthority}},
			}}}
			_, _, encodingError := CanonicalizePolicyDocument(policy)
			if (ValidatePolicyDocument(policy) == nil) != test.current || (encodingError == nil) != test.current {
				t.Fatal("policy accepted retired authority or rejected current authority")
			}
			decision := AuthorizationDecision{APIVersion: APIVersion, Kind: "AuthorizationDecision", ID: "decision-one",
				Allowed: true, Reason: DecisionAllowed, TenantID: "account-one", Subject: &Subject{Type: PrincipalUser, ID: "user-one"},
				Action: test.action, Resource: request.Resource, RequestID: request.RequestID,
				DecidedAt: time.Date(2026, 8, 25, 1, 2, 3, 0, time.UTC)}
			if test.scope == AuthorityScopeInstallation {
				decision.TenantID, decision.InstallationID = "", "installation-one"
			}
			check := func(value AuthorizationDecision, valid bool) {
				t.Helper()
				if (ValidateAuthorizationDecision(value) == nil) != valid || (decisionSchema.Validate(instance(value)) == nil) != valid {
					t.Fatalf("decision schema/validator: action=%s resource=%s expected valid=%t", value.Action, value.Resource.Kind, valid)
				}
			}
			check(decision, true)
			wrong := decision
			wrong.Resource.Kind = ResourceSession
			check(wrong, false)
			wrong = decision
			wrong.TenantID, wrong.InstallationID = "account-one", "installation-one"
			check(wrong, false)
			wrong = decision
			if test.scope == AuthorityScopeInstallation {
				wrong.TenantID, wrong.InstallationID = "account-one", ""
			} else {
				wrong.TenantID, wrong.InstallationID = "", "installation-one"
			}
			check(wrong, false)
			wrong = decision
			wrong.Action += ".unknown"
			check(wrong, false)
			if test.scope == AuthorityScopeInstallation {
				wrong = decision
				wrong.Subject = &Subject{Type: PrincipalServiceAccount, ID: "service-one"}
				check(wrong, false)
			}
			decision.Allowed, decision.Reason, decision.Subject = false, DecisionDenied, nil
			decision.TenantID, decision.InstallationID = "", ""
			check(decision, true)
		})
	}
}

func TestUserDirectoryUsesBoundedTenantPolicyAttachments(t *testing.T) {
	document := loadIAMOpenAPI(t)
	schema := compileIAMOpenAPISchema(t, document, "UserAccess")
	user := decodeIAMExample[User](t, "examples/user.json")
	attachment := PolicyAttachment{APIVersion: APIVersion, Kind: "PolicyAttachment", ID: "directory-attachment",
		AccountID: user.AccountID, Target: PolicyAttachmentTarget{Kind: PolicyTargetUser, ID: string(user.ID)},
		PolicyID: SystemPolicyPaaSViewer, Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: user.CreatedAt, UpdatedAt: user.CreatedAt}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{"user attachment", func(map[string]any) {}, true},
		{"no implicit permission", func(v map[string]any) { v["policyAttachments"] = []any{} }, true},
		{"retired role projection", func(v map[string]any) { delete(v, "policyAttachments"); v["roleBindings"] = []any{} }, false},
		{"null relations", func(v map[string]any) { v["policyAttachments"] = nil }, false},
		{"service carrier", func(v map[string]any) {
			v["policyAttachments"].([]any)[0].(map[string]any)["target"].(map[string]any)["kind"] = "SERVICE_ACCOUNT"
		}, false},
		{"revoked relation", func(v map[string]any) {
			a := v["policyAttachments"].([]any)[0].(map[string]any)
			a["resourceVersion"] = float64(2)
			a["revokedAt"] = a["updatedAt"]
		}, false},
		{"over budget", func(v map[string]any) {
			a := v["policyAttachments"].([]any)[0]
			items := make([]any, 257)
			for i := range items {
				items[i] = a
			}
			v["policyAttachments"] = items
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(UserAccess{User: user, PolicyAttachments: []PolicyAttachment{attachment}})
			if err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			if json.Unmarshal(encoded, &value) != nil {
				t.Fatal("invalid directory fixture")
			}
			test.mutate(value)
			if valid := schema.Validate(value) == nil; valid != test.valid {
				t.Fatalf("directory schema accepts=%t want=%t", valid, test.valid)
			}
		})
	}
}

func TestPolicyDirectoryScopeBudgetAndOwnership(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "PolicyList")
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	policy := Policy{APIVersion: APIVersion, Kind: "Policy", ID: "customer.reader", Management: PolicyCustomerManaged,
		AccountID: "account-a", DisplayName: "Reader", Scope: AuthorityScopeTenant, Status: PolicyActive,
		DefaultVersionID: "version-one", ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	base := PolicyList{APIVersion: APIVersion, Kind: "PolicyList", AccountID: "account-a", Scope: AuthorityScopeTenant, Items: []Policy{policy}}
	for _, test := range []struct {
		name   string
		mutate func(*PolicyList)
		valid  bool
	}{
		{"metadata", func(*PolicyList) {}, true},
		{"empty complete directory", func(v *PolicyList) { v.Items = []Policy{} }, true},
		{"retired remains visible", func(v *PolicyList) { v.Items[0].Status = PolicyRetired }, true},
		{"foreign account", func(v *PolicyList) { v.AccountID = "account-b" }, false},
		{"missing items", func(v *PolicyList) { v.Items = nil }, false},
		{"mixed installation", func(v *PolicyList) { v.InstallationID = "installation-a" }, false},
		{"missing installation", func(v *PolicyList) { v.Scope = AuthorityScopeInstallation }, false},
		{"probe directory", func(v *PolicyList) { v.Scope = AuthorityScopeInstallationProbe }, false},
		{"foreign item scope", func(v *PolicyList) {
			v.Items[0].Management, v.Items[0].AccountID, v.Items[0].ID, v.Items[0].Scope = PolicySystemManaged, "", "system.platform", AuthorityScopeInstallation
		}, false},
		{"duplicate identity", func(v *PolicyList) { v.Items = append(v.Items, policy) }, false},
		{"not sorted", func(v *PolicyList) { first := policy; first.ID = "customer.z"; v.Items = []Policy{first, policy} }, false},
		{"over budget", func(v *PolicyList) { v.Items = make([]Policy, MaxPolicyListItems+1) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := base
			value.Items = append([]Policy{}, base.Items...)
			test.mutate(&value)
			if (ValidatePolicyList(value) == nil) != test.valid {
				t.Fatal("directory validator disagrees with ownership or scope")
			}
		})
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{"metadata", func(map[string]any) {}, true},
		{"unknown permit", func(v map[string]any) { v["permit"] = true }, false},
		{"unknown cursor", func(v map[string]any) { v["nextAfter"] = "hidden-partial-directory" }, false},
		{"unknown policy status", func(v map[string]any) { v["items"].([]any)[0].(map[string]any)["status"] = "DELETED" }, false},
		{"unknown policy management", func(v map[string]any) { v["items"].([]any)[0].(map[string]any)["management"] = "PROVIDER" }, false},
		{"customer missing owner", func(v map[string]any) { delete(v["items"].([]any)[0].(map[string]any), "accountId") }, false},
		{"customer reserved id", func(v map[string]any) { v["items"].([]any)[0].(map[string]any)["id"] = "system.forged" }, false},
		{"system customer owner", func(v map[string]any) {
			p := v["items"].([]any)[0].(map[string]any)
			p["management"], p["id"] = "SYSTEM", "system.reader"
		}, false},
		{"system metadata", func(v map[string]any) {
			p := v["items"].([]any)[0].(map[string]any)
			p["management"], p["id"] = "SYSTEM", "system.reader"
			delete(p, "accountId")
		}, true},
		{"system empty reserved id", func(v map[string]any) {
			p := v["items"].([]any)[0].(map[string]any)
			p["management"], p["id"] = "SYSTEM", "system."
			delete(p, "accountId")
		}, false},
		{"metadata excludes policy content", func(v map[string]any) { v["items"].([]any)[0].(map[string]any)["document"] = map[string]any{} }, false},
		{"metadata excludes subjects", func(v map[string]any) { v["items"].([]any)[0].(map[string]any)["principals"] = []any{} }, false},
		{"tenant installation", func(v map[string]any) { v["installationId"] = "installation-a" }, false},
		{"null", func(v map[string]any) { v["items"] = nil }, false},
		{"missing", func(v map[string]any) { delete(v, "items") }, false},
		{"probe", func(v map[string]any) { v["scope"] = "INSTALLATION_PROBE" }, false},
		{"platform metadata", func(v map[string]any) {
			v["scope"], v["installationId"], v["items"] = "INSTALLATION", "installation-a", []any{}
		}, true},
		{"oversized", func(v map[string]any) {
			item := v["items"].([]any)[0]
			items := make([]any, MaxPolicyListItems+1)
			for i := range items {
				items[i] = item
			}
			v["items"] = items
		}, false},
	} {
		t.Run("schema/"+test.name, func(t *testing.T) {
			encoded, _ := json.Marshal(base)
			var value map[string]any
			if json.Unmarshal(encoded, &value) != nil {
				t.Fatal("invalid fixture")
			}
			test.mutate(value)
			if (schema.Validate(value) == nil) != test.valid {
				t.Fatal("directory schema accepted invalid output")
			}
		})
	}
}

func TestPolicyAttachmentMutationSchemaMatchesStrictRequests(t *testing.T) {
	document := loadIAMOpenAPI(t)
	for _, test := range []struct {
		name   string
		schema string
		body   string
		valid  bool
	}{
		{"direct user", "CreatePolicyAttachmentRequest", `{"target":{"kind":"USER","id":"user-a"},"policyId":"system.paas-viewer","policyResourceVersion":1,"requestId":"attach-a"}`, true},
		{"policy identity is not authorization", "CreatePolicyAttachmentRequest", `{"target":{"kind":"USER","id":"user-a"},"policyId":"system.platform-operator","policyResourceVersion":1,"requestId":"attach-a"}`, true},
		{"missing revision", "CreatePolicyAttachmentRequest", `{"target":{"kind":"USER","id":"user-a"},"policyId":"system.paas-viewer","requestId":"attach-a"}`, false},
		{"zero revision", "CreatePolicyAttachmentRequest", `{"target":{"kind":"USER","id":"user-a"},"policyId":"system.paas-viewer","policyResourceVersion":0,"requestId":"attach-a"}`, false},
		{"unsafe revision", "CreatePolicyAttachmentRequest", `{"target":{"kind":"USER","id":"user-a"},"policyId":"system.paas-viewer","policyResourceVersion":9007199254740992,"requestId":"attach-a"}`, false},
		{"account selector", "CreatePolicyAttachmentRequest", `{"target":{"kind":"USER","id":"user-a"},"policyId":"system.paas-viewer","policyResourceVersion":1,"requestId":"attach-a","accountId":"account-b"}`, false},
		{"installation selector", "CreatePolicyAttachmentRequest", `{"target":{"kind":"USER","id":"user-a"},"policyId":"system.paas-viewer","policyResourceVersion":1,"requestId":"attach-a","installationId":"installation-b"}`, false},
		{"scope selector", "CreatePolicyAttachmentRequest", `{"target":{"kind":"USER","id":"user-a"},"policyId":"system.paas-viewer","policyResourceVersion":1,"requestId":"attach-a","scope":"TENANT"}`, false},
		{"role carrier unavailable", "CreatePolicyAttachmentRequest", `{"target":{"kind":"ROLE","id":"role-a"},"policyId":"system.paas-viewer","policyResourceVersion":1,"requestId":"attach-a"}`, false},
		{"group carrier unavailable", "CreatePolicyAttachmentRequest", `{"target":{"kind":"GROUP","id":"group-a"},"policyId":"system.paas-viewer","policyResourceVersion":1,"requestId":"attach-a"}`, false},
		{"service workflow unavailable", "CreatePolicyAttachmentRequest", `{"target":{"kind":"SERVICE_ACCOUNT","id":"service-a"},"policyId":"system.paas-viewer","policyResourceVersion":1,"requestId":"attach-a"}`, false},
		{"revoke exact revision", "RevokePolicyAttachmentRequest", `{"resourceVersion":1,"requestId":"revoke-a"}`, true},
		{"revoke maximal revision", "RevokePolicyAttachmentRequest", `{"resourceVersion":9007199254740991,"requestId":"revoke-a"}`, true},
		{"revoke missing revision", "RevokePolicyAttachmentRequest", `{"requestId":"revoke-a"}`, false},
		{"revoke null revision", "RevokePolicyAttachmentRequest", `{"resourceVersion":null,"requestId":"revoke-a"}`, false},
		{"revoke zero revision", "RevokePolicyAttachmentRequest", `{"resourceVersion":0,"requestId":"revoke-a"}`, false},
		{"revoke authority selector", "RevokePolicyAttachmentRequest", `{"resourceVersion":1,"requestId":"revoke-a","tenantId":"other"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value any
			if err := json.Unmarshal([]byte(test.body), &value); err != nil {
				t.Fatal(err)
			}
			if valid := compileIAMOpenAPISchema(t, document, test.schema).Validate(value) == nil; valid != test.valid {
				t.Fatalf("schema accepts=%t want=%t", valid, test.valid)
			}
			var err error
			if test.schema == "CreatePolicyAttachmentRequest" {
				var request CreatePolicyAttachmentRequest
				err = DecodeRequest(bytes.NewBufferString(test.body), &request)
				if err == nil {
					err = ValidateCreatePolicyAttachmentRequest(request)
				}
			} else {
				var request RevokePolicyAttachmentRequest
				err = DecodeRequest(bytes.NewBufferString(test.body), &request)
				if err == nil {
					err = ValidateRevokePolicyAttachmentRequest(request)
				}
			}
			if (err == nil) != test.valid {
				t.Fatalf("strict contract accepts=%t want=%t", err == nil, test.valid)
			}
		})
	}
	var request CreatePolicyAttachmentRequest
	if DecodeRequest(bytes.NewBufferString(`{"target":{"kind":"USER","id":"user-a","id":"user-b"},"policyId":"system.paas-viewer","policyResourceVersion":1,"requestId":"attach-a"}`), &request) == nil {
		t.Fatal("duplicate attachment target identity was accepted")
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

func TestIAMAccountLifecycleRequestsBindVersionAndDeriveRoot(t *testing.T) {
	document := loadIAMOpenAPI(t)
	status := map[string]any{"status": "DISABLED", "resourceVersion": float64(1), "requestId": "request-status"}
	recovery := map[string]any{"initialPassword": "Recovery-Temporary-Password-79!", "resourceVersion": float64(1), "requestId": "request-recovery"}
	for name, instance := range map[string]map[string]any{"SetAccountStatusRequest": status, "RecoverRootCredentialsRequest": recovery} {
		schema := compileIAMOpenAPISchema(t, document, name)
		if err := schema.Validate(instance); err != nil {
			t.Fatalf("valid %s: %v", name, err)
		}
		for _, selector := range []string{"tenantId", "installationId", "organizationId", "principalId", "newRootId", "role"} {
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
	var request RecoverRootCredentialsRequest
	if err := DecodeRequest(bytes.NewReader(encoded), &request); err != nil || ValidateRecoverRootCredentialsRequest(request) != nil {
		t.Fatal("valid root recovery request rejected")
	}
	if _, err := json.Marshal(request); !errors.Is(err, ErrSecretSerialization) {
		t.Fatal("primary recovery serialized its temporary credential")
	}
	request.ResourceVersion = 0
	if ValidateRecoverRootCredentialsRequest(request) == nil {
		t.Fatal("recovery accepted missing concurrency authority")
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
		t.Fatalf("creation without implicit authority: %v", err)
	}
	for _, role := range removedBuiltinRoleNames {
		create["initialRole"] = role
		if createSchema.Validate(create) == nil {
			t.Fatalf("member creation schema accepted removed initial role %s", role)
		}
	}
	grantSchema := compileIAMOpenAPISchema(t, document, "CreatePolicyAttachmentRequest")
	grant := loadIAMSchemaExample(t, "examples/create-policy-attachment-request.json")
	grant["policyId"] = string(SystemPolicyPlatformOperator)
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
		Producer: ServiceIdentity{APIVersion: APIVersion, Kind: "ServiceIdentity", InstallationID: "installation-example", AccountID: "organization-platform", PrincipalID: "service-iam", Purpose: ServiceIAM}}
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
		"examples/account.json":                          "Account",
		"examples/user.json":                             "User",
		"examples/bootstrap-document.json":               "BootstrapDocument",
		"examples/bootstrap-status.json":                 "BootstrapStatus",
		"examples/service-identity.json":                 "ServiceIdentity",
		"examples/login-request.json":                    "LoginRequest",
		"examples/login-response.json":                   "LoginResponse",
		"examples/logout-request.json":                   "LogoutRequest",
		"examples/logout-response.json":                  "LogoutResponse",
		"examples/change-password-request.json":          "ChangePasswordRequest",
		"examples/change-password-response.json":         "ChangePasswordResponse",
		"examples/create-user-request.json":              "CreateUserRequest",
		"examples/create-policy-attachment-request.json": "CreatePolicyAttachmentRequest",
		"examples/revoke-policy-attachment-request.json": "RevokePolicyAttachmentRequest",
		"examples/revoke-session-request.json":           "RevokeSessionRequest",
		"examples/revocation.json":                       "Revocation",
		"examples/authorization-request.json":            "AuthorizationRequest",
		"examples/authorization-decision-allowed.json":   "AuthorizationDecision",
		"examples/authorization-decision-denied.json":    "AuthorizationDecision",
		"examples/readiness.json":                        "Readiness",
		"examples/problem.json":                          "Problem",
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
