package iamv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

func TestRoleDisplayAndSelfDiscoverySchemasStayClosed(t *testing.T) {
	api := loadIAMOpenAPI(t)
	session := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RoleSession","id":"role-session-a","accountId":"account-a","roleId":"role-a","sourceUserId":"user-a","status":"ACTIVE","issuedAt":"2026-09-16T00:00:00Z","expiresAt":"2026-09-16T01:00:00Z"}`
	identity := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"CurrentRoleIdentity","session":` + session +
		`,"account":{"id":"account-a","displayName":"Account A"},"role":{"id":"role-a","name":"Reader"},"sourceUser":{"id":"user-a","loginName":"member","displayName":"Member"}}`
	item := `{"roleId":"role-a","accountId":"account-a","name":"Reader","status":"ACTIVE","maxSessionDurationSeconds":3600,"resourceVersion":2,"capability":{"action":"iam.role.assume","resource":{"kind":"ROLE","id":"role-a"},"available":true}}`
	empty := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"AssumableRoleList","accountId":"account-a","sourceUserId":"user-a","items":[]}`
	listed := strings.Replace(empty, `"items":[]`, `"items":[`+item+`]`, 1)
	for index, sample := range []struct {
		kind, wire         string
		schemaValid, valid bool
	}{
		{"CurrentRoleIdentity", identity, true, true},
		{"CurrentRoleIdentity", session, false, false},
		{"CurrentRoleIdentity", strings.Replace(identity, `"displayName":"Member"`, `"displayName":""`, 1), false, false},
		{"CurrentRoleIdentity", strings.Replace(identity, `"name":"Reader"`, `"name":"Reader","trustVersionId":"private"`, 1), false, false},
		{"CurrentRoleIdentity", strings.Replace(identity, `"status":"ACTIVE"`, `"status":"ACTIVE","revokedAt":null`, 1), false, false},
		{"CurrentRoleIdentity", strings.Replace(identity, `"id":"user-a"`, `"id":"user-b"`, 1), true, false}, // ID equality is an authoritative invariant.
		{"AssumableRoleList", empty, true, true},
		{"AssumableRoleList", strings.TrimSuffix(empty, "}") + `,"nextAfter":"ir1.opaque-candidate"}`, true, true},
		{"AssumableRoleList", strings.TrimSuffix(empty, "}") + `,"nextAfter":"ic1.opaque-management"}`, false, false},
		{"AssumableRoleList", listed, true, true},
		{"AssumableRoleList", strings.Replace(listed, `"status":"ACTIVE"`, `"status":"DISABLED"`, 1), false, false},
		{"AssumableRoleList", strings.Replace(listed, `"iam.role.assume"`, `"iam.role.read"`, 1), false, false},
		{"AssumableRoleList", strings.Replace(listed, `"available":true`, `"available":false,"restrictionReason":"AUTHORITY_REQUIRED"`, 1), false, false},
		{"AssumableRoleList", strings.Replace(listed, `"available":true`, `"available":true,"restrictionReason":""`, 1), false, false},
		{"AssumableRoleList", strings.TrimSuffix(empty, "}") + `,"nextAfter":null}`, false, false},
		{"AssumableRoleList", strings.TrimSuffix(empty, "}") + `,"total":20}`, false, false},
		{"AssumableRoleList", strings.Replace(listed, `"id":"role-a"`, `"id":"role-b"`, 1), true, false},
		{"AssumableRoleList", strings.Replace(empty, `"items":[]`, `"items":[`+strings.Repeat(item+",", RoleDiscoveryPageSize)+item+`]`, 1), false, false},
	} {
		schema := compileIAMOpenAPISchema(t, api, sample.kind)
		value, err := jsonschema.UnmarshalJSON(strings.NewReader(sample.wire))
		if err != nil {
			t.Fatalf("sample %d has invalid fixture JSON", index)
		}
		schemaErr := schema.Validate(value)
		if (schemaErr == nil) != sample.schemaValid {
			t.Fatalf("sample %d %s schema changed the display/discovery boundary: %v", index, sample.kind, schemaErr)
		}
		var valid bool
		if sample.kind == "CurrentRoleIdentity" {
			var decoded CurrentRoleIdentity
			valid = DecodeRequest(strings.NewReader(sample.wire), &decoded) == nil && ValidateCurrentRoleIdentity(decoded) == nil
		} else {
			var decoded AssumableRoleList
			valid = DecodeRequest(strings.NewReader(sample.wire), &decoded) == nil && ValidateAssumableRoleList(decoded) == nil
		}
		if valid != sample.valid {
			t.Fatalf("%s codec lost the stricter authoritative binding", sample.kind)
		}
	}
}

func TestAssumeRoleRequestSchemaMatchesTheClosedIntent(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "AssumeRoleRequest")
	base := `{"resourceVersion":1,"requestId":"assume-role"}`
	policy := `{"languageVersion":"1","scope":"TENANT","statements":[{"sid":"read","effect":"ALLOW","actions":["paas.application.read"],"resources":[{"kind":"APPLICATION","match":"ANY_IN_AUTHORITY"}]}]}`
	with := func(member string) string { return strings.TrimSuffix(base, "}") + "," + member + "}" }
	for _, sample := range []struct {
		wire  string
		valid bool
	}{
		{base, true}, {with(`"durationSeconds":60`), true}, {with(`"durationSeconds":43200`), true},
		{with(`"sessionPolicy":` + policy), true},
		{with(`"durationSeconds":null`), false}, {with(`"durationSeconds":59`), false},
		{with(`"durationSeconds":43201`), false}, {with(`"durationSeconds":"60"`), false},
		{with(`"sessionPolicy":null`), false}, {with(`"sessionPolicy":{}`), false},
		{with(`"sessionPolicy":` + strings.Replace(policy, `"TENANT"`, `"INSTALLATION"`, 1)), false},
		{with(`"accountId":"other"`), false}, {with(`"sourceSessionId":"session-foreign"`), false},
		{with(`"sourceUserId":"root"`), false}, {with(`"compilation":{}`), false},
		{`{"resourceVersion":0,"requestId":"assume-role"}`, false}, {`{"requestId":"assume-role"}`, false},
	} {
		value, err := jsonschema.UnmarshalJSON(strings.NewReader(sample.wire))
		if err != nil || (schema.Validate(value) == nil) != sample.valid {
			t.Fatal("issuance intent schema accepted a different input contract")
		}
		var decoded AssumeRoleRequest
		err = DecodeRequest(strings.NewReader(sample.wire), &decoded)
		if err == nil {
			err = ValidateAssumeRoleRequest(decoded)
		}
		if (err == nil) != sample.valid {
			t.Fatal("issuance intent runtime validation differs")
		}
	}
}

func TestRoleSessionResponseSchemaHasNoSecretReplayOrPrivateLineage(t *testing.T) {
	api := loadIAMOpenAPI(t)
	session := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RoleSession","id":"role-session-a","accountId":"account-a","roleId":"role-a","sourceUserId":"user-a","status":"ACTIVE","issuedAt":"2026-09-16T00:00:00Z","expiresAt":"2026-09-16T01:00:00Z"}`
	for _, sample := range []struct {
		kind, wire string
		valid      bool
	}{
		{"RoleSession", session, true},
		{"RoleSession", strings.Replace(session, `"id":"role-session-a"`, `"id":""`, 1), false},
		{"RoleSession", strings.Replace(session, `"status":"ACTIVE"`, `"status":"REVOKED"`, 1), false},
		{"RoleSession", strings.Replace(session, `"status":"ACTIVE"`, `"status":"ACTIVE","sourceSessionId":"private"`, 1), false},
		{"RoleSession", strings.Replace(session, `"status":"ACTIVE"`, `"status":"ACTIVE","credentialGeneration":4`, 1), false},
		{"AssumeRoleResponse", `{"outcome":"APPLIED","session":` + session + `,"credential":"once-only"}`, true},
		{"AssumeRoleResponse", `{"outcome":"EQUAL_REPLAY","session":` + session + `}`, true},
		{"AssumeRoleResponse", `{"outcome":"EQUAL_REPLAY","session":` + session + `,"credential":""}`, false},
		{"AssumeRoleResponse", `{"outcome":"APPLIED","session":` + session + `}`, false},
		{"AssumeRoleResponse", `{"outcome":"APPLIED","session":` + session + `,"credential":null}`, false},
		{"AssumeRoleResponse", `{"outcome":"UNKNOWN","session":` + session + `}`, false},
		{"RevokeRoleSessionRequest", `{"requestId":"revoke"}`, true},
		{"RevokeRoleSessionRequest", `{"requestId":"revoke","sourceUserId":"caller"}`, false},
	} {
		schema := compileIAMOpenAPISchema(t, api, sample.kind)
		value, err := jsonschema.UnmarshalJSON(strings.NewReader(sample.wire))
		if err != nil || (schema.Validate(value) == nil) != sample.valid {
			t.Fatal("role session schema disagrees with closed response", sample.kind, sample.valid)
		}
	}
}

func TestRoleBoundarySchemaRequiresAnExplicitCeilingReference(t *testing.T) {
	api := loadIAMOpenAPI(t)
	base := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RolePermissionBoundary","accountId":"account-a","roleId":"role-a","resourceVersion":1,"policy":null}`
	set := `{"policyId":"policy-a","policyResourceVersion":1,"resourceVersion":1,"requestId":"set-boundary"}`
	remove := `{"resourceVersion":1,"requestId":"remove-boundary"}`
	for _, sample := range []struct {
		name, wire string
		valid      bool
	}{
		{"RolePermissionBoundary", base, true},
		{"RolePermissionBoundary", strings.Replace(base, `,"policy":null`, "", 1), false},
		{"RolePermissionBoundary", strings.Replace(base, `"policy":null`, `"policy":{}`, 1), false},
		{"RolePermissionBoundary", strings.Replace(base, `"policy":null`, `"policy":null,"allow":true`, 1), false},
		{"RolePermissionBoundary", strings.Replace(base, `"roleId":"role-a"`, `"userId":"role-a"`, 1), false},
		{"SetRolePermissionBoundaryRequest", set, true},
		{"SetRolePermissionBoundaryRequest", strings.Replace(set, `"policyId":"policy-a"`, `"policyId":null`, 1), false},
		{"SetRolePermissionBoundaryRequest", strings.Replace(set, `"policyResourceVersion":1,`, "", 1), false},
		{"SetRolePermissionBoundaryRequest", strings.Replace(set, `"resourceVersion":1`, `"resourceVersion":9007199254740991`, 1), false},
		{"SetRolePermissionBoundaryRequest", strings.Replace(set, `"requestId"`, `"actorSessionId":"caller","requestId"`, 1), false},
		{"RemoveRolePermissionBoundaryRequest", remove, true},
		{"RemoveRolePermissionBoundaryRequest", strings.Replace(remove, `"resourceVersion":1`, `"resourceVersion":0`, 1), false},
		{"RemoveRolePermissionBoundaryRequest", strings.Replace(remove, `"resourceVersion":1`, `"resourceVersion":9007199254740991`, 1), false},
		{"RemoveRolePermissionBoundaryRequest", strings.Replace(remove, `"requestId"`, `"policyId":"policy-a","requestId"`, 1), false},
	} {
		schema := compileIAMOpenAPISchema(t, api, sample.name)
		decoded, err := jsonschema.UnmarshalJSON(strings.NewReader(sample.wire))
		if err != nil || (schema.Validate(decoded) == nil) != sample.valid {
			t.Fatalf("%s schema disagrees with explicit boundary input: %s", sample.name, sample.wire)
		}
		switch sample.name {
		case "RolePermissionBoundary":
			var value RolePermissionBoundary
			err = errors.Join(DecodeRequest(strings.NewReader(sample.wire), &value), ValidateRolePermissionBoundary(value))
		case "SetRolePermissionBoundaryRequest":
			var value SetRolePermissionBoundaryRequest
			err = errors.Join(DecodeRequest(strings.NewReader(sample.wire), &value), ValidateSetRolePermissionBoundaryRequest(value))
		case "RemoveRolePermissionBoundaryRequest":
			var value RemoveRolePermissionBoundaryRequest
			err = errors.Join(DecodeRequest(strings.NewReader(sample.wire), &value), ValidateRemoveRolePermissionBoundaryRequest(value))
		}
		if (err == nil) != sample.valid {
			t.Fatal("role boundary schema and authoritative validation disagree")
		}
	}
}

func TestRoleManagementRequestsKeepSelectorsAndDefaultsClosed(t *testing.T) {
	api := loadIAMOpenAPI(t)
	create := `{"name":"Readers","tags":[],"trustPolicy":{"languageVersion":"1","statements":[]},"requestId":"create-role"}`
	update := `{"name":"Readers","description":"","tags":[],"maxSessionDurationSeconds":3600,"resourceVersion":1,"requestId":"update-role"}`
	for _, test := range []struct {
		name, schema, wire string
		valid              bool
	}{
		{"default duration", "CreateRoleRequest", create, true},
		{"minimum duration", "CreateRoleRequest", strings.Replace(create, `"tags"`, `"maxSessionDurationSeconds":60,"tags"`, 1), true},
		{"null duration", "CreateRoleRequest", strings.Replace(create, `"tags"`, `"maxSessionDurationSeconds":null,"tags"`, 1), false},
		{"zero duration", "CreateRoleRequest", strings.Replace(create, `"tags"`, `"maxSessionDurationSeconds":0,"tags"`, 1), false},
		{"null description", "CreateRoleRequest", strings.Replace(create, `"tags"`, `"description":null,"tags"`, 1), false},
		{"caller account", "CreateRoleRequest", strings.Replace(create, `"tags"`, `"accountId":"other","tags"`, 1), false},
		{"caller session", "CreateRoleRequest", strings.Replace(create, `"tags"`, `"actorSessionId":"other","tags"`, 1), false},
		{"caller manager", "CreateRoleRequest", strings.Replace(create, `"tags"`, `"management":"SERVICE","tags"`, 1), false},
		{"null tags", "CreateRoleRequest", strings.Replace(create, `"tags":[]`, `"tags":null`, 1), false},
		{"missing tag value", "CreateRoleRequest", strings.Replace(create, `"tags":[]`, `"tags":[{"key":"env"}]`, 1), false},
		{"null tag value", "CreateRoleRequest", strings.Replace(create, `"tags":[]`, `"tags":[{"key":"env","value":null}]`, 1), false},
		{"empty tag value", "CreateRoleRequest", strings.Replace(create, `"tags":[]`, `"tags":[{"key":"env","value":""}]`, 1), true},
		{"complete replacement", "UpdateRoleRequest", update, true},
		{"missing replacement description", "UpdateRoleRequest", strings.Replace(update, `"description":"",`, ``, 1), false},
		{"null replacement description", "UpdateRoleRequest", strings.Replace(update, `"description":""`, `"description":null`, 1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := jsonschema.UnmarshalJSON(strings.NewReader(test.wire))
			if err != nil || (compileIAMOpenAPISchema(t, api, test.schema).Validate(value) == nil) != test.valid {
				t.Fatal("schema acceptance differs")
			}
			if test.schema == "CreateRoleRequest" {
				var decoded CreateRoleRequest
				err = DecodeRequest(strings.NewReader(test.wire), &decoded)
				if err == nil {
					err = ValidateCreateRoleRequest(decoded)
				}
			} else {
				var decoded UpdateRoleRequest
				err = DecodeRequest(strings.NewReader(test.wire), &decoded)
				if err == nil {
					err = ValidateUpdateRoleRequest(decoded)
				}
			}
			if (err == nil) != test.valid {
				t.Fatal("runtime request acceptance differs")
			}
		})
	}
}

func TestRoleTrustSchemasKeepCarrierAdmissionSeparateFromIdentityPolicies(t *testing.T) {
	api := loadIAMOpenAPI(t)
	schema := compileIAMOpenAPISchema(t, api, "TrustPolicyDocument")
	valid := `{"languageVersion":"1","statements":[{"sid":"one","effect":"ALLOW","principals":[{"type":"USER","id":"user-a"}]}]}`
	for name, wire := range map[string]string{
		"explicit empty": `{"languageVersion":"1","statements":[]}`,
		"allow":          valid,
		"deny":           strings.Replace(valid, `"ALLOW"`, `"DENY"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			value, err := jsonschema.UnmarshalJSON(strings.NewReader(wire))
			if err != nil || schema.Validate(value) != nil {
				t.Fatal("valid closed role trust syntax rejected")
			}
		})
	}
	for name, wire := range map[string]string{
		"missing statements":  `{"languageVersion":"1"}`,
		"null statements":     `{"languageVersion":"1","statements":null}`,
		"unknown language":    strings.Replace(valid, `"1"`, `"2"`, 1),
		"unknown effect":      strings.Replace(valid, `"ALLOW"`, `"PERMIT"`, 1),
		"permission scope":    strings.Replace(valid, `"statements"`, `"scope":"TENANT","statements"`, 1),
		"account selector":    strings.Replace(valid, `"statements"`, `"accountId":"other","statements"`, 1),
		"empty carriers":      strings.Replace(valid, `[{"type":"USER","id":"user-a"}]`, `[]`, 1),
		"service carrier":     strings.Replace(valid, `"USER"`, `"SERVICE_ACCOUNT"`, 1),
		"role carrier":        strings.Replace(valid, `"USER"`, `"ROLE"`, 1),
		"group carrier":       strings.Replace(valid, `"USER"`, `"GROUP"`, 1),
		"wildcard carrier":    strings.Replace(valid, `"user-a"`, `"*"`, 1),
		"carrier realm":       strings.Replace(valid, `"user-a"`, `"user@account"`, 1),
		"carrier account":     strings.Replace(valid, `"type":"USER"`, `"accountId":"other","type":"USER"`, 1),
		"identity actions":    strings.Replace(valid, `"sid"`, `"actions":["iam.role.assume"],"sid"`, 1),
		"identity resources":  strings.Replace(valid, `"sid"`, `"resources":[],"sid"`, 1),
		"identity conditions": strings.Replace(valid, `"sid"`, `"conditions":[],"sid"`, 1),
		"duplicate carrier":   strings.Replace(valid, `[{"type":"USER","id":"user-a"}]`, `[{"type":"USER","id":"user-a"},{"type":"USER","id":"user-a"}]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			value, err := jsonschema.UnmarshalJSON(strings.NewReader(wire))
			if err != nil || schema.Validate(value) == nil {
				t.Fatal("role trust schema accepted authority confusion or an unimplemented carrier")
			}
		})
	}
	for _, tooManyStatements := range []bool{false, true} {
		document := sampleRoleTrustDocument()
		if tooManyStatements {
			for len(document.Statements) <= MaxTrustPolicyStatements {
				document.Statements = append(document.Statements, TrustPolicyStatement{SID: fmt.Sprintf("s%d", len(document.Statements)), Effect: PolicyAllow, Principals: []TrustPrincipal{{Type: PrincipalUser, ID: "user-a"}}})
			}
		} else {
			for len(document.Statements[0].Principals) <= MaxTrustStatementPrincipals {
				document.Statements[0].Principals = append(document.Statements[0].Principals, TrustPrincipal{Type: PrincipalUser, ID: PrincipalID(fmt.Sprintf("p%d", len(document.Statements[0].Principals)))})
			}
		}
		encoded, _ := json.Marshal(document)
		value, _ := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
		if schema.Validate(value) == nil {
			t.Fatal("schema accepted an oversized carrier collection")
		}
	}
	// JSON Schema does not establish digest equality, unique SID across
	// different statements, current selection or real USER/account membership.
	versionSchema := compileIAMOpenAPISchema(t, api, "RoleTrustVersion")
	document := sampleRoleTrustDocument()
	_, digest, _ := CanonicalizeTrustPolicyDocument(document)
	version := RoleTrustVersion{APIVersion: APIVersion, Kind: "RoleTrustVersion", ID: "version-a", AccountID: "account-a", RoleID: "role-a", Document: document, ContentDigest: digest, CreatedAt: time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)}
	encoded, _ := json.Marshal(version)
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil || versionSchema.Validate(value) != nil {
		t.Fatal("version schema rejected valid immutable content")
	}
	for _, field := range []string{"accountId", "roleId", "contentDigest", "document", "createdAt"} {
		var candidate map[string]any
		_ = json.Unmarshal(encoded, &candidate)
		delete(candidate, field)
		if versionSchema.Validate(candidate) == nil {
			t.Fatal("version schema omitted required lineage or content")
		}
	}
}

func TestAuthorizationProfileSubjectSchemaKeepsPrincipalAndCapabilitySeparate(t *testing.T) {
	api := loadIAMOpenAPI(t)
	schema := compileIAMOpenAPISchema(t, api, "AuthorizationProfile")
	profile := authorizationProfileFixture()
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, field string
		valid       bool
	}{
		{"sealed absence", "", true},
		{"user", `"subjectTypes":["USER"],`, true},
		{"role and user", `"subjectTypes":["ROLE","USER"],`, true},
		{"service", `"subjectTypes":["SERVICE_ACCOUNT"],`, true},
		{"null", `"subjectTypes":null,`, false},
		{"empty", `"subjectTypes":[],`, false},
		{"duplicate", `"subjectTypes":["USER","USER"],`, false},
		{"unknown", `"subjectTypes":["ADMIN"],`, false},
		{"case alias", `"SubjectTypes":["USER"],`, false},
		{"object", `"subjectTypes":{},`, false},
		{"nullable element", `"subjectTypes":[null],`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := strings.Replace(string(encoded), `"action":`, test.field+`"action":`, 1)
			wire, err := jsonschema.UnmarshalJSON(strings.NewReader(candidate))
			if err != nil || (schema.Validate(wire) == nil) != test.valid {
				t.Fatal("subject capability schema disagrees with the bounded contract", err)
			}
			if _, err := DecodeAuthorizationProfile(strings.NewReader(candidate)); (err == nil) != test.valid {
				t.Fatal("subject capability decoder diverged from its schema", err)
			}
		})
	}
	principal := compileIAMOpenAPISchema(t, api, "PrincipalType")
	if principal.Validate("ROLE") == nil || principal.Validate("USER") != nil || principal.Validate("SERVICE_ACCOUNT") != nil {
		t.Fatal("authorization subject capability changed the login principal contract")
	}
}

func TestRoleSubjectKeepsExactPublicLineageAndPrincipalSeparation(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "Subject")
	for _, test := range []struct {
		name, source string
		valid        bool
	}{
		{"user", `{"type":"USER","id":"user-one"}`, true},
		{"service", `{"type":"SERVICE_ACCOUNT","id":"service-one"}`, true},
		{"role", `{"type":"ROLE","id":"role-one","roleSession":{"sessionId":"role-session-one","sourceUserId":"user-one"}}`, true},
		{"missing lineage", `{"type":"ROLE","id":"role-one"}`, false},
		{"null lineage", `{"type":"ROLE","id":"role-one","roleSession":null}`, false},
		{"missing source", `{"type":"ROLE","id":"role-one","roleSession":{"sessionId":"role-session-one"}}`, false},
		{"user with lineage", `{"type":"USER","id":"user-one","roleSession":{"sessionId":"role-session-one","sourceUserId":"user-one"}}`, false},
		{"user with null lineage", `{"type":"USER","id":"user-one","roleSession":null}`, false},
		{"service with null lineage", `{"type":"SERVICE_ACCOUNT","id":"service-one","roleSession":null}`, false},
		{"service with lineage", `{"type":"SERVICE_ACCOUNT","id":"service-one","roleSession":{"sessionId":"role-session-one","sourceUserId":"user-one"}}`, false},
		{"private source session", `{"type":"ROLE","id":"role-one","roleSession":{"sessionId":"role-session-one","sourceUserId":"user-one","sourceSessionId":"login-one"}}`, false},
		{"private generation", `{"type":"ROLE","id":"role-one","roleSession":{"sessionId":"role-session-one","sourceUserId":"user-one","credentialGeneration":1}}`, false},
		{"unknown carrier", `{"type":"GROUP","id":"group-one"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire, err := jsonschema.UnmarshalJSON(strings.NewReader(test.source))
			if err != nil || (schema.Validate(wire) == nil) != test.valid {
				t.Fatal("subject schema diverges", err)
			}
			var subject Subject
			err = DecodeRequest(strings.NewReader(test.source), &subject)
			if (err == nil && ValidateSubject(subject) == nil) != test.valid {
				t.Fatal("subject validator diverges", err)
			}
			if test.valid {
				encoded, err := json.Marshal(subject)
				if err != nil || string(encoded) != test.source {
					t.Fatal("subject public bytes changed", err)
				}
			}
		})
	}
}

func TestDecisionSubjectCapabilityIsCheckedByPEPAndFrozenEvidence(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "AuthorizationDecision")
	for _, test := range []struct {
		action Action
		kind   ResourceKind
		typeID SubjectType
	}{
		{ActionPaaSApplicationRead, ResourceApplication, SubjectUser},
		{ActionIAMRoleRead, ResourceRole, SubjectUser},
		{ActionPaaSExecutionTargetRead, ResourceExecutionTarget, SubjectUser},
		{ActionInstallationVerify, ResourceInstallation, SubjectServiceAccount},
	} {
		request, err := NewAuthorizationRequest(test.action, ResourceReference{Kind: test.kind, ID: "target-one"}, AuthorizationResourceInstance, "", "request-one", "correlation-one")
		if err != nil {
			t.Fatal(err)
		}
		profile, _ := LookupAuthorizationProfile(request.Profile.Product)
		for _, subjectType := range []SubjectType{SubjectUser, SubjectServiceAccount, SubjectRole, "GROUP"} {
			decision := AuthorizationDecision{APIVersion: APIVersion, Kind: "AuthorizationDecision", ID: "decision-one", Allowed: true, Reason: DecisionAllowed,
				Action: request.Action, Resource: request.Resource, Profile: &request.Profile, ResourceMode: request.ResourceMode,
				RequestID: request.RequestID, CorrelationID: request.CorrelationID, DecidedAt: time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC),
				Subject: &Subject{Type: SubjectType(subjectType), ID: "subject-one"}, TenantID: "account-one"}
			if subjectType == SubjectRole {
				decision.Subject.RoleSession = &RoleSessionReference{SessionID: "role-session-one", SourceUserID: "source-user"}
			}
			if IsPlatformAction(test.action) {
				decision.TenantID, decision.InstallationID = "", "installation-one"
			}
			encoded, _ := json.Marshal(decision)
			wire, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
			want := subjectType == test.typeID || (test.action == ActionPaaSApplicationRead && subjectType == SubjectRole)
			if err != nil || (schema.Validate(wire) == nil) != want || (CheckAuthorizationDecisionForRequest(decision, request) == nil) != want ||
				(ValidateAuthorizationDecisionForProfile(decision, profile) == nil) != want {
				t.Fatalf("PEP/schema/frozen evidence disagree for %s / %s", test.action, subjectType)
			}
		}
	}
}

func TestAuthorizationProfileDiscoverySchemaPreservesDeclaredScopeAndShape(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "AuthorizationProfileList")
	base := currentAuthorizationProfileList(t)
	for _, test := range []struct {
		name   string
		mutate func(*AuthorizationProfileList)
		valid  bool
	}{
		{"complete current catalog", func(*AuthorizationProfileList) {}, true},
		{"empty", func(v *AuthorizationProfileList) { v.Items = []AuthorizationProfileEntry{} }, false},
		{"null items", func(v *AuthorizationProfileList) { v.Items = nil }, false},
		{"unknown kind", func(v *AuthorizationProfileList) { v.Kind = "PolicyList" }, false},
		{"zero revision", func(v *AuthorizationProfileList) { v.Items[0].Profile.Revision = 0 }, false},
		{"unknown scope", func(v *AuthorizationProfileList) { v.Items[0].Profile.Actions[0].Scope = "GLOBAL" }, false},
		{"pattern declaration", func(v *AuthorizationProfileList) { v.Items[0].Profile.Actions[0].Action = "audit.record.*" }, false},
		{"collection prefix", func(v *AuthorizationProfileList) {
			v.Items[0].Profile.Actions[0].ResourceShapes[0] = AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList, PrefixAllowed: true}
		}, false},
		{"collection create no result", func(v *AuthorizationProfileList) {
			v.Items[0].Profile.Actions[0].ResourceShapes[0] = AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}
			v.Items[0].Profile.Actions[0].ResultResourceKind = ""
		}, false},
		{"list with create result", func(v *AuthorizationProfileList) {
			v.Items[0].Profile.Actions[0].ResourceShapes[0] = AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}
			v.Items[0].Profile.Actions[0].ResultResourceKind = "AUDIT_RECORD"
		}, false},
		{"platform condition", func(v *AuthorizationProfileList) {
			v.Items[0].Profile.Actions[0].Scope = AuthorityScopeInstallation
			v.Items[0].Profile.Actions[0].Conditions = []AuthorizationProfileCondition{{Key: ConditionIAMCurrentTime, ValueType: ConditionTime, Source: ConditionIAMTransactionTime}}
		}, false},
		{"forged condition source", func(v *AuthorizationProfileList) {
			v.Items[0].Profile.Actions[0].Scope = AuthorityScopeTenant
			v.Items[0].Profile.Actions[0].Conditions = []AuthorizationProfileCondition{{Key: ConditionIAMCurrentTime, ValueType: ConditionTime, Source: "CALLER"}}
		}, false},
		{"future declared namespace syntax", func(v *AuthorizationProfileList) {
			profile := &v.Items[0].Profile
			profile.Product, profile.CallingService = "future-product", "FUTURE_SERVICE"
			profile.Actions = []AuthorizationProfileAction{{Action: "future-product.resource.read", ResourceKind: "FUTURE_RESOURCE", Scope: AuthorityScopeTenant, ResourceShapes: []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}}}
			v.Items = v.Items[:1]
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, _ := json.Marshal(base)
			candidate, _ := DecodeAuthorizationProfileList(bytes.NewReader(encoded))
			test.mutate(&candidate)
			encoded, _ = json.Marshal(candidate)
			wire, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
			if err != nil || (schema.Validate(wire) == nil) != test.valid {
				t.Fatal("profile response schema disagrees with declared syntax/scope/shape")
			}
		})
	}
	encoded, _ := json.Marshal(base)
	for _, fragment := range []string{`"permit":true,`, `"nextAfter":"hidden-partial-catalog",`, `"callingService":"CALLER",`} {
		wire, err := jsonschema.UnmarshalJSON(strings.NewReader("{" + fragment + string(encoded[1:])))
		if err != nil || schema.Validate(wire) == nil {
			t.Fatal("discovery schema accepted an authority or partial-directory selector")
		}
	}
}

func TestEveryIAMOpenAPISchemaCompilesAsJSONSchema202012(t *testing.T) {
	document := loadIAMOpenAPI(t)
	for name := range iamOpenAPISchemas(t, document) {
		t.Run(name, func(t *testing.T) {
			_ = compileIAMOpenAPISchema(t, document, name)
		})
	}
}

func TestPolicyFamilySchemasUseAllMatchedCurrentCapabilities(t *testing.T) {
	api := loadIAMOpenAPI(t)
	documentSchema := compileIAMOpenAPISchema(t, api, "PolicyDocument")
	versionSchema := compileIAMOpenAPISchema(t, api, "PolicyVersion")
	instance := func(value any) any {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	for pattern, actions := range PolicyActionFamilies() {
		t.Run(string(pattern), func(t *testing.T) {
			document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
				Statements: []PolicyStatement{{SID: "family", Effect: PolicyAllow, Actions: []Action{pattern}}}}
			kinds := make(map[ResourceKind]bool)
			for _, action := range actions {
				definition, found := LookupActionDefinition(action)
				if !found {
					t.Fatal("projection contains unknown action")
				}
				if !kinds[definition.ResourceKind] {
					kinds[definition.ResourceKind] = true
					document.Statements[0].Resources = append(document.Statements[0].Resources, PolicyResourceSelector{Kind: definition.ResourceKind, Match: PolicyResourceAnyInAuthority})
				}
			}
			for name, change := range map[string]func(*PolicyDocument){
				"exact":        func(*PolicyDocument) {},
				"missing kind": func(v *PolicyDocument) { v.Statements[0].Resources = v.Statements[0].Resources[1:] },
				"wrong scope":  func(v *PolicyDocument) { v.Scope = AuthorityScopeInstallation },
				"duplicate":    func(v *PolicyDocument) { v.Statements[0].Actions = []Action{pattern, pattern} },
				"prefix": func(v *PolicyDocument) {
					for index := range v.Statements[0].Resources {
						v.Statements[0].Resources[index].Match = PolicyResourcePrefixInAuthority
						v.Statements[0].Resources[index].ID = "prefix-"
					}
				},
			} {
				t.Run(name, func(t *testing.T) {
					encoded, _ := json.Marshal(document)
					var changed PolicyDocument
					if json.Unmarshal(encoded, &changed) != nil {
						t.Fatal("invalid fixture")
					}
					change(&changed)
					accepted := ValidatePolicyDocument(changed) == nil
					if (documentSchema.Validate(instance(changed)) == nil) != accepted || (name == "exact" && !accepted) {
						t.Fatal("family schema and validator disagree on all-member capabilities")
					}
				})
			}
			compilation, err := CompilePolicyDocument(document, AllAuthorizationProfiles())
			if err != nil {
				t.Fatal(err)
			}
			_, digest, err := CanonicalizePolicyCompilation(document, compilation, AllAuthorizationProfiles())
			if err != nil {
				t.Fatal(err)
			}
			version := PolicyVersion{PolicyID: "policy-family", ID: "version-family", Document: document, ContentDigest: digest,
				ContractVersion: PolicyVersionCompiledContract, Compilation: &compilation}
			if ValidatePolicyVersion(version) != nil || versionSchema.Validate(instance(version)) != nil {
				t.Fatal("compiled family response rejected")
			}
			version.ContractVersion, version.Compilation = PolicyVersionLegacyContract, nil
			if ValidatePolicyVersion(version) == nil || versionSchema.Validate(instance(version)) == nil {
				t.Fatal("legacy shape admitted a pattern")
			}
		})
	}
}

func TestPolicyVersionResponseSchemaDoesNotSubstituteCurrentProductCatalog(t *testing.T) {
	profile := AuthorizationProfile{APIVersion: APIVersion, Kind: "AuthorizationProfile", Product: "archiveproduct", Revision: 7, CallingService: "ARCHIVEPRODUCER",
		Actions: []AuthorizationProfileAction{{Action: "archiveproduct.object.read", ResourceKind: "ARCHIVE_OBJECT", Scope: AuthorityScopeTenant,
			ResourceShapes: []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}}}}
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "read", Effect: PolicyAllow, Actions: []Action{"archiveproduct.object.read"},
			Resources: []PolicyResourceSelector{{Kind: "ARCHIVE_OBJECT", Match: PolicyResourceAnyInAuthority}}}}}
	compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{profile})
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{profile})
	if err != nil {
		t.Fatal(err)
	}
	version := PolicyVersion{PolicyID: "policy-archive", ID: "version-archive", Document: document, ContentDigest: digest,
		ContractVersion: PolicyVersionCompiledContract, Compilation: &compilation}
	encoded, err := json.Marshal(version)
	if err != nil {
		t.Fatal(err)
	}
	api := loadIAMOpenAPI(t)
	schema := compileIAMOpenAPISchema(t, api, "PolicyVersion")
	for _, test := range []struct {
		name     string
		source   string
		accepted bool
	}{
		{"exact frozen response", string(encoded), true},
		{"missing explicit contract", strings.Replace(string(encoded), `"contractVersion":2,`, "", 1), false},
		{"unsupported contract", strings.Replace(string(encoded), `"contractVersion":2`, `"contractVersion":3`, 1), false},
		{"legacy cannot carry compilation", strings.Replace(string(encoded), `"contractVersion":2`, `"contractVersion":1`, 1), false},
		{"storage wrapper not public", `{"value":` + string(encoded) + `,"canonical":"private"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			instance, err := jsonschema.UnmarshalJSON(strings.NewReader(test.source))
			if err != nil {
				t.Fatal(err)
			}
			if (schema.Validate(instance) == nil) != test.accepted {
				t.Fatal("response schema changed archived syntax or admitted an invalid format")
			}
			var decoded PolicyVersion
			if (json.Unmarshal([]byte(test.source), &decoded) == nil && ValidatePolicyVersion(decoded) == nil) != test.accepted {
				t.Fatal("strict version codec differs from response format")
			}
		})
	}
	author, _ := json.Marshal(document)
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(author))
	if err != nil {
		t.Fatal(err)
	}
	if compileIAMOpenAPISchema(t, api, "PolicyDocument").Validate(instance) == nil || ValidatePolicyDocument(document) == nil {
		t.Fatal("historical response syntax widened the current publisher")
	}
}

func TestUserPermissionBoundarySchemaAgreesWithStrictCodec(t *testing.T) {
	document := loadIAMOpenAPI(t)
	for _, name := range []string{"UserPermissionBoundary", "SetUserPermissionBoundaryRequest", "RemoveUserPermissionBoundaryRequest"} {
		t.Run(name, func(t *testing.T) {
			schema := compileIAMOpenAPISchema(t, document, name)
			var valid string
			switch name {
			case "UserPermissionBoundary":
				valid = `{"apiVersion":"` + APIVersion + `","kind":"UserPermissionBoundary","accountId":"account-example","userId":"user-example","resourceVersion":3,"policy":null}`
			case "SetUserPermissionBoundaryRequest":
				valid = `{"policyId":"policy-example","policyResourceVersion":2,"resourceVersion":3,"requestId":"request-example"}`
			default:
				valid = `{"resourceVersion":3,"requestId":"request-example"}`
			}
			check := func(source string, want bool) {
				t.Helper()
				instance, err := jsonschema.UnmarshalJSON(strings.NewReader(source))
				if err != nil {
					t.Fatal(err)
				}
				var codecErr error
				switch name {
				case "UserPermissionBoundary":
					var value UserPermissionBoundary
					codecErr = DecodeRequest(strings.NewReader(source), &value)
					if codecErr == nil {
						codecErr = ValidateUserPermissionBoundary(value)
					}
				case "SetUserPermissionBoundaryRequest":
					var value SetUserPermissionBoundaryRequest
					codecErr = DecodeRequest(strings.NewReader(source), &value)
					if codecErr == nil {
						codecErr = ValidateSetUserPermissionBoundaryRequest(value)
					}
				default:
					var value RemoveUserPermissionBoundaryRequest
					codecErr = DecodeRequest(strings.NewReader(source), &value)
					if codecErr == nil {
						codecErr = ValidateRemoveUserPermissionBoundaryRequest(value)
					}
				}
				if (schema.Validate(instance) == nil) != want || (codecErr == nil) != want {
					t.Fatalf("boundary schema/codec disagrees with expected acceptance=%v", want)
				}
			}
			check(valid, true)
			check(strings.Replace(valid, `"resourceVersion":3`, `"resourceVersion":0`, 1), false)
			check(strings.Replace(valid, `"resourceVersion":3`, `"resourceVersion":9007199254740992`, 1), false)
			check(`{"scope":"INSTALLATION",`+valid[1:], false)
			if name == "UserPermissionBoundary" {
				check(strings.Replace(valid, APIVersion, "untrusted/v1", 1), false)
				check(strings.Replace(valid, `"kind":"UserPermissionBoundary"`, `"kind":"PolicyAttachment"`, 1), false)
				check(strings.Replace(valid, `,"policy":null`, "", 1), false)
				check(strings.Replace(valid, `"policy":null`, `"policy":{}`, 1), false)
				check(strings.Replace(valid, `"policy":null`, `"policy":{"policyId":"policy-example","versionId":"version-example","contentDigest":"sha256:`+strings.Repeat("a", 64)+`"}`, 1), true)
			} else {
				check(strings.Replace(valid, `"resourceVersion":3`, `"resourceVersion":9007199254740991`, 1), false)
				check(`{"userId":"other",`+valid[1:], false)
			}
		})
	}
}

func TestPolicyConditionSchemaRejectsUntrustedShape(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "CreatePolicyRequest")
	value := CreatePolicyRequest{DisplayName: "Timed read", RequestID: "timed-create", Document: policyDocumentFixture()}
	value.Document.Statements[0].Conditions = []PolicyCondition{{Key: ConditionIAMCurrentTime, Operator: PolicyDateLessThan, Values: []string{"2026-09-15T00:00:00Z"}}}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	check := func(encoded []byte, want bool) {
		t.Helper()
		instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		if (schema.Validate(instance) == nil) != want {
			t.Fatal("schema condition acceptance differs")
		}
	}
	check(encoded, true)
	for _, invalid := range []string{
		strings.Replace(string(encoded), "iam.current-time", "request.time", 1),
		strings.Replace(string(encoded), "DATE_LESS_THAN", "DATE_NOT_EQUALS", 1),
		strings.Replace(string(encoded), `"values":["2026-09-15T00:00:00Z"]`, `"values":[]`, 1),
		strings.Replace(string(encoded), `"values":["2026-09-15T00:00:00Z"]`, `"values":["2026-09-15T00:00:00+00:00"]`, 1),
		strings.Replace(string(encoded), `"key":`, `"source":"CALLER","key":`, 1),
	} {
		check([]byte(invalid), false)
	}
	for _, definition := range AllActionDefinitions() {
		if definition.AuthorityScope == AuthorityScopeTenant {
			continue
		}
		document := value.Document
		document.Scope = definition.AuthorityScope
		document.Statements = append([]PolicyStatement(nil), value.Document.Statements[:1]...)
		document.Statements[0].Actions = []Action{definition.Action}
		document.Statements[0].Resources = []PolicyResourceSelector{{Kind: definition.ResourceKind, Match: PolicyResourceAnyInAuthority}}
		if ValidatePolicyDocument(document) == nil {
			t.Fatal("undeclared platform/probe time condition accepted")
		}
	}
}

func TestResourcePrefixSchemaIsLiteralAndTenantOnly(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "PolicyDocument")
	for _, action := range AllActionDefinitions() {
		value := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: action.AuthorityScope,
			Statements: []PolicyStatement{{SID: "Prefix", Effect: PolicyAllow, Actions: []Action{action.Action},
				Resources: []PolicyResourceSelector{{Kind: action.ResourceKind, Match: "PREFIX_IN_AUTHORITY", ID: "resource-"}}}}}
		for _, id := range []string{"resource-", "", "resource-*", "resource?", strings.Repeat("r", 129)} {
			value.Statements[0].Resources[0].ID = id
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			valid := action.ResourcePrefixAllowed && id == "resource-"
			if (schema.Validate(instance) == nil) != valid || (ValidatePolicyDocument(value) == nil) != valid {
				t.Fatal("prefix schema/validator scope or grammar differs")
			}
		}
	}
}

func TestIdentityConditionSchemaUsesKeySpecificOperatorsAndBoundedIDs(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "CreatePolicyRequest")
	for _, key := range []ConditionKey{ConditionIAMAccountID, ConditionIAMPrincipalID} {
		for _, operator := range []PolicyConditionOperator{PolicyStringEquals, PolicyStringNotEquals} {
			value := CreatePolicyRequest{DisplayName: "Identity read", RequestID: "identity-create", Document: policyDocumentFixture()}
			value.Document.Statements[0].Conditions = []PolicyCondition{{Key: key, Operator: operator, Values: []string{"identity-b", "identity-a"}}}
			check := func(want bool) {
				t.Helper()
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
				if err != nil {
					t.Fatal(err)
				}
				if (schema.Validate(instance) == nil) != want || (ValidateCreatePolicyRequest(value) == nil) != want {
					t.Fatal("identity schema/validator acceptance differs")
				}
			}
			check(true)
			duplicate := value.Document.Statements[0].Conditions[0]
			duplicate.Values = []string{"identity-c"}
			value.Document.Statements[0].Conditions = append(value.Document.Statements[0].Conditions, duplicate)
			check(false)
			otherKey := ConditionIAMAccountID
			if key == otherKey {
				otherKey = ConditionIAMPrincipalID
			}
			value.Document.Statements[0].Conditions[1].Key = otherKey
			check(true)
			value.Document.Statements[0].Conditions = value.Document.Statements[0].Conditions[:1]
			condition := &value.Document.Statements[0].Conditions[0]
			condition.Operator = PolicyDateLessThan
			check(false)
			condition.Operator = operator
			for _, values := range [][]string{nil, {}, {""}, {"identity-*"}, {"identity-a", "identity-a"}, {"2026-09-15T00:00:00Z"}} {
				// A time-looking value still follows the ID grammar, not its label;
				// ':' is a valid opaque ID character.
				condition.Values = values
				check(len(values) == 1 && values[0] == "2026-09-15T00:00:00Z")
			}
			condition.Values = make([]string, MaxStringConditionValues+1)
			for index := range condition.Values {
				condition.Values[index] = fmt.Sprintf("id-%d", index)
			}
			check(false)
		}
	}
}

func TestCustomerPolicyPublicationUsesTheStrictTenantLanguage(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "CreatePolicyRequest")
	check := func(value CreatePolicyRequest, valid bool) {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		if (ValidateCreatePolicyRequest(value) == nil) != valid || (schema.Validate(instance) == nil) != valid {
			t.Fatalf("policy creation schema/validator disagree: expected valid=%t", valid)
		}
	}
	valid := func() CreatePolicyRequest {
		return CreatePolicyRequest{DisplayName: "Application access", RequestID: "create-policy", Document: policyDocumentFixture()}
	}
	check(valid(), true)
	for _, action := range AllActionDefinitions() {
		value := valid()
		value.Document.Scope = action.AuthorityScope
		value.Document.Statements = []PolicyStatement{{SID: "one", Effect: PolicyAllow, Actions: []Action{action.Action},
			Resources: []PolicyResourceSelector{{Kind: action.ResourceKind, Match: PolicyResourceAnyInAuthority}}}}
		check(value, action.AuthorityScope == AuthorityScopeTenant)
	}
	for name, mutate := range map[string]func(*CreatePolicyRequest){
		"empty display name": func(v *CreatePolicyRequest) { v.DisplayName = "" },
		"unknown language":   func(v *CreatePolicyRequest) { v.Document.LanguageVersion = "future" },
		"duplicate action": func(v *CreatePolicyRequest) {
			v.Document.Statements[0].Actions = []Action{ActionPaaSApplicationRead, ActionPaaSApplicationRead}
		},
		"missing resource":     func(v *CreatePolicyRequest) { v.Document.Statements[0].Resources = nil },
		"caller wildcard":      func(v *CreatePolicyRequest) { v.Document.Statements[0].Actions = []Action{"*"} },
		"unknown selector":     func(v *CreatePolicyRequest) { v.Document.Statements[0].Resources[0].Match = "PREFIX" },
		"oversized statements": func(v *CreatePolicyRequest) { v.Document.Statements = make([]PolicyStatement, MaxPolicyStatements+1) },
	} {
		t.Run(name, func(t *testing.T) { value := valid(); mutate(&value); check(value, false) })
	}
	encoded, _ := json.Marshal(valid())
	var instance map[string]any
	if json.Unmarshal(encoded, &instance) != nil {
		t.Fatal("decode policy request")
	}
	for _, field := range []string{"accountId", "tenantId", "management", "policyId", "installationId"} {
		instance[field] = "caller-selected"
		if schema.Validate(instance) == nil {
			t.Fatalf("policy request allows caller authority selector %s", field)
		}
		delete(instance, field)
	}
}

func TestPolicyVersionCommandsBindOwnerRevisionAndImmutableContent(t *testing.T) {
	openapi := loadIAMOpenAPI(t)
	createSchema := compileIAMOpenAPISchema(t, openapi, "CreatePolicyVersionRequest")
	selectSchema := compileIAMOpenAPISchema(t, openapi, "SetDefaultPolicyVersionRequest")
	updateSchema := compileIAMOpenAPISchema(t, openapi, "UpdatePolicyRequest")
	deleteSchema := compileIAMOpenAPISchema(t, openapi, "DeletePolicyRequest")
	deleteVersionSchema := compileIAMOpenAPISchema(t, openapi, "DeletePolicyVersionRequest")
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
	create := CreatePolicyVersionRequest{Document: policyDocumentFixture(), ResourceVersion: 2, RequestID: "version-create"}
	selection := SetDefaultPolicyVersionRequest{VersionID: "version-one", ResourceVersion: 2, RequestID: "version-select"}
	update := UpdatePolicyRequest{DisplayName: "Renamed policy", ResourceVersion: 2, RequestID: "policy-rename"}
	deletion := DeletePolicyRequest{ResourceVersion: 2, RequestID: "policy-delete"}
	versionDeletion := DeletePolicyVersionRequest{ResourceVersion: 2, RequestID: "version-delete"}
	if ValidateDeletePolicyVersionRequest(versionDeletion) != nil || deleteVersionSchema.Validate(instance(versionDeletion)) != nil {
		t.Fatal("valid version deletion rejected")
	}
	if ValidateDeletePolicyRequest(deletion) != nil || deleteSchema.Validate(instance(deletion)) != nil {
		t.Fatal("valid policy deletion rejected")
	}
	if ValidateUpdatePolicyRequest(update) != nil || updateSchema.Validate(instance(update)) != nil {
		t.Fatal("valid metadata update rejected")
	}
	for _, name := range []string{"", strings.Repeat("x", 129)} {
		invalid := update
		invalid.DisplayName = name
		if ValidateUpdatePolicyRequest(invalid) == nil || updateSchema.Validate(instance(invalid)) == nil {
			t.Fatal("metadata name budget was not enforced")
		}
	}
	for _, field := range []string{"accountId", "management", "scope", "document", "defaultVersionId", "id"} {
		versionAttack := instance(versionDeletion).(map[string]any)
		versionAttack[field] = "injected"
		if deleteVersionSchema.Validate(versionAttack) == nil {
			t.Fatal("version deletion admitted selector")
		}
		deleteAttack := instance(deletion).(map[string]any)
		deleteAttack[field] = "injected"
		if deleteSchema.Validate(deleteAttack) == nil {
			t.Fatal("policy deletion admitted selector")
		}
		attack := instance(update).(map[string]any)
		attack[field] = "injected"
		if updateSchema.Validate(attack) == nil {
			t.Fatal("metadata update admitted an authority selector")
		}
	}
	if ValidateCreatePolicyVersionRequest(create) != nil || createSchema.Validate(instance(create)) != nil || ValidateSetDefaultPolicyVersionRequest(selection) != nil || selectSchema.Validate(instance(selection)) != nil {
		t.Fatal("valid version command rejected")
	}
	for _, revision := range []uint64{0, 9007199254740991, 9007199254740992} {
		versionDeletion.ResourceVersion = revision
		if ValidateDeletePolicyVersionRequest(versionDeletion) == nil || deleteVersionSchema.Validate(instance(versionDeletion)) == nil {
			t.Fatal("invalid version deletion revision admitted")
		}
		deletion.ResourceVersion = revision
		if ValidateDeletePolicyRequest(deletion) == nil || deleteSchema.Validate(instance(deletion)) == nil {
			t.Fatal("invalid deletion revision admitted")
		}
		update.ResourceVersion = revision
		if ValidateUpdatePolicyRequest(update) == nil || updateSchema.Validate(instance(update)) == nil {
			t.Fatal("metadata update admitted non-incrementable revision")
		}
		create.ResourceVersion, selection.ResourceVersion = revision, revision
		if ValidateCreatePolicyVersionRequest(create) == nil || createSchema.Validate(instance(create)) == nil || ValidateSetDefaultPolicyVersionRequest(selection) == nil || selectSchema.Validate(instance(selection)) == nil {
			t.Fatal("non-incrementable version command admitted")
		}
	}
	create.ResourceVersion = 2
	create.Document.Scope = AuthorityScopeInstallation
	if ValidateCreatePolicyVersionRequest(create) == nil || createSchema.Validate(instance(create)) == nil {
		t.Fatal("tenant version admitted installation content")
	}
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	document := policyDocumentFixture()
	_, digest, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{APIVersion: APIVersion, Kind: "Policy", ID: "policy-version-example", Management: PolicyCustomerManaged, AccountID: "account-one", DisplayName: "Versioned policy", Scope: AuthorityScopeTenant, Status: PolicyActive, DefaultVersionID: "version-a", ResourceVersion: 2, CreatedAt: now, UpdatedAt: now}
	version := PolicyVersion{PolicyID: policy.ID, ID: "version-b", Document: document, ContentDigest: digest, ContractVersion: PolicyVersionLegacyContract}
	detail := PolicyVersionDetail{APIVersion: APIVersion, Kind: "PolicyVersionDetail", Policy: policy, Version: version}
	if ValidatePolicyVersionDetail(detail) != nil {
		t.Fatal("nondefault version read rejected")
	}
	if ValidatePolicyDetail(PolicyDetail{APIVersion: APIVersion, Kind: "PolicyDetail", Policy: policy, Version: version}) == nil {
		t.Fatal("nondefault version widened existing current-default contract")
	}
	defaultVersion := version
	defaultVersion.ID = policy.DefaultVersionID
	list := PolicyVersionList{APIVersion: APIVersion, Kind: "PolicyVersionList", Policy: policy, Items: []PolicyVersion{defaultVersion, version}}
	listSchema := compileIAMOpenAPISchema(t, openapi, "PolicyVersionList")
	detailSchema := compileIAMOpenAPISchema(t, openapi, "PolicyVersionDetail")
	if ValidatePolicyVersionList(list) != nil || listSchema.Validate(instance(list)) != nil || detailSchema.Validate(instance(detail)) != nil {
		t.Fatal("valid version inventory/detail rejected")
	}
	for name, mutate := range map[string]func(*PolicyVersionList){
		"empty":           func(v *PolicyVersionList) { v.Items = nil },
		"missing default": func(v *PolicyVersionList) { v.Items = []PolicyVersion{version} },
		"wrong owner":     func(v *PolicyVersionList) { v.Items[0].PolicyID = "another-policy" },
		"duplicate":       func(v *PolicyVersionList) { v.Items[1] = v.Items[0] },
		"unsorted":        func(v *PolicyVersionList) { v.Items[0], v.Items[1] = v.Items[1], v.Items[0] },
		"retired":         func(v *PolicyVersionList) { v.Policy.Status = PolicyRetired },
		"too many":        func(v *PolicyVersionList) { v.Items = make([]PolicyVersion, MaxPolicyVersions+1) },
	} {
		t.Run(name, func(t *testing.T) {
			value := list
			value.Items = append([]PolicyVersion(nil), list.Items...)
			mutate(&value)
			if ValidatePolicyVersionList(value) == nil {
				t.Fatal("invalid version inventory accepted")
			}
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
			if test.current {
				var err error
				request, err = NewAuthorizationRequest(test.action, request.Resource, AuthorizationResourceInstance, "", request.RequestID, request.CorrelationID)
				if err != nil {
					t.Fatal(err)
				}
			}
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
				Allowed: true, Reason: DecisionAllowed, TenantID: "account-one", Subject: &Subject{Type: SubjectUser, ID: "user-one"},
				Action: test.action, Resource: request.Resource, RequestID: request.RequestID,
				DecidedAt: time.Date(2026, 8, 25, 1, 2, 3, 0, time.UTC)}
			if test.scope == AuthorityScopeInstallation {
				decision.TenantID, decision.InstallationID = "", "installation-one"
			}
			if test.current {
				decision.Profile, decision.ResourceMode, decision.CorrelationID = &request.Profile, request.ResourceMode, request.CorrelationID
			}
			check := func(value AuthorizationDecision, valid bool) {
				t.Helper()
				if !test.current && (ValidateLegacyAuthorizationDecision(value) == nil) != valid {
					t.Fatal("explicit legacy validator lost the original evidence contract")
				}
				if (ValidateAuthorizationDecision(value) == nil) != (valid && test.current) || (decisionSchema.Validate(instance(value)) == nil) != (valid && test.current) {
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
				wrong.Subject = &Subject{Type: SubjectServiceAccount, ID: "service-one"}
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
	blocked := func(action Action, kind ResourceKind, id string) ActionCapability {
		return ActionCapability{Action: action, Resource: ResourceReference{Kind: kind, ID: id}, RestrictionReason: CapabilityAuthorityRequired}
	}
	capabilities := []ActionCapability{
		blocked(ActionIAMUserSetStatus, ResourceUser, string(user.ID)),
		blocked(ActionIAMUserPasswordReset, ResourceUser, string(user.ID)),
		blocked(ActionIAMPolicyAttachmentCreate, ResourceUser, string(user.ID)),
		blocked(ActionIAMPlatformPolicyAttachmentCreate, ResourceUser, string(user.ID)),
		blocked(ActionIAMPolicyAttachmentRevoke, ResourcePolicyAttachment, string(attachment.ID)),
	}
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
			encoded, err := json.Marshal(UserAccess{User: user, PolicyAttachments: []PolicyAttachment{attachment}, Capabilities: capabilities})
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
		{"retired does not consume active inventory", func(v *PolicyList) { v.Items[0].Status = PolicyRetired }, false},
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
		{"retired policy excluded", func(v map[string]any) { v["items"].([]any)[0].(map[string]any)["status"] = "RETIRED" }, false},
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
		{"role syntax does not grant management authority", "CreatePolicyAttachmentRequest", `{"target":{"kind":"ROLE","id":"role-a"},"policyId":"system.paas-viewer","policyResourceVersion":1,"requestId":"attach-a"}`, true},
		{"direct group", "CreatePolicyAttachmentRequest", `{"target":{"kind":"GROUP","id":"group-a"},"policyId":"system.paas-viewer","policyResourceVersion":1,"requestId":"attach-a"}`, true},
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

func TestActionCapabilitySchemaAcceptsEveryCurrentRestriction(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "ActionCapability")
	for _, restriction := range AllCapabilityRestrictions() {
		value := map[string]any{
			"action":            string(ActionIAMUserDelete),
			"resource":          map[string]any{"kind": string(ResourceUser), "id": "user-a"},
			"available":         false,
			"restrictionReason": string(restriction),
		}
		if err := schema.Validate(value); err != nil {
			t.Fatalf("current restriction %q is absent from ActionCapability schema: %v", restriction, err)
		}
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
	platform["resourceMode"] = string(AuthorizationResourceInstance)
	delete(platform, "collectionUsage")
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
