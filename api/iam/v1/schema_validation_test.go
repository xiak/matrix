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

func TestAuthenticatorRecoverySchemasSeparateLoginProofFromRebinding(t *testing.T) {
	api := loadIAMOpenAPI(t)
	recovery := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"AuthenticatorRecovery","id":"recovery-a","requestId":"request-a","state":"STARTED","createdAt":"2026-09-20T12:01:00Z","expiresAt":"2026-09-20T12:05:00Z"}`
	challenge := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"AuthenticationChallenge","id":"challenge-b","purpose":"RECOVERY","nextStep":"ENROLLMENT","expiresAt":"2026-09-20T12:05:00Z"}`
	start := `{"recovery":` + recovery + `,"challenge":` + challenge + `,"challengeCredential":"synthetic-credential","provisioning":{"seed":"synthetic-seed","uri":"synthetic-uri"}}`
	request := `{"requestId":"request-a","challengeCredential":"synthetic-credential","recoveryCode":"candidate"}`
	query := `{"requestId":"request-a","challengeCredential":"synthetic-credential"}`
	login := `{"outcome":"CHALLENGE_REQUIRED","challenge":` + challenge + `,"challengeCredential":"synthetic-credential"}`
	for index, sample := range []struct {
		kind, wire string
		valid      bool
	}{
		{"AuthenticatorRecovery", recovery, true},
		{"AuthenticatorRecovery", strings.TrimSuffix(recovery, "}") + `,"completedAt":null}`, false},
		{"AuthenticatorRecovery", strings.Replace(recovery, `"STARTED"`, `"COMPLETED"`, 1), false},
		{"StartAuthenticatorRecoveryRequest", request, true},
		{"StartAuthenticatorRecoveryRequest", strings.Replace(request, `"candidate"`, `""`, 1), false},
		{"StartAuthenticatorRecoveryRequest", strings.TrimSuffix(request, "}") + `,"accountId":"other"}`, false},
		{"InspectAuthenticatorRecoveryRequest", query, true},
		{"InspectAuthenticatorRecoveryRequest", strings.TrimSuffix(query, "}") + `,"recoveryCode":"another"}`, false},
		{"StartAuthenticatorRecoveryResponse", start, true},
		{"StartAuthenticatorRecoveryResponse", strings.Replace(start, `"RECOVERY"`, `"LOGIN"`, 1), false},
		{"StartAuthenticatorRecoveryResponse", strings.Replace(start, `"ENROLLMENT"`, `"TOTP"`, 1), false},
		{"StartAuthenticatorRecoveryResponse", strings.TrimSuffix(start, "}") + `,"session":null}`, false},
		{"LoginResponse", login, false},
		{"LoginResponse", strings.Replace(strings.Replace(login, `"RECOVERY"`, `"LOGIN"`, 1), `"ENROLLMENT"`, `"RECOVER"`, 1), true},
	} {
		schema := compileIAMOpenAPISchema(t, api, sample.kind)
		var raw any
		if json.Unmarshal([]byte(sample.wire), &raw) != nil {
			t.Fatal("invalid synthetic fixture")
		}
		if (schema.Validate(raw) == nil) != sample.valid {
			t.Fatalf("sample %d schema/runtime recovery boundary differs", index)
		}
		var value any
		switch sample.kind {
		case "AuthenticatorRecovery":
			value = new(AuthenticatorRecovery)
		case "StartAuthenticatorRecoveryRequest":
			value = new(StartAuthenticatorRecoveryRequest)
		case "InspectAuthenticatorRecoveryRequest":
			value = new(InspectAuthenticatorRecoveryRequest)
		case "StartAuthenticatorRecoveryResponse":
			value = new(StartAuthenticatorRecoveryResponse)
		case "LoginResponse":
			value = new(LoginResponse)
		}
		if (json.Unmarshal([]byte(sample.wire), value) == nil) != sample.valid {
			t.Fatalf("sample %d decoder recovery boundary differs", index)
		}
	}
}

func TestAuthenticationChallengeRequestHasOneRestrictedSecretCarrier(t *testing.T) {
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "VerifyAuthenticationChallengeRequest")
	valid := `{"requestId":"verify-one","challengeCredential":"synthetic-challenge-material","code":"123456"}`
	for _, sample := range []struct {
		wire  string
		valid bool
	}{
		{valid, true},
		{strings.Replace(valid, `"123456"`, `"not-a-code"`, 1), true},
		{strings.Replace(valid, `"requestId":`, `"userId":"other","requestId":`, 1), false},
		{strings.Replace(valid, `"requestId":`, `"purpose":"LOGIN","requestId":`, 1), false},
		{strings.Replace(valid, `"synthetic-challenge-material"`, `null`, 1), false},
		{strings.Replace(valid, `"123456"`, `null`, 1), false},
		{strings.Replace(valid, `"123456"`, `""`, 1), false},
		{strings.Replace(valid, `,"code":"123456"`, "", 1), false},
	} {
		var raw any
		if json.Unmarshal([]byte(sample.wire), &raw) != nil {
			t.Fatal("invalid fixture")
		}
		if (schema.Validate(raw) == nil) != sample.valid {
			t.Fatal("challenge request schema mismatch")
		}
		var request VerifyAuthenticationChallengeRequest
		err := DecodeRequest(strings.NewReader(sample.wire), &request)
		if (err == nil) != sample.valid {
			t.Fatal("challenge request decoder mismatch")
		}
		if sample.valid {
			if data, err := json.Marshal(request); err == nil || len(data) > 0 {
				t.Fatal("ordinary encoding emitted authentication material")
			}
			encoded, err := EncodeVerifyAuthenticationChallengeRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			var replay VerifyAuthenticationChallengeRequest
			if DecodeRequest(bytes.NewReader(encoded), &replay) != nil {
				t.Fatal("explicit transport failed")
			}
			clear(encoded)
		}
	}
	for _, duplicate := range []string{"requestId", "challengeCredential", "code"} {
		var request VerifyAuthenticationChallengeRequest
		if DecodeRequest(strings.NewReader(strings.TrimSuffix(valid, "}")+`,"`+duplicate+`":"duplicate"}`), &request) == nil {
			t.Fatal("duplicate field accepted")
		}
	}
}

func TestChallengePasswordChangeCannotIssueOrRetainASession(t *testing.T) {
	api := loadIAMOpenAPI(t)
	requestSchema := compileIAMOpenAPISchema(t, api, "ChallengePasswordChangeRequest")
	valid := `{"requestId":"forced-one","challengeCredential":"synthetic-password-challenge","newPassword":"synthetic-replacement-password"}`
	for _, sample := range []struct {
		wire  string
		valid bool
	}{
		{valid, true},
		{strings.Replace(valid, `"synthetic-password-challenge"`, `null`, 1), false},
		{strings.Replace(valid, `"synthetic-replacement-password"`, `""`, 1), false},
		{strings.TrimSuffix(valid, "}") + `,"session":null}`, false},
		{strings.TrimSuffix(valid, "}") + `,"userId":"other"}`, false},
		{strings.TrimSuffix(valid, "}") + `,"revokeOtherSessions":false}`, false},
		{strings.TrimSuffix(valid, "}") + `,"currentPassword":"another"}`, false},
	} {
		var raw any
		if json.Unmarshal([]byte(sample.wire), &raw) != nil {
			t.Fatal("invalid fixture")
		}
		if (requestSchema.Validate(raw) == nil) != sample.valid {
			t.Fatal("forced password request schema differs")
		}
		var request ChallengePasswordChangeRequest
		if (DecodeRequest(strings.NewReader(sample.wire), &request) == nil) != sample.valid {
			t.Fatal("forced password request codec differs")
		}
		if sample.valid {
			if encoded, err := json.Marshal(request); err == nil || len(encoded) > 0 {
				t.Fatal("ordinary JSON disclosed challenge/password")
			}
			if strings.Contains(fmt.Sprintf("%+v %#v", request, request), "synthetic-") {
				t.Fatal("formatted request disclosed material")
			}
			encoded, err := EncodeChallengePasswordChangeRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			var decoded ChallengePasswordChangeRequest
			if DecodeRequest(bytes.NewReader(encoded), &decoded) != nil {
				t.Fatal("explicit challenge transport failed")
			}
			clear(encoded)
		}
	}
	for _, field := range []string{"requestId", "newPassword", "challengeCredential"} {
		var request ChallengePasswordChangeRequest
		if DecodeRequest(strings.NewReader(strings.TrimSuffix(valid, "}")+`,"`+field+`":"duplicate"}`), &request) == nil {
			t.Fatal("duplicate password command field accepted")
		}
	}
	responseSchema := compileIAMOpenAPISchema(t, api, "ChallengePasswordChangeResponse")
	completion := `{"nextStep":"REAUTHENTICATE","changedAt":"2026-09-20T12:00:00Z"}`
	for _, sample := range []struct {
		wire  string
		valid bool
	}{
		{completion, true},
		{strings.Replace(completion, "REAUTHENTICATE", "AUTHENTICATED", 1), false},
		{strings.TrimSuffix(completion, "}") + `,"credential":null}`, false},
		{strings.TrimSuffix(completion, "}") + `,"session":null}`, false},
	} {
		var raw any
		if json.Unmarshal([]byte(sample.wire), &raw) != nil {
			t.Fatal("invalid fixture")
		}
		if (responseSchema.Validate(raw) == nil) != sample.valid {
			t.Fatal("password completion schema differs")
		}
		var response ChallengePasswordChangeResponse
		if (DecodeRequest(strings.NewReader(sample.wire), &response) == nil) != sample.valid {
			t.Fatal("password completion codec differs")
		}
	}
	challengeSchema := compileIAMOpenAPISchema(t, api, "AuthenticationChallenge")
	for _, step := range []string{"TOTP", "PASSWORD_CHANGE", "RECOVERY", "SESSION"} {
		challenge := AuthenticationChallenge{APIVersion: APIVersion, Kind: "AuthenticationChallenge", ID: "one", Purpose: "LOGIN", NextStep: step, ExpiresAt: time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)}
		encoded, _ := json.Marshal(challenge)
		var raw any
		_ = json.Unmarshal(encoded, &raw)
		want := step == "TOTP" || step == "PASSWORD_CHANGE"
		if (challengeSchema.Validate(raw) == nil) != want || (ValidateAuthenticationChallenge(challenge) == nil) != want {
			t.Fatal("undeclared challenge step accepted")
		}
	}
}

func TestTOTPEnrollmentContractsKeepOneTimeMaterialOutOfReplay(t *testing.T) {
	api := loadIAMOpenAPI(t)
	paths := mustIAMObject(t, api["paths"], "paths")
	for _, endpoint := range []struct {
		path, method string
		statuses     []string
	}{
		{"/v1/auth/authenticators", "get", []string{"200", "400", "401", "503"}},
		{"/v1/auth/totp/enrollments/{enrollmentId}", "get", []string{"200", "400", "401", "404", "503"}},
		{"/v1/auth/totp/enrollments/{enrollmentId}", "delete", []string{"200", "400", "401", "404", "409", "503"}},
		{"/v1/auth/totp/enrollments/by-request/{requestId}", "get", []string{"200", "400", "401", "404", "503"}},
	} {
		path := mustIAMObject(t, paths[endpoint.path], "enrollment path")
		operation := mustIAMObject(t, path[endpoint.method], "enrollment operation")
		if _, present := operation["requestBody"]; present {
			t.Fatal("metadata or cancellation accepts an extra command body")
		}
		responses := mustIAMObject(t, operation["responses"], "enrollment responses")
		for _, status := range endpoint.statuses {
			if responses[status] == nil {
				t.Fatalf("%s %s omits actual response %s", endpoint.method, endpoint.path, status)
			}
		}
	}
	enrollment := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"TOTPEnrollment","id":"factor-one","requestId":"enroll-one","factorRevision":1,"state":"PENDING","createdAt":"2026-09-20T01:00:00Z","expiresAt":"2026-09-20T01:05:00Z"}`
	applied := `{"outcome":"APPLIED","enrollment":` + enrollment + `,"provisioning":{"seed":"synthetic-seed-only","uri":"synthetic-uri-only"}}`
	replay := `{"outcome":"EQUAL_REPLAY","enrollment":` + enrollment + `}`
	schema := compileIAMOpenAPISchema(t, api, "StartTOTPEnrollmentResponse")
	for _, sample := range []struct {
		wire  string
		valid bool
	}{
		{applied, true}, {replay, true},
		{strings.Replace(applied, `"APPLIED"`, `"EQUAL_REPLAY"`, 1), false},
		{strings.Replace(replay, `"EQUAL_REPLAY"`, `"APPLIED"`, 1), false},
		{strings.TrimSuffix(replay, "}") + `,"provisioning":null}`, false},
		{strings.Replace(applied, `"synthetic-seed-only"`, `null`, 1), false},
		{strings.Replace(applied, `"PENDING"`, `"CONFIRMED"`, 1), false},
		{strings.TrimSuffix(applied, "}") + `,"session":null}`, false},
		{strings.Replace(applied, `"factorRevision":1`, `"factorRevision":0`, 1), false},
	} {
		var wire any
		if json.Unmarshal([]byte(sample.wire), &wire) != nil {
			t.Fatal("invalid fixture")
		}
		if (schema.Validate(wire) == nil) != sample.valid {
			t.Fatal("enrollment schema branch differs")
		}
		var result StartTOTPEnrollmentResponse
		if (DecodeRequest(strings.NewReader(sample.wire), &result) == nil) != sample.valid {
			t.Fatal("enrollment codec branch differs")
		}
		if sample.valid {
			encoded, err := EncodeStartTOTPEnrollmentResponse(result)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(encoded)
			if result.Outcome == "EQUAL_REPLAY" && bytes.Contains(encoded, []byte("provisioning")) {
				t.Fatal("replay exposed provisioning")
			}
			if raw, err := json.Marshal(result); err == nil || len(raw) != 0 {
				t.Fatal("ordinary JSON exposed enrollment response")
			}
			if strings.Contains(fmt.Sprintf("%+v %#v", result, result), "synthetic-seed-only") || strings.Contains(fmt.Sprintf("%+v %#v", result, result), "synthetic-uri-only") {
				t.Fatal("formatted enrollment exposed secrets")
			}
		}
	}
	confirmed := strings.Replace(enrollment, `"PENDING"`, `"CONFIRMED"`, 1)
	confirmed = strings.TrimSuffix(confirmed, "}") + `,"completedAt":"2026-09-20T01:00:30Z"}`
	codes := make([]string, 10)
	for i := range codes {
		codes[i] = fmt.Sprintf("synthetic-recovery-%02d", i)
	}
	encodedCodes, _ := json.Marshal(codes)
	completion := `{"enrollment":` + confirmed + `,"nextStep":"REAUTHENTICATE","recoveryCodes":` + string(encodedCodes) + `}`
	confirmSchema := compileIAMOpenAPISchema(t, api, "ConfirmTOTPEnrollmentResponse")
	for _, sample := range []struct {
		wire  string
		valid bool
	}{
		{completion, true},
		{strings.Replace(completion, `"REAUTHENTICATE"`, `"AUTHENTICATED"`, 1), false},
		{strings.Replace(completion, `"CONFIRMED"`, `"PENDING"`, 1), false},
		{strings.Replace(completion, `"synthetic-recovery-00",`, "", 1), false},
		{strings.Replace(completion, `"synthetic-recovery-01"`, `"synthetic-recovery-00"`, 1), false},
		{strings.TrimSuffix(completion, "}") + `,"credential":"not-a-session"}`, false},
	} {
		var raw any
		if json.Unmarshal([]byte(sample.wire), &raw) != nil {
			t.Fatal("invalid confirmation fixture")
		}
		if (confirmSchema.Validate(raw) == nil) != sample.valid {
			t.Fatal("confirmation schema differs")
		}
		var result ConfirmTOTPEnrollmentResponse
		if (DecodeRequest(strings.NewReader(sample.wire), &result) == nil) != sample.valid {
			t.Fatal("confirmation codec differs")
		}
		if sample.valid {
			encoded, err := EncodeConfirmTOTPEnrollmentResponse(result)
			if err != nil || !bytes.Contains(encoded, []byte("synthetic-recovery-00")) {
				t.Fatal("explicit confirmation transport failed")
			}
			clear(encoded)
			if raw, err := json.Marshal(result); err == nil || len(raw) != 0 {
				t.Fatal("ordinary JSON exposed recovery codes")
			}
			if strings.Contains(fmt.Sprintf("%+v %#v", result, result), "synthetic-recovery") {
				t.Fatal("formatting exposed recovery material")
			}
		}
	}
}

func TestTOTPEnrollmentRequestsRejectSelectorsAndAmbiguousSecrets(t *testing.T) {
	for _, name := range []string{"StartTOTPEnrollmentRequest", "ConfirmTOTPEnrollmentRequest"} {
		schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), name)
		valid := `{"requestId":"enroll-one","password":"synthetic-password","expectedFactorRevision":1}`
		secretField := "password"
		if name == "ConfirmTOTPEnrollmentRequest" {
			valid = `{"requestId":"confirm-one","code":"123456"}`
			secretField = "code"
		}
		for _, sample := range []struct {
			wire  string
			valid bool
		}{
			{valid, true},
			{strings.Replace(valid, `"requestId":`, `"userId":"other","requestId":`, 1), false},
			{strings.Replace(valid, `"requestId":`, `"challengeCredential":"other","requestId":`, 1), false},
			{strings.Replace(valid, `"requestId":`, `"purpose":"RECOVERY","requestId":`, 1), false},
			{strings.Replace(valid, `"`+secretField+`":"`+map[string]string{"password": "synthetic-password", "code": "123456"}[secretField]+`"`, `"`+secretField+`":null`, 1), false},
		} {
			var wire any
			if json.Unmarshal([]byte(sample.wire), &wire) != nil {
				t.Fatal("invalid request fixture")
			}
			if (schema.Validate(wire) == nil) != sample.valid {
				t.Fatal("enrollment request schema mismatch")
			}
			var result any = &StartTOTPEnrollmentRequest{}
			if name == "ConfirmTOTPEnrollmentRequest" {
				result = &ConfirmTOTPEnrollmentRequest{}
			}
			if (DecodeRequest(strings.NewReader(sample.wire), result) == nil) != sample.valid {
				t.Fatal("enrollment request decoder mismatch")
			}
			if sample.valid {
				if output, err := json.Marshal(result); err == nil || len(output) != 0 {
					t.Fatal("ordinary request encoding exposed a secret")
				}
			}
		}
		for _, field := range []string{"requestId", secretField} {
			var destination any = &StartTOTPEnrollmentRequest{}
			if name == "ConfirmTOTPEnrollmentRequest" {
				destination = &ConfirmTOTPEnrollmentRequest{}
			}
			if DecodeRequest(strings.NewReader(strings.TrimSuffix(valid, "}")+`,"`+field+`":"duplicate"}`), destination) == nil {
				t.Fatal("duplicate enrollment field accepted")
			}
		}
	}
}

func TestLoginResultKeepsChallengeSeparateFromSession(t *testing.T) {
	authenticated, err := os.ReadFile("examples/login-response.json")
	if err != nil {
		t.Fatal(err)
	}
	var original map[string]any
	if json.Unmarshal(authenticated, &original) != nil {
		t.Fatal("invalid login example")
	}
	original["outcome"] = "AUTHENTICATED"
	authenticated, err = json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	session, err := json.Marshal(original["session"])
	if err != nil {
		t.Fatal("invalid session fixture")
	}
	challenge := `{"outcome":"CHALLENGE_REQUIRED","challenge":{"apiVersion":"iam.matrix.xiak.com/v1","kind":"AuthenticationChallenge","id":"challenge-example","purpose":"LOGIN","nextStep":"TOTP","expiresAt":"2026-09-20T01:07:03Z"},"challengeCredential":"example-only-challenge-secret"}`
	schema := compileIAMOpenAPISchema(t, loadIAMOpenAPI(t), "LoginResponse")
	for _, sample := range []struct {
		name, wire string
		valid      bool
	}{
		{"authenticated", string(authenticated), true},
		{"authenticated-no-password-change", strings.Replace(string(authenticated), `"mustChangePassword":true`, `"mustChangePassword":false`, 1), true},
		{"challenge", challenge, true},
		{"legacy-ambiguous-result", strings.Replace(string(authenticated), `"outcome":"AUTHENTICATED",`, "", 1), false},
		{"challenge-is-not-session", strings.Replace(challenge, `"challengeCredential":`, `"mustChangePassword":false,"challengeCredential":`, 1), false},
		{"challenge-with-session", strings.Replace(challenge, `"challengeCredential":`, `"session":`+string(session)+`,"challengeCredential":`, 1), false},
		{"challenge-with-null-session", strings.Replace(challenge, `"challengeCredential":`, `"session":null,"challengeCredential":`, 1), false},
		{"challenge-with-login-secret", strings.Replace(challenge, `"challengeCredential":`, `"credential":"not-a-session","challengeCredential":`, 1), false},
		{"challenge-without-possession", strings.Replace(challenge, `,"challengeCredential":"example-only-challenge-secret"`, "", 1), false},
		{"challenge-with-null-possession", strings.Replace(challenge, `"example-only-challenge-secret"`, "null", 1), false},
		{"challenge-with-selector", strings.Replace(challenge, `"purpose":`, `"userId":"someone-else","purpose":`, 1), false},
		{"caller-purpose", strings.Replace(challenge, `"LOGIN"`, `"AUTHORIZE"`, 1), false},
		{"unimplemented-stage", strings.Replace(challenge, `"TOTP"`, `"AUTHENTICATED"`, 1), false},
		{"authenticated-with-challenge-secret", strings.Replace(string(authenticated), `"outcome":`, `"challengeCredential":"unexpected","outcome":`, 1), false},
		{"authenticated-without-password-state", strings.Replace(string(authenticated), `"mustChangePassword":true,`, "", 1), false},
		{"authenticated-null-password-state", strings.Replace(string(authenticated), `"mustChangePassword":true`, `"mustChangePassword":null`, 1), false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var document any
			if json.Unmarshal([]byte(sample.wire), &document) != nil {
				t.Fatal("invalid JSON fixture")
			}
			if got := schema.Validate(document) == nil; got != sample.valid {
				t.Fatalf("schema valid=%v, want %v", got, sample.valid)
			}
			var result LoginResponse
			err := DecodeRequest(strings.NewReader(sample.wire), &result)
			if got := err == nil && ValidateLoginResponse(result) == nil; got != sample.valid {
				t.Fatalf("contract valid=%v, want %v", got, sample.valid)
			}
			if sample.valid {
				encoded, err := EncodeLoginResponse(result)
				defer clear(encoded)
				if err != nil {
					t.Fatal("explicit result encoding failed")
				}
				var roundTrip any
				if json.Unmarshal(encoded, &roundTrip) != nil || schema.Validate(roundTrip) != nil {
					t.Fatal("explicit encoding changed the result branch")
				}
				if output, err := json.Marshal(result); err == nil || len(output) != 0 {
					t.Fatal("ordinary JSON emitted a credential-bearing result")
				}
			}
		})
	}
}

func TestAccessKeySigningSchemasMatchExplicitTransportAndSanitizedResults(t *testing.T) {
	api := loadIAMOpenAPI(t)
	request, err := NewAuthorizationRequest(ActionPaaSApplicationRead, ResourceReference{Kind: ResourceApplication, ID: "application-one"},
		AuthorizationResourceInstance, "", "request-key", "correlation-key")
	if err != nil {
		t.Fatal(err)
	}
	// Only codec/schema agreement: this does not authenticate the fixture's
	// signature or claim that the product PEP accepts its HTTP/action mapping.
	input := AccessKeyAuthorizationRequest{Authorization: request, SignedRequest: accessKeySigningFixture(t)}
	encoded, err := EncodeAccessKeyAuthorizationRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	wire := string(encoded)
	replace := func(source, from, to string) string {
		t.Helper()
		changed := strings.Replace(source, from, to, 1)
		if changed == source {
			t.Fatal("schema attack did not change its fixture")
		}
		return changed
	}
	empty := input
	empty.SignedRequest.HTTP = AccessKeyHTTPRequest{Method: "GET", Scheme: "https", Authority: "fixture.invalid:443", EscapedPath: "/api/paas/v1/applications/application-one",
		BodyDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
	emptyEncoded, err := EncodeAccessKeyAuthorizationRequest(empty)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(emptyEncoded)
	digest, _ := AccessKeySignedRequestDigest(input.SignedRequest)
	result := AccessKeyAuthorization{APIVersion: APIVersion, Kind: "AccessKeyAuthorization", SignedRequestDigest: digest,
		Decision: AuthorizationDecision{APIVersion: APIVersion, Kind: "AuthorizationDecision", ID: "decision-key", Reason: DecisionDenied,
			Action: request.Action, Resource: request.Resource, ResourceMode: request.ResourceMode, Profile: &request.Profile,
			RequestID: request.RequestID, CorrelationID: request.CorrelationID, DecidedAt: time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)}}
	response, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	loginResult := result
	loginResult.Decision.Allowed, loginResult.Decision.Reason = true, DecisionAllowed
	loginResult.Decision.TenantID = "account-one"
	loginResult.Decision.Subject = &Subject{Type: SubjectUser, ID: "user-one"}
	if ValidateAuthorizationDecision(loginResult.Decision) != nil {
		t.Fatal("ordinary USER decision fixture must be valid before carrier substitution")
	}
	loginWire, err := json.Marshal(loginResult)
	if err != nil {
		t.Fatal(err)
	}
	loginResult.Decision.Subject.AccessKeyID = "key-one"
	unsupportedKeyWire, err := json.Marshal(loginResult)
	if err != nil {
		t.Fatal(err)
	}
	schemas := map[string]*jsonschema.Schema{
		"AccessKeyAuthorizationRequest": compileIAMOpenAPISchema(t, api, "AccessKeyAuthorizationRequest"),
		"AccessKeyAuthorization":        compileIAMOpenAPISchema(t, api, "AccessKeyAuthorization"),
	}
	for _, sample := range []struct {
		name, kind, wire   string
		schemaValid, valid bool
	}{
		{"explicit-wire", "AccessKeyAuthorizationRequest", wire, true, true},
		{"empty-covered-fields", "AccessKeyAuthorizationRequest", string(emptyEncoded), true, true},
		{"missing-request", "AccessKeyAuthorizationRequest", `{}`, false, false},
		{"wrong-field-case", "AccessKeyAuthorizationRequest", replace(wire, `"signedRequest":`, `"SignedRequest":`), false, false},
		{"account-selector", "AccessKeyAuthorizationRequest", replace(wire, `"authorization":`, `"accountId":"other","authorization":`), false, false},
		{"actor-selector", "AccessKeyAuthorizationRequest", replace(wire, `"authorization":`, `"subject":{"type":"USER","id":"other"},"authorization":`), false, false},
		{"method-case", "AccessKeyAuthorizationRequest", replace(wire, `"method":"POST"`, `"method":"post"`), false, false},
		{"media-parameters", "AccessKeyAuthorizationRequest", replace(wire, `"contentType":"application/json"`, `"contentType":"application/json; charset=utf-8"`), false, false},
		{"unsigned-media", "AccessKeyAuthorizationRequest", replace(wire, `"contentType":"application/json"`, `"contentType":""`), false, false},
		{"missing-empty-header", "AccessKeyAuthorizationRequest", replace(string(emptyEncoded), `"ifMatch":"",`, ``), false, false},
		{"null-empty-header", "AccessKeyAuthorizationRequest", replace(string(emptyEncoded), `"ifMatch":""`, `"ifMatch":null`), false, false},
		{"wrong-algorithm", "AccessKeyAuthorizationRequest", replace(wire, "Matrix-HMAC-SHA256-V1", "HMAC-SHA256"), false, false},
		{"noncanonical-nonce", "AccessKeyAuthorizationRequest", replace(wire, "oKGio6SlpqeoqaqrrK2urw", "oKGio6SlpqeoqaqrrK2urx"), false, false},
		{"noncanonical-signature", "AccessKeyAuthorizationRequest", replace(wire, "IG55lQ4P2B4", "IG55lQ4P2B5"), false, false},
		// These require semantic/canonical checks, not JSON Schema alone.
		{"different-audience", "AccessKeyAuthorizationRequest", replace(wire, ",Audience=paas,", ",Audience=audit,"), true, false},
		{"time-outside-encoding-range", "AccessKeyAuthorizationRequest", replace(wire, "SignedAt=1800000000,", "SignedAt=253402300800,"), true, false},
		{"header-leading-space", "AccessKeyAuthorizationRequest", replace(wire, `"idempotencyKey":"deploy-intent-a"`, `"idempotencyKey":" deploy-intent-a"`), true, false},
		{"sanitized-deny", "AccessKeyAuthorization", string(response), true, true},
		{"login-allow-is-not-key-allow", "AccessKeyAuthorization", string(loginWire), false, false},
		{"undeclared-key-allow", "AccessKeyAuthorization", string(unsupportedKeyWire), false, false},
		{"deny-account-leak", "AccessKeyAuthorization", replace(string(response), `"allowed":false`, `"allowed":false,"tenantId":"account-a"`), false, false},
		{"deny-actor-leak", "AccessKeyAuthorization", replace(string(response), `"allowed":false`, `"allowed":false,"subject":{"type":"USER","id":"user-a","accessKeyId":"key-a"}`), false, false},
		{"private-nonce", "AccessKeyAuthorization", replace(string(response), `"decision":`, `"nonce":"private","decision":`), false, false},
		{"private-key-evidence", "AccessKeyAuthorization", replace(string(response), `"decision":`, `"keyEvidence":{},"decision":`), false, false},
		{"wrong-content-digest", "AccessKeyAuthorization", replace(string(response), `"signedRequestDigest":"sha256:`, `"signedRequestDigest":"sha512:`), false, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			value, err := jsonschema.UnmarshalJSON(strings.NewReader(sample.wire))
			if err != nil {
				t.Fatal("invalid fixture JSON")
			}
			if err := schemas[sample.kind].Validate(value); (err == nil) != sample.schemaValid {
				t.Fatal("schema changed the explicit signing boundary", err)
			}
			if sample.kind == "AccessKeyAuthorizationRequest" {
				_, err = DecodeAccessKeyAuthorizationRequest(strings.NewReader(sample.wire))
			} else {
				_, err = DecodeAccessKeyAuthorization(strings.NewReader(sample.wire))
			}
			if (err == nil) != sample.valid {
				t.Fatal("strict signing codec disagrees with the intended boundary", err)
			}
		})
	}
}

func TestAccessKeyManagementSchemasAgreeWithBoundedNonSecretContracts(t *testing.T) {
	api := loadIAMOpenAPI(t)
	key := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"AccessKey","id":"key-a","accountId":"account-a","userId":"user-a","status":"ENABLED","resourceVersion":1,"createdAt":"2026-09-17T00:00:00Z","updatedAt":"2026-09-17T00:00:00Z"}`
	create := `{"userResourceVersion":1,"requestId":"key-create"}`
	status := `{"accessKeyResourceVersion":1,"status":"DISABLED","requestId":"key-disable"}`
	remove := `{"accessKeyResourceVersion":2,"requestId":"key-delete"}`
	applied := `{"outcome":"APPLIED","key":` + key + `,"secret":"mak1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}`
	replayed := `{"outcome":"EQUAL_REPLAY","key":` + key + `}`
	capabilities := `[{"action":"iam.access-key.read","resource":{"kind":"ACCESS_KEY","id":"key-a"},"available":true},{"action":"iam.access-key.set-status","resource":{"kind":"ACCESS_KEY","id":"key-a"},"available":true},{"action":"iam.access-key.delete","resource":{"kind":"ACCESS_KEY","id":"key-a"},"available":false,"restrictionReason":"TARGET_MUST_BE_DISABLED"}]`
	access := `{"key":` + key + `,"capabilities":` + capabilities + `}`
	list := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"AccessKeyList","accountId":"account-a","userId":"user-a","userResourceVersion":1,"capabilities":[{"action":"iam.access-key.create","resource":{"kind":"USER","id":"user-a"},"available":true}],"items":[]}`
	twoKeys := strings.Replace(list, `"items":[]`, `"items":[`+access+`,`+strings.ReplaceAll(access, "key-a", "key-b")+`]`, 1)
	validators := map[string]func(string) bool{
		"AccessKey": func(w string) bool {
			var v AccessKey
			return DecodeRequest(strings.NewReader(w), &v) == nil && ValidateAccessKey(v) == nil
		},
		"AccessKeyAccess": func(w string) bool {
			var v AccessKeyAccess
			return DecodeRequest(strings.NewReader(w), &v) == nil && ValidateAccessKeyAccess(v) == nil
		},
		"AccessKeyList": func(w string) bool {
			var v AccessKeyList
			return DecodeRequest(strings.NewReader(w), &v) == nil && ValidateAccessKeyList(v) == nil
		},
		"CreateAccessKeyRequest": func(w string) bool {
			var v CreateAccessKeyRequest
			return DecodeRequest(strings.NewReader(w), &v) == nil && ValidateCreateAccessKeyRequest(v) == nil
		},
		"SetAccessKeyStatusRequest": func(w string) bool {
			var v SetAccessKeyStatusRequest
			return DecodeRequest(strings.NewReader(w), &v) == nil && ValidateSetAccessKeyStatusRequest(v) == nil
		},
		"DeleteAccessKeyRequest": func(w string) bool {
			var v DeleteAccessKeyRequest
			return DecodeRequest(strings.NewReader(w), &v) == nil && ValidateDeleteAccessKeyRequest(v) == nil
		},
		"CreateAccessKeyResponse": func(w string) bool {
			var v CreateAccessKeyResponse
			return DecodeRequest(strings.NewReader(w), &v) == nil && ValidateCreateAccessKeyResponse(v) == nil
		},
	}
	schemas := make(map[string]*jsonschema.Schema, len(validators))
	for kind := range validators {
		schemas[kind] = compileIAMOpenAPISchema(t, api, kind)
	}
	for index, sample := range []struct {
		kind, wire         string
		schemaValid, valid bool
	}{
		{"AccessKey", key, true, true},
		{"AccessKey", strings.Replace(key, "ENABLED", "ACTIVE", 1), false, false},
		{"AccessKey", strings.Replace(key, "ENABLED", "DISABLED", 1), false, false},
		{"AccessKey", strings.TrimSuffix(key, "}") + `,"secret":"forged"}`, false, false},
		{"AccessKeyAccess", access, true, true},
		{"AccessKeyAccess", strings.Replace(access, capabilities, `[]`, 1), false, false},
		{"AccessKeyAccess", strings.Replace(access, "iam.access-key.delete", "iam.access-key.read", 1), false, false},
		{"AccessKeyAccess", strings.Replace(access, `"kind":"ACCESS_KEY","id":"key-a"`, `"kind":"ACCESS_KEY","id":"key-b"`, 1), true, false},
		{"AccessKeyList", list, true, true},
		{"AccessKeyList", twoKeys, true, true},
		{"AccessKeyList", strings.Replace(twoKeys, `"items":[`, `"items":[`+strings.ReplaceAll(access, "key-a", "key-c")+`,`, 1), false, false},
		{"AccessKeyList", strings.Replace(twoKeys, "key-b", "key-a", -1), false, false},
		{"AccessKeyList", strings.Replace(twoKeys, `"userId":"user-a"`, `"userId":"foreign-user"`, 1), true, false},
		{"AccessKeyList", strings.Replace(list, `"items":[]`, `"items":null`, 1), false, false},
		{"AccessKeyList", strings.TrimSuffix(list, "}") + `,"nextAfter":"foreign-cursor"}`, false, false},
		{"AccessKeyList", strings.Replace(list, "iam.access-key.create", "iam.user.create", 1), false, false},
		{"CreateAccessKeyRequest", create, true, true},
		{"CreateAccessKeyRequest", strings.Replace(create, `:1`, `:9007199254740991`, 1), true, true},
		{"CreateAccessKeyRequest", strings.Replace(create, `:1`, `:0`, 1), false, false},
		{"CreateAccessKeyRequest", strings.Replace(create, "userResourceVersion", "resourceVersion", 1), false, false},
		{"CreateAccessKeyRequest", strings.TrimSuffix(create, "}") + `,"accountId":"other"}`, false, false},
		{"CreateAccessKeyRequest", strings.TrimSuffix(create, "}") + `,"secret":"caller-secret"}`, false, false},
		{"CreateAccessKeyRequest", strings.TrimSuffix(create, "}") + `,"accessKeyId":"caller-id"}`, false, false},
		{"SetAccessKeyStatusRequest", status, true, true},
		{"SetAccessKeyStatusRequest", strings.Replace(status, "DISABLED", "ENABLED", 1), true, true},
		{"SetAccessKeyStatusRequest", strings.Replace(status, "DISABLED", "REVOKED", 1), false, false},
		{"SetAccessKeyStatusRequest", strings.Replace(status, `:1`, `:9007199254740991`, 1), false, false},
		{"SetAccessKeyStatusRequest", strings.TrimSuffix(status, "}") + `,"actorSessionId":"forged"}`, false, false},
		{"DeleteAccessKeyRequest", remove, true, true},
		{"DeleteAccessKeyRequest", strings.Replace(remove, `:2`, `:9007199254740991`, 1), false, false},
		{"DeleteAccessKeyRequest", strings.Replace(remove, `:2`, `:0`, 1), false, false},
		{"DeleteAccessKeyRequest", strings.TrimSuffix(remove, "}") + `,"userResourceVersion":1}`, false, false},
		{"CreateAccessKeyResponse", applied, true, true},
		{"CreateAccessKeyResponse", replayed, true, true},
		{"CreateAccessKeyResponse", strings.Replace(applied, "APPLIED", "EQUAL_REPLAY", 1), false, false},
		{"CreateAccessKeyResponse", strings.Replace(replayed, "EQUAL_REPLAY", "APPLIED", 1), false, false},
		{"CreateAccessKeyResponse", strings.TrimSuffix(replayed, "}") + `,"secret":null}`, false, false},
		{"CreateAccessKeyResponse", strings.Replace(replayed, `"resourceVersion":1`, `"resourceVersion":2`, 1), false, false},
		{"CreateAccessKeyResponse", strings.Replace(applied, `"secret":"mak1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`, `"secret":""`, 1), false, false},
	} {
		t.Run(fmt.Sprintf("%d_%s", index, sample.kind), func(t *testing.T) {
			wire, err := jsonschema.UnmarshalJSON(strings.NewReader(sample.wire))
			if err != nil {
				t.Fatal("invalid fixture JSON")
			}
			if err := schemas[sample.kind].Validate(wire); (err == nil) != sample.schemaValid {
				t.Fatalf("schema violated key management boundary: %v", err)
			}
			if validators[sample.kind](sample.wire) != sample.valid {
				t.Fatal("strict contract lost key ownership, lifecycle or secret boundary")
			}
		})
	}
}

func TestRoleCapabilitySchemasAcceptCompleteBoundedResponses(t *testing.T) {
	api := loadIAMOpenAPI(t)
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	role := Role{APIVersion: APIVersion, Kind: "Role", ID: "role-a", AccountID: "account-a", Name: "Readers",
		Tags: []RoleTag{}, Management: RoleCustomerManaged, Status: RoleActive, MaxSessionDurationSeconds: 3600,
		ResourceVersion: 1, CurrentTrustVersionID: "trust-a", CreatedAt: now, UpdatedAt: now}
	var capabilities []ActionCapability
	for _, action := range []Action{ActionIAMRoleRead, ActionIAMRoleUpdate, ActionIAMRoleSetStatus, ActionIAMRoleDelete,
		ActionIAMRoleTrustSet, ActionIAMRolePolicyAttachmentCreate, ActionIAMRolePermissionBoundarySet,
		ActionIAMRolePermissionBoundaryRemove, ActionIAMRoleSessionList} {
		capabilities = append(capabilities, ActionCapability{Action: action,
			Resource: ResourceReference{Kind: ResourceRole, ID: string(role.ID)}, RestrictionReason: CapabilityAuthorityRequired})
	}
	assertResponse := func(kind string, value any, semanticErr error, valid bool) {
		t.Helper()
		if (semanticErr == nil) != valid {
			t.Fatalf("%s semantic fixture mismatch: %v", kind, semanticErr)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		if err := compileIAMOpenAPISchema(t, api, kind).Validate(wire); (err == nil) != valid {
			t.Errorf("%s schema disagrees with complete response boundary: %v", kind, err)
		}
	}
	list := RoleList{APIVersion: APIVersion, Kind: "RoleList", AccountID: role.AccountID,
		Items: []RoleListing{{Role: role, Capabilities: capabilities}}}
	assertResponse("RoleList", list, ValidateRoleList(list), true)
	list.Items[0].Capabilities = capabilities[:len(capabilities)-1]
	assertResponse("RoleList", list, ValidateRoleList(list), false)
	list.Items[0].Capabilities = append(append([]ActionCapability{}, capabilities...), capabilities[0])
	assertResponse("RoleList", list, ValidateRoleList(list), false)
	document := sampleRoleTrustDocument()
	_, digest, err := CanonicalizeTrustPolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	access := RoleAccess{Role: role, TrustVersion: RoleTrustVersion{APIVersion: APIVersion, Kind: "RoleTrustVersion",
		ID: "trust-a", AccountID: role.AccountID, RoleID: role.ID, Document: document, ContentDigest: digest, CreatedAt: now},
		PolicyAttachments: []PolicyAttachment{}, Capabilities: append([]ActionCapability{}, capabilities...)}
	assertResponse("RoleAccess", access, ValidateRoleAccess(access), false) // missing exact Assume capability
	access.Capabilities = append(access.Capabilities, ActionCapability{Action: ActionIAMRoleAssume,
		Resource: ResourceReference{Kind: ResourceRole, ID: string(role.ID)}, RestrictionReason: CapabilityAuthorityRequired})
	assertResponse("RoleAccess", access, ValidateRoleAccess(access), true)
	for i := range 256 {
		attachment := PolicyAttachment{APIVersion: APIVersion, Kind: "PolicyAttachment", ID: PolicyAttachmentID(fmt.Sprintf("attachment-%03d", i)),
			AccountID: role.AccountID, Target: PolicyAttachmentTarget{Kind: PolicyTargetRole, ID: string(role.ID)},
			PolicyID: PolicyID(fmt.Sprintf("policy-%03d", i)), Scope: AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
		access.PolicyAttachments = append(access.PolicyAttachments, attachment)
		access.Capabilities = append(access.Capabilities, ActionCapability{Action: ActionIAMRolePolicyAttachmentRevoke,
			Resource: ResourceReference{Kind: ResourcePolicyAttachment, ID: string(attachment.ID)}, RestrictionReason: CapabilityAuthorityRequired})
	}
	assertResponse("RoleAccess", access, ValidateRoleAccess(access), true)
	access.Capabilities = append(access.Capabilities, access.Capabilities[0])
	assertResponse("RoleAccess", access, ValidateRoleAccess(access), false)
}

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

func TestOwnLoginSessionSchemasExposeOnlyBoundedPublicObservations(t *testing.T) {
	api := loadIAMOpenAPI(t)
	session := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"Session","id":"session-a","organizationId":"account-a","principalId":"user-a","status":"ACTIVE","issuedAt":"2026-09-17T00:00:00Z","expiresAt":"2026-09-17T01:00:00Z"}`
	list := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"SessionList","accountId":"account-a","userId":"user-a","currentSessionId":"session-current","observedAt":"2026-09-17T00:01:00Z","items":[` + session + `]}`
	revocation := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"Revocation","id":"session-a","resourceVersion":2,"revokedAt":"2026-09-17T00:01:00Z"}`
	others := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"OtherSessionsRevocation","outcome":"APPLIED","accountId":"account-a","userId":"user-a","currentSessionId":"session-a","requestId":"request-a","revokedCount":0,"completedAt":"2026-09-18T00:00:00Z"}`
	for _, test := range []struct {
		kind, wire string
		valid      bool
	}{
		{"SessionList", list, true},
		{"SessionList", strings.Replace(list, `"items":[`+session+`]`, `"items":[]`, 1), true},
		{"SessionList", strings.Replace(list, `"items":[`+session+`]`, `"items":null`, 1), false},
		{"SessionList", strings.Replace(list, `"items":[`+session+`]`, `"items":[`+strings.Repeat(session+",", DirectoryPageSize)+session+`]`, 1), false},
		{"SessionList", strings.Replace(list, `"ACTIVE"`, `"REVOKED"`, 1), false},
		{"SessionList", strings.TrimSuffix(list, "}") + `,"credentialGeneration":1}`, false},
		{"SessionList", strings.TrimSuffix(list, "}") + `,"nextCursor":"ir1.wrong-purpose"}`, false},
		{"SessionList", strings.Replace(list, `"id":"session-a"`, `"id":"session-a","credential":"secret"`, 1), false},
		{"RevokeOwnSessionResponse", `{"outcome":"APPLIED","revocation":` + revocation + `}`, true},
		{"RevokeOwnSessionResponse", `{"outcome":"EQUAL_REPLAY","revocation":` + revocation + `}`, true},
		{"RevokeOwnSessionResponse", `{"outcome":"ALREADY_REVOKED","revocation":` + revocation + `}`, false},
		{"RevokeSessionRequest", `{"requestId":"revoke-own"}`, true},
		{"RevokeSessionRequest", `{"requestId":"revoke-own","currentSessionId":"caller-selected"}`, false},
		{"RevokeSessionRequest", `{"requestId":"revoke-own","accountId":"foreign"}`, false},
		{"RevokeOtherSessionsResponse", others, true},
		{"RevokeOtherSessionsResponse", strings.Replace(others, `"APPLIED"`, `"EQUAL_REPLAY"`, 1), true},
		{"RevokeOtherSessionsResponse", strings.Replace(others, `"revokedCount":0`, `"revokedCount":101`, 1), true},
		{"RevokeOtherSessionsResponse", strings.Replace(others, `"revokedCount":0`, `"revokedCount":-1`, 1), false},
		{"RevokeOtherSessionsResponse", strings.Replace(others, `"revokedCount":0`, `"revokedCount":9007199254740992`, 1), false},
		{"RevokeOtherSessionsResponse", strings.Replace(others, `"APPLIED"`, `"UNKNOWN"`, 1), false},
		{"RevokeOtherSessionsResponse", strings.TrimSuffix(others, "}") + `,"targets":[]}`, false},
		{"RevokeOtherSessionsResponse", strings.Replace(others, `"kind":"OtherSessionsRevocation"`, `"kind":"Revocation"`, 1), false},
	} {
		instance, err := jsonschema.UnmarshalJSON(strings.NewReader(test.wire))
		if err != nil {
			t.Fatal(err)
		}
		if err := compileIAMOpenAPISchema(t, api, test.kind).Validate(instance); (err == nil) != test.valid {
			t.Fatalf("%s accepted=%v want=%v: %v", test.kind, err == nil, test.valid, err)
		}
	}
}

func TestRoleSessionManagementSchemasAreBoundedAndNonSecret(t *testing.T) {
	api := loadIAMOpenAPI(t)
	session := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RoleSession","id":"session-a","accountId":"account-a","roleId":"role-a","sourceUserId":"user-a","status":"ACTIVE","issuedAt":"2026-09-17T00:00:00Z","expiresAt":"2026-09-17T01:00:00Z"}`
	item := `{"session":` + session + `,"sourceUser":{"id":"user-a","loginName":"member","displayName":"Member"},"lifecycle":"UNREVOKED","revokeCapability":{"action":"iam.role-session.revoke","resource":{"kind":"ROLE_SESSION","id":"session-a"},"available":true}}`
	list := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RoleSessionList","accountId":"account-a","roleId":"role-a","observedAt":"2026-09-17T00:01:00Z","items":[]}`
	access := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RoleSessionAccess","observedAt":"2026-09-17T00:01:00Z","item":` + item + `}`
	revoked := strings.Replace(session, `"status":"ACTIVE"`, `"status":"REVOKED","revokedAt":"2026-09-17T00:01:00Z"`, 1)
	for index, sample := range []struct {
		kind, wire string
		valid      bool
	}{
		{"RoleSessionList", list, true},
		{"RoleSessionList", strings.TrimSuffix(list, "}") + `,"nextAfter":"ic1.next-window"}`, true},
		{"RoleSessionList", strings.TrimSuffix(list, "}") + `,"nextAfter":"ir1.private"}`, false},
		{"RoleSessionList", strings.Replace(list, `"items":[]`, `"items":null`, 1), false},
		{"RoleSessionList", strings.TrimSuffix(list, "}") + `,"total":10}`, false},
		{"RoleSessionList", strings.Replace(list, `"items":[]`, `"items":[`+strings.Repeat(item+",", DirectoryPageSize)+item+`]`, 1), false},
		{"RoleSessionAccess", access, true},
		{"RoleSessionAccess", strings.Replace(access, `"UNREVOKED"`, `"USABLE"`, 1), false},
		{"RoleSessionAccess", strings.Replace(access, `"UNREVOKED"`, `"EXPIRED"`, 1), false},
		{"RoleSessionAccess", strings.Replace(access, `"UNREVOKED"`, `"REVOKED"`, 1), false},
		{"RoleSessionAccess", strings.Replace(access, `"iam.role-session.revoke"`, `"iam.role-session.read"`, 1), false},
		{"RoleSessionAccess", strings.Replace(access, `"sourceUserId":"user-a"`, `"sourceUserId":"user-a","credentialGeneration":1`, 1), false},
		{"RoleSessionAccess", strings.Replace(access, `"displayName":"Member"`, `"displayName":"Member","principalType":"FEDERATION"`, 1), false},
		{"RevokeRoleSessionResponse", `{"outcome":"APPLIED","session":` + revoked + `}`, true},
		{"RevokeRoleSessionResponse", `{"outcome":"EQUAL_REPLAY","session":` + revoked + `}`, true},
		{"RevokeRoleSessionResponse", `{"outcome":"APPLIED","session":` + session + `}`, false},
		{"RevokeRoleSessionResponse", `{"outcome":"UNKNOWN","session":` + revoked + `}`, false},
		{"RevokeRoleSessionResponse", `{"outcome":"APPLIED","session":` + revoked + `,"credential":"secret"}`, false},
	} {
		schema := compileIAMOpenAPISchema(t, api, sample.kind)
		value, err := jsonschema.UnmarshalJSON(strings.NewReader(sample.wire))
		if err != nil {
			t.Fatal(err)
		}
		if err = schema.Validate(value); (err == nil) != sample.valid {
			t.Fatalf("sample %d %s: %v", index, sample.kind, err)
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

func TestAuthorizationProfileUserAuthenticationSchema(t *testing.T) {
	api := loadIAMOpenAPI(t)
	schema := compileIAMOpenAPISchema(t, api, "AuthorizationProfile")
	encoded, err := json.Marshal(authorizationProfileFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, field string
		valid       bool
	}{
		{"legacy absence", "", true},
		{"login", `"userAuthenticationMethods":["LOGIN_SESSION"],`, true},
		{"key", `"userAuthenticationMethods":["ACCESS_KEY"],`, true},
		{"both", `"userAuthenticationMethods":["LOGIN_SESSION","ACCESS_KEY"],`, true},
		{"explicit USER", `"subjectTypes":["ROLE","USER"],"userAuthenticationMethods":["ACCESS_KEY"],`, true},
		{"ROLE only", `"subjectTypes":["ROLE"],"userAuthenticationMethods":["ACCESS_KEY"],`, false},
		{"service only", `"subjectTypes":["SERVICE_ACCOUNT"],"userAuthenticationMethods":["LOGIN_SESSION"],`, false},
		{"null", `"userAuthenticationMethods":null,`, false},
		{"empty", `"userAuthenticationMethods":[],`, false},
		{"duplicate", `"userAuthenticationMethods":["ACCESS_KEY","ACCESS_KEY"],`, false},
		{"unknown", `"userAuthenticationMethods":["TOKEN"],`, false},
		{"case alias", `"UserAuthenticationMethods":["ACCESS_KEY"],`, false},
		{"object", `"userAuthenticationMethods":{},`, false},
		{"nullable element", `"userAuthenticationMethods":[null],`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := strings.Replace(string(encoded), `"action":`, test.field+`"action":`, 1)
			wire, err := jsonschema.UnmarshalJSON(strings.NewReader(candidate))
			if err != nil || (schema.Validate(wire) == nil) != test.valid {
				t.Fatal("authentication capability schema disagrees with its contract", err)
			}
			if _, err := DecodeAuthorizationProfile(strings.NewReader(candidate)); (err == nil) != test.valid {
				t.Fatal("authentication capability decoder diverged from its schema", err)
			}
		})
	}
	probe := declaredProductProfile("probe", "PROBE", 1,
		declaredProfileAction("probe.check", "INSTALLATION", AuthorityScopeInstallationProbe, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
	probe.Actions[0].UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationAccessKey}
	probeBytes, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := jsonschema.UnmarshalJSON(bytes.NewReader(probeBytes))
	if err != nil || schema.Validate(wire) == nil || ValidateAuthorizationProfile(probe) == nil {
		t.Fatal("legacy service probe inferred USER credential capability")
	}
	for _, typeName := range []string{"PrincipalType", "SubjectType"} {
		if compileIAMOpenAPISchema(t, api, typeName).Validate("ACCESS_KEY") == nil {
			t.Fatal("credential method became a subject or principal type")
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
		{"key USER", `{"type":"USER","id":"user-one","accessKeyId":"key-one"}`, true},
		{"null key", `{"type":"USER","id":"user-one","accessKeyId":null}`, false},
		{"empty key", `{"type":"USER","id":"user-one","accessKeyId":""}`, false},
		{"service with key", `{"type":"SERVICE_ACCOUNT","id":"service-one","accessKeyId":"key-one"}`, false},
		{"role with key", `{"type":"ROLE","id":"role-one","roleSession":{"sessionId":"role-session-one","sourceUserId":"user-one"},"accessKeyId":"key-one"}`, false},
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
