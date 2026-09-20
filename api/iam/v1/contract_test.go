package iamv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
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

func TestOwnLoginSessionContractsBindARealObservation(t *testing.T) {
	now := time.Date(2026, 9, 17, 8, 0, 0, 0, time.UTC)
	valid := SessionList{APIVersion: APIVersion, Kind: "SessionList", AccountID: "account-one", UserID: "user-one",
		CurrentSessionID: "session-current", ObservedAt: now, Items: []Session{{APIVersion: APIVersion, Kind: "Session",
			ID: "session-other", AccountID: "account-one", PrincipalID: "user-one", Status: SessionActive,
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}}}
	if err := ValidateSessionList(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SessionList){
		"null items":                func(v *SessionList) { v.Items = nil },
		"wrong account":             func(v *SessionList) { v.Items[0].AccountID = "account-two" },
		"wrong user":                func(v *SessionList) { v.Items[0].PrincipalID = "user-two" },
		"duplicate":                 func(v *SessionList) { v.Items = append(v.Items, v.Items[0]) },
		"expired":                   func(v *SessionList) { v.Items[0].ExpiresAt = now },
		"future issuance":           func(v *SessionList) { v.Items[0].IssuedAt = now.Add(time.Minute) },
		"revoked":                   func(v *SessionList) { v.Items[0].Status = SessionRevoked; v.Items[0].RevokedAt = &now },
		"invalid current reference": func(v *SessionList) { v.CurrentSessionID = "" },
		"short continued page":      func(v *SessionList) { v.NextCursor = "ic1.AAAA" },
		"oversized":                 func(v *SessionList) { v.Items = make([]Session, DirectoryPageSize+1) },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			value.Items = append([]Session(nil), valid.Items...)
			mutate(&value)
			if ValidateSessionList(value) == nil {
				t.Fatal("invalid session observation accepted")
			}
		})
	}
	empty := valid
	empty.Items = []Session{}
	if err := ValidateSessionList(empty); err != nil {
		t.Fatal(err)
	}
	result := RevokeOwnSessionResponse{Outcome: "APPLIED", Revocation: Revocation{APIVersion: APIVersion, Kind: "Revocation",
		ID: "session-other", ResourceVersion: 2, RevokedAt: now}}
	for _, outcome := range []string{"APPLIED", "EQUAL_REPLAY", "", "ALREADY_REVOKED"} {
		result.Outcome = outcome
		if (ValidateRevokeOwnSessionResponse(result) == nil) != (outcome == "APPLIED" || outcome == "EQUAL_REPLAY") {
			t.Fatalf("unexpected revocation outcome validation for %q", outcome)
		}
	}
}

func TestOtherSessionRevocationIsAClosedCompletionIncludingZeroTargets(t *testing.T) {
	valid := RevokeOtherSessionsResponse{APIVersion: APIVersion, Kind: "OtherSessionsRevocation", Outcome: "APPLIED",
		AccountID: "account-one", UserID: "user-one", CurrentSessionID: "session-one", RequestID: "request-one",
		CompletedAt: time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)}
	for _, count := range []uint64{0, 1, 101, 9007199254740991} {
		for _, outcome := range []string{"APPLIED", "EQUAL_REPLAY"} {
			value := valid
			value.RevokedCount, value.Outcome = count, outcome
			if err := ValidateRevokeOtherSessionsResponse(value); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, mutate := range []func(*RevokeOtherSessionsResponse){
		func(v *RevokeOtherSessionsResponse) { v.APIVersion = "other/v1" },
		func(v *RevokeOtherSessionsResponse) { v.Kind = "Revocation" },
		func(v *RevokeOtherSessionsResponse) { v.Outcome = "ALREADY_REVOKED" },
		func(v *RevokeOtherSessionsResponse) { v.AccountID = "" },
		func(v *RevokeOtherSessionsResponse) { v.UserID = "" },
		func(v *RevokeOtherSessionsResponse) { v.CurrentSessionID = "" },
		func(v *RevokeOtherSessionsResponse) { v.RequestID = "" },
		func(v *RevokeOtherSessionsResponse) { v.CompletedAt = time.Time{} },
		func(v *RevokeOtherSessionsResponse) { v.RevokedCount = 9007199254740992 },
	} {
		value := valid
		mutate(&value)
		if ValidateRevokeOtherSessionsResponse(value) == nil {
			t.Fatal("invalid other-session completion accepted")
		}
	}
}

func TestAccessKeySubjectLineageRequiresItsOwnDeclaredCarrier(t *testing.T) {
	valid := `{"type":"USER","id":"user-one","accessKeyId":"key-one"}`
	for _, test := range []struct {
		wire  string
		valid bool
	}{
		{valid, true},
		{`{"type":"USER","id":"user-one"}`, true},
		{strings.Replace(valid, `"key-one"`, `null`, 1), false},
		{strings.Replace(valid, `"key-one"`, `""`, 1), false},
		{strings.Replace(valid, `"key-one"`, `[]`, 1), false},
		{strings.Replace(valid, `"accessKeyId":`, `"AccessKeyId":`, 1), false},
		{strings.Replace(valid, `"accessKeyId":`, `"accessKeyId":"key-two","accessKeyId":`, 1), false},
		{strings.Replace(valid, `"USER"`, `"SERVICE_ACCOUNT"`, 1), false},
		{`{"type":"ROLE","id":"role-one","roleSession":{"sessionId":"role-session","sourceUserId":"user-one"},"accessKeyId":"key-one"}`, false},
		{`{"type":"USER","id":"user-one","accessKeyId":"key-one","roleSession":null}`, false},
	} {
		var subject Subject
		if err := DecodeRequest(strings.NewReader(test.wire), &subject); (err == nil) != test.valid {
			t.Fatalf("key attribution decoder accepted=%v want=%v", err == nil, test.valid)
		}
		if test.valid {
			encoded, err := json.Marshal(subject)
			if err != nil || string(encoded) != test.wire {
				t.Fatal("public attribution changed its exact bytes")
			}
		}
	}
	request, err := NewAuthorizationRequest(ActionPaaSApplicationRead, ResourceReference{Kind: ResourceApplication, ID: "application-one"}, AuthorizationResourceInstance, "", "request-key", "correlation-key")
	if err != nil {
		t.Fatal(err)
	}
	decision := AuthorizationDecision{APIVersion: APIVersion, Kind: "AuthorizationDecision", ID: "decision-key", Allowed: true, Reason: DecisionAllowed,
		Action: request.Action, Resource: request.Resource, RequestID: request.RequestID, CorrelationID: request.CorrelationID,
		Profile: &request.Profile, ResourceMode: request.ResourceMode, DecidedAt: time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC),
		TenantID: "account-one", Subject: &Subject{Type: SubjectUser, ID: "user-one", AccessKeyID: "key-one"}}
	profile, _ := LookupAuthorizationProfile(ProductPaaS)
	if ValidateAuthorizationDecision(decision) == nil || ValidateAuthorizationDecisionForProfile(decision, profile) == nil {
		t.Fatal("USER capability alone admitted a key-attributed decision")
	}
	profile.Revision++
	for index := range profile.Actions {
		if profile.Actions[index].Action == request.Action {
			profile.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession, UserAuthenticationAccessKey}
		}
	}
	_, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	decision.Profile = &AuthorizationProfileReference{profile.Product, profile.Revision, digest}
	if ValidateAuthorizationDecisionForProfile(decision, profile) != nil {
		t.Fatal("explicit archived key capability was not recognized")
	}
	if ValidateAuthorizationDecision(decision) == nil {
		t.Fatal("archive syntax validation advanced the current source head")
	}
	legacy := decision
	legacy.Profile, legacy.ResourceMode, legacy.CollectionUsage, legacy.CorrelationID = nil, "", "", ""
	legacy.Subject = &Subject{Type: SubjectUser, ID: "user-one"}
	if ValidateLegacyAuthorizationDecision(legacy) != nil {
		t.Fatal("original USER legacy decision was rejected")
	}
	legacy.Subject.AccessKeyID = "key-one"
	if ValidateLegacyAuthorizationDecision(legacy) == nil {
		t.Fatal("legacy decision gained an unproven key lineage")
	}
}

func TestAccessKeyAuthorizationTransportBindsOneRequestWithoutSelectors(t *testing.T) {
	request, err := NewAuthorizationRequest(ActionPaaSApplicationRead, ResourceReference{Kind: ResourceApplication, ID: "application-one"}, AuthorizationResourceInstance, "", "request-key", "correlation-key")
	if err != nil {
		t.Fatal(err)
	}
	value := AccessKeyAuthorizationRequest{Authorization: request, SignedRequest: accessKeySigningFixture(t)}
	encoded, err := EncodeAccessKeyAuthorizationRequest(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := DecodeAccessKeyAuthorizationRequest(bytes.NewReader(encoded))
	if err != nil || !reflect.DeepEqual(value, decoded) {
		t.Fatal("dedicated authorization transport changed the original request")
	}
	if _, err := json.Marshal(value); err == nil || json.Unmarshal(encoded, &decoded) == nil {
		t.Fatal("ordinary JSON bypassed the dedicated signature transport")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", value, value), "Uz5Xlnd") {
		t.Fatal("authorization request formatting leaked its signature")
	}
	for _, replacement := range []struct{ from, to string }{
		{`"authorization":`, `"accountId":"chosen","authorization":`},
		{`"authorization":`, `"subjectId":"chosen","authorization":`},
		{`"authorization":`, `"servicePurpose":"PAAS","authorization":`},
		{`"signedRequest":`, `"signedRequest":null,"signedRequest":`},
		{`"signedRequest":`, `"SignedRequest":`},
		{`,Audience=paas,`, `,Audience=audit,`},
	} {
		attack := strings.Replace(string(encoded), replacement.from, replacement.to, 1)
		if attack == string(encoded) {
			t.Fatal("attack did not change the request")
		}
		if _, err := DecodeAccessKeyAuthorizationRequest(strings.NewReader(attack)); !errors.Is(err, ErrInvalidAccessKeySignature) {
			t.Fatal("authority selector, ambiguity or wrong audience decoded", err)
		}
	}
	for _, source := range []string{`{}`, `{"authorization":null,"signedRequest":null}`, string(encoded) + `{}`, strings.Repeat(" ", int(MaxRequestBytes)) + string(encoded)} {
		if _, err := DecodeAccessKeyAuthorizationRequest(strings.NewReader(source)); !errors.Is(err, ErrInvalidAccessKeySignature) {
			t.Fatal("partial, extra or unbounded request decoded", err)
		}
	}
	digest, _ := AccessKeySignedRequestDigest(value.SignedRequest)
	result := AccessKeyAuthorization{APIVersion: APIVersion, Kind: "AccessKeyAuthorization", SignedRequestDigest: digest,
		Decision: AuthorizationDecision{APIVersion: APIVersion, Kind: "AuthorizationDecision", ID: "decision-key", Allowed: false, Reason: DecisionDenied,
			Action: request.Action, Resource: request.Resource, RequestID: request.RequestID, CorrelationID: request.CorrelationID, Profile: &request.Profile,
			ResourceMode: request.ResourceMode, DecidedAt: time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)}}
	if CheckAccessKeyAuthorizationForRequest(result, value) != nil {
		t.Fatal("valid request-bound Deny rejected")
	}
	wire, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeAccessKeyAuthorization(bytes.NewReader(wire)); err != nil || !reflect.DeepEqual(result, decoded) {
		t.Fatal("sanitized response changed on strict decode")
	}
	for name, change := range map[string]func(*AccessKeyAuthorization){
		"different request": func(v *AccessKeyAuthorization) { v.Decision.RequestID = "another-request" },
		"different target":  func(v *AccessKeyAuthorization) { v.Decision.Resource.ID = "another-resource" },
		"wrong digest":      func(v *AccessKeyAuthorization) { v.SignedRequestDigest = "sha256:" + strings.Repeat("0", 64) },
		"exposed account":   func(v *AccessKeyAuthorization) { v.Decision.TenantID = "account-one" },
		"exposed actor": func(v *AccessKeyAuthorization) {
			v.Decision.Subject = &Subject{Type: SubjectUser, ID: "user-one", AccessKeyID: "key-one"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := result
			change(&changed)
			if CheckAccessKeyAuthorizationForRequest(changed, value) == nil {
				t.Fatal("response substitution was accepted")
			}
		})
	}
	if _, err := DecodeAccessKeyAuthorization(strings.NewReader(strings.Replace(string(wire), `"decision":`, `"nonce":"private","decision":`, 1))); err == nil {
		t.Fatal("response admitted private material")
	}
}

func accessKeySigningFixture(t testing.TB) AccessKeySignedRequest {
	t.Helper()
	nonce, _ := NewSecret("oKGio6SlpqeoqaqrrK2urw")
	signature, _ := NewSecret("Uz5XlndRsGE-aCQEe1dapqyjZJPmgm5fIG55lQ4P2B4")
	return AccessKeySignedRequest{
		Parameters: AccessKeySignatureParameters{AccessKeyID: "access-key-a", InstallationID: "install-a", Audience: ProductPaaS, SignedAt: 1800000000, Nonce: nonce},
		HTTP: AccessKeyHTTPRequest{Method: "POST", Scheme: "https", Authority: "matrix.example:8443", EscapedPath: "/api/paas/v1/applications/app-a:deploy",
			RawQuery: "after=a%2Fb&label=%E4%B8%AD&label=second", ContentType: "application/json", IdempotencyKey: "deploy-intent-a", IfMatch: `"7"`,
			BodyDigest: "sha256:17d084291987b1fa52e98eaf615b891da5cf03cdb3e659518aa8c53c68ef42a6"}, Signature: signature,
	}
}

func TestAccessKeySigningUsesIndependentTransportVectors(t *testing.T) {
	value := accessKeySigningFixture(t)
	before := value
	// Generated independently with Node crypto/Buffer, not a Go round-trip.
	const expectedHex = "000000276d61747269782e69616d2e6163636573732d6b65792d687474702d7369676e61747572652e7631000000154d61747269782d484d41432d5348413235362d56310000000c6163636573732d6b65792d6100000009696e7374616c6c2d6100000004706161730000000a31383030303030303030000000166f4b47696f36536c7071656f71617172724b3275727700000004504f5354000000056874747073000000136d61747269782e6578616d706c653a38343433000000262f6170692f706161732f76312f6170706c69636174696f6e732f6170702d613a6465706c6f790000002861667465723d6125324662266c6162656c3d254534254238254144266c6162656c3d7365636f6e64000000106170706c69636174696f6e2f6a736f6e0000000f6465706c6f792d696e74656e742d6100000003223722000000477368613235363a31376430383432393139383762316661353265393865616636313562383931646135636630336364623365363539353138616138633533633638656634326136"
	base, err := AccessKeySigningBytes(value.Parameters, value.HTTP)
	if err != nil || hex.EncodeToString(base) != expectedHex {
		t.Fatal("signature base differs from independent vector")
	}
	digest, err := AccessKeySignedRequestDigest(value)
	if err != nil || digest != "sha256:62e845ae36ef92e71f3150eb0a047bbd557752d64fa8aef32676a833ee500716" {
		t.Fatal("request digest differs from independent vector")
	}
	nonceDigest, err := AccessKeyNonceDigest(value.Parameters)
	if err != nil || nonceDigest != "sha256:83d5a36550871210968d8bb64149df16f54c5c387704e87c5efb993b44838bef" {
		t.Fatal("nonce digest differs from independent vector")
	}
	changed := value
	changed.HTTP.RawQuery = "after=a%2Fb&label=second&label=%E4%B8%AD"
	other, err := AccessKeySignedRequestDigest(changed)
	if err != nil || other == digest {
		t.Fatal("reordering repeated query values did not change the signed request")
	}
	changed.Parameters.Audience = "future-product"
	changed.Parameters.SignedAt++
	otherNonce, err := AccessKeyNonceDigest(changed.Parameters)
	if err != nil || otherNonce != nonceDigest {
		t.Fatal("nonce identity was scoped to request time or product")
	}
	changed.Parameters.InstallationID = "install-b"
	otherNonce, err = AccessKeyNonceDigest(changed.Parameters)
	if err != nil || otherNonce == nonceDigest {
		t.Fatal("nonce identity lost installation binding")
	}
	if !reflect.DeepEqual(before, value) {
		t.Fatal("encoding mutated caller-owned request")
	}
}

func TestAccessKeySignatureRejectsAmbiguousHTTPComponents(t *testing.T) {
	base := accessKeySigningFixture(t)
	for _, host := range []string{"matrix", "matrix.example", "127.0.0.1:8443", "[::1]", "[2001:db8::1]:443"} {
		value := base.HTTP
		value.Authority = host
		if ValidateAccessKeyHTTPRequest(value) != nil {
			t.Errorf("canonical authority rejected: %q", host)
		}
	}
	for _, path := range []string{"/", "/api/audit/v1/records:query", "/v1/%E4%B8%AD", "/v1/a-b._~!$&'()*+,;=:@"} {
		value := base.HTTP
		value.EscapedPath = path
		if ValidateAccessKeyHTTPRequest(value) != nil {
			t.Errorf("canonical path rejected: %q", path)
		}
	}
	for _, query := range []string{"", "a=", "a=one&a=two", "a=%20%2B%3B%3D%26&b=%E4%B8%AD", "a=2&a=1"} {
		value := base.HTTP
		value.RawQuery = query
		if ValidateAccessKeyHTTPRequest(value) != nil {
			t.Errorf("canonical query rejected: %q", query)
		}
	}
	invalid := map[string][]string{
		"authority": {"", "UPPER.example", "user@host", "host.", "host:0443", "host:0", "host:65536", "host:", "[127.0.0.1]", "[::1%eth0]", "::1", "[2001:0db8::1]", "127.0.0.01", "a..b", "a/b", "a#b", "a?b", "-a", "a-", strings.Repeat("a", 64) + ".example"},
		"path":      {"", "v1/path", "https://host/v1", "/v1//a", "/v1/a/", "/v1/./a", "/v1/../a", "/v1/%2E", "/v1/%2f", "/v1/%2F", "/v1/%5C", "/v1/%252F", "/v1/%41", "/v1/%e4%b8%ad", "/v1/中", "/v1/%FF", "/v1/%00", "/v1/%0D", "/v1/%", "/v1/a?b", "/v1/a#b", "/" + strings.Repeat("a", 2048)},
		"query":     {"a", "=b", "a=b&", "&a=b", "a=b&&b=c", "b=2&a=1", "a=one+two", "a=%2f", "a=%41", "a=%", "a=%00", "a=%FF", "a=b;c=d", "a=b=c", "a=中", "a=b#c", strings.Repeat("a=1&", 64) + "a=1", "a=" + strings.Repeat("x", 4096)},
	}
	for field, values := range invalid {
		for i, input := range values {
			t.Run(fmt.Sprintf("%s-%d", field, i), func(t *testing.T) {
				value := base
				switch field {
				case "authority":
					value.HTTP.Authority = input
				case "path":
					value.HTTP.EscapedPath = input
				case "query":
					value.HTTP.RawQuery = input
				}
				if ValidateAccessKeySignedRequest(value) != ErrInvalidAccessKeySignature {
					t.Fatal("ambiguous HTTP component accepted")
				}
				if b, err := AccessKeySigningBytes(value.Parameters, value.HTTP); err != ErrInvalidAccessKeySignature || b != nil {
					t.Fatal("invalid HTTP component acquired signature bytes")
				}
			})
		}
	}
	for _, mutation := range []func(*AccessKeySignedRequest){
		func(v *AccessKeySignedRequest) { v.HTTP.Method = "post" },
		func(v *AccessKeySignedRequest) { v.HTTP.Scheme = "HTTPS" },
		func(v *AccessKeySignedRequest) { v.HTTP.ContentType = "application/json; charset=utf-8" },
		func(v *AccessKeySignedRequest) { v.HTTP.ContentType = "" },
		func(v *AccessKeySignedRequest) { v.HTTP.IdempotencyKey = " x" },
		func(v *AccessKeySignedRequest) { v.HTTP.IfMatch = "\"7\"\r\nInjected: x" },
		func(v *AccessKeySignedRequest) { v.HTTP.BodyDigest = strings.ToUpper(v.HTTP.BodyDigest) },
		func(v *AccessKeySignedRequest) { v.Parameters.SignedAt = 0 },
		func(v *AccessKeySignedRequest) { v.Parameters.SignedAt = 253402300800 },
		func(v *AccessKeySignedRequest) { v.Parameters.Audience = "paas,other" },
		func(v *AccessKeySignedRequest) { v.Parameters.Nonce, _ = NewSecret("oKGio6SlpqeoqaqrrK2urx") },
	} {
		value := base
		mutation(&value)
		if ValidateAccessKeySignedRequest(value) == nil {
			t.Fatal("invalid protocol component accepted")
		}
	}
}

func TestAccessKeyReadSignatureBindsExplicitEmptyComponents(t *testing.T) {
	value := accessKeySigningFixture(t)
	value.Parameters.Nonce, _ = NewSecret("sLGys7S1tre4ubq7vL2-vw")
	value.Signature, _ = NewSecret("wvQNQPPSaqkf7m09RDLN_zWd6yzdr8CARcyzRMhkbGo")
	value.HTTP = AccessKeyHTTPRequest{Method: "GET", Scheme: "https", Authority: "matrix.example",
		EscapedPath: "/api/paas/v1/applications/app-a",
		BodyDigest:  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
	// Independently computed Node vector covers an empty body and all four
	// empty query/header values. Absence in the private wire is not equivalent.
	if digest, err := AccessKeySignedRequestDigest(value); err != nil || digest != "sha256:9110fb2418ebbeeefd15171522a219e46aec319edb7fd2ca296cca27a6d527c3" {
		t.Fatal("empty-body request differs from independent vector")
	}
	header, err := EncodeAccessKeyAuthorization(value.Parameters, value.Signature)
	if err != nil || string(header.CopyBytes()) != "Matrix-HMAC-SHA256-V1 KeyId=access-key-a,Installation=install-a,Audience=paas,SignedAt=1800000000,Nonce=sLGys7S1tre4ubq7vL2-vw,Signature=wvQNQPPSaqkf7m09RDLN_zWd6yzdr8CARcyzRMhkbGo" {
		t.Fatal("canonical Authorization field differs from independent vector")
	}
	encoded, err := EncodeAccessKeySignedRequest(value)
	if err != nil {
		t.Fatal("empty components could not be explicitly encoded")
	}
	if decoded, err := DecodeAccessKeySignedRequest(bytes.NewReader(encoded)); err != nil || !reflect.DeepEqual(value, decoded) {
		t.Fatal("explicit empty components did not survive transport")
	}
	for _, name := range []string{"rawQuery", "contentType", "idempotencyKey", "ifMatch"} {
		missing := strings.Replace(string(encoded), `"`+name+`":"",`, "", 1)
		if missing == string(encoded) {
			t.Fatal("fixture did not remove covered empty component")
		}
		if _, err := DecodeAccessKeySignedRequest(strings.NewReader(missing)); err != ErrInvalidAccessKeySignature {
			t.Fatal("missing empty covered component accepted")
		}
	}
	value.HTTP.ContentType = "application/json"
	if ValidateAccessKeyHTTPRequest(value.HTTP) != ErrInvalidAccessKeySignature {
		t.Fatal("empty body with a conflicting media-type declaration accepted")
	}
}

func TestAccessKeySignatureWireIsExplicitStrictAndRedacted(t *testing.T) {
	value := accessKeySigningFixture(t)
	header, err := EncodeAccessKeyAuthorization(value.Parameters, value.Signature)
	if err != nil {
		t.Fatal(err)
	}
	text := string(header.CopyBytes())
	parameters, signature, err := ParseAccessKeyAuthorization(text)
	if err != nil || !reflect.DeepEqual(parameters, value.Parameters) || !reflect.DeepEqual(signature, value.Signature) {
		t.Fatal("explicit Authorization codec lost claims")
	}
	for _, bad := range []string{
		" " + text, text + " ", strings.ToLower(text), strings.Replace(text, ",", ", ", 1),
		text + ",Nonce=other", strings.Replace(text, ",Installation=install-a", "", 1),
		strings.Replace(text, "SignedAt=1800000000", "SignedAt=01800000000", 1),
		strings.Replace(text, "SignedAt=1800000000", "SignedAt=+1800000000", 1),
		strings.Replace(text, "KeyId=access-key-a", `KeyId="access-key-a"`, 1),
		strings.Replace(text, "KeyId=", "keyId=", 1), text + "=", text + "," + text,
		strings.Repeat("x", MaxAccessKeyAuthorizationBytes+1),
	} {
		p, s, err := ParseAccessKeyAuthorization(bad)
		if err != ErrInvalidAccessKeySignature || p.AccessKeyID != "" || s.Present() {
			t.Fatal("ambiguous Authorization accepted or leaked claims")
		}
	}
	encoded, err := EncodeAccessKeySignedRequest(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAccessKeySignedRequest(bytes.NewReader(encoded))
	if err != nil || !reflect.DeepEqual(value, decoded) {
		t.Fatal("explicit signed request lost fields")
	}
	for _, v := range []any{value, value.Parameters} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("ordinary JSON exposed signature material")
		}
		printed := fmt.Sprintf("%v %+v %#v", v, v, v)
		if strings.Contains(printed, string(value.Parameters.Nonce.CopyBytes())) || strings.Contains(printed, string(value.Signature.CopyBytes())) {
			t.Fatal("formatting exposed signature material")
		}
	}
	base := string(encoded)
	for _, bad := range []string{
		strings.Replace(base, `"kind":"AccessKeySignedRequest"`, `"kind":"AccessKeySignedRequest","kind":"AccessKeySignedRequest"`, 1),
		strings.Replace(base, `"method":"POST"`, `"method":"POST","method":"GET"`, 1),
		strings.Replace(base, `"rawQuery":`, `"unknown":`, 1),
		strings.Replace(base, `"idempotencyKey":"deploy-intent-a",`, "", 1),
		strings.Replace(base, `"ifMatch":"\"7\""`, `"ifMatch": null`, 1),
		strings.Replace(base, `"contentType":"application/json"`, `"contentType":7`, 1),
		strings.Replace(base, `"http":{`, `"http":{"scheme":null,`, 1),
		base + `{}`, `null`, strings.Repeat(" ", int(MaxAccessKeySignedRequestBytes)) + base,
	} {
		if out, err := DecodeAccessKeySignedRequest(strings.NewReader(bad)); err != ErrInvalidAccessKeySignature || out.Signature.Present() {
			t.Fatal("invalid private request was decoded")
		}
	}
	if _, err := DecodeAccessKeySignedRequest(iotest.ErrReader(errors.New("private request bytes"))); err != ErrInvalidAccessKeySignature {
		t.Fatal("reader error was not sanitized")
	}
}

func FuzzAccessKeySignatureWire(f *testing.F) {
	encoded, err := EncodeAccessKeySignedRequest(accessKeySigningFixture(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(encoded))
	f.Add(`{"http":null}`)
	f.Fuzz(func(t *testing.T, source string) {
		value, err := DecodeAccessKeySignedRequest(strings.NewReader(source))
		if err != nil {
			if err != ErrInvalidAccessKeySignature || value.Signature.Present() {
				t.Fatal("invalid input exposed partial claims")
			}
			return
		}
		encoded, err := EncodeAccessKeySignedRequest(value)
		if err != nil {
			t.Fatal("valid typed request cannot be explicitly encoded")
		}
		second, err := DecodeAccessKeySignedRequest(bytes.NewReader(encoded))
		if err != nil || !reflect.DeepEqual(value, second) {
			t.Fatal("explicit wire changed request")
		}
	})
}

func TestAccessKeyManagementUsesAnExplicitNewUserOnlyProfile(t *testing.T) {
	profile, found := LookupAuthorizationProfile(ProductIAM)
	if !found || profile.Revision != 5 {
		t.Fatal("missing source-owned access key management declaration")
	}
	_, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	ref := AuthorizationProfileReference{Product: ProductIAM, Revision: profile.Revision, ContentDigest: digest}
	for action, target := range map[Action]ResourceKind{
		ActionIAMAccessKeyList: ResourceUser, ActionIAMAccessKeyCreate: ResourceUser,
		ActionIAMAccessKeyRead: ResourceAccessKey, ActionIAMAccessKeySetStatus: ResourceAccessKey, ActionIAMAccessKeyDelete: ResourceAccessKey,
	} {
		definition, found := LookupActionDefinition(action)
		if !found || definition.ResourceKind != target || definition.AuthorityScope != AuthorityScopeTenant || definition.CallingService != ServiceIAM {
			t.Fatal("key management acquired a different authority or producer")
		}
		request, err := NewAuthorizationRequest(action, ResourceReference{Kind: target, ID: "exact-target"}, AuthorizationResourceInstance, "", "request-a", "correlation-a")
		if err != nil || ValidateAuthorizationRequest(request) != nil {
			t.Fatal("key management cannot authorize its exact target")
		}
		if _, err := NewAuthorizationRequest(action, request.Resource, AuthorizationResourceCollection, AuthorizationCollectionList, "request-a", "correlation-a"); err == nil {
			t.Fatal("key management unexpectedly admitted an unbound collection")
		}
		if CheckAuthorizationProfileSubject(profile, ref, action, SubjectUser) != nil ||
			CheckAuthorizationProfileSubject(profile, ref, action, SubjectRole) == nil ||
			CheckAuthorizationProfileSubject(profile, ref, action, SubjectServiceAccount) == nil {
			t.Fatal("key management widened the USER boundary")
		}
		for _, historical := range HistoricalAuthorizationProfiles() {
			if historical.Product != ProductIAM {
				continue
			}
			for _, declaration := range historical.Actions {
				if declaration.Action == action {
					t.Fatal("old declaration gained key management authority")
				}
			}
		}
	}
	archives := HistoricalAuthorizationProfiles()
	index := slices.IndexFunc(archives, func(p AuthorizationProfile) bool { return p.Product == ProductIAM && p.Revision == 4 })
	if index < 0 {
		t.Fatal("missing original session administration declaration")
	}
	_, oldDigest, err := CanonicalizeAuthorizationProfile(archives[index])
	// Read through the public codec of the fixed bc7d0595 code export, not
	// derived from the new current declaration or a manufactured legacy row.
	if err != nil || oldDigest != "sha256:eabe31550549c1303370067c5ac2dbcc8759c397beb98759961b67fa6664bda0" {
		t.Fatal("registered IAM r4 bytes changed")
	}
}

func TestAccessKeyCreationSecretIsNotAReplayOrDeletionResult(t *testing.T) {
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	key := AccessKey{APIVersion: APIVersion, Kind: "AccessKey", ID: "key-a", AccountID: "account-a", UserID: "user-a",
		Status: AccessKeyEnabled, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}
	secret, err := NewSecret("mak1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil {
		t.Fatal(err)
	}
	response := CreateAccessKeyResponse{Outcome: "APPLIED", Key: key, Secret: secret}
	if ValidateCreateAccessKeyResponse(response) != nil {
		t.Fatal("new key result was rejected")
	}
	if encoded, err := json.Marshal(response); !errors.Is(err, ErrSecretSerialization) || len(encoded) != 0 {
		t.Fatal("ordinary JSON emitted the new key secret")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", response, response, response), "AAECAwQ") {
		t.Fatal("key creation leaked secret through formatting")
	}
	encoded, err := EncodeCreateAccessKeyResponse(response)
	defer clear(encoded)
	if err != nil || !bytes.Contains(encoded, []byte(`"secret":"mak1.`)) {
		t.Fatal("explicit creation response omitted its one-time secret")
	}
	for _, outcome := range []string{"EQUAL_REPLAY", "UNKNOWN", ""} {
		response.Outcome = outcome
		if encoded, err := EncodeCreateAccessKeyResponse(response); err == nil || len(encoded) != 0 {
			t.Fatal("non-creation outcome disclosed a secret")
		}
	}
	response.Outcome, response.Secret = "EQUAL_REPLAY", Secret{}
	encoded, err = EncodeCreateAccessKeyResponse(response)
	if err != nil || bytes.Contains(encoded, []byte("secret")) {
		t.Fatal("equal replay did not remain non-secret")
	}
	clear(encoded)
	response.Secret = Secret{value: "\x00"}
	if encoded, err := EncodeCreateAccessKeyResponse(response); err == nil || len(encoded) != 0 {
		t.Fatal("invalid nonempty secret bypassed the replay prohibition")
	}
	response.Secret = Secret{}
	response.Key.ResourceVersion = 2
	response.Key.Status = AccessKeyDisabled
	if ValidateCreateAccessKeyResponse(response) == nil {
		t.Fatal("replay substituted current metadata for the immutable creation result")
	}
	changed := SetAccessKeyStatusResponse{Outcome: "APPLIED", Key: response.Key}
	if ValidateSetAccessKeyStatusResponse(changed) != nil {
		t.Fatal("valid status result was rejected")
	}
	changed.Key.ResourceVersion = 1
	if ValidateSetAccessKeyStatusResponse(changed) == nil {
		t.Fatal("status result had no versioned mutation")
	}
	deletion := DeleteAccessKeyResponse{Outcome: "APPLIED", Deletion: AccessKeyDeletion{APIVersion: APIVersion, Kind: "AccessKeyDeletion",
		ID: key.ID, AccountID: key.AccountID, UserID: key.UserID, ResourceVersion: 3, DeletedAt: now}}
	if ValidateDeleteAccessKeyResponse(deletion) != nil {
		t.Fatal("valid terminal key result was rejected")
	}
	encoded, err = json.Marshal(deletion)
	if err != nil || bytes.Contains(encoded, []byte("secret")) || bytes.Contains(encoded, []byte("status")) {
		t.Fatal("deletion exposed secret or a reversible status")
	}
}

func totpTestKeyring(t testing.TB) TOTPKeyring {
	t.Helper()
	var keys []TOTPWrappingKey
	for index, material := range []string{"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"} {
		secret, err := NewSecret(material)
		if err != nil {
			t.Fatal("invalid synthetic key material")
		}
		keys = append(keys, TOTPWrappingKey{KeyID: "key-" + string(rune('a'+index)), FormatVersion: 1, KeyMaterial: secret})
	}
	return TOTPKeyring{APIVersion: APIVersion, Kind: "TOTPKeyring", Purpose: TOTPWrappingPurpose,
		Scope:          TOTPWrappingScope{InstallationID: "install-a", BootstrapDigest: "sha256:" + strings.Repeat("a", 64)},
		KeysetRevision: 1, ActiveKeyID: "key-a", Keys: keys}
}

func TestTOTPKeyringPrivateCodecAndStrictBounds(t *testing.T) {
	value := totpTestKeyring(t)
	encoded, err := EncodeTOTPKeyring(value)
	defer clear(encoded)
	if err != nil {
		t.Fatal("valid private keyring did not encode")
	}
	decoded, err := DecodeTOTPKeyring(bytes.NewReader(encoded))
	if err != nil || !reflect.DeepEqual(decoded, value) {
		t.Fatal("private codec changed the scoped keyset")
	}
	for _, protected := range []any{value, &value, value.Keys[0], &value.Keys[0]} {
		if output, err := json.Marshal(protected); !errors.Is(err, ErrInvalidTOTPKeyring) || len(output) != 0 {
			t.Fatal("ordinary JSON exposed key material")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(format, protected), string(value.Keys[0].KeyMaterial.CopyBytes())) {
				t.Fatal("key material escaped formatting")
			}
		}
	}
	var ordinary TOTPKeyring
	var ordinaryKey TOTPWrappingKey
	if err := json.Unmarshal(encoded, &ordinary); !errors.Is(err, ErrInvalidTOTPKeyring) || len(ordinary.Keys) != 0 {
		t.Fatal("ordinary decoder bypassed private codec")
	}
	if err := json.Unmarshal([]byte(`{"keyId":"key-a","formatVersion":1,"keyMaterial":"secret"}`), &ordinaryKey); !errors.Is(err, ErrInvalidTOTPKeyring) || ordinaryKey.KeyMaterial.Present() {
		t.Fatal("ordinary key decoder accepted material")
	}
	wire := string(encoded)
	for name, invalid := range map[string]string{
		"empty": "", "null": "null", "array": "[]", "whitespace": " " + wire, "newline": wire + "\n", "trailing": wire + "{}",
		"duplicate":         strings.Replace(wire, `"keysetRevision":1`, `"keysetRevision":1,"keysetRevision":1`, 1),
		"nested duplicate":  strings.Replace(wire, `"formatVersion":1`, `"formatVersion":1,"formatVersion":1`, 1),
		"unknown":           strings.Replace(wire, `"formatVersion":1`, `"formatVersion":1,"targetUser":"user-a"`, 1),
		"case alias":        strings.Replace(wire, `"activeKeyId"`, `"ActiveKeyId"`, 1),
		"escaped field":     strings.Replace(wire, `"kind"`, `"k\u0069nd"`, 1),
		"reordered":         strings.Replace(wire, `"apiVersion":"iam.matrix.xiak.com/v1","kind":"TOTPKeyring"`, `"kind":"TOTPKeyring","apiVersion":"iam.matrix.xiak.com/v1"`, 1),
		"purpose":           strings.Replace(wire, TOTPWrappingPurpose, AccessKeyWrappingPurpose, 1),
		"kind":              strings.Replace(wire, `"TOTPKeyring"`, `"AccessKeyWrappingKeyring"`, 1),
		"version":           strings.Replace(wire, APIVersion, "iam.matrix.xiak.com/v2", 1),
		"missing revision":  strings.Replace(wire, `"keysetRevision":1,`, "", 1),
		"zero revision":     strings.Replace(wire, `"keysetRevision":1`, `"keysetRevision":0`, 1),
		"null revision":     strings.Replace(wire, `"keysetRevision":1`, `"keysetRevision":null`, 1),
		"bigint overflow":   strings.Replace(wire, `"keysetRevision":1`, `"keysetRevision":9223372036854775808`, 1),
		"negative revision": strings.Replace(wire, `"keysetRevision":1`, `"keysetRevision":-1`, 1),
		"decimal revision":  strings.Replace(wire, `"keysetRevision":1`, `"keysetRevision":1.0`, 1),
		"exponent revision": strings.Replace(wire, `"keysetRevision":1`, `"keysetRevision":1e0`, 1),
		"null scope":        strings.Replace(wire, `"installationId":"install-a"`, `"installationId":null`, 1),
		"id":                strings.Replace(wire, `"install-a"`, `"install a"`, 1),
		"digest":            strings.Replace(wire, "sha256:", "SHA256:", 1),
		"missing active":    strings.Replace(wire, `"activeKeyId":"key-a"`, `"activeKeyId":"key-missing"`, 1),
		"duplicate keys":    strings.Replace(wire, `"keyId":"key-b"`, `"keyId":"key-a"`, 1),
		"unordered keys":    strings.Replace(wire, `"keyId":"key-b"`, `"keyId":"key-0"`, 1),
		"unknown format":    strings.Replace(wire, `"formatVersion":1`, `"formatVersion":2`, 1),
		"null material":     strings.Replace(wire, `"keyMaterial":"`+string(value.Keys[0].KeyMaterial.CopyBytes())+`"`, `"keyMaterial":null`, 1),
		"short material":    strings.Replace(wire, string(value.Keys[0].KeyMaterial.CopyBytes()), base64.RawURLEncoding.EncodeToString(make([]byte, 31)), 1),
		"padded material":   strings.Replace(wire, string(value.Keys[0].KeyMaterial.CopyBytes()), string(value.Keys[0].KeyMaterial.CopyBytes())+"=", 1),
		"pad bits":          strings.Replace(wire, "kaGxwdHh8", "kaGxwdHh9", 1),
		"null keys":         wire[:strings.Index(wire, `"keys":`)] + `"keys":null}`,
		"empty keys":        wire[:strings.Index(wire, `"keys":`)] + `"keys":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			decoded, err := DecodeTOTPKeyring(strings.NewReader(invalid))
			if err != ErrInvalidTOTPKeyring || !reflect.DeepEqual(decoded, TOTPKeyring{}) {
				t.Fatal("malformed private file exposed partial material or an unnormalized error")
			}
		})
	}
	for _, reader := range []io.Reader{nil, iotest.ErrReader(errors.New(wire)), io.MultiReader(strings.NewReader(wire), iotest.ErrReader(errors.New(wire)))} {
		if got, err := DecodeTOTPKeyring(reader); err != ErrInvalidTOTPKeyring || !reflect.DeepEqual(got, TOTPKeyring{}) {
			t.Fatal("reader failure exposed material or an underlying error")
		}
	}
	oversized := strings.NewReader(strings.Repeat(" ", int(MaxTOTPKeyringBytes)+100))
	if got, err := DecodeTOTPKeyring(oversized); err != ErrInvalidTOTPKeyring || len(got.Keys) != 0 || oversized.Len() < 99 {
		t.Fatal("private read exceeded its bound")
	}
	for _, count := range []int{0, 1, 8, 9} {
		candidate := totpTestKeyring(t)
		candidate.Keys = nil
		for i := range count {
			candidate.Keys = append(candidate.Keys, TOTPWrappingKey{KeyID: "key-" + string(rune('a'+i)), FormatVersion: 1, KeyMaterial: value.Keys[0].KeyMaterial})
		}
		candidate.KeysetRevision = MaxTOTPKeysetRevision
		output, err := EncodeTOTPKeyring(candidate)
		defer clear(output)
		if count == 0 || count == 9 {
			if err != ErrInvalidTOTPKeyring || len(output) != 0 {
				t.Fatal("invalid key count encoded")
			}
		} else if got, err := DecodeTOTPKeyring(bytes.NewReader(output)); err != nil || len(got.Keys) != count || got.KeysetRevision != MaxTOTPKeysetRevision {
			t.Fatal("supported key count or exact maximum revision failed round trip")
		}
	}
	if output, err := EncodeTOTPKeyring(TOTPKeyring{}); err != ErrInvalidTOTPKeyring || len(output) != 0 {
		t.Fatal("zero keyring encoded")
	}
	if _, err := DecodeAccessKeyWrappingKeyring(bytes.NewReader(encoded)); err != ErrInvalidAccessKeyWrappingKeyring {
		t.Fatal("AccessKey accepted a TOTP keyring")
	}
}

func TestTOTPCommitmentsSeparateImmutableKeysFromTheirSet(t *testing.T) {
	value := totpTestKeyring(t)
	// Independently computed with Node standard SHA256 and uint32BE framing.
	want := "sha256:fb8f77f4172568f896c5d473f79ddf5b96647aabcef0aad85172973e55bfaf7d"
	wantSet := "sha256:45a5565aea0c9252a9b37bd4969048d4fa8628b9ae7242b3679b149e6e309353"
	if got, err := TOTPKeyMaterialCommitment(value, "key-a"); err != nil || got != want {
		t.Fatal("key commitment differed from independent vector")
	}
	if got, err := TOTPKeysetDigest(value); err != nil || got != wantSet {
		t.Fatal("set digest differed from independent vector")
	}
	for name, mutate := range map[string]func(*TOTPKeyring){
		"revision":        func(v *TOTPKeyring) { v.KeysetRevision++ },
		"active":          func(v *TOTPKeyring) { v.ActiveKeyID = "key-b" },
		"retained subset": func(v *TOTPKeyring) { v.Keys = v.Keys[:1] },
		"added key":       func(v *TOTPKeyring) { key := v.Keys[1]; key.KeyID = "key-c"; v.Keys = append(v.Keys, key) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := value
			candidate.Keys = slices.Clone(value.Keys)
			mutate(&candidate)
			if got, err := TOTPKeyMaterialCommitment(candidate, "key-a"); err != nil || got != want {
				t.Fatal("set change invalidated retained immutable key evidence")
			}
			if got, err := TOTPKeysetDigest(candidate); err != nil || got == wantSet {
				t.Fatal("set change did not change set digest")
			}
		})
	}
	for name, mutate := range map[string]func(*TOTPKeyring){
		"installation": func(v *TOTPKeyring) { v.Scope.InstallationID = "install-b" },
		"bootstrap":    func(v *TOTPKeyring) { v.Scope.BootstrapDigest = "sha256:" + strings.Repeat("b", 64) },
		"material":     func(v *TOTPKeyring) { v.Keys[0].KeyMaterial = v.Keys[1].KeyMaterial },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := value
			candidate.Keys = slices.Clone(value.Keys)
			mutate(&candidate)
			if got, err := TOTPKeyMaterialCommitment(candidate, "key-a"); err != nil || got == want {
				t.Fatal("substituted key kept commitment")
			}
			if got, err := TOTPKeysetDigest(candidate); err != nil || got == wantSet {
				t.Fatal("substituted key kept set digest")
			}
		})
	}
	if got, err := TOTPKeyMaterialCommitment(value, "missing"); err != ErrInvalidTOTPKeyring || got != "" {
		t.Fatal("unknown key produced a commitment")
	}
	if got, err := TOTPKeysetDigest(TOTPKeyring{}); err != ErrInvalidTOTPKeyring || got != "" {
		t.Fatal("invalid set produced a digest")
	}
	access := AccessKeyWrappingKeyring{APIVersion: APIVersion, Kind: "AccessKeyWrappingKeyring", Purpose: AccessKeyWrappingPurpose,
		Scope: AccessKeyWrappingScope{InstallationID: value.Scope.InstallationID, BootstrapDigest: value.Scope.BootstrapDigest}, ActiveWrappingKeyID: "key-a",
		Keys: []AccessKeyWrappingKey{{WrappingKeyID: "key-a", FormatVersion: 1, KeyMaterial: value.Keys[0].KeyMaterial}}}
	if digest, err := AccessKeyWrappingKeyCommitment(access, "key-a"); err != nil || digest == want {
		t.Fatal("different credential purposes shared a commitment")
	}
	encoded, err := EncodeAccessKeyWrappingKeyring(access)
	defer clear(encoded)
	if err != nil {
		t.Fatal("could not build AccessKey private source")
	}
	if got, err := DecodeTOTPKeyring(bytes.NewReader(encoded)); err != ErrInvalidTOTPKeyring || len(got.Keys) != 0 {
		t.Fatal("TOTP accepted AccessKey private source")
	}
}

func FuzzTOTPKeyringCanonicalPrivateFile(f *testing.F) {
	encoded, err := EncodeTOTPKeyring(totpTestKeyring(f))
	if err != nil {
		f.Fatal("synthetic keyring failed")
	}
	defer clear(encoded)
	for _, wire := range []string{string(encoded), "null", "{}", string(encoded) + "\n", strings.Replace(string(encoded), `"keysetRevision":1`, `"keysetRevision":null`, 1)} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		value, err := DecodeTOTPKeyring(strings.NewReader(wire))
		if err != nil {
			if err != ErrInvalidTOTPKeyring || !reflect.DeepEqual(value, TOTPKeyring{}) {
				t.Fatal("invalid private input returned data")
			}
			return
		}
		canonical, err := EncodeTOTPKeyring(value)
		defer clear(canonical)
		if err != nil || string(canonical) != wire {
			t.Fatal("accepted input was not canonical")
		}
		if digest, err := TOTPKeysetDigest(value); err != nil || ValidateDigest("keyset", digest) != nil {
			t.Fatal("valid keyring had no set evidence")
		}
	})
}

func TestAccessKeyWrappingKeyringHasOneExplicitCanonicalPrivateCodec(t *testing.T) {
	material := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	wire := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"AccessKeyWrappingKeyring","purpose":"IAM_ACCESS_KEY_SECRET_WRAPPING","scope":{"installationId":"install-a","bootstrapDigest":"sha256:` + strings.Repeat("a", 64) + `"},"activeWrappingKeyId":"wrap-a","keys":[{"wrappingKeyId":"wrap-a","formatVersion":1,"keyMaterial":"` + material + `"}]}`
	decoded, err := DecodeAccessKeyWrappingKeyring(strings.NewReader(wire))
	if err != nil || ValidateAccessKeyWrappingKeyring(decoded) != nil || len(decoded.Keys) != 1 || string(decoded.Keys[0].KeyMaterial.CopyBytes()) != material {
		t.Fatal("canonical private keyring was not decoded")
	}
	encoded, err := EncodeAccessKeyWrappingKeyring(decoded)
	defer clear(encoded)
	if err != nil || string(encoded) != wire {
		t.Fatal("explicit keyring encoder changed the canonical file")
	}
	for _, value := range []any{decoded, &decoded, decoded.Keys[0], &decoded.Keys[0]} {
		if strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), material) {
			t.Fatal("private keyring leaked through formatting")
		}
		if output, err := json.Marshal(value); !errors.Is(err, ErrInvalidAccessKeyWrappingKeyring) || bytes.Contains(output, []byte(material)) {
			t.Fatal("private keyring allowed ordinary JSON serialization")
		}
	}
	var ordinary AccessKeyWrappingKeyring
	if err := json.Unmarshal([]byte(wire), &ordinary); !errors.Is(err, ErrInvalidAccessKeyWrappingKeyring) || len(ordinary.Keys) != 0 {
		t.Fatal("ordinary JSON bypassed the private file codec")
	}
	var ordinaryKey AccessKeyWrappingKey
	if err := json.Unmarshal([]byte(`{"wrappingKeyId":"wrap-a","formatVersion":1,"keyMaterial":"`+material+`"}`), &ordinaryKey); !errors.Is(err, ErrInvalidAccessKeyWrappingKeyring) || ordinaryKey.KeyMaterial.Present() {
		t.Fatal("ordinary JSON decoded private key material")
	}
	for name, invalid := range map[string]string{
		"empty": "", "null": "null", "array": "[]", "whitespace": " " + wire,
		"newline": wire + "\n", "trailing": wire + `{}`, "duplicate": strings.Replace(wire, `"formatVersion":1`, `"formatVersion":1,"formatVersion":1`, 1),
		"unknown":             strings.Replace(wire, `"formatVersion":1`, `"formatVersion":1,"secretSelector":true`, 1),
		"case alias":          strings.Replace(wire, `"activeWrappingKeyId"`, `"ActiveWrappingKeyId"`, 1),
		"escaped field":       strings.Replace(wire, `"kind"`, `"k\u0069nd"`, 1),
		"reordered":           strings.Replace(wire, `"apiVersion":"iam.matrix.xiak.com/v1","kind":"AccessKeyWrappingKeyring"`, `"kind":"AccessKeyWrappingKeyring","apiVersion":"iam.matrix.xiak.com/v1"`, 1),
		"wrong api":           strings.Replace(wire, APIVersion, "other/v1", 1),
		"wrong purpose":       strings.Replace(wire, AccessKeyWrappingPurpose, LocalCredentialRecoveryPurpose, 1),
		"wrong kind":          strings.Replace(wire, `"AccessKeyWrappingKeyring"`, `"AccessKey"`, 1),
		"missing scope":       strings.Replace(wire, `"installationId":"install-a",`, ``, 1),
		"null scope":          strings.Replace(wire, `"installationId":"install-a"`, `"installationId":null`, 1),
		"noncanonical id":     strings.Replace(wire, `"install-a"`, `" install-a"`, 1),
		"invalid digest":      strings.Replace(wire, "sha256:", "SHA256:", 1),
		"inactive reference":  strings.Replace(wire, `"activeWrappingKeyId":"wrap-a"`, `"activeWrappingKeyId":"wrap-b"`, 1),
		"unknown format":      strings.Replace(wire, `"formatVersion":1`, `"formatVersion":2`, 1),
		"missing format":      strings.Replace(wire, `"formatVersion":1,`, ``, 1),
		"wrong format type":   strings.Replace(wire, `"formatVersion":1`, `"formatVersion":"1"`, 1),
		"noncanonical number": strings.Replace(wire, `"formatVersion":1`, `"formatVersion":1.0`, 1),
		"null material":       strings.Replace(wire, `"keyMaterial":"`+material+`"`, `"keyMaterial":null`, 1),
		"short material":      strings.Replace(wire, material, base64.RawURLEncoding.EncodeToString(make([]byte, 31)), 1),
		"long material":       strings.Replace(wire, material, base64.RawURLEncoding.EncodeToString(make([]byte, 33)), 1),
		"padded material":     strings.Replace(wire, material, material+"=", 1),
		"pad bits":            strings.Replace(wire, material, material[:42]+"9", 1),
		"empty keys":          strings.Replace(wire, wire[strings.Index(wire, `"keys":`):], `"keys":[]}`, 1),
		"two keys":            strings.Replace(wire, `}]}`, `},{"wrappingKeyId":"wrap-b","formatVersion":1,"keyMaterial":"`+material+`"}]}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			value, err := DecodeAccessKeyWrappingKeyring(strings.NewReader(invalid))
			if err != ErrInvalidAccessKeyWrappingKeyring || len(value.Keys) != 0 || strings.Contains(err.Error(), material) {
				t.Fatal("invalid private file returned data or a non-normalized error")
			}
		})
	}
	for _, invalid := range []AccessKeyWrappingKeyring{{}, {APIVersion: APIVersion, Kind: "AccessKeyWrappingKeyring", Purpose: AccessKeyWrappingPurpose, Scope: decoded.Scope, ActiveWrappingKeyID: "wrap-a"}} {
		if output, err := EncodeAccessKeyWrappingKeyring(invalid); err != ErrInvalidAccessKeyWrappingKeyring || len(output) != 0 {
			t.Fatal("invalid typed keyring was encoded")
		}
	}
	if value, err := DecodeAccessKeyWrappingKeyring(nil); err != ErrInvalidAccessKeyWrappingKeyring || len(value.Keys) != 0 {
		t.Fatal("nil file reader was accepted")
	}
	for _, reader := range []io.Reader{
		iotest.ErrReader(errors.New(material)),
		io.MultiReader(strings.NewReader(wire), iotest.ErrReader(errors.New(material))),
	} {
		value, err := DecodeAccessKeyWrappingKeyring(reader)
		if err != ErrInvalidAccessKeyWrappingKeyring || !reflect.DeepEqual(value, AccessKeyWrappingKeyring{}) {
			t.Fatal("reader failure exposed partial material or its underlying error")
		}
	}
	oversized := strings.NewReader(strings.Repeat(" ", int(MaxAccessKeyWrappingKeyringBytes)+100))
	if value, err := DecodeAccessKeyWrappingKeyring(oversized); err != ErrInvalidAccessKeyWrappingKeyring || len(value.Keys) != 0 || oversized.Len() < 99 {
		t.Fatal("private file decoder exceeded its bounded read")
	}
}

func FuzzAccessKeyWrappingCanonicalPrivateFile(f *testing.F) {
	material, _ := NewSecret("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	value := AccessKeyWrappingKeyring{APIVersion: APIVersion, Kind: "AccessKeyWrappingKeyring", Purpose: AccessKeyWrappingPurpose,
		Scope:               AccessKeyWrappingScope{InstallationID: "install-a", BootstrapDigest: "sha256:" + strings.Repeat("a", 64)},
		ActiveWrappingKeyID: "wrap-a", Keys: []AccessKeyWrappingKey{{WrappingKeyID: "wrap-a", FormatVersion: 1, KeyMaterial: material}}}
	seed, err := EncodeAccessKeyWrappingKeyring(value)
	if err != nil {
		f.Fatal("could not encode the public fuzz seed")
	}
	for _, wire := range []string{string(seed), "{}", "null", string(seed) + "\n", string(seed) + `{}`, strings.Replace(string(seed), `"formatVersion":1`, `"formatVersion":1,"formatVersion":1`, 1)} {
		f.Add(wire)
	}
	clear(seed)
	f.Fuzz(func(t *testing.T, wire string) {
		value, err := DecodeAccessKeyWrappingKeyring(strings.NewReader(wire))
		if err != nil {
			if err != ErrInvalidAccessKeyWrappingKeyring || !reflect.DeepEqual(value, AccessKeyWrappingKeyring{}) {
				t.Fatal("rejected file returned partial data or a non-normalized error")
			}
			return
		}
		encoded, err := EncodeAccessKeyWrappingKeyring(value)
		defer clear(encoded)
		if err != nil || string(encoded) != wire {
			t.Fatal("private decoder accepted noncanonical bytes")
		}
		commitment, err := AccessKeyWrappingKeyCommitment(value, value.ActiveWrappingKeyID)
		if err != nil || ValidateDigest("commitment", commitment) != nil {
			t.Fatal("accepted private file had no exact material commitment")
		}
	})
}

func TestAccessKeyWrappingKeyCommitmentBindsExactMaterialAndInstallation(t *testing.T) {
	material, err := NewSecret("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil {
		t.Fatal("invalid public test material")
	}
	value := AccessKeyWrappingKeyring{APIVersion: APIVersion, Kind: "AccessKeyWrappingKeyring", Purpose: AccessKeyWrappingPurpose,
		Scope:               AccessKeyWrappingScope{InstallationID: "install-a", BootstrapDigest: "sha256:" + strings.Repeat("a", 64)},
		ActiveWrappingKeyID: "wrap-a", Keys: []AccessKeyWrappingKey{{WrappingKeyID: "wrap-a", FormatVersion: 1, KeyMaterial: material}}}
	// Independently produced by Node crypto.createHash(sha256) over explicit
	// uint32BE-framed fields, including the decoded public 00..1f test KEK.
	want := "sha256:8111150ca7512038ed411a1e2efaa56e817deba04c0929c03cab71087870c17f"
	for range 2 {
		got, err := AccessKeyWrappingKeyCommitment(value, "wrap-a")
		if err != nil || got != want {
			t.Fatal("per-key commitment differed from the independent vector")
		}
	}
	for name, mutation := range map[string]struct {
		change func(*AccessKeyWrappingKeyring)
		valid  bool
	}{
		"installation": {func(v *AccessKeyWrappingKeyring) { v.Scope.InstallationID = "install-b" }, true},
		"bootstrap":    {func(v *AccessKeyWrappingKeyring) { v.Scope.BootstrapDigest = "sha256:" + strings.Repeat("b", 64) }, true},
		"key identity": {func(v *AccessKeyWrappingKeyring) {
			v.ActiveWrappingKeyID = "wrap-b"
			v.Keys[0].WrappingKeyID = "wrap-b"
		}, true},
		"material under same id": {func(v *AccessKeyWrappingKeyring) {
			v.Keys[0].KeyMaterial, _ = NewSecret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32)))
		}, true},
		"purpose":         {func(v *AccessKeyWrappingKeyring) { v.Purpose = LocalCredentialRecoveryPurpose }, false},
		"format":          {func(v *AccessKeyWrappingKeyring) { v.Keys[0].FormatVersion = 2 }, false},
		"active mismatch": {func(v *AccessKeyWrappingKeyring) { v.ActiveWrappingKeyID = "wrap-b" }, false},
		"bad id":          {func(v *AccessKeyWrappingKeyring) { v.Scope.InstallationID += " " }, false},
		"incomplete":      {func(v *AccessKeyWrappingKeyring) { v.Keys = nil }, false},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := value
			candidate.Keys = slices.Clone(value.Keys)
			mutation.change(&candidate)
			got, err := AccessKeyWrappingKeyCommitment(candidate, candidate.ActiveWrappingKeyID)
			if mutation.valid {
				if err != nil || ValidateDigest("commitment", got) != nil || got == want {
					t.Fatal("substituted binding or material retained the original commitment")
				}
			} else if err != ErrInvalidAccessKeyWrappingKeyring || got != "" {
				t.Fatal("invalid keyring produced commitment or a revealing error")
			}
		})
	}
	if got, err := AccessKeyWrappingKeyCommitment(value, "wrap-missing"); err != ErrInvalidAccessKeyWrappingKeyring || got != "" {
		t.Fatal("unknown key selector produced a commitment")
	}
	info, aad, err := AccessKeySecretContext("install-a", "account-a", "user-a", "key-a", "wrap-a")
	if err != nil || bytes.Equal(info, aad) {
		t.Fatal("secret context domains were not distinct")
	}
	aadBefore := bytes.Clone(aad)
	info[0] ^= 1
	if !bytes.Equal(aad, aadBefore) {
		t.Fatal("secret contexts shared a mutable buffer")
	}
	for field := range 5 {
		values := []string{"install-a", "account-a", "user-a", "key-a", "wrap-a"}
		values[field] += " "
		info, aad, err := AccessKeySecretContext(values[0], AccountID(values[1]), PrincipalID(values[2]), values[3], values[4])
		if err != ErrInvalidAccessKeySecretContext || len(info) != 0 || len(aad) != 0 {
			t.Fatal("invalid context field was normalized or encoded")
		}
	}
}

func TestCurrentRoleIdentityHasOnlyBoundDisplayContext(t *testing.T) {
	session := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RoleSession","id":"role-session-a","accountId":"account-a","roleId":"role-a","sourceUserId":"user-a","status":"ACTIVE","issuedAt":"2026-09-16T00:00:00Z","expiresAt":"2026-09-16T01:00:00Z"}`
	wire := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"CurrentRoleIdentity","session":` + session +
		`,"account":{"id":"account-a","displayName":"Account A"},"role":{"id":"role-a","name":"Reader"},"sourceUser":{"id":"user-a","loginName":"member","displayName":"Member"}}`
	var identity CurrentRoleIdentity
	if DecodeRequest(strings.NewReader(wire), &identity) != nil || ValidateCurrentRoleIdentity(identity) != nil {
		t.Fatal("valid current role display was rejected")
	}
	encoded, err := json.Marshal(identity)
	var repeated CurrentRoleIdentity
	if err != nil || DecodeRequest(bytes.NewReader(encoded), &repeated) != nil || !reflect.DeepEqual(identity, repeated) {
		t.Fatal("current role display changed through its strict codec")
	}
	for name, candidate := range map[string]string{
		"old receipt":       session,
		"wrong kind":        strings.Replace(wire, `"CurrentRoleIdentity"`, `"RoleSession"`, 1),
		"foreign account":   strings.Replace(wire, `"id":"account-a"`, `"id":"account-b"`, 1),
		"foreign role":      strings.Replace(wire, `"id":"role-a"`, `"id":"role-b"`, 1),
		"foreign source":    strings.Replace(wire, `"id":"user-a"`, `"id":"user-b"`, 1),
		"empty source name": strings.Replace(wire, `"displayName":"Member"`, `"displayName":""`, 1),
		"root relation":     strings.Replace(wire, `"displayName":"Account A"`, `"displayName":"Account A","rootIdentity":{"principalId":"root"}`, 1),
		"private lineage":   strings.Replace(wire, `"sourceUserId":"user-a"`, `"sourceUserId":"user-a","sourceSessionId":"private"`, 1),
		"private epoch":     strings.Replace(wire, `"sourceUserId":"user-a"`, `"sourceUserId":"user-a","credentialGeneration":1`, 1),
		"revoked receipt":   strings.Replace(wire, `"status":"ACTIVE"`, `"status":"REVOKED","revokedAt":"2026-09-16T00:01:00Z"`, 1),
		"null revocation":   strings.Replace(wire, `"status":"ACTIVE"`, `"status":"ACTIVE","revokedAt":null`, 1),
		"secret":            strings.TrimSuffix(wire, "}") + `,"credential":"private"}`,
		"trust":             strings.Replace(wire, `"name":"Reader"`, `"name":"Reader","trustPolicy":{"statements":[]}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var rejected CurrentRoleIdentity
			if DecodeRequest(strings.NewReader(candidate), &rejected) == nil && ValidateCurrentRoleIdentity(rejected) == nil {
				t.Fatal("unbound or private display context was admitted")
			}
		})
	}
}

func TestRoleSessionManagementObservationAndIntent(t *testing.T) {
	issued := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	session := RoleSession{APIVersion: APIVersion, Kind: "RoleSession", ID: "session-a", AccountID: "account-a", RoleID: "role-a",
		SourceUserID: "user-a", Status: SessionActive, IssuedAt: issued, ExpiresAt: issued.Add(time.Hour)}
	for _, sample := range []struct {
		at   time.Time
		want RoleSessionLifecycle
	}{
		{issued, RoleSessionUnrevoked}, {session.ExpiresAt.Add(-time.Microsecond), RoleSessionUnrevoked},
		{session.ExpiresAt, RoleSessionExpired}, {session.ExpiresAt.Add(time.Hour), RoleSessionExpired},
	} {
		got, err := ObserveRoleSession(session, sample.at)
		if err != nil || got != sample.want {
			t.Fatal("lifecycle changed at the expiry boundary", got, err)
		}
	}
	if _, err := ObserveRoleSession(session, issued.Add(-time.Microsecond)); err == nil {
		t.Fatal("accepted a future issuance")
	}
	revoked := issued.Add(time.Minute)
	session.Status, session.RevokedAt = SessionRevoked, &revoked
	if got, err := ObserveRoleSession(session, session.ExpiresAt); err != nil || got != RoleSessionRevoked {
		t.Fatal("expiry hid explicit revocation")
	}
	if _, err := ObserveRoleSession(session, revoked.Add(-time.Microsecond)); err == nil {
		t.Fatal("accepted a future revocation")
	}
	for _, outcome := range []string{"APPLIED", "EQUAL_REPLAY"} {
		if ValidateRevokeRoleSessionResponse(RevokeRoleSessionResponse{Outcome: outcome, Session: session}) != nil {
			t.Fatal("lost terminal outcome")
		}
	}
	if ValidateRevokeRoleSessionResponse(RevokeRoleSessionResponse{Outcome: "UNKNOWN", Session: session}) == nil {
		t.Fatal("unknown outcome became success")
	}
	session.Status, session.RevokedAt = SessionActive, nil
	if ValidateRevokeRoleSessionResponse(RevokeRoleSessionResponse{Outcome: "APPLIED", Session: session}) == nil {
		t.Fatal("unrevoked record became success")
	}
	for _, lifecycle := range []string{"", "ALL", "UNREVOKED", "EXPIRED", "REVOKED"} {
		filter, err := NormalizeRoleSessionFilter(RoleSessionFilter{SourceUserID: "user-a", SessionID: "session-a", Lifecycle: lifecycle})
		if err != nil || (lifecycle == "" && filter.Lifecycle != "UNREVOKED") {
			t.Fatal("valid closed filter rejected")
		}
	}
	for _, filter := range []RoleSessionFilter{{Lifecycle: "USABLE"}, {Lifecycle: "ACTIVE"}, {Lifecycle: "all"}, {SourceUserID: "*"}, {SessionID: "a/b"}} {
		if _, err := NormalizeRoleSessionFilter(filter); err == nil {
			t.Fatal("unsupported filter accepted")
		}
	}
}

func TestRoleSessionManagementViewsBindMinimalCurrentObservation(t *testing.T) {
	session := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RoleSession","id":"role-session-a","accountId":"account-a","roleId":"role-a","sourceUserId":"user-a","status":"ACTIVE","issuedAt":"2026-09-17T00:00:00Z","expiresAt":"2026-09-17T01:00:00Z"}`
	item := `{"session":` + session + `,"sourceUser":{"id":"user-a","loginName":"member","displayName":"Member"},"lifecycle":"UNREVOKED","revokeCapability":{"action":"iam.role-session.revoke","resource":{"kind":"ROLE_SESSION","id":"role-session-a"},"available":true}}`
	wire := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RoleSessionList","accountId":"account-a","roleId":"role-a","observedAt":"2026-09-17T00:01:00Z","items":[` + item + `]}`
	var listed RoleSessionList
	if DecodeRequest(strings.NewReader(wire), &listed) != nil || ValidateRoleSessionList(listed) != nil {
		t.Fatal("valid management observation rejected")
	}
	for name, broken := range map[string]string{
		"source mismatch":                    strings.Replace(wire, `"id":"user-a"`, `"id":"user-b"`, 1),
		"account mismatch":                   strings.Replace(wire, `"accountId":"account-a"`, `"accountId":"account-b"`, 1),
		"role mismatch":                      strings.Replace(wire, `"roleId":"role-a"`, `"roleId":"role-b"`, 1),
		"capability target":                  strings.Replace(wire, `"kind":"ROLE_SESSION","id":"role-session-a"`, `"kind":"ROLE_SESSION","id":"another"`, 1),
		"capability action":                  strings.Replace(wire, `"iam.role-session.revoke"`, `"iam.role-session.read"`, 1),
		"lifecycle does not prove usability": strings.Replace(wire, `"UNREVOKED"`, `"USABLE"`, 1),
		"expired authority":                  strings.Replace(wire, `"observedAt":"2026-09-17T00:01:00Z"`, `"observedAt":"2026-09-17T01:00:00Z"`, 1),
		"private lineage":                    strings.Replace(wire, `"sourceUserId":"user-a"`, `"sourceUserId":"user-a","sourceSessionId":"private"`, 1),
		"diagnostic leakage":                 strings.Replace(wire, `"lifecycle":"UNREVOKED"`, `"lifecycle":"UNREVOKED","invalidationReason":"private"`, 1),
		"null rows":                          strings.Replace(wire, `"items":[`+item+`]`, `"items":null`, 1),
		"duplicate rows":                     strings.Replace(wire, `"items":[`+item+`]`, `"items":[`+item+`,`+item+`]`, 1),
		"private cursor":                     strings.TrimSuffix(wire, "}") + `,"nextAfter":"ir1.private"}`,
		"empty cursor":                       strings.TrimSuffix(wire, "}") + `,"nextAfter":""}`,
		"caller total":                       strings.TrimSuffix(wire, "}") + `,"total":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			var value RoleSessionList
			if DecodeRequest(strings.NewReader(broken), &value) == nil {
				t.Fatal("invalid projection accepted")
			}
		})
	}
	empty := strings.Replace(wire, `"items":[`+item+`]`, `"items":[]`, 1)
	empty = strings.TrimSuffix(empty, "}") + `,"nextAfter":"ic1.opaque-next-window"}`
	if DecodeRequest(strings.NewReader(empty), &listed) != nil || len(listed.Items) != 0 || listed.NextAfter == "" {
		t.Fatal("sparse continuation was lost")
	}
	access := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RoleSessionAccess","observedAt":"2026-09-17T00:01:00Z","item":` + item + `}`
	var detail RoleSessionAccess
	if DecodeRequest(strings.NewReader(access), &detail) != nil {
		t.Fatal("precise observation rejected")
	}
}

func TestAssumableRoleDirectoryIsMinimalBoundedAndAllowsEmptyContinuation(t *testing.T) {
	item := `{"roleId":"role-a","accountId":"account-a","name":"Reader","status":"ACTIVE","maxSessionDurationSeconds":3600,"resourceVersion":2,"capability":{"action":"iam.role.assume","resource":{"kind":"ROLE","id":"role-a"},"available":true}}`
	empty := `{"apiVersion":"iam.matrix.xiak.com/v1","kind":"AssumableRoleList","accountId":"account-a","sourceUserId":"user-a","items":[]}`
	withItem := strings.Replace(empty, `"items":[]`, `"items":[`+item+`]`, 1)
	continued := strings.TrimSuffix(empty, "}") + `,"nextAfter":"ir1.opaque-candidate"}`
	for _, valid := range []string{empty, continued, withItem} {
		var result AssumableRoleList
		if DecodeRequest(strings.NewReader(valid), &result) != nil || ValidateAssumableRoleList(result) != nil {
			t.Fatal("valid bounded discovery response was rejected")
		}
		encoded, err := json.Marshal(result)
		var repeated AssumableRoleList
		if err != nil || DecodeRequest(bytes.NewReader(encoded), &repeated) != nil || !reflect.DeepEqual(result, repeated) {
			t.Fatal("discovery response changed through its strict codec")
		}
	}
	for name, candidate := range map[string]string{
		"null items":        strings.Replace(empty, `"items":[]`, `"items":null`, 1),
		"null cursor":       strings.TrimSuffix(empty, "}") + `,"nextAfter":null}`,
		"raw cursor":        strings.TrimSuffix(empty, "}") + `,"nextAfter":"role-a"}`,
		"unbound source":    strings.Replace(empty, `,"sourceUserId":"user-a"`, "", 1),
		"total count":       strings.TrimSuffix(empty, "}") + `,"total":20}`,
		"foreign item":      strings.Replace(withItem, `"roleId":"role-a","accountId":"account-a"`, `"roleId":"role-a","accountId":"account-b"`, 1),
		"wrong action":      strings.Replace(withItem, `"action":"iam.role.assume"`, `"action":"iam.role.read"`, 1),
		"wrong target":      strings.Replace(withItem, `"id":"role-a"`, `"id":"role-b"`, 1),
		"denied candidate":  strings.Replace(withItem, `"available":true`, `"available":false,"restrictionReason":"AUTHORITY_REQUIRED"`, 1),
		"disabled role":     strings.Replace(withItem, `"status":"ACTIVE"`, `"status":"DISABLED"`, 1),
		"empty restriction": strings.Replace(withItem, `"available":true`, `"available":true,"restrictionReason":""`, 1),
		"private trust":     strings.Replace(withItem, `"name":"Reader"`, `"name":"Reader","trustVersionId":"private"`, 1),
		"duplicate role":    strings.Replace(empty, `"items":[]`, `"items":[`+item+`,`+item+`]`, 1),
		"excess candidates": strings.Replace(empty, `"items":[]`, `"items":[`+strings.Repeat(item+",", RoleDiscoveryPageSize)+item+`]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var rejected AssumableRoleList
			if DecodeRequest(strings.NewReader(candidate), &rejected) == nil && ValidateAssumableRoleList(rejected) == nil {
				t.Fatal("invalid discovery response was admitted")
			}
		})
	}
}

func FuzzAssumeRoleIntentRoundTrip(f *testing.F) {
	for _, seed := range []string{
		`{"resourceVersion":1,"requestId":"assume-a"}`,
		`{"resourceVersion":1,"durationSeconds":60,"requestId":"assume-a"}`,
		`{"resourceVersion":1,"sessionPolicy":null,"requestId":"assume-a"}`,
		`{"resourceVersion":1,"sourceUserId":"other","requestId":"assume-a"}`,
		`{"resourceVersion":1,"durationSeconds":43200,"sessionPolicy":{"languageVersion":"1","scope":"TENANT","statements":[{"sid":"read","effect":"ALLOW","actions":["paas.application.*"],"resources":[{"kind":"APPLICATION","match":"ANY_IN_AUTHORITY"}]}]},"requestId":"assume-a"}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		var request AssumeRoleRequest
		if DecodeRequest(strings.NewReader(wire), &request) != nil || ValidateAssumeRoleRequest(request) != nil {
			return
		}
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal("valid issuance intent could not be encoded")
		}
		var decoded AssumeRoleRequest
		if DecodeRequest(bytes.NewReader(encoded), &decoded) != nil || ValidateAssumeRoleRequest(decoded) != nil || !reflect.DeepEqual(request, decoded) {
			t.Fatal("issuance intent changed through its strict codec")
		}
	})
}

func TestAssumeRoleInputCannotSupplyItsOwnIdentityOrCompiledAuthority(t *testing.T) {
	base := `{"resourceVersion":1,"requestId":"assume-a"}`
	var request AssumeRoleRequest
	if DecodeRequest(strings.NewReader(base), &request) != nil || ValidateAssumeRoleRequest(request) != nil || request.DurationSeconds != nil || request.SessionPolicy != nil {
		t.Fatal("valid intent without optional limits was not preserved")
	}
	policy := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant, Statements: []PolicyStatement{
		{SID: "read-only", Effect: PolicyAllow, Actions: []Action{ActionPaaSApplicationRead}, Resources: []PolicyResourceSelector{{Kind: ResourceApplication, Match: PolicyResourceAnyInAuthority}}},
	}}
	encodedPolicy, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	withPolicy := strings.TrimSuffix(base, "}") + `,"durationSeconds":60,"sessionPolicy":` + string(encodedPolicy) + `}`
	if DecodeRequest(strings.NewReader(withPolicy), &request) != nil || ValidateAssumeRoleRequest(request) != nil || request.DurationSeconds == nil || *request.DurationSeconds != 60 || request.SessionPolicy == nil {
		t.Fatal("bounded authored session policy was not accepted")
	}
	for _, member := range []string{
		`"accountId":"other"`, `"tenantId":"other"`, `"sourceUserId":"root"`, `"sourceSessionId":"other"`,
		`"credentialGeneration":1`, `"roleGeneration":1`, `"roleId":"other"`, `"trustVersionId":"other"`,
		`"sourceIdentity":"root"`, `"credentials":"secret"`, `"compilation":{}`, `"profiles":[]`,
		`"durationSeconds":null`, `"sessionPolicy":null`, `"sessionPolicy":{}`, `"durationSeconds":0`,
		`"durationSeconds":59`, `"durationSeconds":43201`, `"durationSeconds":-1`, `"durationSeconds":"60"`,
		`"resourceVersion":1`, `"RequestId":"assume-a"`,
	} {
		candidate := strings.TrimSuffix(base, "}") + "," + member + "}"
		var rejected AssumeRoleRequest
		if DecodeRequest(strings.NewReader(candidate), &rejected) == nil && ValidateAssumeRoleRequest(rejected) == nil {
			t.Fatalf("invalid or authority-bearing intent accepted: %s", member)
		}
	}
	for _, candidate := range []string{
		`{}`, `{"requestId":"assume-a"}`, `{"resourceVersion":0,"requestId":"assume-a"}`,
		`{"resourceVersion":1,"requestId":""}`, base + `{}`, "null",
		strings.TrimSuffix(base, "}") + `,"padding":"` + strings.Repeat("x", int(MaxRequestBytes)) + `"}`,
		strings.Replace(withPolicy, `"scope":"TENANT"`, `"scope":"INSTALLATION"`, 1),
		strings.Replace(withPolicy, `"sessionPolicy":{`, `"sessionPolicy":{"principal":"root",`, 1),
	} {
		var rejected AssumeRoleRequest
		if DecodeRequest(strings.NewReader(candidate), &rejected) == nil && ValidateAssumeRoleRequest(rejected) == nil {
			t.Fatal("malformed or excessive issuance intent accepted")
		}
	}
}

func TestRoleMetadataAndAccessAreSeparateFromLoginAuthority(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	role := Role{APIVersion: APIVersion, Kind: "Role", ID: "role-a", AccountID: "account-a", Name: "Readers",
		Tags: []RoleTag{}, Management: RoleCustomerManaged, Status: RoleActive, MaxSessionDurationSeconds: 3600,
		ResourceVersion: 1, CurrentTrustVersionID: "trust-a", CreatedAt: now, UpdatedAt: now}
	document := sampleRoleTrustDocument()
	_, digest, err := CanonicalizeTrustPolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	access := RoleAccess{Role: role, TrustVersion: RoleTrustVersion{APIVersion: APIVersion, Kind: "RoleTrustVersion", ID: "trust-a",
		AccountID: role.AccountID, RoleID: role.ID, Document: document, ContentDigest: digest, CreatedAt: now}, PolicyAttachments: []PolicyAttachment{}}
	for _, action := range []Action{ActionIAMRoleRead, ActionIAMRoleUpdate, ActionIAMRoleSetStatus, ActionIAMRoleDelete, ActionIAMRoleTrustSet,
		ActionIAMRolePolicyAttachmentCreate, ActionIAMRolePermissionBoundarySet, ActionIAMRolePermissionBoundaryRemove, ActionIAMRoleSessionList, ActionIAMRoleAssume} {
		access.Capabilities = append(access.Capabilities, ActionCapability{Action: action, Resource: ResourceReference{Kind: ResourceRole, ID: string(role.ID)}, RestrictionReason: CapabilityAuthorityRequired})
	}
	if ValidateRoleAccess(access) != nil {
		t.Fatal("valid closed role detail rejected")
	}
	for name, change := range map[string]func(*RoleAccess){
		"foreign trust account":    func(v *RoleAccess) { v.TrustVersion.AccountID = "other" },
		"foreign trust role":       func(v *RoleAccess) { v.TrustVersion.RoleID = "other" },
		"unselected trust":         func(v *RoleAccess) { v.TrustVersion.ID = "other" },
		"trust beyond revision":    func(v *RoleAccess) { v.TrustVersion.CreatedAt = now.Add(time.Second) },
		"managed service selector": func(v *RoleAccess) { v.Role.Management = "SERVICE" },
		"null tags":                func(v *RoleAccess) { v.Role.Tags = nil },
		"duplicate tag key":        func(v *RoleAccess) { v.Role.Tags = []RoleTag{{"env", "a"}, {"env", "b"}} },
		"control tag":              func(v *RoleAccess) { v.Role.Tags = []RoleTag{{"env", "a\u0085"}} },
		"short duration":           func(v *RoleAccess) { v.Role.MaxSessionDurationSeconds = 59 },
		"long duration":            func(v *RoleAccess) { v.Role.MaxSessionDurationSeconds = 43201 },
		"missing capabilities":     func(v *RoleAccess) { v.Capabilities = nil },
		"implicit attachments":     func(v *RoleAccess) { v.PolicyAttachments = nil },
	} {
		t.Run(name, func(t *testing.T) {
			value := access
			change(&value)
			if ValidateRoleAccess(value) == nil {
				t.Fatal("invalid role detail accepted")
			}
		})
	}
	page := RoleList{APIVersion: APIVersion, Kind: "RoleList", AccountID: role.AccountID, Items: []RoleListing{}}
	for index := range DirectoryPageSize {
		item := RoleListing{Role: role, Capabilities: slices.Clone(access.Capabilities)}
		item.Capabilities = slices.DeleteFunc(item.Capabilities, func(capability ActionCapability) bool { return capability.Action == ActionIAMRoleAssume })
		item.Role.ID = RoleID(fmt.Sprintf("role-%03d", index))
		item.Role.Name = strings.Repeat("<", 64)
		item.Role.Description = strings.Repeat("&", 512)
		remaining := 4096 - 64 - 512
		for key := 0; remaining > 0; key++ {
			name := fmt.Sprintf("tag%02d", key)
			size := min(256, remaining-len(name))
			item.Role.Tags = append(item.Role.Tags, RoleTag{name, strings.Repeat(">", size)})
			remaining -= len(name) + size
		}
		for i := range item.Capabilities {
			item.Capabilities[i].Resource.ID = string(item.Role.ID)
		}
		page.Items = append(page.Items, item)
	}
	if ValidateRoleList(page) != nil {
		t.Fatal("valid full metadata directory exceeds declared budget")
	}
	page.Items[0].Role.Tags[len(page.Items[0].Role.Tags)-1].Value += "x"
	if ValidateRoleList(page) == nil {
		t.Fatal("aggregate role metadata budget was bypassed")
	}
}

func TestRoleProfilesPreserveRegisteredAuthority(t *testing.T) {
	archives := HistoricalAuthorizationProfiles()
	for revision, expected := range map[uint64]string{
		1: "sha256:9e6176c37a0b1566987e6c666c1fef9da1f81b90078c6d7fb8a91473ae666a44",
		2: "sha256:69c3366eed3d18fcc05a0e54d826e27fdf62664d76ef94ef30d16c4d70dd262a",
	} {
		index := slices.IndexFunc(archives, func(profile AuthorizationProfile) bool {
			return profile.Product == ProductIAM && profile.Revision == revision
		})
		if index < 0 {
			t.Fatal("missing retained IAM revision")
		}
		_, digest, err := CanonicalizeAuthorizationProfile(archives[index])
		if err != nil || digest != expected {
			t.Fatal("registered IAM declaration was rewritten")
		}
		for _, action := range archives[index].Actions {
			if action.Action == ActionIAMRoleAssume || action.Action == ActionIAMRolePermissionBoundarySet ||
				(revision == 1 && action.Action == ActionIAMRoleCreate) || len(action.SubjectTypes) != 0 {
				t.Fatal("historical IAM declaration silently gained authority")
			}
		}
		archives[index].Actions[0].Action = "iam.invalid.mutation"
		_, again, err := CanonicalizeAuthorizationProfile(HistoricalAuthorizationProfiles()[index])
		if err != nil || again != digest {
			t.Fatal("caller changed archived source declaration")
		}
	}
	current, found := LookupAuthorizationProfile(ProductIAM)
	if !found || current.Revision < 4 {
		t.Fatal("missing current IAM role-session declaration")
	}
	for _, action := range current.Actions {
		if !slices.Equal(action.SubjectTypes, []SubjectType{SubjectUser}) {
			t.Fatal("role management or assumption accepts a non-USER caller")
		}
	}
}

func TestRoleSessionAdministrationDoesNotReinterpretRegisteredProfiles(t *testing.T) {
	archives := HistoricalAuthorizationProfiles()
	index := slices.IndexFunc(archives, func(profile AuthorizationProfile) bool { return profile.Product == ProductIAM && profile.Revision == 3 })
	if index < 0 {
		t.Fatal("missing original STS declaration")
	}
	_, digest, err := CanonicalizeAuthorizationProfile(archives[index])
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256:b6556c9b8f8f6978c67c1ffa6a32f51dec13d21dbac656779fd1d0a78dc0ce63" {
		t.Fatal("registered IAM r3 bytes changed")
	}
	for _, action := range archives[index].Actions {
		if action.Action == ActionIAMRoleSessionList || action.Action == ActionIAMRoleSessionRead || action.Action == ActionIAMRoleSessionRevoke {
			t.Fatal("archive gained administrator actions")
		}
	}
	current, _ := LookupAuthorizationProfile(ProductIAM)
	_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
	if err != nil {
		t.Fatal(err)
	}
	ref := AuthorizationProfileReference{Product: ProductIAM, Revision: current.Revision, ContentDigest: currentDigest}
	for action, target := range map[Action]ResourceKind{ActionIAMRoleSessionList: ResourceRole, ActionIAMRoleSessionRead: ResourceRoleSession, ActionIAMRoleSessionRevoke: ResourceRoleSession} {
		request, err := NewAuthorizationRequest(action, ResourceReference{Kind: target, ID: "exact"}, AuthorizationResourceInstance, "", "request-a", "correlation-a")
		if err != nil || ValidateAuthorizationRequest(request) != nil {
			t.Fatal("missing exact management action", err)
		}
		if _, err := NewAuthorizationRequest(action, request.Resource, AuthorizationResourceCollection, AuthorizationCollectionList, "request-a", "correlation-a"); err == nil {
			t.Fatal("management accepted a collection")
		}
		if CheckAuthorizationProfileSubject(current, ref, action, SubjectUser) != nil || CheckAuthorizationProfileSubject(current, ref, action, SubjectRole) == nil ||
			CheckAuthorizationProfileSubject(current, ref, action, SubjectServiceAccount) == nil {
			t.Fatal("management crossed the USER boundary")
		}
	}
}

func TestRoleBusinessProfilesRequireExplicitCurrentCapabilities(t *testing.T) {
	for product, digest := range map[ProductID]string{
		ProductPaaS:  "sha256:f2409682d451b564cbd55b2b315543c2f4b333e3f027f3b4377b103ecc1e2876",
		ProductAudit: "sha256:6bae9c16c05ad781662190c02ab2adb1e552ef2889c0a05d78de7d4553147052",
	} {
		archives := HistoricalAuthorizationProfiles()
		index := slices.IndexFunc(archives, func(profile AuthorizationProfile) bool { return profile.Product == product && profile.Revision == 1 })
		if index < 0 {
			t.Fatal("missing previously registered product")
		}
		_, original, err := CanonicalizeAuthorizationProfile(archives[index])
		if err != nil || original != digest {
			t.Fatal("registered product bytes changed")
		}
		current, found := LookupAuthorizationProfile(product)
		if !found || current.Revision != 2 {
			t.Fatal("missing explicit new product revision")
		}
		_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
		if err != nil || currentDigest == original {
			t.Fatal("subject capability change did not change commitment")
		}
		for _, action := range current.Actions {
			ref := AuthorizationProfileReference{Product: product, Revision: current.Revision, ContentDigest: currentDigest}
			if CheckAuthorizationProfileSubject(current, ref, action.Action, SubjectUser) != nil ||
				(CheckAuthorizationProfileSubject(current, ref, action.Action, SubjectRole) == nil) != (action.Scope == AuthorityScopeTenant) ||
				CheckAuthorizationProfileSubject(current, ref, action.Action, SubjectServiceAccount) == nil {
				t.Fatal("product granted an undeclared subject capability", action.Action)
			}
			old := AuthorizationProfileReference{Product: product, Revision: 1, ContentDigest: original}
			if CheckAuthorizationProfileSubject(archives[index], old, action.Action, SubjectRole) == nil ||
				CheckAuthorizationProfileSubject(archives[index], old, action.Action, SubjectUser) != nil {
				t.Fatal("old declaration gained ROLE or lost USER semantics")
			}
		}
	}
}

func sampleRoleTrustDocument() TrustPolicyDocument {
	return TrustPolicyDocument{LanguageVersion: TrustPolicyLanguageVersion, Statements: []TrustPolicyStatement{
		{SID: "z-allow", Effect: PolicyAllow, Principals: []TrustPrincipal{{Type: PrincipalUser, ID: "user-b"}, {Type: PrincipalUser, ID: "user-a"}}},
		{SID: "a-deny", Effect: PolicyDeny, Principals: []TrustPrincipal{{Type: PrincipalUser, ID: "user-a"}}},
	}}
}

func TestRoleTrustCanonicalCommitmentIsBoundedAndPurposeSeparated(t *testing.T) {
	document := sampleRoleTrustDocument()
	before, _ := json.Marshal(document)
	canonical, digest, err := CanonicalizeTrustPolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(document)
	if !bytes.Equal(before, after) {
		t.Fatal("canonicalization changed caller-owned trust slices")
	}
	copy, err := DecodeTrustPolicyDocument(strings.NewReader(canonical))
	if err != nil || copy.Statements[0].SID != "a-deny" || copy.Statements[1].Principals[0].ID != "user-a" {
		t.Fatal("trust content did not round-trip in canonical order")
	}
	slices.Reverse(copy.Statements)
	slices.Reverse(copy.Statements[0].Principals)
	other, otherDigest, err := CanonicalizeTrustPolicyDocument(copy)
	if err != nil || other != canonical || otherDigest != digest {
		t.Fatal("set ordering changed the trust commitment")
	}
	expected := sha256.Sum256(append([]byte("matrix.iam.role-trust.v1\x00"), []byte(canonical)...))
	policyPurpose := sha256.Sum256(append([]byte("matrix.iam.policy.v1\x00"), []byte(canonical)...))
	if digest != "sha256:"+hex.EncodeToString(expected[:]) || expected == policyPurpose {
		t.Fatal("trust commitment lost its distinct content purpose")
	}
	copy.Statements[0].Effect = PolicyDeny
	_, changedDigest, err := CanonicalizeTrustPolicyDocument(copy)
	if err != nil || changedDigest == digest {
		t.Fatal("changing an effect retained the old content commitment")
	}
	empty := TrustPolicyDocument{LanguageVersion: TrustPolicyLanguageVersion, Statements: []TrustPolicyStatement{}}
	emptyCanonical, _, err := CanonicalizeTrustPolicyDocument(empty)
	if err != nil || emptyCanonical != `{"languageVersion":"1","statements":[]}` {
		t.Fatal("explicit empty trust was lost or rewritten as null")
	}
}

func TestRoleTrustStrictDecoderRejectsAuthoritySelectorsAndAmbiguity(t *testing.T) {
	valid := `{"languageVersion":"1","statements":[{"sid":"read-carrier","effect":"ALLOW","principals":[{"type":"USER","id":"stable-user"}]}]}`
	for name, wire := range map[string]string{
		"missing statements":     `{"languageVersion":"1"}`,
		"null statements":        `{"languageVersion":"1","statements":null}`,
		"missing version":        `{"statements":[]}`,
		"null":                   `null`,
		"wrong version":          strings.Replace(valid, `"1"`, `"2"`, 1),
		"duplicate version":      strings.Replace(valid, `"languageVersion":"1"`, `"languageVersion":"1","languageVersion":"1"`, 1),
		"case fallback":          strings.Replace(valid, `"languageVersion"`, `"LanguageVersion"`, 1),
		"account selector":       strings.Replace(valid, `"statements"`, `"accountId":"other","statements"`, 1),
		"tenant selector":        strings.Replace(valid, `"statements"`, `"tenantId":"other","statements"`, 1),
		"permission scope":       strings.Replace(valid, `"statements"`, `"scope":"TENANT","statements"`, 1),
		"permission actions":     strings.Replace(valid, `"sid"`, `"actions":["iam.role.assume"],"sid"`, 1),
		"permission resources":   strings.Replace(valid, `"sid"`, `"resources":[],"sid"`, 1),
		"caller conditions":      strings.Replace(valid, `"sid"`, `"conditions":[],"sid"`, 1),
		"service":                strings.Replace(valid, `"USER"`, `"SERVICE_ACCOUNT"`, 1),
		"group":                  strings.Replace(valid, `"USER"`, `"GROUP"`, 1),
		"role":                   strings.Replace(valid, `"USER"`, `"ROLE"`, 1),
		"root discriminator":     strings.Replace(valid, `"USER"`, `"ROOT"`, 1),
		"wildcard":               strings.Replace(valid, `"stable-user"`, `"*"`, 1),
		"realm":                  strings.Replace(valid, `"stable-user"`, `"member@account"`, 1),
		"null identity":          strings.Replace(valid, `"stable-user"`, `null`, 1),
		"identity scope":         strings.Replace(valid, `"type":"USER"`, `"accountId":"other","type":"USER"`, 1),
		"duplicate identity":     strings.Replace(valid, `"id":"stable-user"`, `"id":"stable-user","id":"different"`, 1),
		"identity case fallback": strings.Replace(valid, `"type"`, `"Type"`, 1),
		"missing principals":     `{"languageVersion":"1","statements":[{"sid":"allow","effect":"ALLOW"}]}`,
		"null principals":        `{"languageVersion":"1","statements":[{"sid":"allow","effect":"ALLOW","principals":null}]}`,
		"empty principals":       `{"languageVersion":"1","statements":[{"sid":"allow","effect":"ALLOW","principals":[]}]}`,
		"trailing document":      valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			decoded, err := DecodeTrustPolicyDocument(strings.NewReader(wire))
			if !errors.Is(err, ErrInvalidTrustPolicy) || !reflect.DeepEqual(decoded, TrustPolicyDocument{}) {
				t.Fatal("invalid trust was not rejected with a sanitized empty result")
			}
			prior := sampleRoleTrustDocument()
			before, _ := json.Marshal(prior)
			if json.Unmarshal([]byte(wire), &prior) == nil {
				t.Fatal("ordinary nested JSON decode bypassed trust validation")
			}
			after, _ := json.Marshal(prior)
			if !bytes.Equal(before, after) {
				t.Fatal("failed trust decode partially replaced the destination")
			}
		})
	}
	// IDs are syntax, not a namespace convention. Even a valid looking ID must
	// later be resolved to a real same-account USER under the transaction lock.
	for _, id := range []string{"original-primary", "service-looking-id", "role-looking-id"} {
		document, err := DecodeTrustPolicyDocument(strings.NewReader(strings.Replace(valid, "stable-user", id, 1)))
		if err != nil || document.Statements[0].Principals[0].ID != PrincipalID(id) {
			t.Fatal("contract tried to infer account or principal type from an ID prefix")
		}
	}
	var identityPolicy PolicyDocument
	if DecodeRequest(strings.NewReader(valid), &identityPolicy) == nil {
		t.Fatal("identity policy decoder accepted a role trust document")
	}
}

func TestRoleTrustBudgetsAndImmutableVersionBinding(t *testing.T) {
	// Reader boundaries include whitespace. encoding/json alone strips outer
	// whitespace before UnmarshalJSON and is not a replacement for this limit.
	emptyWire := `{"languageVersion":"1","statements":[]}`
	exactWire := emptyWire + strings.Repeat(" ", int(MaxTrustPolicyBytes)-len(emptyWire))
	if _, err := DecodeTrustPolicyDocument(strings.NewReader(exactWire)); err != nil {
		t.Fatal("exact input byte budget was rejected")
	}
	if _, err := DecodeTrustPolicyDocument(strings.NewReader(exactWire + " ")); !errors.Is(err, ErrInvalidTrustPolicy) {
		t.Fatal("wire byte budget was bypassed with trailing whitespace")
	}
	document := TrustPolicyDocument{LanguageVersion: TrustPolicyLanguageVersion, Statements: make([]TrustPolicyStatement, MaxTrustPolicyStatements)}
	for index := range document.Statements {
		statement := &document.Statements[index]
		statement.SID, statement.Effect = fmt.Sprintf("statement-%d", index), PolicyAllow
		for principal := range MaxTrustStatementPrincipals {
			statement.Principals = append(statement.Principals, TrustPrincipal{Type: PrincipalUser, ID: PrincipalID(fmt.Sprintf("user-%d", principal))})
		}
	}
	if ValidateTrustPolicyDocument(document) != nil {
		t.Fatal("valid bounded full trust document was rejected")
	}
	for name, change := range map[string]func(*TrustPolicyDocument){
		"nil statements":     func(v *TrustPolicyDocument) { v.Statements = nil },
		"statement overflow": func(v *TrustPolicyDocument) { v.Statements = append(v.Statements, v.Statements[0]) },
		"principal overflow": func(v *TrustPolicyDocument) {
			v.Statements[0].Principals = append(v.Statements[0].Principals, TrustPrincipal{Type: PrincipalUser, ID: "one-more"})
		},
		"duplicate SID":       func(v *TrustPolicyDocument) { v.Statements[1].SID = v.Statements[0].SID },
		"duplicate principal": func(v *TrustPolicyDocument) { v.Statements[0].Principals[1] = v.Statements[0].Principals[0] },
		"unbounded bytes": func(v *TrustPolicyDocument) {
			for i := range v.Statements {
				for j := range v.Statements[i].Principals {
					v.Statements[i].Principals[j].ID = PrincipalID(fmt.Sprintf("u%03d", j) + strings.Repeat("a", 124))
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, _ := json.Marshal(document)
			copy, _ := DecodeTrustPolicyDocument(bytes.NewReader(encoded))
			change(&copy)
			if ValidateTrustPolicyDocument(copy) == nil {
				t.Fatal("invalid trust budget or duplicate accepted")
			}
			canonical, digest, err := CanonicalizeTrustPolicyDocument(copy)
			if !errors.Is(err, ErrInvalidTrustPolicy) || canonical != "" || digest != "" {
				t.Fatal("invalid trust acquired a canonical commitment")
			}
		})
	}
	document = sampleRoleTrustDocument()
	_, digest, _ := CanonicalizeTrustPolicyDocument(document)
	version := RoleTrustVersion{APIVersion: APIVersion, Kind: "RoleTrustVersion", ID: "trust-version-a", AccountID: "account-a", RoleID: "role-a",
		Document: document, ContentDigest: digest, CreatedAt: time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)}
	encoded, _ := json.Marshal(version)
	read, err := DecodeRoleTrustVersion(bytes.NewReader(encoded))
	if err != nil || !reflect.DeepEqual(read, version) {
		t.Fatal("immutable trust version failed strict content round-trip")
	}
	for name, change := range map[string]func(*RoleTrustVersion){
		"missing account":          func(v *RoleTrustVersion) { v.AccountID = "" },
		"missing role":             func(v *RoleTrustVersion) { v.RoleID = "" },
		"missing version":          func(v *RoleTrustVersion) { v.ID = "" },
		"wrong kind":               func(v *RoleTrustVersion) { v.Kind = "PolicyVersion" },
		"changed content":          func(v *RoleTrustVersion) { v.Document.Statements[0].Effect = PolicyDeny },
		"changed digest":           func(v *RoleTrustVersion) { v.ContentDigest = "sha256:" + strings.Repeat("0", 64) },
		"non UTC timestamp":        func(v *RoleTrustVersion) { v.CreatedAt = v.CreatedAt.In(time.FixedZone("offset", 3600)) },
		"submicrosecond timestamp": func(v *RoleTrustVersion) { v.CreatedAt = v.CreatedAt.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			copy, _ := DecodeRoleTrustVersion(bytes.NewReader(encoded))
			change(&copy)
			if ValidateRoleTrustVersion(copy) == nil {
				t.Fatal("incomplete or mismatched immutable trust version accepted")
			}
		})
	}
	withPermit := strings.Replace(string(encoded), `"kind":"RoleTrustVersion"`, `"kind":"RoleTrustVersion","permit":true`, 1)
	if _, err := DecodeRoleTrustVersion(strings.NewReader(withPermit)); err == nil {
		t.Fatal("trust version accepted a permit extension")
	}
}

func currentAuthorizationProfileList(t *testing.T) AuthorizationProfileList {
	t.Helper()
	value := AuthorizationProfileList{APIVersion: APIVersion, Kind: "AuthorizationProfileList", AccountID: "account-catalog"}
	for _, profile := range AllAuthorizationProfiles() {
		_, digest, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		value.Items = append(value.Items, AuthorizationProfileEntry{Profile: profile, ContentDigest: digest})
	}
	slices.SortFunc(value.Items, func(left, right AuthorizationProfileEntry) int {
		return strings.Compare(string(left.Profile.Product), string(right.Profile.Product))
	})
	return value
}

func TestAuthorizationProfileListCommitmentsAndWholeResponseBudget(t *testing.T) {
	value := currentAuthorizationProfileList(t)
	encoded, err := json.Marshal(value)
	if err != nil || ValidateAuthorizationProfileList(value) != nil || int64(len(encoded)) > MaxRequestBytes {
		t.Fatal("current complete product directory exceeds its response contract")
	}
	t.Logf("complete current product directory: %d products, %d bytes", len(value.Items), len(encoded))
	decoded, err := DecodeAuthorizationProfileList(bytes.NewReader(encoded))
	if err != nil || !reflect.DeepEqual(value, decoded) {
		t.Fatal("current product directory did not round trip")
	}
	for _, mutate := range []func(*AuthorizationProfileList){
		func(v *AuthorizationProfileList) { v.Kind = "PolicyList" },
		func(v *AuthorizationProfileList) { v.AccountID = "" },
		func(v *AuthorizationProfileList) { v.Items = nil },
		func(v *AuthorizationProfileList) { v.Items = []AuthorizationProfileEntry{} },
		func(v *AuthorizationProfileList) { v.Items[0], v.Items[1] = v.Items[1], v.Items[0] },
		func(v *AuthorizationProfileList) { v.Items = append(v.Items, v.Items[0]) },
		func(v *AuthorizationProfileList) { v.Items[0].ContentDigest = "sha256:" + strings.Repeat("0", 64) },
		func(v *AuthorizationProfileList) { v.Items[0].Profile.Actions[0].ResourceKind = "FORGED" },
		func(v *AuthorizationProfileList) {
			v.Items = make([]AuthorizationProfileEntry, MaxAuthorizationProfileListItems+1)
		},
	} {
		candidate, _ := DecodeAuthorizationProfileList(bytes.NewReader(encoded))
		mutate(&candidate)
		if ValidateAuthorizationProfileList(candidate) == nil {
			t.Fatal("directory accepted an incomplete, ambiguous or altered commitment")
		}
	}
	for _, body := range []string{
		string(encoded) + `{}`,
		strings.Repeat(" ", int(MaxRequestBytes)) + string(encoded),
		strings.Replace(string(encoded), `"items":`, `"permit":true,"items":`, 1),
		strings.Replace(string(encoded), `"items":`, `"items":[],"items":`, 1),
		strings.Replace(string(encoded), `"contentDigest":`, `"callingService":"FORGED","contentDigest":`, 1),
		strings.Replace(string(encoded), `"accountId":`, `"AccountId":"forged","accountId":`, 1),
	} {
		if _, err := DecodeAuthorizationProfileList(strings.NewReader(body)); err == nil {
			t.Fatal("directory decoder accepted an unknown field, ambiguity or unbounded response")
		}
	}
	// Legitimate individual declarations can collectively exceed the ordinary
	// wire budget. Reject the whole response; never truncate its product set.
	value.Items = nil
	for index := 0; index < MaxAuthorizationProfileListItems; index++ {
		profile, _ := LookupAuthorizationProfile(ProductIAM)
		profile.Product = ProductID(fmt.Sprintf("product-%02d", index))
		for actionIndex := range profile.Actions {
			_, suffix, _ := strings.Cut(string(profile.Actions[actionIndex].Action), ".")
			profile.Actions[actionIndex].Action = Action(string(profile.Product) + "." + suffix)
		}
		_, digest, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			t.Fatal("whole-budget fixture must contain individually valid profiles")
		}
		value.Items = append(value.Items, AuthorizationProfileEntry{Profile: profile, ContentDigest: digest})
	}
	oversized, _ := json.Marshal(value)
	if int64(len(oversized)) <= MaxRequestBytes || ValidateAuthorizationProfileList(value) == nil {
		t.Fatal("per-profile limits replaced the complete response budget")
	}
}

func TestAuthorizationProfileTargetsUseExplicitDeclaredModes(t *testing.T) {
	for _, profile := range AllAuthorizationProfiles() {
		before, digest, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		reference := AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}
		for _, declared := range profile.Actions {
			t.Run(string(declared.Action), func(t *testing.T) {
				for _, candidate := range []AuthorizationResourceShape{
					{Mode: AuthorizationResourceInstance},
					{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList},
					{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate},
					{Mode: AuthorizationResourceCollection},
					{Mode: AuthorizationResourceInstance, CollectionUsage: AuthorizationCollectionList},
					{Mode: "FILTERED", CollectionUsage: AuthorizationCollectionList},
					{},
				} {
					for _, id := range []string{"real-instance", "collection", "records", "chain", ""} {
						want := false
						for _, shape := range declared.ResourceShapes {
							if shape.Mode == candidate.Mode && shape.CollectionUsage == candidate.CollectionUsage {
								want = id != "" && (shape.Mode == AuthorizationResourceInstance || id == "collection")
							}
						}
						resource := ResourceReference{Kind: declared.ResourceKind, ID: id}
						actual := CheckAuthorizationProfileTarget(profile, reference, declared.Action, resource, candidate.Mode, candidate.CollectionUsage)
						if (actual == nil) != want {
							t.Fatalf("mode=%s usage=%s id=%q accepted=%t want=%t", candidate.Mode, candidate.CollectionUsage, id, actual == nil, want)
						}
						resource.Kind = ResourceKind("UNDECLARED")
						if CheckAuthorizationProfileTarget(profile, reference, declared.Action, resource, candidate.Mode, candidate.CollectionUsage) == nil {
							t.Fatal("wrong resource kind borrowed a declared mode")
						}
					}
				}
				shape := declared.ResourceShapes[0]
				resource := ResourceReference{Kind: declared.ResourceKind, ID: "collection"}
				for _, wrong := range []AuthorizationProfileReference{
					{},
					{Product: "other-product", Revision: reference.Revision, ContentDigest: reference.ContentDigest},
					{Product: reference.Product, Revision: reference.Revision + 1, ContentDigest: reference.ContentDigest},
					{Product: reference.Product, Revision: reference.Revision, ContentDigest: "sha256:" + strings.Repeat("0", 64)},
				} {
					if CheckAuthorizationProfileTarget(profile, wrong, declared.Action, resource, shape.Mode, shape.CollectionUsage) == nil {
						t.Fatal("target admitted without its exact declaration")
					}
				}
				if CheckAuthorizationProfileTarget(profile, reference, "unregistered.inspect", resource, shape.Mode, shape.CollectionUsage) == nil {
					t.Fatal("unregistered action borrowed a known resource shape")
				}
			})
		}
		after, afterDigest, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil || before != after || digest != afterDigest {
			t.Fatal("target validation modified immutable declaration content")
		}
	}
}

func TestProfileBoundAuthorizationRequestAndResponse(t *testing.T) {
	request, err := NewAuthorizationRequest(ActionPaaSApplicationRead, ResourceReference{Kind: ResourceApplication, ID: "collection"}, AuthorizationResourceInstance, "", "request-one", "correlation-one")
	if err != nil {
		t.Fatal(err)
	}
	for _, allowed := range []bool{false, true} {
		decision := AuthorizationDecision{APIVersion: APIVersion, Kind: "AuthorizationDecision", ID: "decision-one",
			Allowed: allowed, Reason: DecisionDenied, Action: request.Action, Resource: request.Resource,
			Profile: &request.Profile, ResourceMode: request.ResourceMode, RequestID: request.RequestID,
			CorrelationID: request.CorrelationID, DecidedAt: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)}
		if allowed {
			decision.Reason, decision.TenantID = DecisionAllowed, "account-one"
			decision.Subject = &Subject{Type: SubjectUser, ID: "user-one"}
		}
		if err := CheckAuthorizationDecisionForRequest(decision, request); err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func(*AuthorizationDecision){
			"profile missing": func(value *AuthorizationDecision) { value.Profile = nil },
			"profile version": func(value *AuthorizationDecision) {
				copy := *value.Profile
				copy.Revision++
				value.Profile = &copy
			},
			"resource":    func(value *AuthorizationDecision) { value.Resource.ID = "another-instance" },
			"mode":        func(value *AuthorizationDecision) { value.ResourceMode = AuthorizationResourceCollection },
			"usage":       func(value *AuthorizationDecision) { value.CollectionUsage = AuthorizationCollectionList },
			"request":     func(value *AuthorizationDecision) { value.RequestID = "other-request" },
			"correlation": func(value *AuthorizationDecision) { value.CorrelationID = "other-correlation" },
		} {
			t.Run(fmt.Sprintf("allowed=%t/%s", allowed, name), func(t *testing.T) {
				changed := decision
				mutate(&changed)
				if CheckAuthorizationDecisionForRequest(changed, request) == nil {
					t.Fatal("response did not bind the full original request")
				}
			})
		}
		legacy := decision
		legacy.Profile, legacy.ResourceMode, legacy.CollectionUsage, legacy.CorrelationID = nil, "", "", ""
		if ValidateAuthorizationDecision(legacy) == nil || ValidateLegacyAuthorizationDecision(legacy) != nil {
			t.Fatal("legacy evidence was either admitted online or lost its explicit read-only validator")
		}
		legacy.CorrelationID = request.CorrelationID
		if ValidateLegacyAuthorizationDecision(legacy) == nil {
			t.Fatal("partial new fields were admitted as legacy")
		}
		encoded, _ := json.Marshal(decision)
		var fields map[string]json.RawMessage
		if json.Unmarshal(encoded, &fields) != nil {
			t.Fatal("decode response fixture")
		}
		for _, field := range []string{"profile", "resourceMode", "correlationId"} {
			changed := make(map[string]json.RawMessage, len(fields))
			for key, value := range fields {
				changed[key] = value
			}
			delete(changed, field)
			raw, _ := json.Marshal(changed)
			var parsed AuthorizationDecision
			if DecodeRequest(bytes.NewReader(raw), &parsed) == nil && ValidateAuthorizationDecision(parsed) == nil {
				t.Fatalf("current response accepted missing %s", field)
			}
		}
	}
	for _, mode := range []AuthorizationResourceMode{"", "BATCH", AuthorizationResourceCollection} {
		if _, err := NewAuthorizationRequest(request.Action, request.Resource, mode, "", request.RequestID, request.CorrelationID); err == nil {
			t.Fatal("constructor inferred a mode or accepted undeclared usage")
		}
	}
}

func TestAuthorizationEncodingRejectsPartialAndPresentEmptyBindings(t *testing.T) {
	for _, shape := range []AuthorizationResourceShape{
		{Mode: AuthorizationResourceInstance},
		{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList},
	} {
		request, err := NewAuthorizationRequest(ActionIAMAccountRead, ResourceReference{Kind: ResourceAccount, ID: "collection"}, shape.Mode, shape.CollectionUsage, "request-encoding", "correlation-encoding")
		if err != nil {
			t.Fatal(err)
		}
		decision := AuthorizationDecision{APIVersion: APIVersion, Kind: "AuthorizationDecision", ID: "decision-encoding", Reason: DecisionDenied,
			Action: request.Action, Resource: request.Resource, Profile: &request.Profile, ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage,
			RequestID: request.RequestID, CorrelationID: request.CorrelationID, DecidedAt: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)}
		for _, input := range []any{request, decision} {
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"profile", "resourceMode", "correlationId", "collectionUsage"} {
				for _, raw := range []json.RawMessage{json.RawMessage("null"), json.RawMessage(`""`)} {
					var document map[string]json.RawMessage
					if json.Unmarshal(encoded, &document) != nil {
						t.Fatal("invalid baseline")
					}
					document[key] = raw
					changed, _ := json.Marshal(document)
					var err error
					if _, ok := input.(AuthorizationRequest); ok {
						var decoded AuthorizationRequest
						err = DecodeRequest(bytes.NewReader(changed), &decoded)
						if err == nil {
							err = ValidateAuthorizationRequest(decoded)
						}
					} else {
						var decoded AuthorizationDecision
						err = DecodeRequest(bytes.NewReader(changed), &decoded)
						if err == nil {
							err = ValidateAuthorizationDecision(decoded)
						}
					}
					if err == nil {
						t.Fatalf("%T/%s accepted %s=%s", input, shape.Mode, key, raw)
					}
				}
			}
		}
	}
}

func TestHistoricalDecisionProfileDoesNotBorrowCurrentHead(t *testing.T) {
	profile, _ := LookupAuthorizationProfile(ProductAudit)
	for index := range profile.Actions {
		profile.Actions[index].ResourceShapes = []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}
	}
	profile.Revision++
	_, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	decision := AuthorizationDecision{APIVersion: APIVersion, Kind: "AuthorizationDecision", ID: "historical-one",
		Reason: DecisionDenied, Action: ActionAuditIntegrityVerify, Resource: ResourceReference{Kind: ResourceAuditChain, ID: "frozen-instance"},
		Profile:      &AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest},
		ResourceMode: AuthorizationResourceInstance, RequestID: "request-one", CorrelationID: "correlation-one",
		DecidedAt: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)}
	if ValidateAuthorizationDecisionForProfile(decision, profile) != nil || ValidateAuthorizationDecision(decision) == nil || ValidateLegacyAuthorizationDecision(decision) == nil {
		t.Fatal("frozen evidence borrowed current collection meaning or became legacy")
	}
	current, _ := LookupAuthorizationProfile(ProductAudit)
	if ValidateAuthorizationDecisionForProfile(decision, current) == nil {
		t.Fatal("historical validator selected current head instead of exact supplied content")
	}
}

func TestPaaSProfileDeclaresCompletePlatformProduct(t *testing.T) {
	profile, found := LookupAuthorizationProfile(ProductPaaS)
	if !found || profile.Revision != 2 {
		t.Fatal("missing current PaaS role-capable declaration")
	}
	expected := map[Action]struct {
		kind       ResourceKind
		collection AuthorizationCollectionUsage
		instance   bool
		result     ResourceKind
	}{
		"paas.execution-pool.create":      {ResourceExecutionPool, "", true, ResourceExecutionPool},
		"paas.execution-pool.read":        {ResourceExecutionPool, AuthorizationCollectionList, true, ""},
		"paas.execution-target.register":  {ResourceExecutionTarget, "", true, ResourceExecutionTarget},
		"paas.execution-target.read":      {ResourceExecutionTarget, AuthorizationCollectionList, true, ""},
		"paas.execution-target.drain":     {ResourceExecutionTarget, "", true, ""},
		"paas.execution-target.activate":  {ResourceExecutionTarget, "", true, ""},
		"paas.execution-target.remove":    {ResourceExecutionTarget, "", true, ""},
		"paas.node-enrollment.create":     {"NODE_ENROLLMENT", AuthorizationCollectionCreate, false, ResourceExecutionTarget},
		"paas.node-enrollment.read":       {"NODE_ENROLLMENT", "", true, ""},
		"paas.node-enrollment.revoke":     {"NODE_ENROLLMENT", "", true, ""},
		"paas.node-enrollment.regenerate": {"NODE_ENROLLMENT", "", true, ""},
		"paas.platform-operation.read":    {ResourceOperation, "", true, ""},
	}
	for _, action := range profile.Actions {
		if action.Scope != AuthorityScopeInstallation {
			continue
		}
		want, ok := expected[action.Action]
		if !ok || action.ResourceKind != want.kind || action.ResultResourceKind != want.result || len(action.Conditions) != 0 {
			t.Fatalf("unexpected platform declaration: %s", action.Action)
		}
		instance, collection := false, AuthorizationCollectionUsage("")
		for _, shape := range action.ResourceShapes {
			if shape.PrefixAllowed {
				t.Fatal("platform action gained prefix permission")
			}
			if shape.Mode == AuthorizationResourceInstance {
				instance = true
			} else {
				collection = shape.CollectionUsage
			}
		}
		definition, known := LookupActionDefinition(action.Action)
		if !known || definition.CallingService != ServicePaaS || definition.ResourceKind != want.kind ||
			definition.AuthorityScope != AuthorityScopeInstallation || instance != want.instance || collection != want.collection {
			t.Fatalf("platform request shape or caller drift: %s", action.Action)
		}
		delete(expected, action.Action)
	}
	if len(expected) != 0 {
		t.Fatalf("platform product is missing declarations: %v", expected)
	}
	_, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil || CheckAuthorizationProfileReference(profile, AuthorizationProfileReference{Product: ProductPaaS, Revision: profile.Revision + 1, ContentDigest: digest}) == nil {
		t.Fatal("numerically newer revision was treated as an exact reference")
	}
}

func TestAuditProfileDeclaresAuthorityWideReadAndVerification(t *testing.T) {
	profile, found := LookupAuthorizationProfile(ProductAudit)
	if !found || profile.Revision != 2 || profile.CallingService != ServiceAudit {
		t.Fatal("invalid current Audit role-capable declaration")
	}
	expected := map[Action]struct {
		kind  ResourceKind
		scope AuthorityScope
	}{
		ActionAuditRecordRead:              {ResourceAuditRecord, AuthorityScopeTenant},
		ActionAuditIntegrityVerify:         {ResourceAuditChain, AuthorityScopeTenant},
		ActionAuditPlatformRecordRead:      {ResourceAuditRecord, AuthorityScopeInstallation},
		ActionAuditPlatformIntegrityVerify: {ResourceAuditChain, AuthorityScopeInstallation},
	}
	for _, action := range profile.Actions {
		want, exists := expected[action.Action]
		if !exists || action.ResourceKind != want.kind || action.Scope != want.scope || action.ResultResourceKind != "" ||
			len(action.ResourceShapes) != 1 || action.ResourceShapes[0] != (AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}) {
			t.Fatal("Audit complete-chain verification cannot select a caller-chosen instance")
		}
		delete(expected, action.Action)
	}
	if len(expected) != 0 {
		t.Fatal("Audit declaration omitted an authority-wide read action")
	}
}

func TestProductProfilesOwnCurrentAdmissionAndDoNotExposeMutableState(t *testing.T) {
	profiles := AllAuthorizationProfiles()
	seen := map[Action]bool{}
	for _, profile := range profiles {
		document, digest, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range profile.Actions {
			if seen[declaration.Action] {
				t.Fatal("action belongs to multiple products")
			}
			seen[declaration.Action] = true
			definition, known := LookupActionDefinition(declaration.Action)
			if !known || definition.Product != profile.Product || definition.CallingService != profile.CallingService || definition.ResourceKind != declaration.ResourceKind || definition.AuthorityScope != declaration.Scope {
				t.Fatal("current admission diverged from the owning profile")
			}
			for _, condition := range declaration.Conditions {
				actual, known := LookupActionConditionDefinition(declaration.Action, condition.Key)
				if !known || actual.ValueType != condition.ValueType || actual.Source != condition.Source {
					t.Fatal("condition capability diverged from its profile")
				}
			}
		}
		copy, known := LookupAuthorizationProfile(profile.Product)
		if !known {
			t.Fatal("declared product cannot be read")
		}
		copy.CallingService = "FORGED"
		copy.Actions[0].ResourceShapes[0].Mode = "FORGED"
		copy.Actions[0].Action = "forged.action"
		for index := range copy.Actions {
			if len(copy.Actions[index].Conditions) > 0 {
				copy.Actions[index].Conditions[0].Source = "CALLER"
			}
		}
		fresh, known := LookupAuthorizationProfile(profile.Product)
		freshDocument, freshDigest, err := CanonicalizeAuthorizationProfile(fresh)
		if !known || err != nil || freshDocument != document || freshDigest != digest {
			t.Fatal("lookup exposed mutable catalog storage", err)
		}
	}
	for _, action := range AllActions() {
		if !seen[action] {
			t.Fatal("current action lacks a product declaration", action)
		}
	}
	if len(seen) != len(AllActions()) {
		t.Fatal("declaration includes an unregistered action")
	}
	profiles[0].Actions[0].Action = "forged.action"
	if actual, known := LookupActionDefinition(ActionIAMAccountCreate); !known || actual.Action != ActionIAMAccountCreate {
		t.Fatal("returned profile changed runtime admission")
	}
	if _, known := LookupAuthorizationProfile("not-registered"); known {
		t.Fatal("unknown product was guessed")
	}
}

func TestProductProfilesDeclareParentInstanceAndCollectionResults(t *testing.T) {
	for _, item := range []struct {
		action           Action
		resource, result ResourceKind
		modes            []AuthorizationResourceShape
	}{
		{ActionIAMUserCreate, ResourceAccount, ResourceUser, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionIAMGroupCreate, ResourceAccount, ResourceGroup, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionIAMPolicyCreate, ResourceAccount, ResourcePolicy, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionIAMGroupMembershipCreate, ResourceGroup, ResourceGroupMembership, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionIAMAccountRead, ResourceAccount, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}},
		{ActionPaaSApplicationCreate, ResourceApplication, ResourceApplication, []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}},
		{ActionPaaSApplicationRead, ResourceApplication, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance, PrefixAllowed: true}}},
		{ActionPaaSExecutionPoolCreate, ResourceExecutionPool, ResourceExecutionPool, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionPaaSExecutionTargetRegister, ResourceExecutionTarget, ResourceExecutionTarget, []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}},
		{ActionPaaSExecutionPoolRead, ResourceExecutionPool, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}},
		{ActionPaaSExecutionTargetRead, ResourceExecutionTarget, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}},
		{ActionManagedServiceOfferingRead, ResourceServiceOffering, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}},
	} {
		t.Run(string(item.action), func(t *testing.T) {
			definition, known := LookupActionDefinition(item.action)
			if !known {
				t.Fatal("missing current action")
			}
			profile, known := LookupAuthorizationProfile(definition.Product)
			if !known {
				t.Fatal("missing product")
			}
			for _, action := range profile.Actions {
				if action.Action != item.action {
					continue
				}
				if action.ResourceKind != item.resource || action.ResultResourceKind != item.result || len(action.ResourceShapes) != len(item.modes) {
					t.Fatal("incorrect authorization versus successful resource mapping", action)
				}
				for _, want := range item.modes {
					found := false
					for _, got := range action.ResourceShapes {
						if want == got {
							found = true
						}
					}
					if !found {
						t.Fatal("missing proved target shape", want)
					}
				}
				return
			}
			t.Fatal("action absent from declared product")
		})
	}
	// A child/result kind is not an alternative authorization target.
	request, err := NewAuthorizationRequest(ActionIAMUserCreate, ResourceReference{Kind: ResourceAccount, ID: "account-one"}, AuthorizationResourceInstance, "", "request-one", "request-one")
	if err != nil || ValidateAuthorizationRequest(request) != nil {
		t.Fatal(err)
	}
	request.Resource = ResourceReference{Kind: ResourceUser, ID: "user-child"}
	if ValidateAuthorizationRequest(request) == nil {
		t.Fatal("result resource widened parent authorization")
	}
}

func TestProductProjectionIsIndependentOfProductName(t *testing.T) {
	profile := authorizationProfileFixture()
	profile.Product, profile.CallingService, profile.Actions[0].Action = "observability", "OBSERVABILITY", "observability.sample.inspect"
	definitions := projectActionDefinitions([]AuthorizationProfile{profile})
	if len(definitions) != 1 || definitions[0].Product != profile.Product || definitions[0].CallingService != profile.CallingService {
		t.Fatal("generic product projection requires a product-name branch")
	}
	if _, known := LookupActionDefinition(profile.Actions[0].Action); known {
		t.Fatal("pure projection modified the active registry")
	}
	for name, profiles := range map[string][]AuthorizationProfile{
		"duplicate product": {profile, profile},
		"same revision other content": {profile, func() AuthorizationProfile {
			v := cloneAuthorizationProfile(profile)
			v.Actions[0].ResourceKind = "OTHER"
			return v
		}()},
		"foreign namespace": {func() AuthorizationProfile {
			v := cloneAuthorizationProfile(profile)
			v.Actions[0].Action = ActionIAMUserCreate
			return v
		}()},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid compiled registry did not fail closed")
				}
			}()
			projectActionDefinitions(profiles)
		})
	}
}

func TestCurrentProfileCommitmentsDoNotTrustMutableCopies(t *testing.T) {
	for _, source := range AllAuthorizationProfiles() {
		canonical, digest, err := canonicalizeAuthorizationProfile(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, encoded := range []string{canonical, canonical + "\n"} {
			decoded, err := DecodeAuthorizationProfile(strings.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			if actual, actualDigest, err := canonicalizeAuthorizationProfile(decoded); err != nil || actual != canonical || actualDigest != digest {
				t.Fatal("source-byte decode changed the complete declaration")
			}
			decoded.Actions[0].ResourceKind = "CHANGED_COPY"
			again, err := DecodeAuthorizationProfile(strings.NewReader(encoded))
			if err != nil || again.Actions[0].ResourceKind == "CHANGED_COPY" {
				t.Fatal("source-byte decode leaked a mutable source slice")
			}
		}
		for _, encoded := range []string{canonical + "{}", canonical + strings.Repeat(" ", int(MaxAuthorizationProfileBytes)),
			strings.Replace(canonical, `"product":`, `"product":"forged","product":`, 1)} {
			if _, err := DecodeAuthorizationProfile(strings.NewReader(encoded)); !errors.Is(err, ErrInvalidAuthorizationProfile) {
				t.Fatal("source prefix bypassed complete bounded strict decoding")
			}
		}
		// Mutate every scalar, including all nested shapes/conditions and any
		// future declaration field. The fast path must equal the full encoder;
		// omitting a field from typed equality must never reuse its commitment.
		changed := cloneAuthorizationProfile(source)
		var visit func(reflect.Value)
		visit = func(value reflect.Value) {
			switch value.Kind() {
			case reflect.Struct:
				for index := 0; index < value.NumField(); index++ {
					visit(value.Field(index))
				}
			case reflect.Slice:
				for index := 0; index < value.Len(); index++ {
					visit(value.Index(index))
				}
			default:
				original := reflect.New(value.Type()).Elem()
				original.Set(value)
				switch value.Kind() {
				case reflect.String:
					value.SetString(value.String() + "x")
				case reflect.Uint64:
					value.SetUint(value.Uint() + 1)
				case reflect.Bool:
					value.SetBool(!value.Bool())
				default:
					t.Fatal("declaration mutation gate needs its new scalar type")
				}
				actual, actualDigest, actualError := CanonicalizeAuthorizationProfile(changed)
				want, wantDigest, wantError := canonicalizeAuthorizationProfile(changed)
				if actual != want || actualDigest != wantDigest || (actualError == nil) != (wantError == nil) {
					t.Fatal("changed declaration bypassed complete encoding")
				}
				value.Set(original)
			}
		}
		visit(reflect.ValueOf(&changed).Elem())
		for _, value := range []AuthorizationProfile{source, sourceProfileCommitments[source.Product].normalized} {
			actual, actualDigest, err := CanonicalizeAuthorizationProfile(value)
			if err != nil || actual != canonical || actualDigest != digest {
				t.Fatal("immutable source encoding differs from complete encoding")
			}
			changed := cloneAuthorizationProfile(value)
			changed.Actions[0].ResourceKind = "DIFFERENT_KIND"
			if CheckAuthorizationProfileReference(changed, AuthorizationProfileReference{Product: source.Product, Revision: source.Revision, ContentDigest: digest}) == nil {
				t.Fatal("nested content substitution reused a source commitment")
			}
		}
		for _, action := range source.Actions {
			for _, shape := range action.ResourceShapes {
				resource := ResourceReference{Kind: action.ResourceKind, ID: "target-one"}
				if shape.Mode == AuthorizationResourceCollection {
					resource.ID = "collection"
				}
				request, err := NewAuthorizationRequest(action.Action, resource, shape.Mode, shape.CollectionUsage, "request-one", "correlation-one")
				if err != nil || request.Profile != (AuthorizationProfileReference{Product: source.Product, Revision: source.Revision, ContentDigest: digest}) || ValidateAuthorizationRequest(request) != nil {
					t.Fatal("current request differs from its full source commitment")
				}
				variant := cloneAuthorizationProfile(source)
				variant.CallingService = "DIFFERENT_CALLER"
				if CheckAuthorizationProfileTarget(variant, request.Profile, request.Action, resource, shape.Mode, shape.CollectionUsage) == nil {
					t.Fatal("supplied same-tuple bytes bypassed full validation")
				}
				_, variantDigest, err := CanonicalizeAuthorizationProfile(variant)
				if err != nil {
					t.Fatal(err)
				}
				request.Profile.ContentDigest = variantDigest
				if ValidateAuthorizationRequest(request) == nil {
					t.Fatal("valid foreign content changed current source admission")
				}
			}
		}
	}
}

func authorizationProfileFixture() AuthorizationProfile {
	return AuthorizationProfile{
		APIVersion: APIVersion, Kind: "AuthorizationProfile", Product: ProductManagedService,
		Revision: 1, CallingService: ServicePaaS,
		Actions: []AuthorizationProfileAction{{
			Action: ActionManagedServiceOfferingRead, ResourceKind: ResourceServiceOffering, Scope: AuthorityScopeTenant,
			ResourceShapes: []AuthorizationResourceShape{
				{Mode: AuthorizationResourceInstance},
				{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList},
			},
			Conditions: []AuthorizationProfileCondition{
				{Key: ConditionIAMCurrentTime, ValueType: ConditionTime, Source: ConditionIAMTransactionTime},
				{Key: ConditionIAMAccountID, ValueType: ConditionString, Source: ConditionIAMIdentity},
			},
		}},
	}
}

func TestRoleBoundaryIsAnExplicitRevisionBoundLimit(t *testing.T) {
	value := RolePermissionBoundary{APIVersion: APIVersion, Kind: "RolePermissionBoundary", AccountID: "account-a", RoleID: "role-a", ResourceVersion: 1}
	if err := ValidateRolePermissionBoundary(value); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil || !bytes.Contains(encoded, []byte(`"policy":null`)) {
		t.Fatalf("missing role boundary must be explicit: %s, %v", encoded, err)
	}
	for _, invalid := range []string{
		`{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RolePermissionBoundary","accountId":"account-a","roleId":"role-a","resourceVersion":1}`,
		`{"apiVersion":"iam.matrix.xiak.com/v1","kind":"RolePermissionBoundary","accountId":"account-a","roleId":"role-a","resourceVersion":1,"policy":null,"allow":true}`,
	} {
		var decoded RolePermissionBoundary
		if DecodeRequest(strings.NewReader(invalid), &decoded) == nil {
			t.Fatalf("accepted ambiguous boundary %s", invalid)
		}
	}
	set := SetRolePermissionBoundaryRequest{PolicyID: "policy-a", PolicyResourceVersion: 1, ResourceVersion: 1, RequestID: "set-boundary"}
	if ValidateSetRolePermissionBoundaryRequest(set) != nil {
		t.Fatal("valid role boundary intent rejected")
	}
	set.PolicyID = ""
	if ValidateSetRolePermissionBoundaryRequest(set) == nil {
		t.Fatal("set with missing policy became remove")
	}
	if ValidateRemoveRolePermissionBoundaryRequest(RemoveRolePermissionBoundaryRequest{ResourceVersion: 9007199254740991, RequestID: "remove-boundary"}) == nil {
		t.Fatal("exhausted role revision accepted")
	}
}

func TestAuthorizationProfileUserAuthenticationIsExplicitAndCommitted(t *testing.T) {
	legacy := authorizationProfileFixture()
	original, originalDigest, err := CanonicalizeAuthorizationProfile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	action := legacy.Actions[0].Action
	legacyReference := AuthorizationProfileReference{Product: legacy.Product, Revision: legacy.Revision, ContentDigest: originalDigest}
	if CheckAuthorizationProfileUserAuthentication(legacy, legacyReference, action, UserAuthenticationLoginSession) != nil ||
		CheckAuthorizationProfileUserAuthentication(legacy, legacyReference, action, UserAuthenticationAccessKey) == nil {
		t.Fatal("legacy USER capability inferred programmatic authentication")
	}
	profile := cloneAuthorizationProfile(legacy)
	profile.Revision++
	profile.Actions[0].SubjectTypes = []SubjectType{SubjectUser, SubjectRole}
	profile.Actions[0].UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession, UserAuthenticationAccessKey}
	before, _ := json.Marshal(profile)
	canonical, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil || digest == originalDigest || !strings.Contains(canonical, `"userAuthenticationMethods":["ACCESS_KEY","LOGIN_SESSION"]`) {
		t.Fatal("authentication capability did not enter the canonical commitment", err)
	}
	after, _ := json.Marshal(profile)
	if !bytes.Equal(before, after) {
		t.Fatal("authentication canonicalization mutated its caller")
	}
	reference := AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}
	for _, method := range []UserAuthenticationMethod{UserAuthenticationLoginSession, UserAuthenticationAccessKey} {
		if CheckAuthorizationProfileUserAuthentication(profile, reference, action, method) != nil {
			t.Fatal("explicit USER authentication capability was rejected")
		}
	}
	if CheckAuthorizationProfileUserAuthentication(profile, legacyReference, action, UserAuthenticationAccessKey) == nil ||
		CheckAuthorizationProfileUserAuthentication(profile, reference, "example.unknown", UserAuthenticationAccessKey) == nil ||
		CheckAuthorizationProfileUserAuthentication(profile, reference, action, "USER") == nil {
		t.Fatal("unbound action or unknown authentication method was accepted")
	}
	reordered := cloneAuthorizationProfile(profile)
	slices.Reverse(reordered.Actions[0].UserAuthenticationMethods)
	if actual, actualDigest, err := CanonicalizeAuthorizationProfile(reordered); err != nil || actual != canonical || actualDigest != digest {
		t.Fatal("method set order changed its commitment")
	}
	reordered.Actions[0].UserAuthenticationMethods[0] = UserAuthenticationLoginSession
	if !slices.Equal(profile.Actions[0].UserAuthenticationMethods, []UserAuthenticationMethod{UserAuthenticationLoginSession, UserAuthenticationAccessKey}) {
		t.Fatal("clone exposed mutable authentication capabilities")
	}
	for name, replacement := range map[string]string{
		"null": `null`, "empty": `[]`, "duplicate": `["ACCESS_KEY","ACCESS_KEY"]`,
		"unknown": `["BEARER"]`, "case alias": `["access_key"]`, "null element": `[null]`,
		"object": `{}`, "scalar": `"ACCESS_KEY"`, "over budget": `["ACCESS_KEY","LOGIN_SESSION","ACCESS_KEY"]`,
	} {
		t.Run(name, func(t *testing.T) {
			encoded := strings.Replace(canonical, `["ACCESS_KEY","LOGIN_SESSION"]`, replacement, 1)
			if _, err := DecodeAuthorizationProfile(strings.NewReader(encoded)); !errors.Is(err, ErrInvalidAuthorizationProfile) {
				t.Fatal("invalid authentication capability decoded", err)
			}
		})
	}
	for _, encoded := range []string{
		strings.Replace(canonical, `"userAuthenticationMethods":`, `"UserAuthenticationMethods":`, 1),
		strings.Replace(canonical, `"userAuthenticationMethods":`, `"userAuthenticationMethods":["LOGIN_SESSION"],"userAuthenticationMethods":`, 1),
	} {
		if _, err := DecodeAuthorizationProfile(strings.NewReader(encoded)); !errors.Is(err, ErrInvalidAuthorizationProfile) {
			t.Fatal("ambiguous authentication capability decoded")
		}
	}
	for _, methods := range [][]UserAuthenticationMethod{{}, {UserAuthenticationAccessKey, UserAuthenticationAccessKey}, {"OTHER"}} {
		invalid := cloneAuthorizationProfile(profile)
		invalid.Actions[0].UserAuthenticationMethods = methods
		if _, _, err := CanonicalizeAuthorizationProfile(invalid); !errors.Is(err, ErrInvalidAuthorizationProfile) {
			t.Fatal("typed invalid authentication set reached encoding")
		}
	}
	for _, types := range [][]SubjectType{{SubjectRole}, {SubjectServiceAccount}, {SubjectRole, SubjectServiceAccount}} {
		invalid := cloneAuthorizationProfile(profile)
		invalid.Actions[0].SubjectTypes = types
		if _, _, err := CanonicalizeAuthorizationProfile(invalid); !errors.Is(err, ErrInvalidAuthorizationProfile) {
			t.Fatal("non-USER subjects acquired USER authentication capability")
		}
	}
	decoded, err := DecodeAuthorizationProfile(strings.NewReader(original))
	if err != nil || decoded.Actions[0].UserAuthenticationMethods != nil {
		t.Fatal("old declaration gained authentication metadata")
	}
	if actual, actualDigest, err := CanonicalizeAuthorizationProfile(decoded); err != nil || actual != original || actualDigest != originalDigest {
		t.Fatal("authentication extension changed old bytes")
	}
	for _, source := range AllAuthorizationProfiles() {
		for _, declared := range source.Actions {
			if declared.UserAuthenticationMethods != nil {
				t.Fatal("pure capability contract changed current product admission")
			}
		}
		_, sourceDigest, _ := CanonicalizeAuthorizationProfile(source)
		changed := cloneAuthorizationProfile(source)
		for index, declared := range changed.Actions {
			if checkValidatedProfileSubject(changed, declared.Action, SubjectUser) != nil {
				continue
			}
			changed.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationAccessKey}
			got, gotDigest, gotErr := CanonicalizeAuthorizationProfile(changed)
			want, wantDigest, wantErr := canonicalizeAuthorizationProfile(changed)
			if gotErr != nil || wantErr != nil || got != want || gotDigest != wantDigest || gotDigest == sourceDigest {
				t.Fatal("authentication substitution borrowed the immutable source commitment")
			}
			break
		}
	}
}

func TestAuthorizationProfileSubjectTypesAreBoundedCommittedSets(t *testing.T) {
	legacy := authorizationProfileFixture()
	legacyCanonical, legacyDigest, err := CanonicalizeAuthorizationProfile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	profile := cloneAuthorizationProfile(legacy)
	profile.Revision++
	profile.Actions[0].SubjectTypes = []SubjectType{SubjectUser, SubjectRole}
	before, _ := json.Marshal(profile)
	canonical, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil || digest == legacyDigest || !strings.Contains(canonical, `"subjectTypes":["ROLE","USER"]`) {
		t.Fatal("subject capabilities were not included as a canonical set", err)
	}
	after, _ := json.Marshal(profile)
	if !bytes.Equal(before, after) {
		t.Fatal("canonicalization changed the caller's declaration")
	}
	reordered := cloneAuthorizationProfile(profile)
	slices.Reverse(reordered.Actions[0].SubjectTypes)
	if actual, actualDigest, err := CanonicalizeAuthorizationProfile(reordered); err != nil || actual != canonical || actualDigest != digest {
		t.Fatal("subject set order changed the commitment")
	}
	reordered.Actions[0].SubjectTypes[0] = SubjectServiceAccount
	if slices.Contains(profile.Actions[0].SubjectTypes, SubjectServiceAccount) {
		t.Fatal("cloning a declaration exposed mutable subject capabilities")
	}
	if _, actualDigest, err := CanonicalizeAuthorizationProfile(reordered); err != nil || actualDigest == digest {
		t.Fatal("different subject meaning reused the same commitment")
	}
	for _, encoded := range []string{canonical, canonical + "\n"} {
		decoded, err := DecodeAuthorizationProfile(strings.NewReader(encoded))
		if err != nil || !slices.Equal(decoded.Actions[0].SubjectTypes, []SubjectType{SubjectRole, SubjectUser}) {
			t.Fatal("explicit subject declaration did not round trip", err)
		}
	}
	for name, replacement := range map[string]string{
		"null": `null`, "empty": `[]`, "duplicate": `["USER","USER"]`,
		"unknown": `["ADMIN"]`, "case alias": `["user"]`, "empty element": `[""]`,
		"null element": `[null]`, "object": `{}`, "scalar": `"ROLE"`,
		"over budget": `["USER","ROLE","SERVICE_ACCOUNT","USER"]`,
	} {
		t.Run(name, func(t *testing.T) {
			encoded := strings.Replace(canonical, `["ROLE","USER"]`, replacement, 1)
			if _, err := DecodeAuthorizationProfile(strings.NewReader(encoded)); !errors.Is(err, ErrInvalidAuthorizationProfile) {
				t.Fatal("invalid subject capability decoded", err)
			}
		})
	}
	for _, types := range [][]SubjectType{{}, {SubjectUser, SubjectUser}, {"OTHER"}} {
		invalid := cloneAuthorizationProfile(profile)
		invalid.Actions[0].SubjectTypes = types
		if _, _, err := CanonicalizeAuthorizationProfile(invalid); !errors.Is(err, ErrInvalidAuthorizationProfile) {
			t.Fatal("typed invalid subject declaration reached encoding")
		}
	}
	for _, encoded := range []string{
		strings.Replace(canonical, `"subjectTypes":`, `"SubjectTypes":`, 1),
		strings.Replace(canonical, `"subjectTypes":`, `"subjectTypes":["USER"],"subjectTypes":`, 1),
	} {
		if _, err := DecodeAuthorizationProfile(strings.NewReader(encoded)); !errors.Is(err, ErrInvalidAuthorizationProfile) {
			t.Fatal("ambiguous subject capability decoded")
		}
	}
	decoded, err := DecodeAuthorizationProfile(strings.NewReader(legacyCanonical))
	if err != nil || decoded.Actions[0].SubjectTypes != nil {
		t.Fatal("old bytes acquired an explicit subject declaration")
	}
	if actual, actualDigest, err := CanonicalizeAuthorizationProfile(decoded); err != nil || actual != legacyCanonical || actualDigest != legacyDigest {
		t.Fatal("old declaration commitment changed")
	}
	// Content equality, not the already-known product/revision, selects the
	// immutable-source fast path. Adding even an equivalent explicit set must
	// change the bytes and cannot reuse the archived digest.
	for _, source := range AllAuthorizationProfiles() {
		_, sourceDigest, _ := CanonicalizeAuthorizationProfile(source)
		changed := cloneAuthorizationProfile(source)
		changed.Actions[0].SubjectTypes = []SubjectType{SubjectRole}
		got, gotDigest, gotErr := CanonicalizeAuthorizationProfile(changed)
		want, wantDigest, wantErr := canonicalizeAuthorizationProfile(changed)
		if gotErr != nil || wantErr != nil || got != want || gotDigest != wantDigest || gotDigest == sourceDigest {
			t.Fatal("subject substitution borrowed immutable source commitment")
		}
	}
}

func TestAuthorizationProfileSubjectAdmissionDoesNotInferRoleAuthority(t *testing.T) {
	for _, scope := range []AuthorityScope{AuthorityScopeTenant, AuthorityScopeInstallation, AuthorityScopeInstallationProbe} {
		for _, explicit := range [][]SubjectType{nil, {SubjectUser}, {SubjectRole}, {SubjectUser, SubjectRole}, {SubjectServiceAccount}} {
			profile := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
				declaredProfileAction("widgets.item.read", "WIDGET", scope, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
			profile.Actions[0].SubjectTypes = explicit
			_, digest, err := CanonicalizeAuthorizationProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			reference := AuthorizationProfileReference{profile.Product, profile.Revision, digest}
			for _, subject := range []SubjectType{SubjectUser, SubjectServiceAccount, SubjectRole, "", "GROUP", "SYSTEM"} {
				want := slices.Contains(explicit, subject)
				if explicit == nil {
					want = subject == SubjectUser && scope != AuthorityScopeInstallationProbe || subject == SubjectServiceAccount && scope == AuthorityScopeInstallationProbe
				}
				err := CheckAuthorizationProfileSubject(profile, reference, "widgets.item.read", subject)
				if (err == nil) != want {
					t.Fatalf("subject admission diverged: %s %v %s: %v", scope, explicit, subject, err)
				}
				if CheckAuthorizationProfileSubject(profile, reference, "widgets.item.other", subject) == nil {
					t.Fatal("unknown action inherited subject admission")
				}
				reference.ContentDigest = "sha256:" + strings.Repeat("0", 64)
				if CheckAuthorizationProfileSubject(profile, reference, "widgets.item.read", subject) == nil {
					t.Fatal("unchecked declaration yielded subject admission")
				}
				reference.ContentDigest = digest
			}
		}
	}
}

func TestPolicyCompilationSubjectCompatibilityCannotGrowOldAuthority(t *testing.T) {
	for _, effect := range []PolicyEffect{PolicyAllow, PolicyDeny} {
		for _, original := range [][]SubjectType{nil, {SubjectUser}, {SubjectRole}, {SubjectUser, SubjectRole}} {
			for _, present := range [][]SubjectType{nil, {SubjectUser}, {SubjectRole}, {SubjectUser, SubjectRole}} {
				frozen := authorizationProfileFixture()
				frozen.Actions[0].SubjectTypes = original
				current := cloneAuthorizationProfile(frozen)
				current.Revision++
				current.Actions[0].SubjectTypes = present
				document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
					Statements: []PolicyStatement{{SID: "one", Effect: effect, Actions: []Action{frozen.Actions[0].Action},
						Resources: []PolicyResourceSelector{{Kind: frozen.Actions[0].ResourceKind, Match: PolicyResourceExact, ID: "not-the-requested-resource"}}}}}
				compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
				if err != nil {
					t.Fatal(err)
				}
				_, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
				if err != nil {
					t.Fatal(err)
				}
				_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
				if err != nil {
					t.Fatal(err)
				}
				request := AuthorizationRequest{Action: frozen.Actions[0].Action,
					Resource:     ResourceReference{Kind: frozen.Actions[0].ResourceKind, ID: "requested-resource"},
					Profile:      AuthorizationProfileReference{current.Product, current.Revision, currentDigest},
					ResourceMode: AuthorizationResourceInstance, RequestID: "request-one", CorrelationID: "correlation-one"}
				for _, subject := range []SubjectType{SubjectUser, SubjectRole, SubjectServiceAccount, ""} {
					want := (slices.Contains(original, subject) || original == nil && subject == SubjectUser) &&
						(slices.Contains(present, subject) || present == nil && subject == SubjectUser)
					err := CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request, subject)
					if (err == nil) != want {
						t.Fatalf("frozen authority grew or disappeared: %s %v -> %v for %s: %v", effect, original, present, subject, err)
					}
				}
			}
		}
	}
}

func TestAuthorizationProfileCanonicalSetsAndExactReferences(t *testing.T) {
	profile := authorizationProfileFixture()
	profile.Actions = append(profile.Actions, AuthorizationProfileAction{
		Action: "managedservice.sample.create", ResourceKind: "SAMPLE", Scope: AuthorityScopeTenant,
		ResourceShapes: []AuthorizationResourceShape{{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}, ResultResourceKind: "SAMPLE",
	})
	original, _ := json.Marshal(profile)
	document, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(profile)
	if !bytes.Equal(original, after) {
		t.Fatal("canonicalization mutated the caller's nested declaration")
	}
	profile.Actions[0], profile.Actions[1] = profile.Actions[1], profile.Actions[0]
	action := &profile.Actions[1]
	action.ResourceShapes[0], action.ResourceShapes[1] = action.ResourceShapes[1], action.ResourceShapes[0]
	action.Conditions[0], action.Conditions[1] = action.Conditions[1], action.Conditions[0]
	reordered, reorderedDigest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil || reordered != document || reorderedDigest != digest {
		t.Fatal("set order changed the immutable profile identity", err)
	}
	decoded, err := DecodeAuthorizationProfile(strings.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	reference := AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}
	if err := CheckAuthorizationProfileReference(decoded, reference); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AuthorizationProfileReference){
		"other product":    func(v *AuthorizationProfileReference) { v.Product = ProductPaaS },
		"newer revision":   func(v *AuthorizationProfileReference) { v.Revision++ },
		"missing digest":   func(v *AuthorizationProfileReference) { v.ContentDigest = "" },
		"different digest": func(v *AuthorizationProfileReference) { v.ContentDigest = "sha256:" + strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			variant := reference
			change(&variant)
			if !errors.Is(CheckAuthorizationProfileReference(decoded, variant), ErrInvalidAuthorizationProfile) {
				t.Fatal("accepted a nonexact profile reference")
			}
		})
	}
}

func TestAuthorizationProfileDigestBindsAuthorizationSemantics(t *testing.T) {
	_, baseline, err := CanonicalizeAuthorizationProfile(authorizationProfileFixture())
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AuthorizationProfile){
		"product": func(v *AuthorizationProfile) {
			v.Product = "otherproduct"
			v.Actions[0].Action = "otherproduct.offering.read"
		},
		"revision":        func(v *AuthorizationProfile) { v.Revision++ },
		"calling service": func(v *AuthorizationProfile) { v.CallingService = "ANOTHER_SERVICE" },
		"action":          func(v *AuthorizationProfile) { v.Actions[0].Action = "managedservice.offering.inspect" },
		"resource kind":   func(v *AuthorizationProfile) { v.Actions[0].ResourceKind = "ANOTHER_KIND" },
		"scope": func(v *AuthorizationProfile) {
			v.Actions[0].Scope = AuthorityScopeInstallation
			v.Actions[0].Conditions = nil
		},
		"prefix":      func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes[0].PrefixAllowed = true },
		"target mode": func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes = v.Actions[0].ResourceShapes[:1] },
		"collection semantics": func(v *AuthorizationProfile) {
			v.Actions[0].ResourceShapes[1].CollectionUsage = AuthorizationCollectionCreate
			v.Actions[0].ResultResourceKind = "RESULT"
		},
		"trusted conditions":  func(v *AuthorizationProfile) { v.Actions[0].Conditions = nil },
		"identity source key": func(v *AuthorizationProfile) { v.Actions[0].Conditions[1].Key = ConditionIAMPrincipalID },
	} {
		t.Run(name, func(t *testing.T) {
			variant := authorizationProfileFixture()
			change(&variant)
			_, digest, err := CanonicalizeAuthorizationProfile(variant)
			if err != nil || digest == baseline {
				t.Fatal("authorization semantics missing from digest", err)
			}
		})
	}
}

func TestAuthorizationProfileRejectsUndeclaredOrAmbiguousCapabilities(t *testing.T) {
	for name, change := range map[string]func(*AuthorizationProfile){
		"version":          func(v *AuthorizationProfile) { v.APIVersion = "other/v1" },
		"kind":             func(v *AuthorizationProfile) { v.Kind = "PolicyDocument" },
		"zero revision":    func(v *AuthorizationProfile) { v.Revision = 0 },
		"unsafe revision":  func(v *AuthorizationProfile) { v.Revision = 1 << 53 },
		"product spelling": func(v *AuthorizationProfile) { v.Product = "ManagedService" },
		"service spelling": func(v *AuthorizationProfile) { v.CallingService = "paas" },
		"empty actions":    func(v *AuthorizationProfile) { v.Actions = nil },
		"action wildcard":  func(v *AuthorizationProfile) { v.Actions[0].Action = "managedservice.*" },
		"other namespace":  func(v *AuthorizationProfile) { v.Actions[0].Action = ActionPaaSApplicationRead },
		"duplicate action": func(v *AuthorizationProfile) { v.Actions = append(v.Actions, v.Actions[0]) },
		"oversized action set": func(v *AuthorizationProfile) {
			v.Actions = make([]AuthorizationProfileAction, MaxAuthorizationProfileActions+1)
		},
		"unknown scope": func(v *AuthorizationProfile) { v.Actions[0].Scope = "ANY" },
		"kind spelling": func(v *AuthorizationProfile) { v.Actions[0].ResourceKind = "serviceOffering" },
		"no shape":      func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes = nil },
		"batch":         func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes[0].Mode = "BATCH" },
		"duplicate shape": func(v *AuthorizationProfile) {
			v.Actions[0].ResourceShapes = append(v.Actions[0].ResourceShapes, v.Actions[0].ResourceShapes[0])
		},
		"collection prefix": func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes[1].PrefixAllowed = true },
		"filtered list":     func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes[1].CollectionUsage = "FILTERED" },
		"creation result absent": func(v *AuthorizationProfile) {
			v.Actions[0].ResourceShapes[1].CollectionUsage = AuthorizationCollectionCreate
		},
		"list claiming creation": func(v *AuthorizationProfile) { v.Actions[0].ResultResourceKind = "RESULT" },
		"list and create": func(v *AuthorizationProfile) {
			v.Actions[0].ResultResourceKind = "RESULT"
			v.Actions[0].ResourceShapes = append(v.Actions[0].ResourceShapes, AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate})
		},
		"instance claiming collection": func(v *AuthorizationProfile) {
			v.Actions[0].ResourceShapes[0].CollectionUsage = AuthorizationCollectionCreate
		},
		"result spelling": func(v *AuthorizationProfile) { v.Actions[0].ResultResourceKind = "bad-result" },
		"platform prefix": func(v *AuthorizationProfile) {
			v.Actions[0].Conditions = nil
			v.Actions[0].Scope = AuthorityScopeInstallation
			v.Actions[0].ResourceShapes[0].PrefixAllowed = true
		},
		"probe tenant conditions": func(v *AuthorizationProfile) { v.Actions[0].Scope = AuthorityScopeInstallationProbe },
		"duplicate condition": func(v *AuthorizationProfile) {
			v.Actions[0].Conditions = append(v.Actions[0].Conditions, v.Actions[0].Conditions[0])
		},
		"caller conditions":  func(v *AuthorizationProfile) { v.Actions[0].Conditions[0].Source = "CALLER_ATTRIBUTES" },
		"unknown source key": func(v *AuthorizationProfile) { v.Actions[0].Conditions[0].Key = "paas.arbitrary" },
		"wrong source type":  func(v *AuthorizationProfile) { v.Actions[0].Conditions[0].ValueType = ConditionString },
	} {
		t.Run(name, func(t *testing.T) {
			variant := authorizationProfileFixture()
			change(&variant)
			if !errors.Is(ValidateAuthorizationProfile(variant), ErrInvalidAuthorizationProfile) {
				t.Fatal("accepted invalid declaration")
			}
			if document, digest, err := CanonicalizeAuthorizationProfile(variant); document != "" || digest != "" || !errors.Is(err, ErrInvalidAuthorizationProfile) {
				t.Fatal("invalid declaration produced usable evidence")
			}
		})
	}
}

func TestAuthorizationProfileStrictDecodeAndNonAdmission(t *testing.T) {
	document, _, err := CanonicalizeAuthorizationProfile(authorizationProfileFixture())
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"unknown":                 strings.Replace(document, `"revision":1`, `"revision":1,"permit":true`, 1),
		"duplicate":               strings.Replace(document, `"revision":1`, `"revision":1,"revision":2`, 1),
		"case alias":              strings.Replace(document, `"revision":1`, `"Revision":1`, 1),
		"nested unknown":          strings.Replace(document, `"prefixAllowed":false`, `"prefixAllowed":false,"authority":"ANY"`, 1),
		"nested duplicate":        strings.Replace(document, `"prefixAllowed":false`, `"prefixAllowed":false,"prefixAllowed":true`, 1),
		"result on request shape": strings.Replace(document, `"prefixAllowed":false`, `"prefixAllowed":false,"resultResourceKind":"USER"`, 1),
		"trailing":                document + `{}`,
		"null":                    `null`,
		"oversized":               document + strings.Repeat(" ", int(MaxAuthorizationProfileBytes)),
	} {
		t.Run(name, func(t *testing.T) {
			value, err := DecodeAuthorizationProfile(strings.NewReader(source))
			if !errors.Is(err, ErrInvalidAuthorizationProfile) || value.Product != "" || value.Actions != nil {
				t.Fatal("invalid input returned a usable declaration", err)
			}
		})
	}
	// Product/action spelling cannot enroll a new service or change the active
	// action catalog, even when a prospective declaration is syntactically valid.
	profile := authorizationProfileFixture()
	profile.Product = "observability"
	profile.CallingService = "OBSERVABILITY"
	profile.Actions[0].Action = "observability.sample.inspect"
	if err := ValidateAuthorizationProfile(profile); err != nil {
		t.Fatal("new product syntax must not require a product-name switch", err)
	}
	if _, known := LookupActionDefinition(profile.Actions[0].Action); known {
		t.Fatal("validating a profile registered an action")
	}
	if _, known := LookupActionConditionDefinition(profile.Actions[0].Action, ConditionIAMAccountID); known {
		t.Fatal("source validation granted unknown action capabilities")
	}
	// Absence, null and empty optional condition sets all declare no condition
	// capability. Their canonical form cannot accidentally enable one.
	profile.Actions[0].Conditions = nil
	without, digest, err := CanonicalizeAuthorizationProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, empty := range []string{`null`, `[]`} {
		input := strings.Replace(without, `"resourceShapes":`, `"conditions":`+empty+`,"resourceShapes":`, 1)
		decoded, err := DecodeAuthorizationProfile(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		_, decodedDigest, err := CanonicalizeAuthorizationProfile(decoded)
		if err != nil || decodedDigest != digest {
			t.Fatal("empty condition capability changed meaning", err)
		}
	}
}

func FuzzAuthorizationProfileCanonicalRoundTrip(f *testing.F) {
	document, _, err := CanonicalizeAuthorizationProfile(authorizationProfileFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(document)
	explicit := authorizationProfileFixture()
	explicit.Revision++
	explicit.Actions[0].SubjectTypes = []SubjectType{SubjectUser, SubjectRole}
	canonicalSubjects, _, err := CanonicalizeAuthorizationProfile(explicit)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(canonicalSubjects)
	explicit.Actions[0].UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession, UserAuthenticationAccessKey}
	canonicalMethods, _, err := CanonicalizeAuthorizationProfile(explicit)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(canonicalMethods)
	for _, profile := range AllAuthorizationProfiles() {
		canonical, _, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(canonical)
	}
	for _, selected := range []Action{ActionIAMUserCreate, ActionPaaSApplicationCreate} {
		definition, known := LookupActionDefinition(selected)
		if !known {
			f.Fatal("missing declared action")
		}
		profile, known := LookupAuthorizationProfile(definition.Product)
		if !known {
			f.Fatal("missing declared product")
		}
		for _, action := range profile.Actions {
			if action.Action != selected {
				continue
			}
			profile.Actions = []AuthorizationProfileAction{action}
			seed, _, err := CanonicalizeAuthorizationProfile(profile)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(seed)
			break
		}
	}
	f.Add(`{"kind":"AuthorizationProfile","actions":null}`)
	f.Add(`{"revision":1,"revision":2}`)
	f.Fuzz(func(t *testing.T, source string) {
		profile, err := DecodeAuthorizationProfile(strings.NewReader(source))
		if err != nil {
			return
		}
		canonical, digest, err := CanonicalizeAuthorizationProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeAuthorizationProfile(strings.NewReader(canonical))
		if err != nil {
			t.Fatal(err)
		}
		second, secondDigest, err := CanonicalizeAuthorizationProfile(decoded)
		if err != nil || second != canonical || secondDigest != digest {
			t.Fatal("accepted declaration is not canonically stable", err)
		}
		if err := CheckAuthorizationProfileReference(decoded, AuthorizationProfileReference{Product: profile.Product, Revision: profile.Revision, ContentDigest: digest}); err != nil {
			t.Fatal(err)
		}
		for _, action := range profile.Actions {
			for _, subject := range []SubjectType{SubjectUser, SubjectServiceAccount, SubjectRole, "UNKNOWN"} {
				if (checkValidatedProfileSubject(profile, action.Action, subject) == nil) != (checkValidatedProfileSubject(decoded, action.Action, subject) == nil) {
					t.Fatal("canonical round trip changed subject capability")
				}
			}
			for _, method := range []UserAuthenticationMethod{UserAuthenticationLoginSession, UserAuthenticationAccessKey, "UNKNOWN"} {
				if (checkValidatedProfileUserAuthentication(profile, action.Action, method) == nil) != (checkValidatedProfileUserAuthentication(decoded, action.Action, method) == nil) {
					t.Fatal("canonical round trip changed USER authentication capability")
				}
			}
		}
	})
}

func TestAuthorizationProfileBoundsTypedDeclarations(t *testing.T) {
	profile := authorizationProfileFixture()
	profile.Actions = make([]AuthorizationProfileAction, MaxAuthorizationProfileActions)
	for index := range profile.Actions {
		action := authorizationProfileFixture().Actions[0]
		action.Action = Action(fmt.Sprintf("managedservice.%s.action%d", strings.Repeat("a", 64), index))
		action.ResourceKind = ResourceKind(strings.Repeat("K", 64))
		action.ResourceShapes = []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}, {Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate}}
		action.ResultResourceKind = ResourceKind(strings.Repeat("R", 64))
		profile.Actions[index] = action
	}
	encoded, err := json.Marshal(profile)
	if err != nil || int64(len(encoded)) <= MaxAuthorizationProfileBytes {
		t.Fatal("fixture must exceed the byte budget", err)
	}
	if !errors.Is(ValidateAuthorizationProfile(profile), ErrInvalidAuthorizationProfile) {
		t.Fatal("typed input bypassed the byte budget")
	}
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
	valid.ResourceMode, valid.CollectionUsage = AuthorizationResourceInstance, ""
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
			subject.Type = SubjectServiceAccount
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
	baseline, err := NewAuthorizationRequest(ActionPaaSDeploymentCreate, ResourceReference{Kind: ResourceDeployment, ID: "collection"}, AuthorizationResourceCollection, AuthorizationCollectionCreate, "request-authorize", "correlation-authorize")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(encoded)
	var baselineDecoded AuthorizationRequest
	if DecodeRequest(strings.NewReader(valid), &baselineDecoded) != nil || ValidateAuthorizationRequest(baselineDecoded) != nil {
		t.Fatal("baseline request is invalid")
	}
	for name, forged := range map[string]string{
		"tenant":  strings.Replace(valid, `"action"`, `"tenantId":"organization-forged","action"`, 1),
		"subject": strings.Replace(valid, `"action"`, `"subject":{"type":"USER","id":"principal-forged"},"action"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var request AuthorizationRequest
			err := DecodeRequest(strings.NewReader(forged), &request)
			if err == nil {
				t.Fatalf("forged %s context was accepted", name)
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
		definition, _ := LookupActionDefinition(action)
		profile, _ := LookupAuthorizationProfile(definition.Product)
		for _, declared := range profile.Actions {
			if declared.Action != action {
				continue
			}
			for _, shape := range declared.ResourceShapes {
				request, err := NewAuthorizationRequest(action, ResourceReference{Kind: kind, ID: "collection"}, shape.Mode, shape.CollectionUsage, "request-example", "correlation-example")
				if err != nil || ValidateAuthorizationRequest(request) != nil {
					t.Fatalf("valid catalog entry %q/%q rejected: %v", action, kind, err)
				}
				request.Resource.Kind = ResourceKind("NOT_A_RESOURCE")
				if ValidateAuthorizationRequest(request) == nil {
					t.Fatalf("action %q accepted an unbound resource kind", action)
				}
			}
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
		{ActionIAMAccountCreate, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeInstallation, false},
		{ActionIAMAccountRootCredentialsRecover, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeInstallation, false},
		{ActionIAMUserCreate, ProductIAM, ServiceIAM, ResourceAccount, AuthorityScopeTenant, false},
		{ActionIAMPolicyAttachmentCreate, ProductIAM, ServiceIAM, ResourceUser, AuthorityScopeTenant, false},
		{ActionIAMPolicyAttachmentRevoke, ProductIAM, ServiceIAM, ResourcePolicyAttachment, AuthorityScopeTenant, false},
		{ActionIAMPlatformPolicyAttachmentCreate, ProductIAM, ServiceIAM, ResourceUser, AuthorityScopeInstallation, false},
		{ActionIAMPlatformPolicyAttachmentRevoke, ProductIAM, ServiceIAM, ResourcePolicyAttachment, AuthorityScopeInstallation, false},
		{ActionIAMSessionRevoke, ProductIAM, ServiceIAM, ResourceSession, AuthorityScopeTenant, false},
		{ActionPaaSApplicationCreate, ProductPaaS, ServicePaaS, ResourceApplication, AuthorityScopeTenant, false},
		{ActionPaaSExecutionPoolCreate, ProductPaaS, ServicePaaS, ResourceExecutionPool, AuthorityScopeInstallation, false},
		{ActionPaaSExecutionTargetRegister, ProductPaaS, ServicePaaS, ResourceExecutionTarget, AuthorityScopeInstallation, false},
		{ActionPaaSOperationRead, ProductPaaS, ServicePaaS, ResourceOperation, AuthorityScopeTenant, false},
		{ActionPaaSPlatformOperationRead, ProductPaaS, ServicePaaS, ResourceOperation, AuthorityScopeInstallation, false},
		{ActionManagedServiceOfferingRead, ProductManagedService, ServicePaaS, ResourceServiceOffering, AuthorityScopeTenant, false},
		{ActionManagedServiceInstallationCreate, ProductManagedService, ServicePaaS, ResourceServiceInstallation, AuthorityScopeTenant, false},
		{ActionAuditRecordRead, ProductAudit, ServiceAudit, ResourceAuditRecord, AuthorityScopeTenant, false},
		{ActionAuditPlatformRecordRead, ProductAudit, ServiceAudit, ResourceAuditRecord, AuthorityScopeInstallation, false},
		{ActionAuditIntegrityVerify, ProductAudit, ServiceAudit, ResourceAuditChain, AuthorityScopeTenant, false},
		{ActionAuditPlatformIntegrityVerify, ProductAudit, ServiceAudit, ResourceAuditChain, AuthorityScopeInstallation, false},
		{ActionInstallationVerify, ProductInstallation, ServiceInstallationVerifier, ResourceInstallation, AuthorityScopeInstallationProbe, false},
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

func TestPolicyCompilationBindsMinimalProductsAndEntireAuthorDocument(t *testing.T) {
	document := policyDocumentFixture()
	document.Statements = append(document.Statements, PolicyStatement{SID: "audit", Effect: PolicyAllow,
		Actions: []Action{ActionAuditRecordRead}, Resources: []PolicyResourceSelector{{Kind: ResourceAuditRecord, Match: PolicyResourceAnyInAuthority}}})
	profiles := AllAuthorizationProfiles()
	documentBefore, _ := json.Marshal(document)
	profilesBefore, _ := json.Marshal(profiles)
	legacyCanonical, legacyDigest, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	compilation, err := CompilePolicyDocument(document, profiles)
	if err != nil {
		t.Fatal(err)
	}
	if compilation.CompilationVersion != "1" || len(compilation.Profiles) != 2 || compilation.Profiles[0].Product != ProductAudit || compilation.Profiles[1].Product != ProductPaaS {
		t.Fatal("compilation did not select the exact sorted product set")
	}
	canonical, digest, err := CanonicalizePolicyCompilation(document, compilation, profiles)
	if err != nil || ValidateDigest("digest", digest) != nil || digest == legacyDigest {
		t.Fatal("compilation must have a distinct complete content commitment", err)
	}
	var content struct {
		Document json.RawMessage `json:"document"`
		PolicyCompilation
	}
	if err := json.Unmarshal([]byte(canonical), &content); err != nil || string(content.Document) != legacyCanonical {
		t.Fatal("compilation changed the unique canonical author document", err)
	}
	for _, reference := range compilation.Profiles {
		profile, found := LookupAuthorizationProfile(reference.Product)
		if !found || CheckAuthorizationProfileReference(profile, reference) != nil {
			t.Fatal("compiled reference did not bind exact product content")
		}
	}
	documentAfter, _ := json.Marshal(document)
	profilesAfter, _ := json.Marshal(profiles)
	if !bytes.Equal(documentBefore, documentAfter) || !bytes.Equal(profilesBefore, profilesAfter) {
		t.Fatal("compilation mutated the author or declaration inputs")
	}
	compilationBefore, _ := json.Marshal(compilation)
	compilation.Profiles[0], compilation.Profiles[1] = compilation.Profiles[1], compilation.Profiles[0]
	compilation.ResolvedStatements[0], compilation.ResolvedStatements[2] = compilation.ResolvedStatements[2], compilation.ResolvedStatements[0]
	compilation.ResolvedStatements[0].Actions[0], compilation.ResolvedStatements[0].Actions[1] = compilation.ResolvedStatements[0].Actions[1], compilation.ResolvedStatements[0].Actions[0]
	document.Statements[0], document.Statements[2] = document.Statements[2], document.Statements[0]
	profiles[0], profiles[4] = profiles[4], profiles[0]
	before, _ := json.Marshal(compilation)
	if reordered, reorderedDigest, err := CanonicalizePolicyCompilation(document, compilation, profiles); err != nil || reordered != canonical || reorderedDigest != digest {
		t.Fatal("set order changed compilation semantics", err)
	}
	after, _ := json.Marshal(compilation)
	if !bytes.Equal(before, after) || bytes.Equal(compilationBefore, after) {
		t.Fatal("canonicalization must not reorder the caller's compilation in place")
	}
	for _, change := range []func(*PolicyDocument){
		func(v *PolicyDocument) { v.Statements[0].Effect = PolicyDeny },
		func(v *PolicyDocument) { v.Statements[2].Resources[0].ID = "different-resource" },
		func(v *PolicyDocument) {
			v.Statements[0].Conditions = []PolicyCondition{{Key: ConditionIAMAccountID, Operator: PolicyStringEquals, Values: []string{"account-one"}}}
		},
	} {
		var changed PolicyDocument
		encoded, _ := json.Marshal(document)
		if json.Unmarshal(encoded, &changed) != nil {
			t.Fatal("invalid fixture")
		}
		change(&changed)
		if _, changedDigest, err := CanonicalizePolicyCompilation(changed, compilation, profiles); err != nil || changedDigest == digest {
			t.Fatal("author effect, resource and condition must enter the whole commitment", err)
		}
	}
	if retained, retainedDigest, err := CanonicalizePolicyDocument(document); err != nil || retained != legacyCanonical || retainedDigest != legacyDigest {
		t.Fatal("new compilation changed the retained document-only encoding", err)
	}
	authorBeforeMutation, _ := json.Marshal(document)
	for _, source := range profiles {
		if source.Product != ProductIAM {
			continue
		}
		// IAM is unused by this document. Minimal dependency indexes must not
		// become permission to skip the rest of a supplied declaration.
		for name, mutate := range map[string]func(*AuthorizationProfile){
			"unrelated action syntax":    func(v *AuthorizationProfile) { v.Actions[0].Action = "iam.*" },
			"unrelated action duplicate": func(v *AuthorizationProfile) { v.Actions = append(v.Actions, v.Actions[0]) },
			"unrelated condition": func(v *AuthorizationProfile) {
				v.Actions[0].Conditions = []AuthorizationProfileCondition{{Key: "untrusted.key", ValueType: ConditionString, Source: ConditionIAMIdentity}}
			},
		} {
			t.Run(name, func(t *testing.T) {
				changed := cloneAuthorizationProfile(source)
				mutate(&changed)
				declarations := slices.Clone(profiles)
				for index := range declarations {
					if declarations[index].Product == ProductIAM {
						declarations[index] = changed
					}
				}
				if _, err := CompilePolicyDocument(document, declarations); !errors.Is(err, ErrInvalidPolicy) {
					t.Fatal("unused malformed Profile was ignored", err)
				}
			})
		}
	}
	compilation.ResolvedStatements[0].Actions[0] = "tampered.action"
	authorAfterMutation, _ := json.Marshal(document)
	if !bytes.Equal(authorBeforeMutation, authorAfterMutation) {
		t.Fatal("compiler output aliases the author input")
	}
}

func TestPolicyCompilationRejectsForgedOrIncompleteInterpretation(t *testing.T) {
	document := policyDocumentFixture()
	profiles := AllAuthorizationProfiles()
	valid, err := CompilePolicyDocument(document, profiles)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(valid)
	for name, change := range map[string]func(*PolicyCompilation){
		"no version":       func(v *PolicyCompilation) { v.CompilationVersion = "" },
		"unknown version":  func(v *PolicyCompilation) { v.CompilationVersion = "2" },
		"no profiles":      func(v *PolicyCompilation) { v.Profiles = nil },
		"extra profile":    func(v *PolicyCompilation) { v.Profiles = append(v.Profiles, v.Profiles[0]) },
		"wrong product":    func(v *PolicyCompilation) { v.Profiles[0].Product = ProductAudit },
		"wrong revision":   func(v *PolicyCompilation) { v.Profiles[0].Revision++ },
		"wrong digest":     func(v *PolicyCompilation) { v.Profiles[0].ContentDigest = "sha256:" + strings.Repeat("0", 64) },
		"no statements":    func(v *PolicyCompilation) { v.ResolvedStatements = nil },
		"duplicate SID":    func(v *PolicyCompilation) { v.ResolvedStatements[0].SID = v.ResolvedStatements[1].SID },
		"unknown SID":      func(v *PolicyCompilation) { v.ResolvedStatements[0].SID = "not-in-author-document" },
		"missing action":   func(v *PolicyCompilation) { v.ResolvedStatements[1].Actions = v.ResolvedStatements[1].Actions[:1] },
		"duplicate action": func(v *PolicyCompilation) { v.ResolvedStatements[1].Actions[1] = v.ResolvedStatements[1].Actions[0] },
		"action moved across SID": func(v *PolicyCompilation) {
			v.ResolvedStatements[0].Actions[0], v.ResolvedStatements[1].Actions[0] = v.ResolvedStatements[1].Actions[0], v.ResolvedStatements[0].Actions[0]
		},
		"unbounded action": func(v *PolicyCompilation) {
			v.ResolvedStatements[0].Actions[0] = Action(strings.Repeat("x", int(MaxPolicyCompilationBytes)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed PolicyCompilation
			if json.Unmarshal(encoded, &changed) != nil {
				t.Fatal("invalid fixture")
			}
			change(&changed)
			if canonical, digest, err := CanonicalizePolicyCompilation(document, changed, profiles); !errors.Is(err, ErrInvalidPolicy) || canonical != "" || digest != "" {
				t.Fatal("forged compilation returned authoritative bytes", err)
			}
		})
	}
	for _, invalid := range []string{
		`{}`, `null`, `[]`, string(encoded) + `{}`,
		strings.Replace(string(encoded), `"compilationVersion":`, `"unknown":true,"compilationVersion":`, 1),
		strings.Replace(string(encoded), `"compilationVersion":"1"`, `"compilationVersion":"1","compilationVersion":"1"`, 1),
		strings.Replace(string(encoded), `"profiles":`, `"Profiles":`, 1),
		strings.Replace(string(encoded), `"revision":`, `"unknown":true,"revision":`, 1),
		strings.Replace(string(encoded), `"sid":`, `"Sid":`, 1),
		strings.Replace(string(encoded), `"sid":`, `"permit":true,"sid":`, 1),
		strings.Repeat(" ", int(MaxPolicyCompilationBytes)) + string(encoded),
	} {
		if _, err := DecodePolicyCompilation(strings.NewReader(invalid), document, profiles); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("strict immutable-content loader accepted malformed compilation", err)
		}
	}
	// This is not an additive caller-selected publication capability.
	canonicalDocument, _, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`"profiles":[]`, `"resolvedStatements":[]`, `"compilationVersion":"1"`} {
		request := `{"displayName":"Example","document":` + canonicalDocument + `,"requestId":"request-one",` + extra + `}`
		var publication CreatePolicyRequest
		if contractjson.DecodeObject(strings.NewReader(request), MaxPolicyBytes, &publication) == nil {
			t.Fatal("author request accepted server-owned profile selection or compilation")
		}
	}
}

func TestPolicyCompilationUsesFrozenDeclarationsNotCurrentCatalog(t *testing.T) {
	profile := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
		declaredProfileAction("widgets.item.read", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance, PrefixAllowed: true}}))
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "read", Effect: PolicyDeny, Actions: []Action{"widgets.item.read"},
			Resources:  []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourcePrefixInAuthority, ID: "widget-"}},
			Conditions: []PolicyCondition{{Key: ConditionIAMAccountID, Operator: PolicyStringNotEquals, Values: []string{"account-one"}}}}}}
	if ValidatePolicyDocument(document) == nil {
		t.Fatal("syntactic declaration registered an unknown product in current authority")
	}
	compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{profile})
	if err != nil {
		t.Fatal("same compiler rejected an explicit non-global product declaration", err)
	}
	canonical, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{profile})
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AuthorizationProfile){
		"next revision": func(v *AuthorizationProfile) { v.Revision++ },
		"new action": func(v *AuthorizationProfile) {
			v.Actions = append(v.Actions, declaredProfileAction("widgets.item.delete", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
		},
		"new shape": func(v *AuthorizationProfile) {
			v.Actions[0].ResourceShapes = append(v.Actions[0].ResourceShapes, AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList})
		},
		"different caller":  func(v *AuthorizationProfile) { v.CallingService = "ANOTHER_SERVICE" },
		"removed prefix":    func(v *AuthorizationProfile) { v.Actions[0].ResourceShapes[0].PrefixAllowed = false },
		"removed condition": func(v *AuthorizationProfile) { v.Actions[0].Conditions = nil },
		"wrong source":      func(v *AuthorizationProfile) { v.Actions[0].Conditions[0].Source = "CALLER" },
		"wrong scope":       func(v *AuthorizationProfile) { v.Actions[0].Scope = AuthorityScopeInstallation },
		"wrong kind":        func(v *AuthorizationProfile) { v.Actions[0].ResourceKind = "OTHER_RESOURCE" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneAuthorizationProfile(profile)
			change(&changed)
			if value, commitment, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{changed}); !errors.Is(err, ErrInvalidPolicy) || value != "" || commitment != "" {
				t.Fatal("different declaration reinterpreted a frozen compilation", err)
			}
		})
	}
	for _, supplied := range [][]AuthorizationProfile{nil, {profile, profile}, make([]AuthorizationProfile, MaxPolicyCompilationProfiles+1)} {
		if _, err := CompilePolicyDocument(document, supplied); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("missing, ambiguous or over-budget declarations accepted")
		}
	}
	if again, againDigest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{profile}); err != nil || again != canonical || againDigest != digest {
		t.Fatal("frozen original content no longer validates independently", err)
	}
	if _, registered := LookupAuthorizationProfile(profile.Product); registered {
		t.Fatal("pure compiler modified current product registration")
	}
}

func TestPolicyFamilyCompilationFreezesExactActionsWithoutRegisteringProfiles(t *testing.T) {
	for _, product := range []ProductID{ProductPaaS, "widgets"} {
		t.Run(string(product), func(t *testing.T) {
			prefix := string(product) + ".item."
			profile := declaredProductProfile(product, "TEST_SERVICE", 7,
				declaredProfileAction(Action(prefix+"read"), "ITEM", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
				declaredProfileAction(Action(prefix+"update"), "ITEM", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
				declaredProfileAction(Action(string(product)+".item-extra.read"), "ITEM", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
				declaredProfileAction(Action(prefix+"child.read"), "ITEM", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
			document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
				Statements: []PolicyStatement{{SID: "one", Effect: PolicyDeny, Actions: []Action{Action(prefix + "*"), Action(prefix + "read")},
					Resources: []PolicyResourceSelector{{Kind: "ITEM", Match: PolicyResourceExact, ID: "item-one"}}}}}
			authorBefore, _ := json.Marshal(document)
			profileBefore, _ := json.Marshal(profile)
			compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{profile})
			if err != nil || !slices.Equal(compilation.ResolvedStatements[0].Actions, []Action{Action(prefix + "read"), Action(prefix + "update")}) {
				t.Fatal("family expansion leaked a different family/nested action or duplicated overlap", err)
			}
			canonical, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{profile})
			if err != nil || !strings.Contains(canonical, prefix+"*") {
				t.Fatal("author pattern must remain in the entire commitment", err)
			}
			for name, change := range map[string]func(*PolicyCompilation){
				"missing matched action": func(v *PolicyCompilation) { v.ResolvedStatements[0].Actions = v.ResolvedStatements[0].Actions[:1] },
				"extra family": func(v *PolicyCompilation) {
					v.ResolvedStatements[0].Actions = append(v.ResolvedStatements[0].Actions, Action(string(product)+".item-extra.read"))
				},
				"nested action": func(v *PolicyCompilation) {
					v.ResolvedStatements[0].Actions = append(v.ResolvedStatements[0].Actions, Action(prefix+"child.read"))
				},
				"pattern as resolution": func(v *PolicyCompilation) { v.ResolvedStatements[0].Actions[0] = Action(prefix + "*") },
				"different SID":         func(v *PolicyCompilation) { v.ResolvedStatements[0].SID = "other" },
			} {
				t.Run(name, func(t *testing.T) {
					encoded, _ := json.Marshal(compilation)
					var forged PolicyCompilation
					if json.Unmarshal(encoded, &forged) != nil {
						t.Fatal("invalid test compilation")
					}
					change(&forged)
					if value, commitment, err := CanonicalizePolicyCompilation(document, forged, []AuthorizationProfile{profile}); !errors.Is(err, ErrInvalidPolicy) || value != "" || commitment != "" {
						t.Fatal("forged family interpretation obtained a content commitment")
					}
				})
			}
			wire, _ := json.Marshal(compilation)
			if _, err := DecodePolicyCompilation(bytes.NewReader(wire), document, []AuthorizationProfile{profile}); err != nil {
				t.Fatal(err)
			}
			authorAfter, _ := json.Marshal(document)
			profileAfter, _ := json.Marshal(profile)
			if !bytes.Equal(authorBefore, authorAfter) || !bytes.Equal(profileBefore, profileAfter) {
				t.Fatal("compilation mutated supplied values")
			}
			if ValidatePolicyDocument(document) == nil || ValidatePolicyVersion(PolicyVersion{PolicyID: "policy-one", ID: "version-one",
				Document: document, ContentDigest: digest, ContractVersion: PolicyVersionCompiledContract, Compilation: &compilation}) != nil {
				t.Fatal("transport integrity was confused with current profile registration")
			}
			current := cloneAuthorizationProfile(profile)
			current.Revision++
			current.Actions = append(current.Actions, declaredProfileAction(Action(prefix+"delete"), "ITEM", AuthorityScopeTenant, "",
				[]AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
			if _, _, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{current}); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("current declaration re-expanded old author pattern")
			}
			updated, err := CompilePolicyDocument(document, []AuthorizationProfile{current})
			if err != nil || !slices.Contains(updated.ResolvedStatements[0].Actions, Action(prefix+"delete")) {
				t.Fatal("explicit new compilation did not use its selected revision", err)
			}
			_, updatedDigest, err := CanonicalizePolicyCompilation(document, updated, []AuthorizationProfile{current})
			if err != nil || updatedDigest == digest {
				t.Fatal("new expansion reused old commitment", err)
			}
			_, currentDigest, _ := CanonicalizeAuthorizationProfile(current)
			request := AuthorizationRequest{Profile: AuthorizationProfileReference{current.Product, current.Revision, currentDigest},
				Action: Action(prefix + "delete"), Resource: ResourceReference{Kind: "ITEM", ID: "item-one"}, ResourceMode: AuthorizationResourceInstance,
				RequestID: "request-one", CorrelationID: "correlation-one"}
			if err := CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{profile}, current, request, SubjectUser); err != nil ||
				slices.Contains(compilation.ResolvedStatements[0].Actions, request.Action) {
				t.Fatal("compatibility check changed the frozen action set", err)
			}
			// Same existing action with an incompatible caller must fail even
			// for a Deny whose resource would not match this request.
			current.CallingService = "CHANGED_SERVICE"
			_, request.Profile.ContentDigest, _ = CanonicalizeAuthorizationProfile(current)
			request.Action, request.Resource.ID = Action(prefix+"read"), "nonmatching-item"
			if err := CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{profile}, current, request, SubjectUser); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("incompatible nonmatching Deny was silently skipped")
			}
			document.Statements[0].Actions[0], document.Statements[0].Actions[1] = document.Statements[0].Actions[1], document.Statements[0].Actions[0]
			slices.Reverse(profile.Actions)
			if again, againDigest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{profile}); err != nil || again != canonical || againDigest != digest {
				t.Fatal("set reordering changed frozen content", err)
			}
			document.Statements[0].Actions = slices.Clone(compilation.ResolvedStatements[0].Actions)
			if _, exactDigest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{profile}); err != nil || exactDigest == digest {
				t.Fatal("author pattern and enumerated author were conflated", err)
			}
		})
	}
	// Also exercise actual source declarations, without treating a synthetic
	// product bearing a familiar name as a registered source.
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "application", Effect: PolicyAllow, Actions: []Action{"paas.application.*"},
			Resources: []PolicyResourceSelector{{Kind: ResourceApplication, Match: PolicyResourceAnyInAuthority}}}}}
	document.Statements = append(document.Statements, PolicyStatement{SID: "audit", Effect: PolicyDeny, Actions: []Action{"audit.record.*"},
		Resources: []PolicyResourceSelector{{Kind: ResourceAuditRecord, Match: PolicyResourceAnyInAuthority}}})
	result, err := CompilePolicyDocument(document, AllAuthorizationProfiles())
	if err != nil || len(result.Profiles) != 2 {
		t.Fatal("actual product declarations rejected minimal family expansion", err)
	}
	_, digest, err := CanonicalizePolicyCompilation(document, result, AllAuthorizationProfiles())
	if err != nil {
		t.Fatal(err)
	}
	if ValidateCreatePolicyRequest(CreatePolicyRequest{DisplayName: "family", Document: document, RequestID: "request-one"}) != nil ||
		ValidateCreatePolicyVersionRequest(CreatePolicyVersionRequest{Document: document, ResourceVersion: 1, RequestID: "request-one"}) != nil ||
		ValidatePolicyVersion(PolicyVersion{PolicyID: "policy-one", ID: "version-one", Document: document, ContentDigest: digest,
			ContractVersion: PolicyVersionCompiledContract, Compilation: &result}) != nil {
		t.Fatal("actual known product family rejected by the compiled contract")
	}
	if _, _, err := CanonicalizePolicyDocument(document); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("pattern obtained a document-only legacy commitment")
	}
}

func TestPolicyFamilyCompilationRejectsGrammarAndEveryIncompatibleMatch(t *testing.T) {
	profile := declaredProductProfile("widgets", "WIDGET_SERVICE", 1,
		declaredProfileAction("widgets.item.read", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance, PrefixAllowed: true}}),
		declaredProfileAction("widgets.item.update", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance, PrefixAllowed: true}}))
	base := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "one", Effect: PolicyAllow, Actions: []Action{"widgets.item.*"},
			Resources:  []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourcePrefixInAuthority, ID: "widget-"}},
			Conditions: []PolicyCondition{{Key: ConditionIAMAccountID, Operator: PolicyStringEquals, Values: []string{"account-one"}}}}}}
	for _, pattern := range []Action{"*", "widgets.*", "*.item.read", "widgets.it*", "widgets.item.r*", "widgets.item.?", "widgets.item.**",
		"widgets.item.*.read", "widgets.item.child.*", "Widgets.item.*", "widgets..*", "widgets.item\\.*", "widgets.other.*", "absent.item.*", Action(strings.Repeat("w", 128) + ".item.*")} {
		t.Run(string(pattern), func(t *testing.T) {
			document := base
			document.Statements = slices.Clone(base.Statements)
			document.Statements[0].Actions = []Action{pattern}
			document.Statements[0].Conditions = nil
			_, err := CompilePolicyDocument(document, []AuthorizationProfile{profile})
			var validation *PolicyValidationError
			if !errors.As(err, &validation) || validation.Pointer != "/statements/0/actions/0" {
				t.Fatal("invalid/empty pattern did not identify the original author token", err)
			}
		})
	}
	for _, effect := range []PolicyEffect{PolicyAllow, PolicyDeny} {
		for name, change := range map[string]func(*AuthorizationProfile){
			"wrong scope": func(v *AuthorizationProfile) {
				v.Actions[1].Scope = AuthorityScopeInstallation
				v.Actions[1].Conditions = nil
				v.Actions[1].ResourceShapes[0].PrefixAllowed = false
			},
			"missing condition": func(v *AuthorizationProfile) { v.Actions[1].Conditions = nil },
			"missing prefix":    func(v *AuthorizationProfile) { v.Actions[1].ResourceShapes[0].PrefixAllowed = false },
			"wrong resource":    func(v *AuthorizationProfile) { v.Actions[1].ResourceKind = "OTHER" },
		} {
			t.Run(string(effect)+"/"+name, func(t *testing.T) {
				changed := cloneAuthorizationProfile(profile)
				change(&changed)
				if ValidateAuthorizationProfile(changed) != nil {
					t.Fatal("negative fixture must have a valid declaration")
				}
				document := base
				document.Statements = slices.Clone(base.Statements)
				document.Statements[0].Effect = effect
				if _, err := CompilePolicyDocument(document, []AuthorizationProfile{changed}); !errors.Is(err, ErrInvalidPolicy) {
					t.Fatal("incompatible matched action was filtered instead of rejecting the statement")
				}
			})
		}
	}
	base.Statements[0].Actions = []Action{"widgets.item.*", "widgets.item.*"}
	if _, err := CompilePolicyDocument(base, []AuthorizationProfile{profile}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("duplicate author pattern accepted")
	}
	base.Statements[0].Actions = []Action{"widgets.item.*"}
	base.Scope = AuthorityScopeInstallation
	if _, err := CompilePolicyDocument(base, []AuthorizationProfile{profile}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("installation author obtained pattern semantics")
	}
}

func FuzzPolicyFamilyCompilationCanonicalRoundTrip(f *testing.F) {
	for _, token := range []string{"widgets.item.*", "widgets.item.read", "widgets.item.update", "widgets.*", "widgets.item.child.*", "*", "widgets.item.?"} {
		f.Add(token)
	}
	profile := declaredProductProfile("widgets", "WIDGET_SERVICE", 1,
		declaredProfileAction("widgets.item.read", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}),
		declaredProfileAction("widgets.item.update", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
	f.Fuzz(func(t *testing.T, token string) {
		document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
			Statements: []PolicyStatement{{SID: "one", Effect: PolicyDeny, Actions: []Action{Action(token)},
				Resources: []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourceAnyInAuthority}}}}}
		compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{profile})
		if err != nil {
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("unstable compiler error", err)
			}
			return
		}
		var expected []Action
		switch token {
		case "widgets.item.*":
			expected = []Action{"widgets.item.read", "widgets.item.update"}
		case "widgets.item.read", "widgets.item.update":
			expected = []Action{Action(token)}
		default:
			t.Fatal("bounded declaration accepted unexpected author language")
		}
		if !slices.Equal(compilation.ResolvedStatements[0].Actions, expected) {
			t.Fatal("incorrect resolved action set")
		}
		canonical, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{profile})
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := json.Marshal(compilation)
		decoded, err := DecodePolicyCompilation(bytes.NewReader(wire), document, []AuthorizationProfile{profile})
		if err != nil {
			t.Fatal(err)
		}
		if again, againDigest, err := CanonicalizePolicyCompilation(document, decoded, []AuthorizationProfile{profile}); err != nil || again != canonical || againDigest != digest {
			t.Fatal("family canonical round trip changed commitment", err)
		}
	})
}

func TestPolicyFamilyCompilationBudgetsCountOverlapBeforeDeduplication(t *testing.T) {
	profile := declaredProductProfile("w", "WIDGET_SERVICE", 1)
	for index := 0; index < MaxStatementActions; index++ {
		profile.Actions = append(profile.Actions, declaredProfileAction(Action(fmt.Sprintf("w.i.a%d", index)), "WIDGET", AuthorityScopeTenant, "",
			[]AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
	}
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "one", Effect: PolicyAllow, Actions: []Action{"w.i.*"}, Resources: []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourceAnyInAuthority}}}}}
	if result, err := CompilePolicyDocument(document, []AuthorizationProfile{profile}); err != nil || len(result.ResolvedStatements[0].Actions) != MaxStatementActions {
		t.Fatal("exact resolved action budget rejected", err)
	}
	other := declaredProductProfile("other", "OTHER_SERVICE", 1, declaredProfileAction("other.item.read", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
	document.Statements[0].Actions = append(document.Statements[0].Actions, "other.item.read")
	if _, err := CompilePolicyDocument(document, []AuthorizationProfile{profile, other}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("expanded action budget bypassed")
	}
	document.Statements[0].Actions = []Action{"w.i.*", "w.i.a0"}
	statement := document.Statements[0]
	document.Statements = nil
	for index := 0; index < MaxPolicyStatements; index++ {
		statement.SID = fmt.Sprintf("statement-%d", index)
		document.Statements = append(document.Statements, statement)
	}
	if _, err := CompilePolicyDocument(document, []AuthorizationProfile{profile}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("deduplicated overlap concealed document work limit")
	}
	for index := range document.Statements {
		document.Statements[index].Actions = []Action{"w.i.*"}
	}
	if _, err := CompilePolicyDocument(document, []AuthorizationProfile{profile}); err != nil {
		t.Fatal("exact document work budget rejected", err)
	}
}

func TestCompiledPolicyVersionHasExplicitCompleteTransportContract(t *testing.T) {
	document := policyDocumentFixture()
	profiles := AllAuthorizationProfiles()
	compilation, err := CompilePolicyDocument(document, profiles)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := CanonicalizePolicyCompilation(document, compilation, profiles)
	if err != nil {
		t.Fatal(err)
	}
	version := PolicyVersion{PolicyID: "policy-one", ID: "version-one", Document: document, ContentDigest: digest,
		ContractVersion: PolicyVersionCompiledContract, Compilation: &compilation}
	if err := ValidatePolicyVersion(version); err != nil {
		t.Fatal("complete compiled transport rejected", err)
	}
	encoded, _ := json.Marshal(version)
	var decoded PolicyVersion
	if json.Unmarshal(encoded, &decoded) != nil || ValidatePolicyVersion(decoded) != nil {
		t.Fatal("compiled version did not round trip")
	}
	for name, mutate := range map[string]func(*PolicyVersion){
		"missing contract":        func(v *PolicyVersion) { v.ContractVersion = 0 },
		"unknown contract":        func(v *PolicyVersion) { v.ContractVersion = 3 },
		"legacy with compilation": func(v *PolicyVersion) { v.ContractVersion = PolicyVersionLegacyContract },
		"missing compilation":     func(v *PolicyVersion) { v.Compilation = nil },
		"changed effect": func(v *PolicyVersion) {
			if v.Document.Statements[0].Effect == PolicyAllow {
				v.Document.Statements[0].Effect = PolicyDeny
			} else {
				v.Document.Statements[0].Effect = PolicyAllow
			}
		},
		"changed digest": func(v *PolicyVersion) { v.ContentDigest = "sha256:" + strings.Repeat("0", 64) },
		"missing refs":   func(v *PolicyVersion) { v.Compilation.Profiles = nil },
		"duplicate refs": func(v *PolicyVersion) {
			v.Compilation.Profiles = append(v.Compilation.Profiles, v.Compilation.Profiles[0])
		},
		"wrong resolved action": func(v *PolicyVersion) { v.Compilation.ResolvedStatements[0].Actions[0] = "paas.unexpected.action" },
	} {
		t.Run(name, func(t *testing.T) {
			var candidate PolicyVersion
			if json.Unmarshal(encoded, &candidate) != nil {
				t.Fatal("bad fixture")
			}
			mutate(&candidate)
			if ValidatePolicyVersion(candidate) == nil {
				t.Fatal("incomplete or changed compiled version accepted")
			}
		})
	}
	for _, wire := range []string{
		strings.Replace(string(encoded), `,"contractVersion":2`, "", 1),
		strings.Replace(string(encoded), `"contractVersion":2`, `"contractVersion":null`, 1),
		strings.Replace(string(encoded), `"contractVersion":2`, `"contractVersion":2,"contractVersion":2`, 1),
		strings.Replace(string(encoded), `"compilation":`, `"compiled":`, 1),
		strings.Replace(string(encoded), `"policyId":`, `"permit":true,"policyId":`, 1),
	} {
		if json.Unmarshal([]byte(wire), &decoded) == nil {
			t.Fatal("strict version codec accepted absent/aliased/duplicate fields")
		}
	}
	_, legacyDigest, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	legacy := PolicyVersion{PolicyID: version.PolicyID, ID: "legacy-version", Document: document, ContentDigest: legacyDigest, ContractVersion: PolicyVersionLegacyContract}
	if ValidatePolicyVersion(legacy) != nil {
		t.Fatal("explicit retained document contract rejected")
	}
	legacyWire, _ := json.Marshal(legacy)
	legacyWire = bytes.Replace(legacyWire, []byte(`"contractVersion":1`), []byte(`"contractVersion":1,"compilation":null`), 1)
	if json.Unmarshal(legacyWire, &decoded) == nil {
		t.Fatal("legacy transport admitted a partial compilation")
	}
}

func TestAccessKeyPolicyCompilationOnlyAddsTheCredentialCarrier(t *testing.T) {
	methods := [][]UserAuthenticationMethod{nil, {UserAuthenticationLoginSession}, {UserAuthenticationAccessKey}, {UserAuthenticationLoginSession, UserAuthenticationAccessKey}}
	for originalIndex, originalMethods := range methods {
		for currentIndex, currentMethods := range methods {
			for _, effect := range []PolicyEffect{PolicyAllow, PolicyDeny} {
				frozen := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
					declaredProfileAction("widgets.item.read", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{
						{Mode: AuthorizationResourceInstance, PrefixAllowed: true},
						{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList}}))
				frozen.Actions[0].SubjectTypes = []SubjectType{SubjectUser, SubjectRole}
				frozen.Actions[0].UserAuthenticationMethods = originalMethods
				document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
					Statements: []PolicyStatement{{SID: "original", Effect: effect, Actions: []Action{"widgets.item.read"},
						Resources: []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourceExact, ID: "unmatched"}}}}}
				compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
				if err != nil {
					t.Fatal(err)
				}
				canonical, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
				if err != nil {
					t.Fatal(err)
				}
				current := cloneAuthorizationProfile(frozen)
				current.Revision++
				current.Actions[0].UserAuthenticationMethods = slices.Clone(currentMethods)
				slices.Reverse(current.Actions[0].SubjectTypes)
				slices.Reverse(current.Actions[0].ResourceShapes)
				slices.Reverse(current.Actions[0].Conditions)
				_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
				if err != nil {
					t.Fatal(err)
				}
				request := AuthorizationRequest{Profile: AuthorizationProfileReference{current.Product, current.Revision, currentDigest},
					Action: "widgets.item.read", Resource: ResourceReference{Kind: "WIDGET", ID: "actual"},
					ResourceMode: AuthorizationResourceInstance, RequestID: "signed-request", CorrelationID: "signed-correlation"}
				want := originalIndex <= 1 && currentIndex == 3 || originalIndex >= 2 && originalIndex == currentIndex
				if err := CheckAccessKeyPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request); (err == nil) != want {
					t.Fatalf("carrier transition %d -> %d, %s: accepted=%v want=%v", originalIndex, currentIndex, effect, err == nil, want)
				}
				if actual, actualDigest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen}); err != nil || actual != canonical || actualDigest != digest {
					t.Fatal("carrier compatibility changed the original policy commitment")
				}
			}
		}
	}
}

func TestAccessKeyPolicyCompilationRejectsOtherMeaningChangesBeforeMatching(t *testing.T) {
	frozen := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
		declaredProfileAction("widgets.item.read", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
	frozen.Actions[0].SubjectTypes = []SubjectType{SubjectUser}
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "unmatched-deny", Effect: PolicyDeny, Actions: []Action{"widgets.item.read"},
			Resources: []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourceExact, ID: "unmatched"}}}}}
	compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]struct {
		modify        func(*AuthorizationProfile, *AuthorizationRequest)
		loginAccepted bool
	}{
		"calling service": {func(p *AuthorizationProfile, _ *AuthorizationRequest) { p.CallingService = "OTHER_SERVICE" }, false},
		"subject expansion": {func(p *AuthorizationProfile, _ *AuthorizationRequest) {
			p.Actions[0].SubjectTypes = append(p.Actions[0].SubjectTypes, SubjectRole)
		}, true},
		"unused condition removed": {func(p *AuthorizationProfile, _ *AuthorizationRequest) { p.Actions[0].Conditions = nil }, true},
		"other target shape": {func(p *AuthorizationProfile, _ *AuthorizationRequest) {
			p.Actions[0].ResourceShapes = append(p.Actions[0].ResourceShapes, AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList})
		}, true},
		"prefix capability": {func(p *AuthorizationProfile, _ *AuthorizationRequest) {
			p.Actions[0].ResourceShapes[0].PrefixAllowed = true
		}, true},
		"result resource": {func(p *AuthorizationProfile, _ *AuthorizationRequest) {
			p.Actions[0].ResultResourceKind = "CHILD_WIDGET"
		}, false},
		"resource kind": {func(p *AuthorizationProfile, r *AuthorizationRequest) {
			p.Actions[0].ResourceKind, r.Resource.Kind = "OTHER_WIDGET", "OTHER_WIDGET"
		}, false},
		"scope": {func(p *AuthorizationProfile, _ *AuthorizationRequest) {
			p.Actions[0].Scope, p.Actions[0].Conditions = AuthorityScopeInstallation, nil
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			current := cloneAuthorizationProfile(frozen)
			current.Revision++
			current.Actions[0].UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession, UserAuthenticationAccessKey}
			request := AuthorizationRequest{Action: "widgets.item.read", Resource: ResourceReference{Kind: "WIDGET", ID: "actual"},
				ResourceMode: AuthorizationResourceInstance, RequestID: "signed-request", CorrelationID: "signed-correlation"}
			change.modify(&current, &request)
			_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
			if err != nil {
				t.Fatal("fixture must be a valid current declaration", err)
			}
			request.Profile = AuthorizationProfileReference{current.Product, current.Revision, currentDigest}
			if err := CheckAuthorizationProfileTarget(current, request.Profile, request.Action, request.Resource, request.ResourceMode, request.CollectionUsage); err != nil {
				t.Fatal("fixture must be a legal current target", err)
			}
			if err := CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request, SubjectUser); (err == nil) != change.loginAccepted {
				t.Fatal("existing USER compatibility changed", err)
			}
			if err := CheckAccessKeyPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("key carrier admitted changed semantics or skipped an unmatched Deny", err)
			}
		})
	}
}

func TestAccessKeyPolicyCompilationDoesNotGrowFrozenActionsOrBorrowEvidence(t *testing.T) {
	frozen := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
		declaredProfileAction("widgets.item.read", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "family", Effect: PolicyAllow, Actions: []Action{"widgets.item.*"},
			Resources: []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourceAnyInAuthority}}}}}
	compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	current := cloneAuthorizationProfile(frozen)
	current.Revision++
	current.Actions = append(current.Actions, declaredProfileAction("widgets.item.delete", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
	for index := range current.Actions {
		current.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationAccessKey, UserAuthenticationLoginSession}
	}
	_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizationRequest{Profile: AuthorizationProfileReference{current.Product, current.Revision, currentDigest},
		Action: "widgets.item.delete", Resource: ResourceReference{Kind: "WIDGET", ID: "actual"},
		ResourceMode: AuthorizationResourceInstance, RequestID: "signed-request", CorrelationID: "signed-correlation"}
	if err := CheckAccessKeyPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request); err != nil {
		t.Fatal("intact nonparticipating policy was treated as an implicit grant or corruption", err)
	}
	if slices.Contains(compilation.ResolvedStatements[0].Actions, request.Action) {
		t.Fatal("new action entered the frozen family")
	}
	for _, participating := range []bool{false, true} {
		if participating {
			request.Action = "widgets.item.read"
		}
		if CheckAccessKeyPolicyCompilationRequest(document, compilation, "sha256:"+strings.Repeat("0", 64), []AuthorizationProfile{frozen}, current, request) == nil ||
			CheckAccessKeyPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{current}, current, request) == nil ||
			CheckAccessKeyPolicyCompilationRequest(document, compilation, digest, nil, current, request) == nil {
			t.Fatal("key compatibility ignored missing or forged policy evidence")
		}
		badRequest := request
		badRequest.Profile.Revision--
		if CheckAccessKeyPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, badRequest) == nil {
			t.Fatal("key compatibility ignored the exact current reference")
		}
	}
}

func TestPolicyCompilationRequestCompatibilityAcrossDeclaredTargets(t *testing.T) {
	for _, frozen := range AllAuthorizationProfiles() {
		current := cloneAuthorizationProfile(frozen)
		current.Revision++ // A new revision with the same meaning is not drift.
		_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
		if err != nil {
			t.Fatal(err)
		}
		for _, action := range frozen.Actions {
			for _, effect := range []PolicyEffect{PolicyAllow, PolicyDeny} {
				document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: action.Scope,
					Statements: []PolicyStatement{{SID: "one", Effect: effect, Actions: []Action{action.Action},
						Resources: []PolicyResourceSelector{{Kind: action.ResourceKind, Match: PolicyResourceAnyInAuthority}}}}}
				compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
				if err != nil {
					t.Fatal(err)
				}
				_, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
				if err != nil {
					t.Fatal(err)
				}
				for _, shape := range action.ResourceShapes {
					request := AuthorizationRequest{Profile: AuthorizationProfileReference{current.Product, current.Revision, currentDigest},
						Action: action.Action, Resource: ResourceReference{Kind: action.ResourceKind, ID: "collection"},
						ResourceMode: shape.Mode, CollectionUsage: shape.CollectionUsage, RequestID: "request-one", CorrelationID: "correlation-one"}
					subject := SubjectUser
					if action.Scope == AuthorityScopeInstallationProbe {
						subject = SubjectServiceAccount
					}
					if err := CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request, subject); err != nil {
						t.Fatalf("same explicit meaning rejected: %s/%s/%s: %v", action.Action, effect, shape.Mode, err)
					}
					if subject == SubjectUser {
						carrierProfile := cloneAuthorizationProfile(current)
						for index := range carrierProfile.Actions {
							if carrierProfile.Actions[index].Action == action.Action {
								carrierProfile.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession, UserAuthenticationAccessKey}
							}
						}
						_, carrierDigest, err := CanonicalizeAuthorizationProfile(carrierProfile)
						if err != nil {
							t.Fatal(err)
						}
						request.Profile.ContentDigest = carrierDigest
						if err := CheckAccessKeyPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, carrierProfile, request); err != nil {
							t.Fatalf("unchanged declared target rejected a pure USER carrier extension: %s/%s/%s: %v", action.Action, effect, shape.Mode, err)
						}
					}
				}
			}
		}
	}
}

func TestPolicyCompilationRequestSameIDDoesNotBridgeTargetModes(t *testing.T) {
	shapes := []AuthorizationResourceShape{
		{Mode: AuthorizationResourceInstance},
		{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList},
		{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionCreate},
	}
	for originalIndex, originalShape := range shapes {
		resultKind := ResourceKind("")
		if originalShape.CollectionUsage == AuthorizationCollectionCreate {
			resultKind = "WIDGET"
		}
		frozen := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
			declaredProfileAction("widgets.item.access", "WIDGET", AuthorityScopeTenant, resultKind, []AuthorizationResourceShape{originalShape}))
		for _, match := range []PolicyResourceMatch{PolicyResourceExact, PolicyResourceAnyInAuthority} {
			selector := PolicyResourceSelector{Kind: "WIDGET", Match: match}
			if match == PolicyResourceExact {
				selector.ID = "collection"
			}
			document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
				Statements: []PolicyStatement{{SID: "one", Effect: PolicyDeny, Actions: []Action{"widgets.item.access"},
					Resources: []PolicyResourceSelector{selector}}}}
			compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
			if err != nil {
				t.Fatal(err)
			}
			_, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
			if err != nil {
				t.Fatal(err)
			}
			for currentIndex, shape := range shapes {
				current := cloneAuthorizationProfile(frozen)
				current.Revision++
				current.Actions[0].ResourceShapes = []AuthorizationResourceShape{shape}
				current.Actions[0].ResultResourceKind = ""
				if shape.CollectionUsage == AuthorizationCollectionCreate {
					current.Actions[0].ResultResourceKind = "WIDGET"
				}
				_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
				if err != nil {
					t.Fatal(err)
				}
				request := AuthorizationRequest{Profile: AuthorizationProfileReference{current.Product, current.Revision, currentDigest},
					Action: "widgets.item.access", Resource: ResourceReference{Kind: "WIDGET", ID: "collection"},
					ResourceMode: shape.Mode, CollectionUsage: shape.CollectionUsage, RequestID: "request-one", CorrelationID: "correlation-one"}
				err = CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request, SubjectUser)
				if (err == nil) != (originalIndex == currentIndex) {
					t.Fatalf("same opaque ID bridged different target modes: %d -> %d, %s: %v", originalIndex, currentIndex, match, err)
				}
			}
		}
	}
}

func TestPolicyCompilationRequestRejectsChangedMeaningBeforeStatementMatching(t *testing.T) {
	frozen := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
		declaredProfileAction("widgets.item.read", "WIDGET", AuthorityScopeTenant, "",
			[]AuthorizationResourceShape{{Mode: AuthorizationResourceInstance, PrefixAllowed: true}}))
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "guard", Effect: PolicyDeny, Actions: []Action{"widgets.item.read"},
			Resources:  []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourcePrefixInAuthority, ID: "unmatched-"}},
			Conditions: []PolicyCondition{{Key: ConditionIAMAccountID, Operator: PolicyStringNotEquals, Values: []string{"account-one"}}}}}}
	compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AuthorizationProfile, *AuthorizationRequest){
		"caller": func(p *AuthorizationProfile, _ *AuthorizationRequest) { p.CallingService = "OTHER_SERVICE" },
		"kind": func(p *AuthorizationProfile, r *AuthorizationRequest) {
			p.Actions[0].ResourceKind, r.Resource.Kind = "OTHER_WIDGET", "OTHER_WIDGET"
		},
		"scope": func(p *AuthorizationProfile, _ *AuthorizationRequest) {
			p.Actions[0].Scope, p.Actions[0].Conditions = AuthorityScopeInstallation, nil
			p.Actions[0].ResourceShapes[0].PrefixAllowed = false
		},
		"result kind": func(p *AuthorizationProfile, _ *AuthorizationRequest) {
			p.Actions[0].ResultResourceKind = "CHILD_WIDGET"
		},
		"new collection shape": func(p *AuthorizationProfile, r *AuthorizationRequest) {
			p.Actions[0].ResourceShapes = append(p.Actions[0].ResourceShapes,
				AuthorizationResourceShape{Mode: AuthorizationResourceCollection, CollectionUsage: AuthorizationCollectionList})
			r.ResourceMode, r.CollectionUsage = AuthorizationResourceCollection, AuthorizationCollectionList
		},
		"prefix removed": func(p *AuthorizationProfile, _ *AuthorizationRequest) {
			p.Actions[0].ResourceShapes[0].PrefixAllowed = false
		},
		"used condition removed": func(p *AuthorizationProfile, _ *AuthorizationRequest) { p.Actions[0].Conditions = nil },
	} {
		t.Run(name, func(t *testing.T) {
			current := cloneAuthorizationProfile(frozen)
			current.Revision++
			request := AuthorizationRequest{Action: "widgets.item.read", Resource: ResourceReference{Kind: "WIDGET", ID: "collection"},
				ResourceMode: AuthorizationResourceInstance, RequestID: "request-one", CorrelationID: "correlation-one"}
			change(&current, &request)
			_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
			if err != nil {
				t.Fatal("fixture must be a valid new declaration, not a grammar rejection", err)
			}
			request.Profile = AuthorizationProfileReference{current.Product, current.Revision, currentDigest}
			if err := CheckAuthorizationProfileTarget(current, request.Profile, request.Action, request.Resource, request.ResourceMode, request.CollectionUsage); err != nil {
				t.Fatal("fixture must independently be a legal current request", err)
			}
			if err := CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request, SubjectUser); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("incompatible old Deny disappeared before resource/condition matching", err)
			}
		})
	}
}

func TestPolicyCompilationRequestDoesNotGrowActionsOrBorrowDeclarations(t *testing.T) {
	frozen := declaredProductProfile("widgets", "WIDGET_SERVICE", 7,
		declaredProfileAction("widgets.item.read", "WIDGET", AuthorityScopeTenant, "", []AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
	document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant,
		Statements: []PolicyStatement{{SID: "read", Effect: PolicyAllow, Actions: []Action{"widgets.item.read"},
			Resources: []PolicyResourceSelector{{Kind: "WIDGET", Match: PolicyResourceExact, ID: "widget-one"}}}}}
	compilation, err := CompilePolicyDocument(document, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	canonical, digest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen})
	if err != nil {
		t.Fatal(err)
	}
	current := cloneAuthorizationProfile(frozen)
	current.Revision++
	current.Actions[0].Conditions = nil // Unused capabilities do not reinterpret this document.
	current.Actions = append(current.Actions, declaredProfileAction("widgets.item.delete", "WIDGET", AuthorityScopeTenant, "",
		[]AuthorizationResourceShape{{Mode: AuthorizationResourceInstance}}))
	_, currentDigest, err := CanonicalizeAuthorizationProfile(current)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizationRequest{Profile: AuthorizationProfileReference{current.Product, current.Revision, currentDigest},
		Action: "widgets.item.read", Resource: ResourceReference{Kind: "WIDGET", ID: "widget-one"},
		ResourceMode: AuthorizationResourceInstance, RequestID: "request-one", CorrelationID: "correlation-one"}
	for _, action := range []Action{"widgets.item.read", "widgets.item.delete"} {
		request.Action = action
		if err := CheckPolicyCompilationRequest(document, compilation, digest, []AuthorizationProfile{frozen}, current, request, SubjectUser); err != nil {
			t.Fatal("unrelated action or unused capability should not rewrite exact resolution", err)
		}
	}
	if slices.Contains(compilation.ResolvedStatements[0].Actions, Action("widgets.item.delete")) {
		t.Fatal("compatibility test granted a newly declared action")
	}
	// Even a nonparticipating policy must retain its entire original commitment.
	for name, change := range map[string]func(*PolicyDocument, *PolicyCompilation, *string, *[]AuthorizationProfile, *AuthorizationRequest){
		"different digest": func(_ *PolicyDocument, _ *PolicyCompilation, d *string, _ *[]AuthorizationProfile, _ *AuthorizationRequest) {
			*d = "sha256:" + strings.Repeat("0", 64)
		},
		"author effect": func(d *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, _ *AuthorizationRequest) {
			d.Statements[0].Effect = PolicyDeny
		},
		"no frozen source": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, p *[]AuthorizationProfile, _ *AuthorizationRequest) {
			*p = nil
		},
		"current not original": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, p *[]AuthorizationProfile, _ *AuthorizationRequest) {
			*p = []AuthorizationProfile{current}
		},
		"no compilation": func(_ *PolicyDocument, c *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, _ *AuthorizationRequest) {
			*c = PolicyCompilation{}
		},
		"stale request": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, r *AuthorizationRequest) {
			r.Profile.Revision--
		},
		"implicit mode": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, r *AuthorizationRequest) {
			r.ResourceMode = ""
		},
		"instance usage": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, r *AuthorizationRequest) {
			r.CollectionUsage = AuthorizationCollectionList
		},
		"missing request identity": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, r *AuthorizationRequest) {
			r.RequestID = ""
		},
		"missing correlation": func(_ *PolicyDocument, _ *PolicyCompilation, _ *string, _ *[]AuthorizationProfile, r *AuthorizationRequest) {
			r.CorrelationID = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changedDocument PolicyDocument
			var changedCompilation PolicyCompilation
			encoded, _ := json.Marshal(document)
			compiled, _ := json.Marshal(compilation)
			if json.Unmarshal(encoded, &changedDocument) != nil || json.Unmarshal(compiled, &changedCompilation) != nil {
				t.Fatal("invalid fixture")
			}
			changedDigest, profiles, changedRequest := digest, []AuthorizationProfile{frozen}, request
			change(&changedDocument, &changedCompilation, &changedDigest, &profiles, &changedRequest)
			if err := CheckPolicyCompilationRequest(changedDocument, changedCompilation, changedDigest, profiles, current, changedRequest, SubjectUser); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("malformed commitment/request was ignored for a different action", err)
			}
		})
	}
	if after, afterDigest, err := CanonicalizePolicyCompilation(document, compilation, []AuthorizationProfile{frozen}); err != nil || after != canonical || afterDigest != digest {
		t.Fatal("current compatibility changed frozen content", err)
	}
	if _, registered := LookupAuthorizationProfile("widgets"); registered {
		t.Fatal("pure compatibility check registered a product")
	}
}

func TestPolicyCompilationAndCurrentValidationShareCapabilities(t *testing.T) {
	for _, action := range AllActions() {
		definition, _ := LookupActionDefinition(action)
		for _, effect := range []PolicyEffect{PolicyAllow, PolicyDeny} {
			document := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: definition.AuthorityScope,
				Statements: []PolicyStatement{{SID: "one", Effect: effect, Actions: []Action{action}, Resources: []PolicyResourceSelector{{Kind: definition.ResourceKind, Match: PolicyResourceAnyInAuthority}}}}}
			canonical, _, currentErr := CanonicalizePolicyDocument(document)
			compiled, compileErr := CompilePolicyDocument(document, AllAuthorizationProfiles())
			if (currentErr == nil) != (compileErr == nil) {
				t.Fatalf("action %s has two policy grammars: %v / %v", action, currentErr, compileErr)
			}
			if currentErr != nil {
				continue
			}
			encoded, _, err := CanonicalizePolicyCompilation(document, compiled, AllAuthorizationProfiles())
			if err != nil || !strings.Contains(encoded, `"document":`+canonical+`,`) {
				t.Fatal("current and explicit declarations changed document encoding", err)
			}
		}
	}
}

func TestPolicyCompilationCannotBorrowCurrentProfileCapabilities(t *testing.T) {
	profile, _ := LookupAuthorizationProfile(ProductPaaS)
	document := policyDocumentFixture()
	document.Statements = document.Statements[:1]
	document.Statements[0].Actions = []Action{ActionPaaSApplicationRead}
	document.Statements[0].Resources = []PolicyResourceSelector{{Kind: ResourceApplication, Match: PolicyResourcePrefixInAuthority, ID: "app-"}}
	document.Statements[0].Conditions = []PolicyCondition{{Key: ConditionIAMPrincipalID, Operator: PolicyStringEquals, Values: []string{"user-one"}}}
	if ValidatePolicyDocument(document) != nil {
		t.Fatal("current source must support the fixture capabilities")
	}
	for _, capability := range []string{"prefix", "condition", "action"} {
		t.Run(capability, func(t *testing.T) {
			restricted := cloneAuthorizationProfile(profile)
			for index := range restricted.Actions {
				if restricted.Actions[index].Action != ActionPaaSApplicationRead {
					continue
				}
				switch capability {
				case "prefix":
					restricted.Actions[index].ResourceShapes[0].PrefixAllowed = false
				case "condition":
					restricted.Actions[index].Conditions = nil
				case "action":
					restricted.Actions = append(restricted.Actions[:index], restricted.Actions[index+1:]...)
				}
				break
			}
			if _, err := CompilePolicyDocument(document, []AuthorizationProfile{restricted}); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("explicit historical capability borrowed from global current catalog")
			}
		})
	}
	large := PolicyDocument{LanguageVersion: PolicyLanguageVersion, Scope: AuthorityScopeTenant}
	for index := 0; index < MaxPolicyStatements; index++ {
		statement := PolicyStatement{SID: fmt.Sprintf("statement-%d", index), Effect: PolicyAllow, Actions: []Action{ActionPaaSApplicationRead}}
		for resource := 0; resource < MaxStatementResources; resource++ {
			statement.Resources = append(statement.Resources, PolicyResourceSelector{Kind: ResourceApplication, Match: PolicyResourceExact, ID: fmt.Sprintf("app-%03d-", resource) + strings.Repeat("x", 112)})
		}
		large.Statements = append(large.Statements, statement)
	}
	if _, err := CompilePolicyDocument(large, []AuthorizationProfile{profile}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("typed compilation bypassed the original author document byte budget")
	}
}

func FuzzPolicyCompilationCanonicalRoundTrip(f *testing.F) {
	document := policyDocumentFixture()
	profiles := AllAuthorizationProfiles()
	current, known := LookupAuthorizationProfile(ProductPaaS)
	request, err := NewAuthorizationRequest(ActionPaaSApplicationRead, ResourceReference{Kind: ResourceApplication, ID: "application-one"},
		AuthorizationResourceInstance, "", "request-one", "correlation-one")
	if !known || err != nil {
		f.Fatal("invalid current request fixture", err)
	}
	keyProfile := cloneAuthorizationProfile(current)
	keyProfile.Revision++
	for index := range keyProfile.Actions {
		if keyProfile.Actions[index].Action == request.Action {
			keyProfile.Actions[index].UserAuthenticationMethods = []UserAuthenticationMethod{UserAuthenticationLoginSession, UserAuthenticationAccessKey}
		}
	}
	_, keyDigest, err := CanonicalizeAuthorizationProfile(keyProfile)
	if err != nil {
		f.Fatal(err)
	}
	keyRequest := request
	keyRequest.Profile = AuthorizationProfileReference{keyProfile.Product, keyProfile.Revision, keyDigest}
	compilation, err := CompilePolicyDocument(document, profiles)
	if err != nil {
		f.Fatal(err)
	}
	encoded, _ := json.Marshal(compilation)
	f.Add(string(encoded))
	f.Add(`{"compilationVersion":"1","profiles":[],"resolvedStatements":[]}`)
	f.Fuzz(func(t *testing.T, source string) {
		value, err := DecodePolicyCompilation(strings.NewReader(source), document, profiles)
		if err != nil {
			return
		}
		canonical, digest, err := CanonicalizePolicyCompilation(document, value, profiles)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		repeated, err := DecodePolicyCompilation(bytes.NewReader(wire), document, profiles)
		if err != nil {
			t.Fatal(err)
		}
		if again, againDigest, err := CanonicalizePolicyCompilation(document, repeated, profiles); err != nil || again != canonical || againDigest != digest {
			t.Fatal("immutable compilation changed after round trip", err)
		}
		if err := CheckPolicyCompilationRequest(document, repeated, digest, profiles, current, request, SubjectUser); err != nil {
			t.Fatal("valid frozen content became incompatible after strict round trip", err)
		}
		if err := CheckPolicyCompilationRequest(document, repeated, "sha256:"+strings.Repeat("0", 64), profiles, current, request, SubjectUser); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("request compatibility ignored the stored whole-content commitment", err)
		}
		if CheckAccessKeyPolicyCompilationRequest(document, repeated, digest, profiles, keyProfile, keyRequest) != nil ||
			CheckAccessKeyPolicyCompilationRequest(document, repeated, "sha256:"+strings.Repeat("0", 64), profiles, keyProfile, keyRequest) == nil {
			t.Fatal("key compatibility lost the original compilation commitment after round trip")
		}
		version := PolicyVersion{PolicyID: "policy-fuzz", ID: "version-fuzz", Document: document, ContentDigest: digest,
			ContractVersion: PolicyVersionCompiledContract, Compilation: &repeated}
		encodedVersion, err := json.Marshal(version)
		if err != nil {
			t.Fatal(err)
		}
		var decodedVersion PolicyVersion
		if json.Unmarshal(encodedVersion, &decodedVersion) != nil {
			t.Fatal("compiled version wire round trip failed")
		}
		if actual, err := CanonicalizePolicyVersion(decodedVersion); err != nil || actual != canonical {
			t.Fatal("version transport lost its complete author/compilation commitment")
		}
	})
}

func TestPolicyResourcePrefixesAreLiteralAndScopeBounded(t *testing.T) {
	document := policyDocumentFixture()
	document.Statements = document.Statements[:1]
	document.Statements[0].Actions = []Action{ActionPaaSApplicationRead}
	document.Statements[0].Resources = []PolicyResourceSelector{{Kind: ResourceApplication, ID: "application-"}}
	for index := range document.Statements[0].Resources {
		document.Statements[0].Resources[index].Match = PolicyResourceMatch("PREFIX_IN_AUTHORITY")
	}
	canonical, digest, err := CanonicalizePolicyDocument(document)
	if err != nil {
		t.Fatal("declared literal resource prefix rejected", err)
	}
	decoded, err := DecodePolicyDocument(strings.NewReader(canonical))
	if err != nil {
		t.Fatal(err)
	}
	if second, secondDigest, err := CanonicalizePolicyDocument(decoded); err != nil || second != canonical || secondDigest != digest {
		t.Fatal("prefix document round trip changed content")
	}
	document.Statements[0].Actions = []Action{ActionPaaSApplicationRead, ActionPaaSApplicationCreate}
	if !errors.Is(ValidatePolicyDocument(document), ErrInvalidPolicy) {
		t.Fatal("instance read capability admitted collection create prefix")
	}
	document.Statements[0].Actions = []Action{ActionPaaSApplicationRead}
	for _, value := range []string{"a", "app-prod-", "A._:-", strings.Repeat("a", 128)} {
		document.Statements[0].Resources[0].ID = value
		if err := ValidatePolicyDocument(document); err != nil {
			t.Fatal("valid literal prefix rejected", err)
		}
	}
	for _, value := range []string{"", "*", "app-*", "app?", "app[ab]", "app/", "app\\", " app", "app\n", "应用", strings.Repeat("a", 129)} {
		document.Statements[0].Resources[0].ID = value
		if !errors.Is(ValidatePolicyDocument(document), ErrInvalidPolicy) {
			t.Fatal("nonliteral or unbounded prefix admitted")
		}
	}
	for _, action := range AllActionDefinitions() {
		if action.ResourcePrefixAllowed {
			continue
		}
		document.Scope = action.AuthorityScope
		document.Statements[0].Actions = []Action{action.Action}
		document.Statements[0].Resources = []PolicyResourceSelector{{Kind: action.ResourceKind, Match: "PREFIX_IN_AUTHORITY", ID: "resource-"}}
		if !errors.Is(ValidatePolicyDocument(document), ErrInvalidPolicy) {
			t.Fatal("prefix crossed tenant policy scope")
		}
	}
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
	version := PolicyVersion{PolicyID: "policy-example", ID: "version-first", Document: decoded, ContentDigest: digest, ContractVersion: PolicyVersionLegacyContract}
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
	prefix := policyDocumentFixture()
	prefix.Statements = prefix.Statements[:1]
	prefix.Statements[0].Actions = []Action{ActionPaaSApplicationRead}
	prefix.Statements[0].Resources = []PolicyResourceSelector{{Kind: ResourceApplication, Match: PolicyResourcePrefixInAuthority, ID: "application-"}}
	prefixCanonical, _, err := CanonicalizePolicyDocument(prefix)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(prefixCanonical)
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
		Version: PolicyVersion{PolicyID: policy.ID, ID: policy.DefaultVersionID, Document: document, ContentDigest: digest, ContractVersion: PolicyVersionLegacyContract}}
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
		PermissionBoundary: UserPermissionBoundary{APIVersion: APIVersion, Kind: "UserPermissionBoundary", AccountID: "account-a", UserID: "user-a", ResourceVersion: 1},
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
			blocked(ActionIAMAccountCreate, ResourceAccount, "collection"),
			blocked(ActionIAMAccountRead, ResourceAccount, "collection"),
			blocked(ActionIAMAccountAliasSet, ResourceAccount, "account-a"),
			blocked(ActionIAMUserList, ResourceAccount, "account-a"),
			blocked(ActionIAMUserCreate, ResourceAccount, "account-a"),
			blocked(ActionIAMPolicyList, ResourceAccount, "account-a"),
			blocked(ActionIAMGroupList, ResourceAccount, "account-a"),
			blocked(ActionIAMGroupCreate, ResourceAccount, "account-a"),
			blocked(ActionIAMRoleList, ResourceAccount, "account-a"),
			blocked(ActionIAMRoleCreate, ResourceAccount, "account-a"),
		}}
	if ValidateCurrentIdentity(identity) != nil {
		t.Fatal("current policy identity rejected")
	}
	for name, mutate := range map[string]func(*CurrentIdentity){
		"missing snapshot":        func(v *CurrentIdentity) { v.PolicySources = nil },
		"missing boundary":        func(v *CurrentIdentity) { v.PermissionBoundary = UserPermissionBoundary{} },
		"foreign boundary":        func(v *CurrentIdentity) { v.PermissionBoundary.AccountID = "account-b" },
		"stale boundary revision": func(v *CurrentIdentity) { v.PermissionBoundary.ResourceVersion++ },
		"another account":         func(v *CurrentIdentity) { v.PolicySources[0].Attachment.AccountID = "account-b" },
		"another user":            func(v *CurrentIdentity) { v.PolicySources[0].Attachment.Target.ID = "user-b" },
		"service carrier":         func(v *CurrentIdentity) { v.PolicySources[0].Attachment.Target.Kind = PolicyTargetService },
		"duplicate attachment":    func(v *CurrentIdentity) { v.PolicySources = append(v.PolicySources, v.PolicySources[0]) },
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
			blocked(ActionIAMUserPermissionBoundarySet, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserPermissionBoundaryRemove, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserSetStatus, ResourceUser, string(user.ID)),
			blocked(ActionIAMUserPasswordReset, ResourceUser, string(user.ID)),
			blocked(ActionIAMPolicyAttachmentCreate, ResourceUser, string(user.ID)),
			blocked(ActionIAMPlatformPolicyAttachmentCreate, ResourceUser, string(user.ID)),
			blocked(ActionIAMPolicyAttachmentRevoke, ResourcePolicyAttachment, string(attachment.ID)),
		}}}}
	if err := ValidateUserList(list); err != nil {
		t.Fatalf("valid directory: %v", err)
	}
	for _, action := range []Action{ActionIAMUserPermissionBoundarySet, ActionIAMUserPermissionBoundaryRemove} {
		changed := list.Items[0]
		changed.Capabilities = nil
		for _, capability := range list.Items[0].Capabilities {
			if capability.Action != action {
				changed.Capabilities = append(changed.Capabilities, capability)
			}
		}
		if ValidateUserAccess(changed) == nil {
			t.Fatal("user projection omitted a boundary management capability")
		}
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
	for _, privateType := range []string{"AccessKeyWrappingKeyring", "AccessKeyWrappingKey", "AccessKeyWrappingScope", "AccessKeyCredential", "AccessKeyAuthorizationEvidence", "AccessKeySignatureParameters", "TOTPKeyring", "TOTPWrappingKey", "TOTPWrappingScope"} {
		if _, exists := iamOpenAPISchemas(t, document)[privateType]; exists {
			t.Fatal("public HTTP contract exposed an installation-private keyring type")
		}
	}
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
	keyPath := mustIAMObject(t, paths["/v1/authorize:access-key"], "signed authorization path")
	keyOperation := mustIAMObject(t, keyPath["post"], "signed authorization operation")
	keySecurity, ok := keyOperation["security"].([]any)
	if !ok || len(keySecurity) != 1 {
		t.Fatal("signed authorization must authenticate one current calling service")
	}
	keyRequirement := mustIAMObject(t, keySecurity[0], "signed authorization security requirement")
	if len(keyRequirement) != 1 || keyRequirement["ServiceCredential"] == nil {
		t.Fatal("signed authorization accepts a session selector or lacks service authentication")
	}
	if _, exists := keyOperation["parameters"]; exists {
		t.Fatal("signed authorization exposes a selector or unsigned parameter")
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

func TestUserPermissionBoundaryContractIsExplicitAndRevisionBound(t *testing.T) {
	set := SetUserPermissionBoundaryRequest{PolicyID: "policy-boundary", PolicyResourceVersion: 2, ResourceVersion: 3, RequestID: "set-boundary"}
	if err := ValidateSetUserPermissionBoundaryRequest(set); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*SetUserPermissionBoundaryRequest){
		func(v *SetUserPermissionBoundaryRequest) { v.PolicyID = "" },
		func(v *SetUserPermissionBoundaryRequest) { v.PolicyResourceVersion = 0 },
		func(v *SetUserPermissionBoundaryRequest) { v.ResourceVersion = 0 },
		func(v *SetUserPermissionBoundaryRequest) { v.ResourceVersion = 9007199254740991 },
		func(v *SetUserPermissionBoundaryRequest) { v.RequestID = "" },
	} {
		invalid := set
		mutate(&invalid)
		if ValidateSetUserPermissionBoundaryRequest(invalid) == nil {
			t.Fatal("invalid boundary mutation accepted")
		}
	}
	remove := RemoveUserPermissionBoundaryRequest{ResourceVersion: 3, RequestID: "remove-boundary"}
	if ValidateRemoveUserPermissionBoundaryRequest(remove) != nil {
		t.Fatal("valid removal rejected")
	}
	remove.ResourceVersion = 9007199254740991
	if ValidateRemoveUserPermissionBoundaryRequest(remove) == nil {
		t.Fatal("nonincrementable removal revision accepted")
	}
	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"accountId":"other",`, `"userId":"other",`, `"scope":"INSTALLATION",`, `"versionId":"other",`, `"policyId":"duplicate",`} {
		var decoded SetUserPermissionBoundaryRequest
		if DecodeRequest(strings.NewReader("{"+field+string(encoded[1:])), &decoded) == nil {
			t.Fatal("boundary selector or duplicate accepted")
		}
	}
	view := UserPermissionBoundary{APIVersion: APIVersion, Kind: "UserPermissionBoundary", AccountID: "account-example", UserID: "user-example", ResourceVersion: 3}
	for _, reference := range []*PolicyVersionReference{nil, {PolicyID: "policy-boundary", VersionID: "version-boundary", ContentDigest: "sha256:" + strings.Repeat("a", 64)}} {
		view.Policy = reference
		if ValidateUserPermissionBoundary(view) != nil {
			t.Fatal("valid boundary projection rejected")
		}
		encoded, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		var decoded UserPermissionBoundary
		if DecodeRequest(bytes.NewReader(encoded), &decoded) != nil || ValidateUserPermissionBoundary(decoded) != nil {
			t.Fatal("boundary round trip failed")
		}
	}
	for _, invalid := range []string{
		`{"apiVersion":"` + APIVersion + `","kind":"UserPermissionBoundary","accountId":"account-example","userId":"user-example","resourceVersion":3}`,
		`{"apiVersion":"` + APIVersion + `","kind":"UserPermissionBoundary","accountId":"account-example","userId":"user-example","resourceVersion":3,"policy":{}}`,
	} {
		var decoded UserPermissionBoundary
		if DecodeRequest(strings.NewReader(invalid), &decoded) == nil && ValidateUserPermissionBoundary(decoded) == nil {
			t.Fatal("missing or corrupt boundary projection treated as unbounded")
		}
	}
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

func TestRoleSessionSecretIsOnceOnly(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	session := RoleSession{APIVersion: APIVersion, Kind: "RoleSession", ID: "role-session-a", AccountID: "account-a", RoleID: "role-a",
		SourceUserID: "user-a", Status: SessionActive, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	secret, err := NewSecret("mx1.RoleSessionTestCredential000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	response := AssumeRoleResponse{Outcome: "APPLIED", Session: session, Credential: secret}
	if _, err := json.Marshal(response); !errors.Is(err, ErrSecretSerialization) {
		t.Fatal("ordinary JSON exposed role credential")
	}
	encoded, err := EncodeAssumeRoleResponse(response)
	if err != nil || !bytes.Contains(encoded, []byte(`"credential"`)) {
		t.Fatal("explicit issuance encoder omitted credential", err)
	}
	response.Outcome = "EQUAL_REPLAY"
	if _, err := EncodeAssumeRoleResponse(response); err == nil {
		t.Fatal("role replay emitted secret")
	}
	response.Credential = Secret{}
	encoded, err = EncodeAssumeRoleResponse(response)
	if err != nil || bytes.Contains(encoded, []byte(`"credential"`)) {
		t.Fatal("role replay included credential field", err)
	}
	response.Outcome = "APPLIED"
	if _, err := EncodeAssumeRoleResponse(response); err == nil {
		t.Fatal("fresh issuance accepted absent credential")
	}
	for _, mutate := range []func(*RoleSession){
		func(s *RoleSession) { s.ID = "" }, func(s *RoleSession) { s.SourceUserID = "" }, func(s *RoleSession) { s.ExpiresAt = s.IssuedAt },
		func(s *RoleSession) { s.ExpiresAt = s.IssuedAt.Add(13 * time.Hour) }, func(s *RoleSession) { s.Status = SessionRevoked },
		func(s *RoleSession) { s.RevokedAt = &now }, func(s *RoleSession) { s.IssuedAt = s.IssuedAt.Add(time.Nanosecond) },
	} {
		invalid := session
		mutate(&invalid)
		if ValidateRoleSession(invalid) == nil {
			t.Fatal("accepted malformed role session")
		}
	}
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
