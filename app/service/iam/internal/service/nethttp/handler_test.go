package nethttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func TestIAMHTTPExposesOnlyCredentialBoundCoreRoutes(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)

	identityRequest := httptest.NewRequest(http.MethodGet, "/v1/service-identity", nil)
	identityRequest.Header.Set("Authorization", "Bearer service-credential")
	identityResponse := httptest.NewRecorder()
	handler.ServeHTTP(identityResponse, identityRequest)
	if identityResponse.Code != http.StatusOK || workflow.identityCalls != 1 {
		t.Fatalf("service identity status=%d calls=%d body=%s", identityResponse.Code, workflow.identityCalls, identityResponse.Body.String())
	}
	if identityResponse.Header().Get("Cache-Control") != "no-store" ||
		identityResponse.Header().Get("Matrix-Request-ID") != "request-http-test" {
		t.Fatalf("IAM security headers = %#v", identityResponse.Header())
	}
	var identity iamv1.ServiceIdentity
	if err := json.Unmarshal(identityResponse.Body.Bytes(), &identity); err != nil || identity != workflow.identity {
		t.Fatalf("decode service identity: identity=%#v err=%v", identity, err)
	}

	for name, target := range map[string]string{
		"tenant selector": "/v1/service-identity?tenantId=forged",
		"source selector": "/v1/service-identity?source=IAM",
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, target, nil)
			request.Header.Set("Authorization", "Bearer service-credential")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || workflow.identityCalls != 1 {
				t.Fatalf("selector response status=%d calls=%d body=%s", response.Code, workflow.identityCalls, response.Body.String())
			}
		})
	}

	authorizeValue, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead, workflow.decision.Resource, iamv1.AuthorizationResourceInstance, "", "request-authorize", "correlation-authorize")
	if err != nil {
		t.Fatal(err)
	}
	authorizeJSON, err := json.Marshal(authorizeValue)
	if err != nil {
		t.Fatal(err)
	}
	authorizeBody := string(authorizeJSON)
	missingSubject := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(authorizeBody))
	missingSubject.Header.Set("Content-Type", "application/json")
	missingSubject.Header.Set("Authorization", "Bearer service-credential")
	missingSubjectResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingSubjectResponse, missingSubject)
	if missingSubjectResponse.Code != http.StatusUnauthorized || workflow.authorizeCalls != 0 {
		t.Fatalf("missing subject status=%d calls=%d", missingSubjectResponse.Code, workflow.authorizeCalls)
	}

	authorizeRequest := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(authorizeBody))
	authorizeRequest.Header.Set("Content-Type", "application/json")
	authorizeRequest.Header.Set("Authorization", "Bearer service-credential")
	authorizeRequest.Header.Set("Matrix-Subject-Credential", "subject-credential")
	authorizeResponse := httptest.NewRecorder()
	handler.ServeHTTP(authorizeResponse, authorizeRequest)
	if authorizeResponse.Code != http.StatusOK || workflow.authorizeCalls != 1 {
		t.Fatalf("authorize status=%d calls=%d body=%s", authorizeResponse.Code, workflow.authorizeCalls, authorizeResponse.Body.String())
	}
	var decision iamv1.AuthorizationDecision
	if err := json.Unmarshal(authorizeResponse.Body.Bytes(), &decision); err != nil || !reflect.DeepEqual(decision, workflow.decision) {
		t.Fatalf("decode authorization decision: decision=%#v err=%v", decision, err)
	}

	verifyValue, err := iamv1.NewAuthorizationRequest(iamv1.ActionInstallationVerify, workflow.verificationDecision.Resource, iamv1.AuthorizationResourceInstance, "", "request-installation-verify", "correlation-installation-verify")
	if err != nil {
		t.Fatal(err)
	}
	verifyJSON, err := json.Marshal(verifyValue)
	if err != nil {
		t.Fatal(err)
	}
	verifyBody := string(verifyJSON)
	verifyRequest := httptest.NewRequest(
		http.MethodPost, "/v1/installation:verify", strings.NewReader(verifyBody),
	)
	verifyRequest.Header.Set("Content-Type", "application/json")
	verifyRequest.Header.Set("Authorization", "Bearer verifier-credential")
	verifyResponse := httptest.NewRecorder()
	handler.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK || workflow.verifyInstallationCalls != 1 {
		t.Fatalf(
			"installation verify status=%d calls=%d body=%s",
			verifyResponse.Code, workflow.verifyInstallationCalls, verifyResponse.Body.String(),
		)
	}
	if err := json.Unmarshal(verifyResponse.Body.Bytes(), &decision); err != nil ||
		!reflect.DeepEqual(decision, workflow.verificationDecision) {
		t.Fatalf("decode installation verification decision: decision=%#v err=%v", decision, err)
	}

	unexpectedSubject := httptest.NewRequest(
		http.MethodPost, "/v1/installation:verify", strings.NewReader(verifyBody),
	)
	unexpectedSubject.Header.Set("Content-Type", "application/json")
	unexpectedSubject.Header.Set("Authorization", "Bearer verifier-credential")
	unexpectedSubject.Header.Set("Matrix-Subject-Credential", "user-session")
	unexpectedSubjectResponse := httptest.NewRecorder()
	handler.ServeHTTP(unexpectedSubjectResponse, unexpectedSubject)
	if unexpectedSubjectResponse.Code != http.StatusBadRequest || workflow.verifyInstallationCalls != 1 {
		t.Fatalf(
			"unexpected installation subject status=%d calls=%d",
			unexpectedSubjectResponse.Code, workflow.verifyInstallationCalls,
		)
	}
}

func TestSignedAuthorizationTransportDoesNotAcceptSubjectSelectors(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	endpoint := newTestHandler(t, workflow)
	request, err := iamv1.NewAuthorizationRequest(iamv1.ActionPaaSApplicationRead, iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-signed"}, iamv1.AuthorizationResourceInstance, "", "signed-request", "signed-correlation")
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := iamv1.NewSecret(strings.Repeat("A", 22))
	signature, _ := iamv1.NewSecret(strings.Repeat("A", 43))
	input := iamv1.AccessKeyAuthorizationRequest{Authorization: request, SignedRequest: iamv1.AccessKeySignedRequest{
		Parameters: iamv1.AccessKeySignatureParameters{AccessKeyID: "key-one", InstallationID: "installation-one", Audience: "paas", SignedAt: 1700000000, Nonce: nonce},
		HTTP: iamv1.AccessKeyHTTPRequest{Method: "GET", Scheme: "https", Authority: "fixture.invalid:443", EscapedPath: "/api/paas/v1/applications/application-signed",
			BodyDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}, Signature: signature}}
	body, err := iamv1.EncodeAccessKeyAuthorizationRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	for _, name := range []string{"valid", "subject-header", "duplicate-bearer", "query-selector", "body-selector", "encoding", "method", "media"} {
		t.Run(name, func(t *testing.T) {
			wire := body
			if name == "body-selector" {
				wire = append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"tenantId":"another-account"}`)...)
				defer clear(wire)
			}
			r := httptest.NewRequest(http.MethodPost, "/v1/authorize:access-key", bytes.NewReader(wire))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer service-credential")
			want := http.StatusBadRequest
			switch name {
			case "valid":
				want = http.StatusOK
			case "subject-header":
				r.Header.Set("Matrix-Subject-Credential", "cannot-select-a-user")
			case "duplicate-bearer":
				r.Header.Add("Authorization", "Bearer another-service")
				want = http.StatusUnauthorized
			case "query-selector":
				r.URL.RawQuery = "tenantId=another-account"
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
				want = http.StatusUnsupportedMediaType
			case "method":
				r.Method = http.MethodGet
				want = http.StatusMethodNotAllowed
			case "media":
				r.Header.Set("Content-Type", "application/json; charset=utf-8")
				want = http.StatusUnsupportedMediaType
			}
			before := workflow.keyCalls
			response := httptest.NewRecorder()
			endpoint.ServeHTTP(response, r)
			if response.Code != want {
				t.Fatalf("transport status=%d want=%d", response.Code, want)
			}
			if name == "valid" {
				result, err := iamv1.DecodeAccessKeyAuthorization(bytes.NewReader(response.Body.Bytes()))
				if err != nil || iamv1.CheckAccessKeyAuthorizationForRequest(result, input) != nil || workflow.keyCalls != before+1 || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("signed wire or sanitized response differs", err)
				}
			} else if workflow.keyCalls != before {
				t.Fatal("invalid transport reached authority")
			}
		})
	}
}

func TestIAMHTTPAuthorizationProfileDiscoveryRequiresUserSession(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	for _, test := range []struct {
		name, method, suffix, body, bearer string
		status                             int
	}{
		{"current metadata", http.MethodGet, "", "", "catalog-session", http.StatusOK},
		{"no bearer", http.MethodGet, "", "", "", http.StatusUnauthorized},
		{"account selector", http.MethodGet, "?accountId=other", "", "catalog-session", http.StatusBadRequest},
		{"history selector", http.MethodGet, "?revision=1", "", "catalog-session", http.StatusBadRequest},
		{"scope body", http.MethodGet, "", `{"scope":"INSTALLATION"}`, "catalog-session", http.StatusBadRequest},
		{"registration", http.MethodPost, "", `{}`, "catalog-session", http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := workflow.policyCalls
			request := httptest.NewRequest(test.method, "/v1/authorization-profiles"+test.suffix, strings.NewReader(test.body))
			if test.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			request.Header.Set("Matrix-Tenant-ID", "forged-account")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("discovery status=%d want=%d", response.Code, test.status)
			}
			if test.status == http.StatusOK {
				wantedCredential, _ := iamv1.NewSecret(test.bearer)
				if workflow.policyCalls != before+1 || workflow.policyCredential != wantedCredential || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("discovery lost its authenticated noncacheable workflow")
				}
				var result map[string]json.RawMessage
				if json.Unmarshal(response.Body.Bytes(), &result) != nil || string(result["kind"]) != `"AuthorizationProfileList"` || string(result["accountId"]) != `"account-catalog"` || len(result) != 4 {
					t.Fatal("discovery lost its strict current account envelope")
				}
			} else if workflow.policyCalls != before {
				t.Fatal("invalid discovery request reached the authority workflow")
			}
		})
	}
}

func TestIAMHTTPAuthorizationProfileDiscoveryRejectsInvalidMetadata(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure error
		invalid bool
		status  int
	}{
		{"unauthenticated", identityaccess.ErrUnauthenticated, false, http.StatusUnauthorized},
		{"forbidden", identityaccess.ErrForbidden, false, http.StatusForbidden},
		{"unavailable", identityaccess.ErrUnavailable, false, http.StatusServiceUnavailable},
		{"invalid metadata", nil, true, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			workflow := newHTTPWorkflow(t)
			workflow.profileErr, workflow.invalidProfile = test.failure, test.invalid
			request := httptest.NewRequest(http.MethodGet, "/v1/authorization-profiles", nil)
			request.Header.Set("Authorization", "Bearer catalog-session")
			response := httptest.NewRecorder()
			newTestHandler(t, workflow).ServeHTTP(response, request)
			if response.Code != test.status || workflow.policyCalls != 1 || strings.Contains(response.Body.String(), "AuthorizationProfileList") || strings.Contains(response.Body.String(), "contentDigest") {
				t.Fatal("directory failure leaked partial metadata or bypassed authority")
			}
		})
	}
}

func TestIAMHTTPPolicyDirectoriesDeriveScopeOnlyFromRoute(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	for _, route := range []string{"/v1/policies", "/v1/platform-policies"} {
		for _, test := range []struct {
			name, method, suffix, body, bearer string
			status                             int
		}{
			{"read", http.MethodGet, "", "", "catalog-session", http.StatusOK},
			{"query scope", http.MethodGet, "?scope=INSTALLATION", "", "catalog-session", http.StatusBadRequest},
			{"query account", http.MethodGet, "?accountId=other", "", "catalog-session", http.StatusBadRequest},
			{"body selector", http.MethodGet, "", `{"installationId":"other"}`, "catalog-session", http.StatusBadRequest},
			{"missing bearer", http.MethodGet, "", "", "", http.StatusUnauthorized},
			{"wrong method", http.MethodPut, "", "", "catalog-session", http.StatusMethodNotAllowed},
		} {
			t.Run(route+"/"+test.name, func(t *testing.T) {
				before := workflow.policyCalls
				request := httptest.NewRequest(test.method, route+test.suffix, strings.NewReader(test.body))
				if test.bearer != "" {
					request.Header.Set("Authorization", "Bearer "+test.bearer)
				}
				request.Header.Set("Matrix-Tenant-ID", "forged-header")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != test.status {
					t.Fatalf("status=%d want=%d", response.Code, test.status)
				}
				if test.status != http.StatusOK {
					if workflow.policyCalls != before {
						t.Fatal("invalid request reached directory workflow")
					}
					return
				}
				wantedCredential, _ := iamv1.NewSecret(test.bearer)
				if workflow.policyCalls != before+1 || workflow.policyPlatform != (route == "/v1/platform-policies") || workflow.policyCredential != wantedCredential {
					t.Fatal("directory route or credential changed")
				}
				var result iamv1.PolicyList
				if json.Unmarshal(response.Body.Bytes(), &result) != nil || iamv1.ValidatePolicyList(result) != nil || result.AccountID != "account-catalog" {
					t.Fatal("directory lost authoritative account")
				}
			})
		}
	}
}

func TestIAMHTTPStrictDecodingAndRedactedProblems(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)

	loginRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"loginName":"admin","password":"Initial-Admin-Password-49!","requestId":"request-login"}`),
	)
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK || workflow.loginCalls != 1 ||
		!bytes.Contains(loginResponse.Body.Bytes(), []byte("issued-session-credential")) ||
		!bytes.Contains(loginResponse.Body.Bytes(), []byte(`"mustChangePassword":true`)) {
		t.Fatalf("login status=%d calls=%d body=%s", loginResponse.Code, workflow.loginCalls, loginResponse.Body.String())
	}

	unknownFieldRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"loginName":"admin","password":"Initial-Admin-Password-49!","requestId":"request-login","tenantId":"forged"}`),
	)
	unknownFieldRequest.Header.Set("Content-Type", "application/json")
	unknownFieldResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownFieldResponse, unknownFieldRequest)
	if unknownFieldResponse.Code != http.StatusBadRequest || workflow.loginCalls != 1 {
		t.Fatalf("unknown field status=%d calls=%d body=%s", unknownFieldResponse.Code, workflow.loginCalls, unknownFieldResponse.Body.String())
	}

	oversizedRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"loginName":"admin","password":"`+strings.Repeat("A", int(iamv1.MaxRequestBytes))+`","requestId":"request-login"}`),
	)
	oversizedRequest.Header.Set("Content-Type", "application/json")
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversizedRequest)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge || workflow.loginCalls != 1 {
		t.Fatalf("oversized status=%d calls=%d body=%s", oversizedResponse.Code, workflow.loginCalls, oversizedResponse.Body.String())
	}

	workflow.loginErr = errors.New("native failure contains Initial-Admin-Password-49!")
	failureRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"loginName":"admin","password":"Initial-Admin-Password-49!","requestId":"request-failure"}`),
	)
	failureRequest.Header.Set("Content-Type", "application/json")
	failureResponse := httptest.NewRecorder()
	handler.ServeHTTP(failureResponse, failureRequest)
	if failureResponse.Code != http.StatusServiceUnavailable ||
		bytes.Contains(failureResponse.Body.Bytes(), []byte("Initial-Admin-Password")) ||
		bytes.Contains(failureResponse.Body.Bytes(), []byte("native failure")) {
		t.Fatalf("failure leaked internal data: status=%d body=%s", failureResponse.Code, failureResponse.Body.String())
	}
	var problem iamv1.Problem
	if err := json.Unmarshal(failureResponse.Body.Bytes(), &problem); err != nil || iamv1.ValidateProblem(problem) != nil {
		t.Fatalf("decode normalized IAM problem: problem=%#v err=%v", problem, err)
	}

	methodResponse := httptest.NewRecorder()
	handler.ServeHTTP(methodResponse, httptest.NewRequest(http.MethodGet, "/v1/auth/login", nil))
	if methodResponse.Code != http.StatusMethodNotAllowed || methodResponse.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("method response status=%d allow=%q", methodResponse.Code, methodResponse.Header().Get("Allow"))
	}
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, httptest.NewRequest(http.MethodGet, "/debug", nil))
	if missingResponse.Code != http.StatusNotFound {
		t.Fatalf("unknown route status=%d body=%s", missingResponse.Code, missingResponse.Body.String())
	}
}

func TestIAMOwnSessionRoutesRejectSelectorsBeforeWorkflow(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	for _, test := range []struct {
		method, target, body string
		bearer               bool
		status               int
	}{
		{http.MethodGet, "/v1/auth/sessions", "", true, http.StatusOK},
		{http.MethodGet, "/v1/auth/sessions", "", false, http.StatusUnauthorized},
		{http.MethodGet, "/v1/auth/sessions?userId=foreign", "", true, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/sessions?accountId=foreign", "", true, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/sessions?currentSessionId=other", "", true, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/sessions?after=ic1.one&after=ic1.two", "", true, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/sessions?after=session-id", "", true, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/sessions", `{}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions", `{}`, true, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/auth/sessions/other:revoke", `{"requestId":"revoke-own"}`, true, http.StatusOK},
		{http.MethodPost, "/v1/auth/sessions/other:revoke", `{"requestId":"revoke-own"}`, false, http.StatusUnauthorized},
		{http.MethodPost, "/v1/auth/sessions/other:revoke?userId=foreign", `{"requestId":"revoke-own"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions/other:revoke", `{"requestId":"revoke-own","currentSessionId":"foreign"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions/other:revoke", `{"requestId":"revoke-own","accountId":"foreign"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions/other:revoke", `{"requestId":"one","requestId":"two"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions/nested/other:revoke", `{"requestId":"revoke-own"}`, true, http.StatusNotFound},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"revoke-others"}`, true, http.StatusOK},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"revoke-others"}`, false, http.StatusUnauthorized},
		{http.MethodGet, "/v1/auth/sessions:revoke-others", "", true, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/auth/sessions:revoke-others?userId=foreign", `{"requestId":"revoke-others"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"revoke-others","currentSessionId":"foreign"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"revoke-others","accountId":"foreign"}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"revoke-others","sessionIds":[]}`, true, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/sessions:revoke-others", `{"requestId":"one","requestId":"two"}`, true, http.StatusBadRequest},
	} {
		before := workflow.ownSessionCalls
		request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
		if test.bearer {
			request.Header.Set("Authorization", "Bearer actual-login-credential")
		}
		if test.body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || (response.Code != http.StatusOK && workflow.ownSessionCalls != before) {
			t.Fatalf("%s %s status=%d want=%d or rejected input reached workflow", test.method, test.target, response.Code, test.status)
		}
		if response.Code == http.StatusOK && (response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "actual-login-credential")) {
			t.Fatal("own session response exposed or cached authentication material")
		}
	}
}

func TestIAMHTTPManagementCommandsRequireCurrentSession(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	requests := []struct {
		name   string
		target string
		body   string
		status int
	}{
		{
			name: "change password", target: "/v1/auth/password", status: http.StatusOK,
			body: `{"currentPassword":"Initial-Admin-Password-49!","newPassword":"Changed-Admin-Password-73!","requestId":"request-password"}`,
		},
		{
			name: "create user", target: "/v1/users", status: http.StatusCreated,
			body: `{"loginName":"developer","displayName":"Developer","initialPassword":"Initial-Developer-Password-84!","requestId":"request-user"}`,
		},
		{
			name: "put binding", target: "/v1/policy-attachments", status: http.StatusOK,
			body: `{"target":{"kind":"USER","id":"principal-user"},"policyId":"system.paas-developer","policyResourceVersion":1,"requestId":"request-binding"}`,
		},
		{
			name: "revoke binding", target: "/v1/policy-attachments/binding-user:revoke", status: http.StatusOK,
			body: `{"resourceVersion":1,"requestId":"request-binding-revoke"}`,
		},
		{
			name: "revoke session", target: "/v1/sessions/session-user:revoke", status: http.StatusOK,
			body: `{"requestId":"request-session-revoke"}`,
		},
		{
			name: "logout", target: "/v1/auth/logout", status: http.StatusOK,
			body: `{"requestId":"request-logout"}`,
		},
	}
	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.target, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer user-session-credential")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || bytes.Contains(response.Body.Bytes(), []byte("Password-")) {
				t.Fatalf("management response status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}

	missingCredential := httptest.NewRequest(
		http.MethodPost,
		"/v1/users",
		strings.NewReader(`{"loginName":"developer","displayName":"Developer","initialPassword":"Initial-Developer-Password-84!","requestId":"request-user"}`),
	)
	missingCredential.Header.Set("Content-Type", "application/json")
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missingCredential)
	if missingResponse.Code != http.StatusUnauthorized {
		t.Fatalf("missing management credential status=%d body=%s", missingResponse.Code, missingResponse.Body.String())
	}

	invalidPath := httptest.NewRequest(
		http.MethodPost,
		"/v1/sessions/not/one-id:revoke",
		strings.NewReader(`{"requestId":"request-session-revoke"}`),
	)
	invalidPath.Header.Set("Content-Type", "application/json")
	invalidPath.Header.Set("Authorization", "Bearer user-session-credential")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalidPath)
	if invalidResponse.Code != http.StatusNotFound {
		t.Fatalf("invalid command path status=%d body=%s", invalidResponse.Code, invalidResponse.Body.String())
	}
}

func TestIAMAccountRoutesRejectSelectorsAndMissingCredentialsBeforeWorkflow(t *testing.T) {
	handler := newTestHandler(t, newHTTPWorkflow(t))
	for _, target := range []string{"/v1/auth/me", "/v1/users", "/v1/accounts", "/v1/accounts/account-a"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s status=%d", target, response.Code)
		}
	}
	for _, target := range []string{"/v1/account:alias", "/v1/accounts", "/v1/users/user-a:set-status", "/v1/users/user-a:reset-password", "/v1/accounts/account-a:set-status", "/v1/accounts/account-a:recover-root-credentials"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{}`)))
		if response.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s status=%d", target, response.Code)
		}
	}
	for _, target := range []string{"/v1/auth/me?tenantId=forged", "/v1/users?tenantId=forged", "/v1/accounts/account-a?tenantId=forged", "/v1/accounts?after=a&after=b", "/v1/users?after=", "/v1/users?after=%2f", "/v1/users?after=" + strings.Repeat("a", 513)} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer only-test-credential")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("forged selector %s status=%d", target, response.Code)
		}
	}
	for _, target := range []string{"/v1/organizations", "/v1/organizations/account-a", "/v1/organization:alias", "/v1/principals", "/v1/principals/user-a:set-status"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer only-test-credential")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Errorf("removed route %s status=%d", target, response.Code)
		}
	}
}

func TestIAMHTTPUserDetailUpdateAndDeleteAreBoundToTheRoute(t *testing.T) {
	workflow := newHTTPWorkflow(t)
	handler := newTestHandler(t, workflow)
	bearer := "user-session-credential"

	detailRequest := httptest.NewRequest(http.MethodGet, "/v1/users/principal-user", nil)
	detailRequest.Header.Set("Authorization", "Bearer "+bearer)
	detailResponse := httptest.NewRecorder()
	handler.ServeHTTP(detailResponse, detailRequest)
	if detailResponse.Code != http.StatusOK || workflow.getUserCalls != 1 || workflow.userID != "principal-user" {
		t.Fatalf("user detail status=%d calls=%d id=%q body=%s", detailResponse.Code, workflow.getUserCalls, workflow.userID, detailResponse.Body.String())
	}
	var detail iamv1.UserAccess
	if json.Unmarshal(detailResponse.Body.Bytes(), &detail) != nil || iamv1.ValidateUserAccess(detail) != nil || detail.User.ID != "principal-user" {
		t.Fatal("user detail response is not the exact validated resource")
	}

	updateBody := `{"displayName":"Renamed Developer","resourceVersion":7,"requestId":"request-user-update"}`
	updateRequest := httptest.NewRequest(http.MethodPost, "/v1/users/principal-user:update", strings.NewReader(updateBody))
	updateRequest.Header.Set("Authorization", "Bearer "+bearer)
	updateRequest.Header.Set("Content-Type", "application/json")
	updateResponse := httptest.NewRecorder()
	handler.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK || workflow.updateUserCalls != 1 || workflow.updateUser.DisplayName != "Renamed Developer" ||
		workflow.updateUser.ResourceVersion != 7 || workflow.updateUser.RequestID != "request-user-update" {
		t.Fatalf("user update status=%d calls=%d request=%#v body=%s", updateResponse.Code, workflow.updateUserCalls, workflow.updateUser, updateResponse.Body.String())
	}

	deleteBody := `{"resourceVersion":8,"requestId":"request-user-delete"}`
	deleteRequest := httptest.NewRequest(http.MethodPost, "/v1/users/principal-user:delete", strings.NewReader(deleteBody))
	deleteRequest.Header.Set("Authorization", "Bearer "+bearer)
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusOK || workflow.deleteUserCalls != 1 || workflow.deleteUser.ResourceVersion != 8 ||
		workflow.deleteUser.RequestID != "request-user-delete" || bytes.Contains(deleteResponse.Body.Bytes(), []byte("password")) {
		t.Fatalf("user deletion status=%d calls=%d request=%#v body=%s", deleteResponse.Code, workflow.deleteUserCalls, workflow.deleteUser, deleteResponse.Body.String())
	}
	var deletion iamv1.UserDeletion
	if json.Unmarshal(deleteResponse.Body.Bytes(), &deletion) != nil || iamv1.ValidateUserDeletion(deletion) != nil || deletion.ID != "principal-user" {
		t.Fatal("user deletion response is not a valid non-secret receipt")
	}

	for _, test := range []struct {
		name, method, target, body string
		status                     int
	}{
		{"detail query selector", http.MethodGet, "/v1/users/principal-user?accountId=forged", "", http.StatusBadRequest},
		{"detail body selector", http.MethodGet, "/v1/users/principal-user", `{"accountId":"forged"}`, http.StatusBadRequest},
		{"update query selector", http.MethodPost, "/v1/users/principal-user:update?tenantId=forged", updateBody, http.StatusBadRequest},
		{"update body selector", http.MethodPost, "/v1/users/principal-user:update", `{"displayName":"Renamed Developer","resourceVersion":7,"requestId":"request-user-update","accountId":"forged"}`, http.StatusBadRequest},
		{"delete body selector", http.MethodPost, "/v1/users/principal-user:delete", `{"resourceVersion":8,"requestId":"request-user-delete","principalId":"forged"}`, http.StatusBadRequest},
		{"unknown command", http.MethodPost, "/v1/users/principal-user:transfer", `{}`, http.StatusNotFound},
		{"unsupported method", http.MethodPut, "/v1/users/principal-user", "", http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			beforeGet, beforeUpdate, beforeDelete := workflow.getUserCalls, workflow.updateUserCalls, workflow.deleteUserCalls
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+bearer)
			if test.method == http.MethodPost {
				request.Header.Set("Content-Type", "application/json")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || workflow.getUserCalls != beforeGet || workflow.updateUserCalls != beforeUpdate || workflow.deleteUserCalls != beforeDelete {
				t.Fatalf("invalid user request status=%d want=%d workflow=%d/%d/%d body=%s", response.Code, test.status, workflow.getUserCalls, workflow.updateUserCalls, workflow.deleteUserCalls, response.Body.String())
			}
			if test.method == http.MethodPut && response.Header().Get("Allow") != "GET, POST" {
				t.Fatalf("user route allow=%q", response.Header().Get("Allow"))
			}
		})
	}
}

type httpWorkflow struct {
	Workflow
	policyCalls             int
	ownSessionCalls         int
	policyPlatform          bool
	policyCredential        iamv1.Secret
	profileErr              error
	invalidProfile          bool
	readiness               iamv1.Readiness
	status                  iamv1.BootstrapStatus
	identity                iamv1.ServiceIdentity
	login                   iamv1.LoginResponse
	decision                iamv1.AuthorizationDecision
	verificationDecision    iamv1.AuthorizationDecision
	loginErr                error
	identityCalls           int
	loginCalls              int
	getUserCalls            int
	updateUserCalls         int
	deleteUserCalls         int
	userID                  iamv1.PrincipalID
	updateUser              iamv1.UpdateUserRequest
	deleteUser              iamv1.DeleteUserRequest
	authorizeCalls          int
	keyCalls                int
	verifyInstallationCalls int
}

func (value *httpWorkflow) ListAuthorizationProfiles(_ context.Context, credential iamv1.Secret, _ string) (iamv1.AuthorizationProfileList, error) {
	value.policyCalls++
	value.policyCredential = credential
	profile, _ := iamv1.LookupAuthorizationProfile(iamv1.ProductIAM)
	_, digest, _ := iamv1.CanonicalizeAuthorizationProfile(profile)
	if value.invalidProfile {
		digest = "invalid-digest"
	}
	return iamv1.AuthorizationProfileList{APIVersion: iamv1.APIVersion, Kind: "AuthorizationProfileList", AccountID: "account-catalog",
		Items: []iamv1.AuthorizationProfileEntry{{Profile: profile, ContentDigest: digest}}}, value.profileErr
}

func (value *httpWorkflow) ListPolicies(_ context.Context, credential iamv1.Secret, platform bool, _ string) (iamv1.PolicyList, error) {
	value.policyCalls++
	value.policyPlatform, value.policyCredential = platform, credential
	result := iamv1.PolicyList{APIVersion: iamv1.APIVersion, Kind: "PolicyList", AccountID: "account-catalog", Scope: iamv1.AuthorityScopeTenant, Items: []iamv1.Policy{}}
	if platform {
		result.Scope, result.InstallationID = iamv1.AuthorityScopeInstallation, "installation-catalog"
	}
	return result, nil
}

func TestIAMRoleRoutesRejectSelectorsBeforeWorkflow(t *testing.T) {
	handler := newTestHandler(t, newHTTPWorkflow(t))
	for _, attack := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/v1/roles?tenantId=other", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/roles/role-a?accountId=other", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/roles/role-a/trust-versions?roleId=other", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/roles/role-a/trust-versions/trust-a?after=ic1.invalid", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/roles", "{}", http.StatusBadRequest},
		{http.MethodPost, "/v1/roles", `{"name":"Readers","tags":[],"trustPolicy":{"languageVersion":"1","statements":[]},"accountId":"other","requestId":"create"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/roles", `{"name":"Readers","tags":[],"maxSessionDurationSeconds":null,"trustPolicy":{"languageVersion":"1","statements":[]},"requestId":"create"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/roles", `{"name":"Readers","name":"Other","tags":[],"trustPolicy":{"languageVersion":"1","statements":[]},"requestId":"create"}`, http.StatusBadRequest},
		{http.MethodPatch, "/v1/roles/role-a", `{"name":"Readers","tags":[],"maxSessionDurationSeconds":3600,"resourceVersion":1,"requestId":"update"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/roles/role-a:set-status", `{"status":"ACTIVE","resourceVersion":1,"actorSessionId":"other","requestId":"status"}`, http.StatusBadRequest},
		{http.MethodDelete, "/v1/roles/role-a?installationId=other", `{"resourceVersion":1,"requestId":"delete"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/roles/role-a:assume", `{}`, http.StatusUnprocessableEntity},
		{http.MethodPost, "/v1/roles/role-a:assume", `{"resourceVersion":1,"requestId":"x","sourceSessionId":"injected"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/roles/role-a:assume?tenantId=other", `{"resourceVersion":1,"requestId":"x"}`, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/role-sessions/by-request/x?userId=other", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/role-session?roleId=other", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/assumable-roles?accountId=other", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/assumable-roles?userId=other", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/assumable-roles?sourceSessionId=other", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/assumable-roles?after=ic1.management", ``, http.StatusBadRequest},
		{http.MethodGet, "/v1/auth/assumable-roles", `{"sourceUserId":"other"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/assumable-roles", `{}`, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/auth/role-session", `{"sourceUserId":"other"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/role-session", `{}`, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/auth/role-sessions/by-request/x:revoke", `{"requestId":"y","roleId":"injected"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/sts/assume-role", `{}`, http.StatusNotFound},
		{http.MethodPost, "/v1/roles/role-a/trust-policy", `{}`, http.StatusMethodNotAllowed},
	} {
		t.Run(attack.method+attack.path+attack.body, func(t *testing.T) {
			request := httptest.NewRequest(attack.method, attack.path, strings.NewReader(attack.body))
			request.Header.Set("Authorization", "Bearer role-test-credential")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != attack.status {
				t.Fatalf("role request status=%d want=%d", response.Code, attack.status)
			}
		})
	}
}

func TestIAMGroupRoutesRejectSelectorsBeforeWorkflow(t *testing.T) {
	handler := newTestHandler(t, newHTTPWorkflow(t))
	for _, attack := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/v1/groups?tenantId=other", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/groups/g1?accountId=other", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/groups/g1/memberships?groupId=g2", "", http.StatusBadRequest},
		{http.MethodGet, "/v1/groups", "{}", http.StatusBadRequest},
		{http.MethodPost, "/v1/groups", `{"name":"group","requestId":"request","accountId":"other"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/groups/g1/memberships", `{"userId":"u1","requestId":"request","kind":"ROLE"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/groups/g1:update", `{"name":"changed","resourceVersion":1,"requestId":"request","policies":[]}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/groups/g1:delete?installationId=other", `{"resourceVersion":1,"requestId":"request"}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/groups/g1/memberships/m1:remove", `{"resourceVersion":1,"requestId":"request","userId":"u2"}`, http.StatusBadRequest},
		{http.MethodDelete, "/v1/groups/g1", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/groups/g1/memberships/m1:activate", "{}", http.StatusNotFound},
	} {
		t.Run(attack.method+attack.path, func(t *testing.T) {
			request := httptest.NewRequest(attack.method, attack.path, strings.NewReader(attack.body))
			request.Header.Set("Authorization", "Bearer group-test-credential")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != attack.status {
				t.Fatalf("group request status=%d want=%d body=%s", response.Code, attack.status, response.Body.String())
			}
		})
	}
}

func newHTTPWorkflow(t *testing.T) *httpWorkflow {
	t.Helper()
	now := time.Date(2026, 8, 26, 9, 10, 11, 123000, time.UTC)
	appliedAt := now.Add(-time.Hour)
	credential, err := iamv1.NewSecret("issued-session-credential")
	if err != nil {
		t.Fatalf("create HTTP test credential: %v", err)
	}
	subject := &iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-admin"}
	workflow := &httpWorkflow{
		readiness: iamv1.Readiness{
			APIVersion:    iamv1.APIVersion,
			Kind:          "Readiness",
			State:         iamv1.ReadinessReady,
			SchemaVersion: 1,
			CheckedAt:     now,
		},
		status: iamv1.BootstrapStatus{
			APIVersion:     iamv1.APIVersion,
			Kind:           "BootstrapStatus",
			State:          iamv1.BootstrapReady,
			InstallationID: "installation-example",
			AccountID:      "organization-example",
			ContentDigest:  "sha256:" + strings.Repeat("1", 64),
			AppliedAt:      &appliedAt,
		},
		identity: iamv1.ServiceIdentity{
			InstallationID: "installation-example",
			APIVersion:     iamv1.APIVersion,
			Kind:           "ServiceIdentity",
			AccountID:      "organization-example",
			PrincipalID:    "service-paas",
			Purpose:        iamv1.ServicePaaS,
		},
		login: iamv1.LoginResponse{
			Session: iamv1.Session{
				APIVersion:  iamv1.APIVersion,
				Kind:        "Session",
				ID:          "session-example",
				AccountID:   "organization-example",
				PrincipalID: "principal-admin",
				Status:      iamv1.SessionActive,
				IssuedAt:    now,
				ExpiresAt:   now.Add(time.Hour),
			},
			Credential:         credential,
			MustChangePassword: true,
		},
		decision: iamv1.AuthorizationDecision{
			APIVersion: iamv1.APIVersion,
			Kind:       "AuthorizationDecision",
			ID:         "decision-example",
			Allowed:    true,
			Reason:     iamv1.DecisionAllowed,
			TenantID:   "organization-example",
			Subject:    subject,
			Action:     iamv1.ActionPaaSApplicationRead,
			Resource:   iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "application-example"},
			RequestID:  "request-authorize",
			DecidedAt:  now,
		},
	}
	verificationSubject := &iamv1.Subject{
		Type: iamv1.SubjectServiceAccount, ID: "service-installation-verifier",
	}
	workflow.verificationDecision = iamv1.AuthorizationDecision{
		APIVersion: iamv1.APIVersion,
		Kind:       "AuthorizationDecision",
		ID:         "decision-installation-verification",
		Allowed:    true,
		Reason:     iamv1.DecisionAllowed,
		TenantID:   "organization-example",
		Subject:    verificationSubject,
		Action:     iamv1.ActionInstallationVerify,
		Resource: iamv1.ResourceReference{
			Kind: iamv1.ResourceInstallation, ID: "installation-example",
		},
		RequestID: "request-installation-verify",
		DecidedAt: now,
	}
	for decision, correlation := range map[*iamv1.AuthorizationDecision]string{
		&workflow.decision: "correlation-authorize", &workflow.verificationDecision: "correlation-installation-verify",
	} {
		request, err := iamv1.NewAuthorizationRequest(decision.Action, decision.Resource, iamv1.AuthorizationResourceInstance, "", decision.RequestID, correlation)
		if err != nil {
			t.Fatal(err)
		}
		decision.Profile, decision.ResourceMode, decision.CorrelationID = &request.Profile, request.ResourceMode, request.CorrelationID
	}
	return workflow
}

func (workflow *httpWorkflow) Readiness(context.Context) (iamv1.Readiness, error) {
	return workflow.readiness, nil
}

func (workflow *httpWorkflow) BootstrapStatus(context.Context, iamv1.Secret) (iamv1.BootstrapStatus, error) {
	return workflow.status, nil
}

func (workflow *httpWorkflow) ServiceIdentity(context.Context, iamv1.Secret) (iamv1.ServiceIdentity, error) {
	workflow.identityCalls++
	return workflow.identity, nil
}

func (workflow *httpWorkflow) Login(context.Context, iamv1.LoginRequest) (iamv1.LoginResponse, error) {
	workflow.loginCalls++
	if workflow.loginErr != nil {
		return iamv1.LoginResponse{}, workflow.loginErr
	}
	return workflow.login, nil
}

func (workflow *httpWorkflow) Logout(
	context.Context,
	iamv1.Secret,
	iamv1.LogoutRequest,
) (iamv1.LogoutResponse, error) {
	return iamv1.LogoutResponse{RevokedAt: workflow.login.Session.IssuedAt}, nil
}

func (workflow *httpWorkflow) ChangePassword(
	context.Context,
	iamv1.Secret,
	iamv1.ChangePasswordRequest,
) (iamv1.ChangePasswordResponse, error) {
	return iamv1.ChangePasswordResponse{
		ChangedAt: workflow.login.Session.IssuedAt, BootstrapFileRetirable: true,
	}, nil
}

func (workflow *httpWorkflow) CreateUser(
	context.Context,
	iamv1.Secret,
	iamv1.CreateUserRequest,
) (iamv1.User, error) {
	now := workflow.login.Session.IssuedAt
	return iamv1.User{
		APIVersion: iamv1.APIVersion, Kind: "User", ID: "principal-user",
		AccountID: "organization-example",
		LoginName: "developer", DisplayName: "Developer", Status: iamv1.PrincipalActive,
		MustChangePassword: true, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (workflow *httpWorkflow) GetUser(
	_ context.Context,
	_ iamv1.Secret,
	id iamv1.PrincipalID,
	_ string,
) (iamv1.UserAccess, error) {
	workflow.getUserCalls++
	workflow.userID = id
	now := workflow.login.Session.IssuedAt
	return iamv1.UserAccess{
		User: iamv1.User{
			APIVersion: iamv1.APIVersion, Kind: "User", ID: id,
			AccountID: "organization-example", LoginName: "developer", DisplayName: "Developer",
			Status: iamv1.PrincipalActive, ResourceVersion: 7, CreatedAt: now, UpdatedAt: now,
		},
		PolicyAttachments: []iamv1.PolicyAttachment{},
		Capabilities: []iamv1.ActionCapability{
			{Action: iamv1.ActionIAMUserRead, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMUserUpdate, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMUserPermissionBoundarySet, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMUserPermissionBoundaryRemove, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMUserDelete, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: false, RestrictionReason: iamv1.CapabilityTargetMustBeDisabled},
			{Action: iamv1.ActionIAMUserSetStatus, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMUserPasswordReset, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMPolicyAttachmentCreate, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
			{Action: iamv1.ActionIAMPlatformPolicyAttachmentCreate, Resource: iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(id)}, Available: true},
		},
	}, nil
}

func (workflow *httpWorkflow) UpdateUser(
	_ context.Context,
	_ iamv1.Secret,
	id iamv1.PrincipalID,
	request iamv1.UpdateUserRequest,
) (iamv1.User, error) {
	workflow.updateUserCalls++
	workflow.userID, workflow.updateUser = id, request
	now := workflow.login.Session.IssuedAt
	return iamv1.User{
		APIVersion: iamv1.APIVersion, Kind: "User", ID: id, AccountID: "organization-example",
		LoginName: "developer", DisplayName: request.DisplayName, Status: iamv1.PrincipalActive,
		ResourceVersion: request.ResourceVersion + 1, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (workflow *httpWorkflow) DeleteUser(
	_ context.Context,
	_ iamv1.Secret,
	id iamv1.PrincipalID,
	request iamv1.DeleteUserRequest,
) (iamv1.UserDeletion, error) {
	workflow.deleteUserCalls++
	workflow.userID, workflow.deleteUser = id, request
	return iamv1.UserDeletion{
		APIVersion: iamv1.APIVersion, Kind: "UserDeletion", AccountID: "organization-example",
		ID: id, LoginName: "developer", ResourceVersion: request.ResourceVersion + 1,
		DeletedAt: workflow.login.Session.IssuedAt,
	}, nil
}

func (workflow *httpWorkflow) CreatePolicyAttachment(
	context.Context,
	iamv1.Secret,
	iamv1.CreatePolicyAttachmentRequest,
) (iamv1.PolicyAttachment, error) {
	now := workflow.login.Session.IssuedAt
	return iamv1.PolicyAttachment{
		APIVersion: iamv1.APIVersion, Kind: "PolicyAttachment", ID: "binding-user",
		AccountID: "organization-example", Target: iamv1.PolicyAttachmentTarget{Kind: iamv1.PolicyTargetUser, ID: "principal-user"},
		PolicyID: iamv1.SystemPolicyPaaSDeveloper, Scope: iamv1.AuthorityScopeTenant, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (workflow *httpWorkflow) RevokePolicyAttachment(
	_ context.Context,
	_ iamv1.Secret,
	id iamv1.PolicyAttachmentID,
	_ iamv1.RevokePolicyAttachmentRequest,
) (iamv1.Revocation, error) {
	return iamv1.Revocation{
		APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(id),
		ResourceVersion: 2, RevokedAt: workflow.login.Session.IssuedAt,
	}, nil
}

func (workflow *httpWorkflow) ListOwnSessions(_ context.Context, _ iamv1.Secret, _ string) (iamv1.SessionList, error) {
	workflow.ownSessionCalls++
	session := workflow.login.Session
	return iamv1.SessionList{APIVersion: iamv1.APIVersion, Kind: "SessionList", AccountID: session.AccountID,
		UserID: session.PrincipalID, CurrentSessionID: session.ID, ObservedAt: session.IssuedAt, Items: []iamv1.Session{session}}, nil
}

func (workflow *httpWorkflow) RevokeOwnSession(ctx context.Context, credential iamv1.Secret, id iamv1.SessionID, request iamv1.RevokeSessionRequest) (iamv1.RevokeOwnSessionResponse, error) {
	workflow.ownSessionCalls++
	revocation, err := workflow.RevokeSession(ctx, credential, id, request)
	return iamv1.RevokeOwnSessionResponse{Outcome: "APPLIED", Revocation: revocation}, err
}

func (workflow *httpWorkflow) RevokeOtherSessions(_ context.Context, _ iamv1.Secret, request iamv1.RevokeSessionRequest) (iamv1.RevokeOtherSessionsResponse, error) {
	workflow.ownSessionCalls++
	session := workflow.login.Session
	return iamv1.RevokeOtherSessionsResponse{APIVersion: iamv1.APIVersion, Kind: "OtherSessionsRevocation", Outcome: "APPLIED",
		AccountID: session.AccountID, UserID: session.PrincipalID, CurrentSessionID: session.ID, RequestID: request.RequestID,
		CompletedAt: session.IssuedAt}, nil
}

func (workflow *httpWorkflow) RevokeSession(
	_ context.Context,
	_ iamv1.Secret,
	id iamv1.SessionID,
	_ iamv1.RevokeSessionRequest,
) (iamv1.Revocation, error) {
	return iamv1.Revocation{
		APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(id),
		ResourceVersion: 2, RevokedAt: workflow.login.Session.IssuedAt,
	}, nil
}

func (workflow *httpWorkflow) Authorize(
	context.Context,
	iamv1.Secret,
	iamv1.Secret,
	iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	workflow.authorizeCalls++
	return workflow.decision, nil
}

func (workflow *httpWorkflow) VerifyInstallation(
	context.Context,
	iamv1.Secret,
	iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	workflow.verifyInstallationCalls++
	return workflow.verificationDecision, nil
}

func (workflow *httpWorkflow) AuthorizeAccessKey(_ context.Context, _ iamv1.Secret, request iamv1.AccessKeyAuthorizationRequest) (iamv1.AccessKeyAuthorization, error) {
	workflow.keyCalls++
	digest, err := iamv1.AccessKeySignedRequestDigest(request.SignedRequest)
	decision := workflow.decision
	decision.Allowed, decision.Reason, decision.Subject, decision.TenantID, decision.InstallationID = false, iamv1.DecisionDenied, nil, "", ""
	decision.Action, decision.Resource, decision.RequestID, decision.CorrelationID = request.Authorization.Action, request.Authorization.Resource, request.Authorization.RequestID, request.Authorization.CorrelationID
	decision.Profile, decision.ResourceMode, decision.CollectionUsage = &request.Authorization.Profile, request.Authorization.ResourceMode, request.Authorization.CollectionUsage
	return iamv1.AccessKeyAuthorization{APIVersion: iamv1.APIVersion, Kind: "AccessKeyAuthorization", Decision: decision, SignedRequestDigest: digest}, err
}

func newTestHandler(t *testing.T, workflow Workflow) http.Handler {
	t.Helper()
	handler, err := NewHandler(workflow, Config{
		NewRequestID: func() (string, error) { return "request-http-test", nil },
	})
	if err != nil {
		t.Fatalf("create IAM HTTP handler: %v", err)
	}
	return handler
}
