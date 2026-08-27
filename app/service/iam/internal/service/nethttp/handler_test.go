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

	authorizeBody := `{"action":"paas.application.read","resource":{"kind":"APPLICATION","id":"application-example"},"requestId":"request-authorize","correlationId":"correlation-authorize"}`
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

	verifyBody := `{"action":"installation.verify","resource":{"kind":"INSTALLATION","id":"installation-example"},"requestId":"request-installation-verify","correlationId":"correlation-installation-verify"}`
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
			name: "create user", target: "/v1/principals", status: http.StatusCreated,
			body: `{"loginName":"developer","displayName":"Developer","initialPassword":"Initial-Developer-Password-84!","requestId":"request-user"}`,
		},
		{
			name: "put binding", target: "/v1/role-bindings", status: http.StatusOK,
			body: `{"principalId":"principal-user","role":"PAAS_DEVELOPER","requestId":"request-binding"}`,
		},
		{
			name: "revoke binding", target: "/v1/role-bindings/binding-user:revoke", status: http.StatusOK,
			body: `{"requestId":"request-binding-revoke"}`,
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
		"/v1/principals",
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
	for _, target := range []string{"/v1/auth/me", "/v1/principals", "/v1/organizations"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s status=%d", target, response.Code)
		}
	}
	for _, target := range []string{"/v1/organization:alias", "/v1/organizations", "/v1/principals/user-a:set-status", "/v1/principals/user-a:reset-password"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{}`)))
		if response.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s status=%d", target, response.Code)
		}
	}
	for _, target := range []string{"/v1/auth/me?tenantId=forged", "/v1/principals?tenantId=forged", "/v1/organizations?after=a&after=b", "/v1/principals?after=", "/v1/principals?after=%2f", "/v1/principals?after=" + strings.Repeat("a", 513)} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer only-test-credential")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("forged selector %s status=%d", target, response.Code)
		}
	}
}

type httpWorkflow struct {
	Workflow
	readiness               iamv1.Readiness
	status                  iamv1.BootstrapStatus
	identity                iamv1.ServiceIdentity
	login                   iamv1.LoginResponse
	decision                iamv1.AuthorizationDecision
	verificationDecision    iamv1.AuthorizationDecision
	loginErr                error
	identityCalls           int
	loginCalls              int
	authorizeCalls          int
	verifyInstallationCalls int
}

func newHTTPWorkflow(t *testing.T) *httpWorkflow {
	t.Helper()
	now := time.Date(2026, 8, 26, 9, 10, 11, 123000, time.UTC)
	appliedAt := now.Add(-time.Hour)
	credential, err := iamv1.NewSecret("issued-session-credential")
	if err != nil {
		t.Fatalf("create HTTP test credential: %v", err)
	}
	subject := &iamv1.Subject{Type: iamv1.PrincipalUser, ID: "principal-admin"}
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
			OrganizationID: "organization-example",
			ContentDigest:  "sha256:" + strings.Repeat("1", 64),
			AppliedAt:      &appliedAt,
		},
		identity: iamv1.ServiceIdentity{
			InstallationID: "installation-example",
			APIVersion:     iamv1.APIVersion,
			Kind:           "ServiceIdentity",
			OrganizationID: "organization-example",
			PrincipalID:    "service-paas",
			Purpose:        iamv1.ServicePaaS,
		},
		login: iamv1.LoginResponse{
			Session: iamv1.Session{
				APIVersion:     iamv1.APIVersion,
				Kind:           "Session",
				ID:             "session-example",
				OrganizationID: "organization-example",
				PrincipalID:    "principal-admin",
				Status:         iamv1.SessionActive,
				IssuedAt:       now,
				ExpiresAt:      now.Add(time.Hour),
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
		Type: iamv1.PrincipalServiceAccount, ID: "service-installation-verifier",
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
) (iamv1.Principal, error) {
	now := workflow.login.Session.IssuedAt
	return iamv1.Principal{
		APIVersion: iamv1.APIVersion, Kind: "Principal", ID: "principal-user",
		OrganizationID: "organization-example", Type: iamv1.PrincipalUser,
		LoginName: "developer", DisplayName: "Developer", Status: iamv1.PrincipalActive,
		MustChangePassword: true, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (workflow *httpWorkflow) PutRoleBinding(
	context.Context,
	iamv1.Secret,
	iamv1.PutRoleBindingRequest,
) (iamv1.RoleBinding, error) {
	now := workflow.login.Session.IssuedAt
	return iamv1.RoleBinding{
		APIVersion: iamv1.APIVersion, Kind: "RoleBinding", ID: "binding-user",
		OrganizationID: "organization-example", PrincipalID: "principal-user",
		Role: iamv1.RolePaaSDeveloper, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (workflow *httpWorkflow) RevokeRoleBinding(
	_ context.Context,
	_ iamv1.Secret,
	id iamv1.RoleBindingID,
	_ iamv1.RevokeRoleBindingRequest,
) (iamv1.Revocation, error) {
	return iamv1.Revocation{
		APIVersion: iamv1.APIVersion, Kind: "Revocation", ID: string(id),
		ResourceVersion: 2, RevokedAt: workflow.login.Session.IssuedAt,
	}, nil
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
