package iamhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
)

func TestBindWorkloadRoleUsesServiceAndCurrentUserCredentials(t *testing.T) {
	template := clientTestTemplateReference()
	access := clientTestServiceLinkedRoleAccess(t, template, "postgres-primary")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/internal/workload-role-bindings" ||
			request.Header.Get("Authorization") != "Bearer paas-service-secret" ||
			request.Header.Get("Matrix-Subject-Credential") != "user-session-secret" ||
			request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected IAM request: method=%s path=%s headers=%v", request.Method, request.URL.Path, request.Header)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		var command iamv1.CreateWorkloadRoleBindingRequest
		if iamv1.DecodeRequest(request.Body, &command) != nil || command.Template != template ||
			command.Authorization.Action != iamv1.ActionManagedServiceInstallationRoleBind ||
			command.Authorization.Resource != (iamv1.ResourceReference{
				Kind: iamv1.ResourceServiceInstallation, ID: "postgres-primary",
			}) || command.Authorization.RequestID != "msrb-command-one" {
			t.Errorf("unexpected binding command: %#v", command)
			response.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(access)
	}))
	defer server.Close()
	serviceCredential, err := iamv1.NewSecret("paas-service-secret")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{Endpoint: server.URL, ServiceCredential: serviceCredential})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.BindWorkloadRole(t.Context(), template, port.AuthorizationRequest{
		Credential: "Bearer user-session-secret", Action: port.AuthorizeInstallationRoleBind,
		Resource:     port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: "postgres-primary"},
		ResourceMode: iamv1.AuthorizationResourceInstance, RequestID: "msrb-command-one",
	})
	if err != nil || result.Bindings[0].ID != access.Bindings[0].ID {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestBindWorkloadRoleFailsClosedOnInvalidShapeStatusAndResponse(t *testing.T) {
	template := clientTestTemplateReference()
	base := port.AuthorizationRequest{
		Credential: "Bearer user-session-secret", Action: port.AuthorizeInstallationRoleBind,
		Resource:     port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: "postgres-primary"},
		ResourceMode: iamv1.AuthorizationResourceInstance, RequestID: "msrb-command-one",
	}
	serviceCredential, _ := iamv1.NewSecret("paas-service-secret")
	for name, status := range map[string]int{
		"expired user":      http.StatusUnauthorized,
		"revoked authority": http.StatusForbidden,
		"binding conflict":  http.StatusConflict,
		"authority outage":  http.StatusServiceUnavailable,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(status)
			}))
			defer server.Close()
			client, err := NewClient(Config{Endpoint: server.URL, ServiceCredential: serviceCredential})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.BindWorkloadRole(t.Context(), template, base)
			want := port.ErrAuthorizationUnavailable
			switch status {
			case http.StatusUnauthorized:
				want = port.ErrUnauthenticated
			case http.StatusForbidden:
				want = port.ErrPermissionDenied
			case http.StatusConflict:
				want = port.ErrWorkloadRoleConflict
			}
			if !errors.Is(err, want) {
				t.Fatalf("status=%d err=%v want=%v", status, err, want)
			}
		})
	}
	for name, forged := range map[string]iamv1.ServiceLinkedRoleAccess{
		"workload": clientTestServiceLinkedRoleAccess(t, template, "another-installation"),
		"purpose": func() iamv1.ServiceLinkedRoleAccess {
			value := clientTestServiceLinkedRoleAccess(t, template, "postgres-primary")
			value.Relation.ServicePrincipal.Purpose = iamv1.ServiceAudit
			return value
		}(),
	} {
		t.Run("forged "+name+" response", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(forged)
			}))
			defer server.Close()
			client, err := NewClient(Config{Endpoint: server.URL, ServiceCredential: serviceCredential})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.BindWorkloadRole(t.Context(), template, base); !errors.Is(err, port.ErrAuthorizationUnavailable) {
				t.Fatalf("forged response error=%v", err)
			}
		})
	}
	client, err := NewClient(Config{Endpoint: "http://127.0.0.1:1", ServiceCredential: serviceCredential})
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.Action = port.AuthorizeInstallationRead
	if _, err := client.BindWorkloadRole(context.Background(), template, changed); !errors.Is(err, port.ErrAuthorizationUnavailable) {
		t.Fatalf("wrong product action error=%v", err)
	}
	changed = base
	changed.Credential = "Basic user-session-secret"
	if _, err := client.BindWorkloadRole(context.Background(), template, changed); !errors.Is(err, port.ErrUnauthenticated) {
		t.Fatalf("non-bearer subject error=%v", err)
	}
}

func TestRevokeWorkloadRoleUsesServiceAndCurrentUserCredentials(t *testing.T) {
	binding := clientTestServiceLinkedRoleAccess(t, clientTestTemplateReference(), "postgres-primary").Bindings[0]
	revokedAt := binding.CreatedAt.Add(time.Second)
	binding.Status, binding.ResourceVersion, binding.UpdatedAt, binding.RevokedAt =
		iamv1.WorkloadRoleBindingRevoked, 2, revokedAt, &revokedAt
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodDelete || request.URL.Path != "/v1/internal/workload-role-bindings/binding-reader" ||
			request.Header.Get("Authorization") != "Bearer paas-service-secret" ||
			request.Header.Get("Matrix-Subject-Credential") != "user-session-secret" ||
			request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected IAM revocation request: method=%s path=%s headers=%v", request.Method, request.URL.Path, request.Header)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		var command iamv1.RevokeWorkloadRoleBindingRequest
		if iamv1.DecodeRequest(request.Body, &command) != nil || command.ResourceVersion != 1 ||
			command.Authorization.Action != iamv1.ActionManagedServiceInstallationRoleUnbind ||
			command.Authorization.Resource != binding.Workload || command.Authorization.RequestID != "msru-command-one" {
			t.Errorf("unexpected revocation command: %#v", command)
			response.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(binding)
	}))
	defer server.Close()
	serviceCredential, err := iamv1.NewSecret("paas-service-secret")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{Endpoint: server.URL, ServiceCredential: serviceCredential})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.RevokeWorkloadRole(t.Context(), binding.ID, 1, port.AuthorizationRequest{
		Credential: "Bearer user-session-secret", Action: port.AuthorizeInstallationRoleUnbind,
		Resource:     port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: "postgres-primary"},
		ResourceMode: iamv1.AuthorizationResourceInstance, RequestID: "msru-command-one",
	})
	if err != nil || result.ID != binding.ID || result.Status != iamv1.WorkloadRoleBindingRevoked {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestRevokeWorkloadRoleFailsClosedOnInvalidShapeStatusAndResponse(t *testing.T) {
	base := port.AuthorizationRequest{
		Credential: "Bearer user-session-secret", Action: port.AuthorizeInstallationRoleUnbind,
		Resource:     port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: "postgres-primary"},
		ResourceMode: iamv1.AuthorizationResourceInstance, RequestID: "msru-command-one",
	}
	serviceCredential, _ := iamv1.NewSecret("paas-service-secret")
	for name, status := range map[string]int{
		"expired user": http.StatusUnauthorized, "revoked authority": http.StatusForbidden,
		"revocation conflict": http.StatusConflict, "authority outage": http.StatusServiceUnavailable,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(status) }))
			defer server.Close()
			client, err := NewClient(Config{Endpoint: server.URL, ServiceCredential: serviceCredential})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.RevokeWorkloadRole(t.Context(), "binding-reader", 1, base)
			want := port.ErrAuthorizationUnavailable
			switch status {
			case http.StatusUnauthorized:
				want = port.ErrUnauthenticated
			case http.StatusForbidden:
				want = port.ErrPermissionDenied
			case http.StatusConflict:
				want = port.ErrWorkloadRoleConflict
			}
			if !errors.Is(err, want) {
				t.Fatalf("status=%d err=%v want=%v", status, err, want)
			}
		})
	}
	active := clientTestServiceLinkedRoleAccess(t, clientTestTemplateReference(), "postgres-primary").Bindings[0]
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(active)
	}))
	defer server.Close()
	client, err := NewClient(Config{Endpoint: server.URL, ServiceCredential: serviceCredential})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RevokeWorkloadRole(t.Context(), active.ID, 1, base); !errors.Is(err, port.ErrAuthorizationUnavailable) {
		t.Fatalf("active forged response error=%v", err)
	}
	changed := base
	changed.Action = port.AuthorizeInstallationRead
	if _, err := client.RevokeWorkloadRole(context.Background(), active.ID, 1, changed); !errors.Is(err, port.ErrAuthorizationUnavailable) {
		t.Fatalf("wrong product action error=%v", err)
	}
	changed = base
	changed.Credential = "Basic user-session-secret"
	if _, err := client.RevokeWorkloadRole(context.Background(), active.ID, 1, changed); !errors.Is(err, port.ErrUnauthenticated) {
		t.Fatalf("non-bearer subject error=%v", err)
	}
}

func TestAssumeWorkloadRoleKeepsCredentialInsideOneMinuteLeaseAndReleasesIt(t *testing.T) {
	session, credential := clientTestServiceRoleSession(t)
	request := port.WorkloadRoleAuthorizationRequest{
		Action:       port.AuthorizeInstallationRead,
		Resource:     port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: "postgres-primary"},
		ResourceMode: iamv1.AuthorizationResourceInstance, RequestID: "service-business-read",
	}
	var issueCalls, authorizationCalls, releaseCalls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, httpRequest *http.Request) {
		switch httpRequest.URL.Path {
		case "/v1/internal/service-role-sessions":
			issueCalls++
			if httpRequest.Method != http.MethodPost || httpRequest.Header.Get("Authorization") != "Bearer paas-service-secret" ||
				httpRequest.Header.Get("Matrix-Subject-Credential") != "" {
				t.Errorf("unexpected service Role issue request: method=%s headers=%v", httpRequest.Method, httpRequest.Header)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			var command iamv1.AssumeServiceRoleRequest
			if iamv1.DecodeRequest(httpRequest.Body, &command) != nil || command.BindingID != "binding-reader" ||
				command.RequestID != "assume-service-read" || command.DurationSeconds == nil || *command.DurationSeconds != 60 {
				t.Errorf("unexpected service Role issue command: %#v", command)
				response.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			encoded, err := iamv1.EncodeAssumeRoleResponse(iamv1.AssumeRoleResponse{
				Outcome: "APPLIED", Session: session, Credential: credential,
			})
			if err != nil {
				t.Fatal(err)
			}
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("Cache-Control", "no-store")
			_, _ = response.Write(encoded)
		case "/v1/authorize":
			authorizationCalls++
			if httpRequest.Method != http.MethodPost || httpRequest.Header.Get("Authorization") != "Bearer paas-service-secret" ||
				httpRequest.Header.Get("Matrix-Subject-Credential") != "role-session-secret" {
				t.Errorf("temporary Role credential escaped its subject carrier: method=%s headers=%v", httpRequest.Method, httpRequest.Header)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			var iamRequest iamv1.AuthorizationRequest
			if iamv1.DecodeRequest(httpRequest.Body, &iamRequest) != nil || iamRequest.Action != request.Action ||
				iamRequest.Resource != (iamv1.ResourceReference{Kind: request.Resource.Kind, ID: request.Resource.ID}) ||
				iamRequest.RequestID != request.RequestID || iamRequest.CorrelationID != request.RequestID {
				t.Errorf("unexpected service Role authorization: %#v", iamRequest)
				response.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(response).Encode(clientTestServiceRoleDecision(iamRequest, session))
		case "/v1/auth/role-session:logout":
			releaseCalls++
			if httpRequest.Method != http.MethodPost || httpRequest.Header.Get("Authorization") != "Bearer role-session-secret" ||
				httpRequest.Header.Get("Matrix-Subject-Credential") != "" {
				t.Errorf("unexpected service Role release request: method=%s headers=%v", httpRequest.Method, httpRequest.Header)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			var logout iamv1.LogoutRequest
			if iamv1.DecodeRequest(httpRequest.Body, &logout) != nil || logout.RequestID != workloadRoleExitRequestID("assume-service-read") {
				t.Errorf("unexpected service Role release intent: %#v", logout)
				response.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			revokedAt := session.IssuedAt.Add(30 * time.Second)
			revoked := session
			revoked.Status, revoked.RevokedAt = iamv1.SessionRevoked, &revokedAt
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(response).Encode(revoked)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serviceCredential, _ := iamv1.NewSecret("paas-service-secret")
	client, err := NewClient(Config{Endpoint: server.URL, ServiceCredential: serviceCredential})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := client.AssumeWorkloadRole(t.Context(), "binding-reader", "assume-service-read", request)
	if err != nil {
		t.Fatal("assume workload Role", err)
	}
	authorization := lease.Authorization()
	if port.ValidateWorkloadRoleAuthorizationForRequest(authorization, "binding-reader", request) != nil ||
		authorization.TenantID != "account-one" || authorization.RoleID != session.RoleID ||
		authorization.RoleSessionID != session.ID || authorization.SourceServicePrincipalID != session.SourceServicePrincipalID {
		t.Fatalf("workload Role authorization=%#v", authorization)
	}
	if err := lease.Release(t.Context()); err != nil {
		t.Fatal("release workload Role", err)
	}
	if err := lease.Release(t.Context()); err != nil {
		t.Fatal("idempotent local release", err)
	}
	if issueCalls != 1 || authorizationCalls != 1 || releaseCalls != 1 {
		t.Fatalf("issue=%d authorize=%d release=%d", issueCalls, authorizationCalls, releaseCalls)
	}
}

func TestAssumeWorkloadRoleFailsClosedAndReleasesIssuedSession(t *testing.T) {
	for _, test := range []struct {
		name            string
		issueOutcome    string
		privateIssue    bool
		forgeDecision   func(*iamv1.AuthorizationDecision)
		want            error
		wantReleaseCall int
	}{
		{name: "equal replay has no consumable secret", issueOutcome: "EQUAL_REPLAY", privateIssue: true, want: port.ErrAuthorizationUnavailable},
		{name: "cacheable issuance is rejected and released", issueOutcome: "APPLIED", privateIssue: false, want: port.ErrAuthorizationUnavailable, wantReleaseCall: 1},
		{name: "forged target account is rejected and released", issueOutcome: "APPLIED", privateIssue: true,
			forgeDecision: func(value *iamv1.AuthorizationDecision) { value.TenantID = "account-other" },
			want:          port.ErrAuthorizationUnavailable, wantReleaseCall: 1},
		{name: "denial is rejected and released", issueOutcome: "APPLIED", privateIssue: true,
			forgeDecision: func(value *iamv1.AuthorizationDecision) {
				value.Allowed, value.Reason, value.TenantID, value.Subject = false, iamv1.DecisionDenied, "", nil
			},
			want: port.ErrPermissionDenied, wantReleaseCall: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, credential := clientTestServiceRoleSession(t)
			request := port.WorkloadRoleAuthorizationRequest{
				Action:       port.AuthorizeInstallationRead,
				Resource:     port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: "postgres-primary"},
				ResourceMode: iamv1.AuthorizationResourceInstance, RequestID: "service-business-read",
			}
			releaseCalls := 0
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, httpRequest *http.Request) {
				switch httpRequest.URL.Path {
				case "/v1/internal/service-role-sessions":
					result := iamv1.AssumeRoleResponse{Outcome: test.issueOutcome, Session: session}
					if test.issueOutcome == "APPLIED" {
						result.Credential = credential
					}
					encoded, err := iamv1.EncodeAssumeRoleResponse(result)
					if err != nil {
						t.Fatal(err)
					}
					response.Header().Set("Content-Type", "application/json")
					if test.privateIssue {
						response.Header().Set("Cache-Control", "no-store")
					}
					_, _ = response.Write(encoded)
				case "/v1/authorize":
					var iamRequest iamv1.AuthorizationRequest
					if iamv1.DecodeRequest(httpRequest.Body, &iamRequest) != nil {
						t.Fatal("decode workload authorization")
					}
					decision := clientTestServiceRoleDecision(iamRequest, session)
					if test.forgeDecision != nil {
						test.forgeDecision(&decision)
					}
					response.Header().Set("Content-Type", "application/json")
					response.Header().Set("Cache-Control", "no-store")
					_ = json.NewEncoder(response).Encode(decision)
				case "/v1/auth/role-session:logout":
					releaseCalls++
					revokedAt := session.IssuedAt.Add(30 * time.Second)
					revoked := session
					revoked.Status, revoked.RevokedAt = iamv1.SessionRevoked, &revokedAt
					response.Header().Set("Content-Type", "application/json")
					response.Header().Set("Cache-Control", "no-store")
					_ = json.NewEncoder(response).Encode(revoked)
				default:
					response.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			serviceCredential, _ := iamv1.NewSecret("paas-service-secret")
			client, err := NewClient(Config{Endpoint: server.URL, ServiceCredential: serviceCredential})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.AssumeWorkloadRole(t.Context(), "binding-reader", "assume-service-read", request)
			if !errors.Is(err, test.want) || releaseCalls != test.wantReleaseCall {
				t.Fatalf("error=%v want=%v releaseCalls=%d want=%d", err, test.want, releaseCalls, test.wantReleaseCall)
			}
		})
	}
}

func clientTestServiceRoleSession(t *testing.T) (iamv1.RoleSession, iamv1.Secret) {
	t.Helper()
	issuedAt := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	session := iamv1.RoleSession{
		APIVersion: iamv1.APIVersion, Kind: "RoleSession", ID: "role-session-service-read",
		AccountID: "account-one", RoleID: "role-reader", SourceServicePrincipalID: "service-paas",
		Status: iamv1.SessionActive, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Minute),
	}
	credential, err := iamv1.NewSecret("role-session-secret")
	if err != nil || iamv1.ValidateRoleSession(session) != nil {
		t.Fatal("construct service RoleSession", err)
	}
	return session, credential
}

func clientTestServiceRoleDecision(request iamv1.AuthorizationRequest, session iamv1.RoleSession) iamv1.AuthorizationDecision {
	return iamv1.AuthorizationDecision{
		APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision", ID: "decision-service-read",
		Allowed: true, Reason: iamv1.DecisionAllowed, TenantID: session.AccountID,
		Subject: &iamv1.Subject{Type: iamv1.SubjectRole, ID: string(session.RoleID), RoleSession: &iamv1.RoleSessionReference{
			SessionID: session.ID, SourceServicePrincipalID: session.SourceServicePrincipalID,
		}},
		Action: request.Action, Resource: request.Resource, RequestID: request.RequestID,
		Profile: &request.Profile, ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage,
		NetworkContext: request.NetworkContext, CorrelationID: request.CorrelationID,
		DecidedAt: time.Date(2026, 9, 30, 8, 0, 1, 0, time.UTC),
	}
}

func clientTestTemplateReference() iamv1.ServiceRoleTemplateReference {
	return iamv1.ServiceRoleTemplateReference{
		ID: "managedservice.installation-reader", Version: 1,
		ContentDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}

func clientTestServiceLinkedRoleAccess(
	t *testing.T,
	template iamv1.ServiceRoleTemplateReference,
	workloadID string,
) iamv1.ServiceLinkedRoleAccess {
	t.Helper()
	now := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	relation := iamv1.ServiceLinkedRole{
		APIVersion: iamv1.APIVersion, Kind: "ServiceLinkedRole",
		Role: iamv1.Role{
			APIVersion: iamv1.APIVersion, Kind: "Role", ID: "role-reader", AccountID: "account-one",
			Name: "ManagedServiceInstallationReader", Description: "Managed service installation reader",
			Tags: []iamv1.RoleTag{}, Management: iamv1.RoleServiceLinked, Status: iamv1.RoleActive,
			MaxSessionDurationSeconds: 900, ResourceVersion: 1, CurrentTrustVersionID: "trust-reader",
			CreatedAt: now, UpdatedAt: now,
		},
		Template: template,
		ServicePrincipal: iamv1.ServicePrincipalReference{
			InstallationID: "installation-platform", PrincipalID: "service-paas", Purpose: iamv1.ServicePaaS,
		},
		PermissionCeiling: iamv1.PolicyVersionReference{
			PolicyID: "policy-reader", VersionID: "version-reader",
			ContentDigest: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
	}
	binding := iamv1.WorkloadRoleBinding{
		APIVersion: iamv1.APIVersion, Kind: "WorkloadRoleBinding", ID: "binding-reader",
		AccountID: relation.Role.AccountID, RoleID: relation.Role.ID, Template: template,
		Workload: iamv1.ResourceReference{Kind: iamv1.ResourceServiceInstallation, ID: workloadID},
		Status:   iamv1.WorkloadRoleBindingActive, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
	result := iamv1.ServiceLinkedRoleAccess{
		APIVersion: iamv1.APIVersion, Kind: "ServiceLinkedRoleAccess", Relation: relation,
		Bindings: []iamv1.WorkloadRoleBinding{binding},
	}
	if iamv1.ValidateServiceLinkedRoleAccess(result) != nil {
		t.Fatal("test service Role response is invalid")
	}
	return result
}
