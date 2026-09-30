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
