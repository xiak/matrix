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
	"github.com/xiak/matrix/app/service/installation/internal/productdiscovery"
)

func TestClientAuthorizesProductDiscoveryWithSeparateCredentials(t *testing.T) {
	now := time.Date(2026, 9, 7, 3, 4, 5, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/authorize" ||
			request.Header.Get("Authorization") != "Bearer platform-service-credential" ||
			request.Header.Get("Matrix-Subject-Credential") != "user-session-credential" {
			t.Errorf("IAM request = %s %s headers=%v", request.Method, request.URL.Path, request.Header)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		var input iamv1.AuthorizationRequest
		if iamv1.DecodeRequest(request.Body, &input) != nil ||
			input.Action != iamv1.ActionInstallationProductRead ||
			input.Resource != (iamv1.ResourceReference{
				Kind: iamv1.ResourceInstallation, ID: "installation-example",
			}) ||
			input.RequestID != "request-products" {
			t.Errorf("IAM authorization request = %#v", input)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(iamv1.AuthorizationDecision{
			APIVersion: iamv1.APIVersion,
			Kind:       "AuthorizationDecision",
			ID:         "decision-products",
			Allowed:    true,
			Reason:     iamv1.DecisionAllowed,
			TenantID:   "organization-example",
			Subject: &iamv1.Subject{
				Type: iamv1.PrincipalUser,
				ID:   "principal-example",
			},
			Action:    input.Action,
			Resource:  input.Resource,
			RequestID: input.RequestID,
			DecidedAt: now,
		})
	}))
	defer server.Close()

	client := newTestClient(t, server)
	err := client.Authorize(context.Background(), productdiscovery.AuthorizationRequest{
		Credential:     "Bearer user-session-credential",
		InstallationID: "installation-example",
		RequestID:      "request-products",
	})
	if err != nil {
		t.Fatalf("authorize product discovery: %v", err)
	}
}

func TestClientReadinessRequiresPlatformServiceIdentity(t *testing.T) {
	for name, purpose := range map[string]iamv1.ServicePurpose{
		"platform": iamv1.ServicePlatform,
		"paas":     iamv1.ServicePaaS,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(iamv1.ServiceIdentity{
					APIVersion:     iamv1.APIVersion,
					Kind:           "ServiceIdentity",
					OrganizationID: "organization-example",
					PrincipalID:    "service-example",
					Purpose:        purpose,
				})
			}))
			defer server.Close()
			err := newTestClient(t, server).Ready(context.Background())
			if (err == nil) != (purpose == iamv1.ServicePlatform) {
				t.Fatalf("readiness error = %v for %s", err, purpose)
			}
		})
	}
}

func TestClientNormalizesAuthenticationDenialAndUnavailableIAM(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   error
	}{
		{name: "unauthenticated", status: http.StatusUnauthorized, want: productdiscovery.ErrUnauthenticated},
		{name: "denied", status: http.StatusForbidden, want: productdiscovery.ErrPermissionDenied},
		{name: "unavailable", status: http.StatusBadGateway, want: productdiscovery.ErrAuthorizationUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(test.status)
			}))
			defer server.Close()
			err := newTestClient(t, server).Authorize(
				context.Background(),
				productdiscovery.AuthorizationRequest{
					Credential:     "Bearer user-session-credential",
					InstallationID: "installation-example",
					RequestID:      "request-products",
				},
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("authorization error = %v, want %v", err, test.want)
			}
		})
	}
}

func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	credential, err := iamv1.NewSecret("platform-service-credential")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{
		Endpoint: server.URL, ServiceCredential: credential, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
