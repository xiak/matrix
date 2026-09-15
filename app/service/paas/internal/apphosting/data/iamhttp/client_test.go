package iamhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

const (
	testServiceCredential  = "mx1.PaaSServiceCredential000000000000000000001"
	testSubjectCredential  = "mx1.PaaSSubjectCredential000000000000000000001"
	testVerifierCredential = "mx1.PaaSVerifierCredential0000000000000000001"
)

func TestClientMapsAllowedIAMDecisionWithoutTrustingCallerAuthority(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/authorize" ||
			request.Header.Get("Authorization") != "Bearer "+testServiceCredential ||
			request.Header.Get("Matrix-Subject-Credential") != testSubjectCredential {
			t.Fatalf("IAM request path=%s headers=%#v", request.URL.Path, request.Header)
		}
		var body iamv1.AuthorizationRequest
		if iamv1.DecodeRequest(request.Body, &body) != nil ||
			body.Action != iamv1.ActionPaaSApplicationCreate ||
			body.Resource != (iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}) ||
			body.RequestID != "request-paas-authorize" || body.CorrelationID != body.RequestID {
			t.Fatalf("IAM authorization request=%#v", body)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(iamv1.AuthorizationDecision{
			APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
			ID: "decision-paas-authorize", Allowed: true, Reason: iamv1.DecisionAllowed,
			TenantID: "organization-a",
			Subject:  &iamv1.Subject{Type: iamv1.PrincipalUser, ID: "principal-developer"},
			Action:   body.Action, Resource: body.Resource, RequestID: body.RequestID,
			Profile: &body.Profile, ResourceMode: body.ResourceMode, CollectionUsage: body.CollectionUsage, CorrelationID: body.CorrelationID,
			DecidedAt: time.Date(2026, 8, 26, 1, 2, 3, 456_000, time.UTC),
		})
	}))
	defer server.Close()

	client := newTestClient(t, server.URL)
	authorization, err := client.Authorize(context.Background(), testAuthorizationRequest())
	if err != nil {
		t.Fatalf("authorize PaaS request: %v", err)
	}
	if authorization.TenantID != "organization-a" ||
		authorization.Subject != (paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "principal-developer"}) ||
		authorization.DecisionID != "decision-paas-authorize" ||
		authorization.RequestID != "request-paas-authorize" {
		t.Fatalf("PaaS authorization=%#v", authorization)
	}
	stopRequest, err := toIAMRequest(port.AuthorizationRequest{
		Credential:   "Bearer " + testSubjectCredential,
		Action:       port.AuthorizeDeploymentStop,
		Resource:     paasv1.ResourceRef{Kind: "Deployment", ID: "deployment-a"},
		ResourceMode: iamv1.AuthorizationResourceInstance,
		RequestID:    "request-paas-stop",
	})
	if err != nil || stopRequest.Action != iamv1.ActionPaaSDeploymentStop {
		t.Fatalf("map PaaS stop authorization=%#v err=%v", stopRequest, err)
	}
}

func TestClientFailsClosedForDenialStatusAndInvalidResponse(t *testing.T) {
	tests := []struct {
		name  string
		serve func(http.ResponseWriter, iamv1.AuthorizationRequest)
		want  error
	}{
		{
			name: "decision denied",
			serve: func(response http.ResponseWriter, request iamv1.AuthorizationRequest) {
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(iamv1.AuthorizationDecision{
					APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
					ID: "decision-denied", Reason: iamv1.DecisionDenied,
					Action: request.Action, Resource: request.Resource, RequestID: request.RequestID,
					Profile: &request.Profile, ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage, CorrelationID: request.CorrelationID,
					DecidedAt: time.Date(2026, 8, 26, 1, 2, 3, 0, time.UTC),
				})
			},
			want: port.ErrPermissionDenied,
		},
		{
			name: "unauthenticated",
			serve: func(response http.ResponseWriter, _ iamv1.AuthorizationRequest) {
				response.WriteHeader(http.StatusUnauthorized)
			},
			want: port.ErrUnauthenticated,
		},
		{
			name: "mismatched response",
			serve: func(response http.ResponseWriter, request iamv1.AuthorizationRequest) {
				request.RequestID = "request-other"
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(iamv1.AuthorizationDecision{
					APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
					ID: "decision-mismatch", Allowed: true, Reason: iamv1.DecisionAllowed,
					TenantID: "organization-a",
					Subject:  &iamv1.Subject{Type: iamv1.PrincipalUser, ID: "principal-developer"},
					Action:   request.Action, Resource: request.Resource, RequestID: request.RequestID,
					Profile: &request.Profile, ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage, CorrelationID: request.CorrelationID,
					DecidedAt: time.Date(2026, 8, 26, 1, 2, 3, 0, time.UTC),
				})
			},
			want: port.ErrAuthorizationUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				var body iamv1.AuthorizationRequest
				if iamv1.DecodeRequest(request.Body, &body) != nil {
					t.Fatal("decode IAM authorization request")
				}
				test.serve(response, body)
			}))
			defer server.Close()
			_, err := newTestClient(t, server.URL).Authorize(context.Background(), testAuthorizationRequest())
			if !errors.Is(err, test.want) {
				t.Fatalf("authorization error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestClientRejectsMalformedBearerBeforeIAMCall(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	request := testAuthorizationRequest()
	for _, credential := range []string{"", testSubjectCredential, "bearer " + testSubjectCredential, "Bearer token with spaces"} {
		request.Credential = credential
		if _, err := newTestClient(t, server.URL).Authorize(context.Background(), request); !errors.Is(err, port.ErrUnauthenticated) {
			t.Fatalf("credential %q error=%v", credential, err)
		}
	}
	if calls != 0 {
		t.Fatalf("malformed credentials reached IAM %d times", calls)
	}
}

func TestClientRejectsEveryMismatchedDecisionBindingForAllowAndDeny(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		for name, mutate := range map[string]func(*iamv1.AuthorizationDecision){
			"missing profile":  func(d *iamv1.AuthorizationDecision) { d.Profile = nil },
			"profile product":  func(d *iamv1.AuthorizationDecision) { d.Profile.Product = "audit" },
			"profile revision": func(d *iamv1.AuthorizationDecision) { d.Profile.Revision++ },
			"profile digest": func(d *iamv1.AuthorizationDecision) {
				d.Profile.ContentDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			},
			"mode absent": func(d *iamv1.AuthorizationDecision) { d.ResourceMode = "" },
			"mode altered": func(d *iamv1.AuthorizationDecision) {
				d.ResourceMode = iamv1.AuthorizationResourceInstance
				d.CollectionUsage = ""
			},
			"usage absent":  func(d *iamv1.AuthorizationDecision) { d.CollectionUsage = "" },
			"usage altered": func(d *iamv1.AuthorizationDecision) { d.CollectionUsage = iamv1.AuthorizationCollectionList },
			"resource":      func(d *iamv1.AuthorizationDecision) { d.Resource.ID = "another-instance" },
			"action": func(d *iamv1.AuthorizationDecision) {
				d.Action = iamv1.ActionPaaSApplicationRead
				d.ResourceMode = iamv1.AuthorizationResourceInstance
				d.CollectionUsage = ""
			},
			"request":     func(d *iamv1.AuthorizationDecision) { d.RequestID = "another-request" },
			"correlation": func(d *iamv1.AuthorizationDecision) { d.CorrelationID = "another-correlation" },
		} {
			t.Run(fmt.Sprintf("allowed=%v/%s", allowed, name), func(t *testing.T) {
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					var request iamv1.AuthorizationRequest
					if iamv1.DecodeRequest(r.Body, &request) != nil || iamv1.ValidateAuthorizationRequest(request) != nil {
						t.Error("invalid outgoing request")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					decision := iamv1.AuthorizationDecision{APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision", ID: "decision-bound",
						Allowed: allowed, Reason: iamv1.DecisionDenied, Action: request.Action, Resource: request.Resource,
						Profile: &request.Profile, ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage,
						RequestID: request.RequestID, CorrelationID: request.CorrelationID, DecidedAt: time.Date(2026, 9, 15, 1, 2, 3, 0, time.UTC)}
					if allowed {
						decision.Reason, decision.TenantID = iamv1.DecisionAllowed, "organization-a"
						decision.Subject = &iamv1.Subject{Type: iamv1.PrincipalUser, ID: "principal-developer"}
					}
					if iamv1.CheckAuthorizationDecisionForRequest(decision, request) != nil {
						t.Error("invalid baseline response")
					}
					mutate(&decision)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(decision)
				}))
				defer server.Close()
				result, err := newTestClient(t, server.URL).Authorize(context.Background(), testAuthorizationRequest())
				if calls != 1 || !errors.Is(err, port.ErrAuthorizationUnavailable) || result != (port.Authorization{}) {
					t.Fatalf("mismatched decision consumed: calls=%d result=%+v err=%v", calls, result, err)
				}
			})
		}
	}
}

func TestClientAuthorizesCredentialBoundInstallationVerifier(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/installation:verify" ||
			request.Header.Get("Authorization") != "Bearer "+testVerifierCredential ||
			request.Header.Get("Matrix-Subject-Credential") != "" {
			t.Fatalf("IAM verifier request path=%s headers=%#v", request.URL.Path, request.Header)
		}
		var body iamv1.AuthorizationRequest
		if iamv1.DecodeRequest(request.Body, &body) != nil ||
			body.Action != iamv1.ActionInstallationVerify ||
			body.Resource != (iamv1.ResourceReference{
				Kind: iamv1.ResourceInstallation,
				ID:   "mxi-0123456789abcdef0123456789abcdef",
			}) || body.RequestID != "request-installation-verify" {
			t.Fatalf("IAM installation verification request=%#v", body)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(iamv1.AuthorizationDecision{
			APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
			ID: "decision-installation-verify", Allowed: true, Reason: iamv1.DecisionAllowed,
			TenantID: "organization-default",
			Subject: &iamv1.Subject{
				Type: iamv1.PrincipalServiceAccount, ID: "service-installation-verifier",
			},
			Action: body.Action, Resource: body.Resource, RequestID: body.RequestID,
			Profile: &body.Profile, ResourceMode: body.ResourceMode, CollectionUsage: body.CollectionUsage, CorrelationID: body.CorrelationID,
			DecidedAt: time.Date(2026, 8, 26, 1, 2, 3, 456_000, time.UTC),
		})
	}))
	defer server.Close()

	authorization, err := newTestClient(t, server.URL).VerifyInstallation(
		context.Background(),
		"Bearer "+testVerifierCredential,
		"mxi-0123456789abcdef0123456789abcdef",
		"request-installation-verify",
	)
	if err != nil {
		t.Fatalf("authorize installation verifier: %v", err)
	}
	if authorization.TenantID != "organization-default" ||
		authorization.Subject != (paasv1.SubjectRef{
			Type: paasv1.SubjectServiceAccount, ID: "service-installation-verifier",
		}) || authorization.DecisionID != "decision-installation-verify" {
		t.Fatalf("installation verifier authorization=%#v", authorization)
	}
}

func TestClientReadinessRequiresPaaSServiceIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(iamv1.ServiceIdentity{
			InstallationID: "installation-example",
			APIVersion:     iamv1.APIVersion, Kind: "ServiceIdentity",
			AccountID: "organization-a", PrincipalID: "service-paas",
			Purpose: iamv1.ServicePaaS,
		})
	}))
	defer server.Close()
	if err := newTestClient(t, server.URL).Ready(context.Background()); err != nil {
		t.Fatalf("PaaS IAM readiness: %v", err)
	}
}

func newTestClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	credential, err := iamv1.NewSecret(testServiceCredential)
	if err != nil {
		t.Fatalf("create PaaS service credential: %v", err)
	}
	client, err := NewClient(Config{Endpoint: endpoint, ServiceCredential: credential})
	if err != nil {
		t.Fatalf("create PaaS IAM client: %v", err)
	}
	return client
}

func testAuthorizationRequest() port.AuthorizationRequest {
	return port.AuthorizationRequest{
		Credential:   "Bearer " + testSubjectCredential,
		Action:       port.AuthorizeApplicationCreate,
		Resource:     paasv1.ResourceRef{Kind: "Application", ID: "collection"},
		ResourceMode: iamv1.AuthorizationResourceCollection, CollectionUsage: iamv1.AuthorizationCollectionCreate,
		RequestID: "request-paas-authorize",
	}
}
