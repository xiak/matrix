package iamhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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
			body.NetworkContext == nil || body.NetworkContext.SourceIP != "192.0.2.10" ||
			!reflect.DeepEqual(body.RequestTags, []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}) ||
			body.RequestID != "request-paas-authorize" || body.CorrelationID != body.RequestID {
			t.Fatalf("IAM authorization request=%#v", body)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(iamv1.AuthorizationDecision{
			APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
			ID: "decision-paas-authorize", Allowed: true, Reason: iamv1.DecisionAllowed,
			TenantID: "organization-a",
			Subject:  &iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-developer"},
			Action:   body.Action, Resource: body.Resource, RequestID: body.RequestID,
			Profile: &body.Profile, ResourceMode: body.ResourceMode, CollectionUsage: body.CollectionUsage, NetworkContext: body.NetworkContext, RequestTags: body.RequestTags, CorrelationID: body.CorrelationID,
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
		authorization.RequestID != "request-paas-authorize" ||
		!reflect.DeepEqual(authorization.RequestTags, []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}) {
		t.Fatalf("PaaS authorization=%#v", authorization)
	}
	stopRequest, err := toIAMRequest(port.AuthorizationRequest{
		Credential:   "Bearer " + testSubjectCredential,
		Action:       port.AuthorizeDeploymentStop,
		Resource:     paasv1.ResourceRef{Kind: "Deployment", ID: "deployment-a"},
		ResourceMode: iamv1.AuthorizationResourceInstance,
		SourceIP:     "192.0.2.10",
		RequestID:    "request-paas-stop",
	})
	if err != nil || stopRequest.Action != iamv1.ActionPaaSDeploymentStop {
		t.Fatalf("map PaaS stop authorization=%#v err=%v", stopRequest, err)
	}
}

func TestClientAuthorizesExactAccessKeyRequestWithoutSubjectBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/authorize:access-key" || request.URL.RawQuery != "" ||
			request.Header.Get("Authorization") != "Bearer "+testServiceCredential ||
			request.Header.Get("Matrix-Subject-Credential") != "" {
			t.Fatalf("IAM AccessKey request path=%s query=%q headers=%#v", request.URL.Path, request.URL.RawQuery, request.Header)
		}
		body, err := iamv1.DecodeAccessKeyAuthorizationRequest(request.Body)
		if err != nil || body.Authorization.Action != iamv1.ActionPaaSApplicationCreate ||
			body.Authorization.Resource != (iamv1.ResourceReference{Kind: iamv1.ResourceApplication, ID: "collection"}) ||
			body.Authorization.NetworkContext == nil || body.Authorization.NetworkContext.SourceIP != "192.0.2.10" ||
			!reflect.DeepEqual(body.Authorization.RequestTags, []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}) ||
			body.SignedRequest.Parameters.AccessKeyID != "key-one" ||
			body.SignedRequest.HTTP.EscapedPath != "/api/paas/v1/applications" {
			t.Fatalf("IAM AccessKey authorization request=%#v err=%v", body.Authorization, err)
		}
		digest, err := iamv1.AccessKeySignedRequestDigest(body.SignedRequest)
		if err != nil {
			t.Fatal(err)
		}
		result := iamv1.AccessKeyAuthorization{
			APIVersion: iamv1.APIVersion, Kind: "AccessKeyAuthorization", SignedRequestDigest: digest,
			Decision: iamv1.AuthorizationDecision{
				APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
				ID: "decision-access-key", Allowed: true, Reason: iamv1.DecisionAllowed,
				TenantID: "organization-a",
				Subject:  &iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-developer", AccessKeyID: "key-one"},
				Action:   body.Authorization.Action, Resource: body.Authorization.Resource,
				Profile: &body.Authorization.Profile, ResourceMode: body.Authorization.ResourceMode,
				CollectionUsage: body.Authorization.CollectionUsage, NetworkContext: body.Authorization.NetworkContext,
				RequestTags: body.Authorization.RequestTags, ResourceTags: body.Authorization.ResourceTags,
				RequestID: body.Authorization.RequestID, CorrelationID: body.Authorization.CorrelationID,
				DecidedAt: time.Date(2026, 10, 1, 1, 2, 3, 456_000, time.UTC),
			},
		}
		if iamv1.CheckAccessKeyAuthorizationForRequest(result, body) != nil {
			t.Fatal("fixture AccessKey response is not bound to the exact request")
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(result)
	}))
	defer server.Close()

	request := testAccessKeyAuthorizationRequest(t)
	authorization, err := newTestClient(t, server.URL).AuthorizeAccessKey(context.Background(), request)
	wantSubject := paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "principal-developer", AccessKeyID: "key-one"}
	if err != nil || authorization.TenantID != "organization-a" || !authorization.Subject.Equal(wantSubject) ||
		authorization.DecisionID != "decision-access-key" || authorization.RequestID != request.RequestID ||
		!reflect.DeepEqual(authorization.RequestTags, []iamv1.AuthorizationTag{{Key: "environment", Value: "production"}}) {
		t.Fatalf("PaaS AccessKey authorization=%#v err=%v", authorization, err)
	}
}

func TestClientMapsConsumedAccessKeyNonceWithoutRetryingAsBearer(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		if request.URL.Path != "/v1/authorize:access-key" || request.Header.Get("Matrix-Subject-Credential") != "" {
			t.Fatalf("unexpected AccessKey replay request path=%s headers=%#v", request.URL.Path, request.Header)
		}
		response.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	result, err := newTestClient(t, server.URL).AuthorizeAccessKey(context.Background(), testAccessKeyAuthorizationRequest(t))
	if calls != 1 || !errors.Is(err, port.ErrAuthorizationReplay) || !reflect.DeepEqual(result, port.Authorization{}) {
		t.Fatalf("AccessKey replay calls=%d result=%#v err=%v", calls, result, err)
	}
}

func TestClientResolvesProfileBoundSubjectWithoutAuthoritySelectors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/internal/authorization-subject:resolve" || request.URL.RawQuery != "" ||
			request.Header.Get("Authorization") != "Bearer "+testServiceCredential ||
			request.Header.Get("Matrix-Subject-Credential") != testSubjectCredential {
			t.Fatalf("IAM subject request path=%s query=%q headers=%#v", request.URL.Path, request.URL.RawQuery, request.Header)
		}
		var body iamv1.ResolveAuthorizationSubjectRequest
		if iamv1.DecodeRequest(request.Body, &body) != nil || iamv1.ValidateResolveAuthorizationSubjectRequest(body) != nil {
			t.Fatalf("invalid IAM subject request=%#v", body)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(iamv1.AuthorizationSubjectContext{
			APIVersion: iamv1.APIVersion,
			Kind:       "AuthorizationSubjectContext",
			TenantID:   "organization-a",
			Subject:    iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-developer"},
			Profile:    body.Profile,
		})
	}))
	defer server.Close()

	resolved, err := newTestClient(t, server.URL).ResolveSubject(context.Background(), port.SubjectResolutionRequest{
		Credential: "Bearer " + testSubjectCredential,
	})
	if err != nil || resolved.TenantID != "organization-a" ||
		resolved.Subject != (paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "principal-developer"}) ||
		port.ValidateAuthorizationSubjectContext(resolved) != nil {
		t.Fatalf("resolved subject=%#v err=%v", resolved, err)
	}
}

func TestClientResolvesServiceOriginRoleWithoutDroppingLineage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body iamv1.ResolveAuthorizationSubjectRequest
		if request.URL.Path != "/v1/internal/authorization-subject:resolve" ||
			iamv1.DecodeRequest(request.Body, &body) != nil {
			t.Fatal("invalid service-origin subject request")
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(iamv1.AuthorizationSubjectContext{
			APIVersion: iamv1.APIVersion, Kind: "AuthorizationSubjectContext", TenantID: "organization-a",
			Subject: iamv1.Subject{Type: iamv1.SubjectRole, ID: "role-service", RoleSession: &iamv1.RoleSessionReference{
				SessionID: "session-service", SourceServicePrincipalID: "service-paas",
			}},
			Profile: body.Profile,
		})
	}))
	defer server.Close()

	resolved, err := newTestClient(t, server.URL).ResolveSubject(context.Background(), port.SubjectResolutionRequest{
		Credential: "Bearer " + testSubjectCredential,
	})
	want := paasv1.SubjectRef{Type: paasv1.SubjectRole, ID: "role-service", RoleSession: &paasv1.RoleSessionReference{
		SessionID: "session-service", SourceServicePrincipalID: "service-paas",
	}}
	if err != nil || resolved.TenantID != "organization-a" || !resolved.Subject.Equal(want) ||
		port.ValidateAuthorizationSubjectContext(resolved) != nil {
		t.Fatalf("resolved service role=%#v err=%v", resolved, err)
	}
}

func TestClientFailsClosedForInvalidResolvedSubject(t *testing.T) {
	tests := map[string]func(*iamv1.AuthorizationSubjectContext){
		"wrong profile": func(value *iamv1.AuthorizationSubjectContext) {
			value.Profile.Revision--
		},
		"service subject": func(value *iamv1.AuthorizationSubjectContext) {
			value.Subject.Type = iamv1.SubjectServiceAccount
		},
		"role without lineage": func(value *iamv1.AuthorizationSubjectContext) {
			value.Subject.Type = iamv1.SubjectRole
		},
		"empty tenant": func(value *iamv1.AuthorizationSubjectContext) {
			value.TenantID = ""
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				var body iamv1.ResolveAuthorizationSubjectRequest
				if iamv1.DecodeRequest(request.Body, &body) != nil {
					t.Fatal("decode subject request")
				}
				resolved := iamv1.AuthorizationSubjectContext{
					APIVersion: iamv1.APIVersion, Kind: "AuthorizationSubjectContext",
					TenantID: "organization-a", Subject: iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-developer"},
					Profile: body.Profile,
				}
				mutate(&resolved)
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(resolved)
			}))
			defer server.Close()

			_, err := newTestClient(t, server.URL).ResolveSubject(context.Background(), port.SubjectResolutionRequest{
				Credential: "Bearer " + testSubjectCredential,
			})
			if !errors.Is(err, port.ErrAuthorizationUnavailable) {
				t.Fatalf("invalid resolved subject err=%v", err)
			}
		})
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
					Profile: &request.Profile, ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage, NetworkContext: request.NetworkContext, RequestTags: request.RequestTags, CorrelationID: request.CorrelationID,
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
					Subject:  &iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-developer"},
					Action:   request.Action, Resource: request.Resource, RequestID: request.RequestID,
					Profile: &request.Profile, ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage, NetworkContext: request.NetworkContext, RequestTags: request.RequestTags, CorrelationID: request.CorrelationID,
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

func TestRoleDecisionMapsCompleteSubjectAndRejectsMissingLineage(t *testing.T) {
	subject := &iamv1.Subject{Type: iamv1.SubjectRole, ID: "role-a", RoleSession: &iamv1.RoleSessionReference{SessionID: "session-a", SourceUserID: "user-a"}}
	decision := iamv1.AuthorizationDecision{Allowed: true, TenantID: "account-a", Subject: subject, ID: "decision-a", RequestID: "request-a"}
	authorization, err := authorizationFromDecision(decision)
	want := paasv1.SubjectRef{Type: paasv1.SubjectRole, ID: "role-a", RoleSession: &paasv1.RoleSessionReference{SessionID: "session-a", SourceUserID: "user-a"}}
	if err != nil || !authorization.Subject.Equal(want) || authorization.TenantID != "account-a" {
		t.Fatal("role business consumer lost authoritative lineage", err)
	}
	subject.RoleSession = nil
	if _, err := authorizationFromDecision(decision); !errors.Is(err, port.ErrAuthorizationUnavailable) {
		t.Fatal("role without lineage was accepted", err)
	}
	serviceSubject := &iamv1.Subject{Type: iamv1.SubjectRole, ID: "role-service", RoleSession: &iamv1.RoleSessionReference{
		SessionID: "session-service", SourceServicePrincipalID: "service-paas",
	}}
	decision.Subject = serviceSubject
	serviceAuthorization, err := authorizationFromDecision(decision)
	serviceWant := paasv1.SubjectRef{Type: paasv1.SubjectRole, ID: "role-service", RoleSession: &paasv1.RoleSessionReference{
		SessionID: "session-service", SourceServicePrincipalID: "service-paas",
	}}
	if err != nil || !serviceAuthorization.Subject.Equal(serviceWant) {
		t.Fatal("service-origin role lost its authoritative lineage", err)
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
			"network": func(d *iamv1.AuthorizationDecision) {
				d.NetworkContext = &iamv1.AuthorizationNetworkContext{SourceIP: "192.0.2.11"}
			},
			"request tag": func(d *iamv1.AuthorizationDecision) {
				d.RequestTags[0].Value = "staging"
			},
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
						Profile: &request.Profile, ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage, NetworkContext: request.NetworkContext, RequestTags: request.RequestTags,
						RequestID: request.RequestID, CorrelationID: request.CorrelationID, DecidedAt: time.Date(2026, 9, 15, 1, 2, 3, 0, time.UTC)}
					if allowed {
						decision.Reason, decision.TenantID = iamv1.DecisionAllowed, "organization-a"
						decision.Subject = &iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-developer"}
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
				if calls != 1 || !errors.Is(err, port.ErrAuthorizationUnavailable) || !reflect.DeepEqual(result, port.Authorization{}) {
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
				Type: iamv1.SubjectServiceAccount, ID: "service-installation-verifier",
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
		SourceIP: "192.0.2.10", RequestLabels: map[string]string{
			"environment": "production", "team": "payments",
		},
		RequestID: "request-paas-authorize",
	}
}

func testAccessKeyAuthorizationRequest(t *testing.T) port.AccessKeyAuthorizationRequest {
	t.Helper()
	nonce, err := iamv1.NewSecret("AAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := iamv1.NewSecret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	return port.AccessKeyAuthorizationRequest{
		Action:       port.AuthorizeApplicationCreate,
		Resource:     paasv1.ResourceRef{Kind: "Application", ID: "collection"},
		ResourceMode: iamv1.AuthorizationResourceCollection, CollectionUsage: iamv1.AuthorizationCollectionCreate,
		SourceIP: "192.0.2.10", RequestLabels: map[string]string{
			"environment": "production", "team": "payments",
		},
		RequestID: "request-paas-access-key",
		SignedRequest: iamv1.AccessKeySignedRequest{
			Parameters: iamv1.AccessKeySignatureParameters{AccessKeyID: "key-one", InstallationID: "installation-one",
				Audience: iamv1.ProductPaaS, SignedAt: 1800000000, Nonce: nonce},
			HTTP: iamv1.AccessKeyHTTPRequest{Method: http.MethodPost, Scheme: "https", Authority: "api.example.test:443",
				EscapedPath: "/api/paas/v1/applications", ContentType: "application/json", IdempotencyKey: "create-application-key",
				BodyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			Signature: signature,
		},
	}
}
