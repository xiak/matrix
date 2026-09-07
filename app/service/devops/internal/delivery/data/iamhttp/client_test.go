package iamhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

const (
	testServiceCredential = "mx1.DevOpsServiceCredential0000000000000000001"
	testSubjectCredential = "mx1.DevOpsSubjectCredential0000000000000000001"
)

func TestClientMapsExactAllowedIAMDecision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/authorize" ||
			request.Header.Get("Authorization") != "Bearer "+testServiceCredential ||
			request.Header.Get("Matrix-Subject-Credential") != testSubjectCredential {
			t.Fatalf("IAM request path=%s headers=%#v", request.URL.Path, request.Header)
		}
		var body iamv1.AuthorizationRequest
		if iamv1.DecodeRequest(request.Body, &body) != nil ||
			body.Action != iamv1.ActionDevOpsPipelineRead ||
			body.Resource != (iamv1.ResourceReference{Kind: iamv1.ResourcePipeline, ID: "pipeline-one"}) ||
			body.RequestID != "request-one" || body.CorrelationID != "correlation-one" {
			t.Fatalf("IAM authorization request=%#v", body)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(iamv1.AuthorizationDecision{
			APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
			ID: "decision-one", Allowed: true, Reason: iamv1.DecisionAllowed,
			TenantID: "organization-one",
			Subject:  &iamv1.Subject{Type: iamv1.PrincipalUser, ID: "user-one"},
			Action:   body.Action, Resource: body.Resource, RequestID: body.RequestID,
			DecidedAt: time.Date(2026, 9, 8, 1, 2, 3, 456_000, time.UTC),
		})
	}))
	defer server.Close()

	request := authorizationRequest()
	authorization, err := newTestClient(t, server.URL).Authorize(context.Background(), request)
	if err != nil {
		t.Fatalf("authorize DevOps request: %v", err)
	}
	if authorization.TenantID != "organization-one" ||
		authorization.Subject != (devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-one"}) ||
		authorization.DecisionID != "decision-one" || authorization.Action != request.Action ||
		authorization.Resource != request.Resource || authorization.RequestID != request.RequestID ||
		authorization.CorrelationID != request.CorrelationID || authorization.TraceParent != request.TraceParent {
		t.Fatalf("DevOps authorization=%#v", authorization)
	}
}

func TestClientFailsClosedForDenialStatusAndMismatchedDecision(t *testing.T) {
	tests := []struct {
		name  string
		serve func(http.ResponseWriter, iamv1.AuthorizationRequest)
		want  error
	}{
		{"decision denied", func(response http.ResponseWriter, request iamv1.AuthorizationRequest) {
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(iamv1.AuthorizationDecision{
				APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision", ID: "decision-denied",
				Reason: iamv1.DecisionDenied, Action: request.Action, Resource: request.Resource,
				RequestID: request.RequestID, DecidedAt: time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC),
			})
		}, port.ErrPermissionDenied},
		{"unauthenticated", func(response http.ResponseWriter, _ iamv1.AuthorizationRequest) {
			response.WriteHeader(http.StatusUnauthorized)
		}, port.ErrUnauthenticated},
		{"mismatched decision", func(response http.ResponseWriter, request iamv1.AuthorizationRequest) {
			response.Header().Set("Content-Type", "application/json")
			request.Resource.ID = "pipeline-other"
			_ = json.NewEncoder(response).Encode(iamv1.AuthorizationDecision{
				APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision", ID: "decision-other",
				Allowed: true, Reason: iamv1.DecisionAllowed, TenantID: "organization-one",
				Subject: &iamv1.Subject{Type: iamv1.PrincipalUser, ID: "user-one"},
				Action:  request.Action, Resource: request.Resource, RequestID: request.RequestID,
				DecidedAt: time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC),
			})
		}, port.ErrAuthorizationUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				var body iamv1.AuthorizationRequest
				if iamv1.DecodeRequest(request.Body, &body) != nil {
					t.Fatal("decode IAM request")
				}
				test.serve(response, body)
			}))
			defer server.Close()
			_, err := newTestClient(t, server.URL).Authorize(context.Background(), authorizationRequest())
			if !errors.Is(err, test.want) {
				t.Fatalf("authorization error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestClientReadinessRequiresDevOpsServiceIdentity(t *testing.T) {
	purpose := iamv1.ServiceDevOps
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(iamv1.ServiceIdentity{
			APIVersion: iamv1.APIVersion, Kind: "ServiceIdentity", OrganizationID: "organization-one",
			PrincipalID: "service-devops", Purpose: purpose,
		})
	}))
	defer server.Close()
	client := newTestClient(t, server.URL)
	if err := client.Ready(context.Background()); err != nil {
		t.Fatalf("DevOps IAM readiness: %v", err)
	}
	purpose = iamv1.ServicePaaS
	if err := client.Ready(context.Background()); !errors.Is(err, port.ErrAuthorizationUnavailable) {
		t.Fatalf("wrong service purpose readiness error=%v", err)
	}
}

func TestClientRejectsMalformedBearerBeforeIAMCall(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	request := authorizationRequest()
	for _, credential := range []string{"", testSubjectCredential, "bearer " + testSubjectCredential, "Bearer token with spaces"} {
		request.Credential = credential
		if _, err := newTestClient(t, server.URL).Authorize(context.Background(), request); !errors.Is(err, port.ErrUnauthenticated) {
			t.Fatalf("credential error=%v", err)
		}
	}
	if calls != 0 {
		t.Fatalf("malformed credentials reached IAM %d times", calls)
	}
}

func newTestClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	credential, err := iamv1.NewSecret(testServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{Endpoint: endpoint, ServiceCredential: credential})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func authorizationRequest() port.AuthorizationRequest {
	return port.AuthorizationRequest{
		Credential: "Bearer " + testSubjectCredential,
		Action:     iamv1.ActionDevOpsPipelineRead,
		Resource:   iamv1.ResourceReference{Kind: iamv1.ResourcePipeline, ID: "pipeline-one"},
		RequestID:  "request-one", CorrelationID: "correlation-one",
		TraceParent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
	}
}
