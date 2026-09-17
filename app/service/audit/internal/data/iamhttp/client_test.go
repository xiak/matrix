package iamhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/audit/internal/usecase/auditlog"
)

func TestClientBindsProducerAndSubjectCredentialsToExactIAMRoutes(t *testing.T) {
	now := time.Date(2026, 8, 26, 17, 18, 19, 123000, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/audit-producer:resolve":
			if request.Method != http.MethodPost || request.URL.RawQuery != "" ||
				request.Header.Get("Authorization") != "Bearer producer-credential" ||
				request.Header.Get("Matrix-Subject-Credential") != "" || request.Body == nil {
				t.Errorf("IAM identity request method=%s url=%s headers=%#v", request.Method, request.URL, request.Header)
			}
			var body iamv1.ResolveAuditProducerRequest
			if err := iamv1.DecodeRequest(request.Body, &body); err != nil || body.Event != clientEvent() {
				t.Errorf("IAM producer request=%#v err=%v", body, err)
			}
			_, digest, _ := auditv1.CanonicalizeEvent(auditv1.SourcePaaS, body.Event)
			_ = json.NewEncoder(response).Encode(iamv1.AuditProducerAuthorization{
				APIVersion: iamv1.APIVersion, Kind: "AuditProducerAuthorization",
				TenantID: iamv1.AccountID(body.Event.TenantID), ContentDigest: digest,
				Producer: iamv1.ServiceIdentity{
					APIVersion: iamv1.APIVersion, Kind: "ServiceIdentity",
					InstallationID: "installation-example",
					AccountID:      "organization-example", PrincipalID: "service-paas", Purpose: iamv1.ServicePaaS,
				},
			})
		case "/v1/authorize":
			if request.Method != http.MethodPost || request.URL.RawQuery != "" ||
				request.Header.Get("Authorization") != "Bearer audit-service-credential" ||
				request.Header.Get("Matrix-Subject-Credential") != "user-session-credential" ||
				request.Header.Get("Content-Type") != "application/json" {
				t.Errorf("IAM authorization request method=%s url=%s headers=%#v", request.Method, request.URL, request.Header)
			}
			var authorization iamv1.AuthorizationRequest
			if err := iamv1.DecodeRequest(request.Body, &authorization); err != nil {
				t.Errorf("decode IAM authorization request: %v", err)
			}
			_ = json.NewEncoder(response).Encode(iamv1.AuthorizationDecision{
				APIVersion: iamv1.APIVersion,
				Kind:       "AuthorizationDecision",
				ID:         "decision-example",
				Allowed:    true,
				Reason:     iamv1.DecisionAllowed,
				TenantID:   "organization-example",
				Subject:    &iamv1.Subject{Type: iamv1.SubjectUser, ID: "principal-reader"},
				Action:     authorization.Action,
				Resource:   authorization.Resource,
				RequestID:  authorization.RequestID,
				Profile:    &authorization.Profile, ResourceMode: authorization.ResourceMode, CollectionUsage: authorization.CollectionUsage, CorrelationID: authorization.CorrelationID,
				DecidedAt: now,
			})
		case "/v1/installation:verify":
			if request.Method != http.MethodPost || request.URL.RawQuery != "" ||
				request.Header.Get("Authorization") != "Bearer installation-verifier-credential" ||
				request.Header.Get("Matrix-Subject-Credential") != "" ||
				request.Header.Get("Content-Type") != "application/json" {
				t.Errorf("IAM verifier request method=%s url=%s headers=%#v", request.Method, request.URL, request.Header)
			}
			var authorization iamv1.AuthorizationRequest
			if err := iamv1.DecodeRequest(request.Body, &authorization); err != nil {
				t.Errorf("decode IAM verifier request: %v", err)
			}
			_ = json.NewEncoder(response).Encode(iamv1.AuthorizationDecision{
				APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
				ID: "decision-installation-verifier", Allowed: true, Reason: iamv1.DecisionAllowed,
				TenantID: "organization-example",
				Subject: &iamv1.Subject{
					Type: iamv1.SubjectServiceAccount, ID: "service-installation-verifier",
				},
				Action: authorization.Action, Resource: authorization.Resource,
				RequestID: authorization.RequestID, DecidedAt: now,
				Profile: &authorization.Profile, ResourceMode: authorization.ResourceMode, CollectionUsage: authorization.CollectionUsage, CorrelationID: authorization.CorrelationID,
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint:          server.URL,
		ServiceCredential: clientSecret(t, "audit-service-credential"),
		HTTPClient:        server.Client(),
	})
	if err != nil {
		t.Fatalf("create IAM HTTP client: %v", err)
	}
	identity, err := client.ResolveAuditProducer(
		context.Background(),
		clientSecret(t, "producer-credential"),
		iamv1.ResolveAuditProducerRequest{Event: clientEvent()},
	)
	if err != nil || identity.Producer.Purpose != iamv1.ServicePaaS ||
		identity.Producer.AccountID != "organization-example" || identity.TenantID != "organization-second" {
		t.Fatalf("IAM service identity=%#v err=%v", identity, err)
	}
	authorization, err := iamv1.NewAuthorizationRequest(iamv1.ActionAuditRecordRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceAuditRecord, ID: "collection"},
		iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList, "request-authorize", "request-authorize")
	if err != nil {
		t.Fatal(err)
	}
	decision, err := client.Authorize(
		context.Background(),
		clientSecret(t, "user-session-credential"),
		authorization,
	)
	if err != nil || !decision.Allowed || decision.Action != authorization.Action ||
		decision.RequestID != authorization.RequestID {
		t.Fatalf("IAM authorization decision=%#v err=%v", decision, err)
	}
	verificationRequest, err := iamv1.NewAuthorizationRequest(iamv1.ActionInstallationVerify,
		iamv1.ResourceReference{Kind: iamv1.ResourceInstallation, ID: "mxi-0123456789abcdef0123456789abcdef"},
		iamv1.AuthorizationResourceInstance, "", "request-installation-verifier", "request-installation-verifier")
	if err != nil {
		t.Fatal(err)
	}
	decision, err = client.VerifyInstallation(
		context.Background(),
		clientSecret(t, "installation-verifier-credential"),
		verificationRequest,
	)
	if err != nil || !decision.Allowed || decision.Subject == nil ||
		decision.Subject.Type != iamv1.SubjectServiceAccount {
		t.Fatalf("IAM verifier decision=%#v err=%v", decision, err)
	}
}

func TestClientBindsOneAccessKeyDecisionToTheSignedAuditRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/authorize:access-key" ||
			request.Header.Get("Authorization") != "Bearer audit-service-credential" ||
			request.Header.Get("Matrix-Subject-Credential") != "" {
			t.Fatalf("IAM signed request path=%s headers=%#v", request.URL.Path, request.Header)
		}
		input, err := iamv1.DecodeAccessKeyAuthorizationRequest(request.Body)
		if err != nil || input.Authorization.Action != iamv1.ActionAuditRecordRead ||
			input.SignedRequest.Parameters.Audience != iamv1.ProductAudit {
			t.Fatalf("decode signed authorization: %#v %v", input.Authorization, err)
		}
		digest, err := iamv1.AccessKeySignedRequestDigest(input.SignedRequest)
		if err != nil {
			t.Fatal(err)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(iamv1.AccessKeyAuthorization{
			APIVersion: iamv1.APIVersion,
			Kind:       "AccessKeyAuthorization",
			Decision: iamv1.AuthorizationDecision{
				APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
				ID: "decision-key", Allowed: true, Reason: iamv1.DecisionAllowed,
				TenantID: "organization-example",
				Subject: &iamv1.Subject{
					Type: iamv1.SubjectUser, ID: "principal-reader", AccessKeyID: "access-key-one",
				},
				Action: input.Authorization.Action, Resource: input.Authorization.Resource,
				RequestID: input.Authorization.RequestID, CorrelationID: input.Authorization.CorrelationID,
				Profile: &input.Authorization.Profile, ResourceMode: input.Authorization.ResourceMode,
				CollectionUsage: input.Authorization.CollectionUsage,
				DecidedAt:       time.Date(2026, 9, 17, 1, 2, 3, 0, time.UTC),
			},
			SignedRequestDigest: digest,
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Endpoint: server.URL, ServiceCredential: clientSecret(t, "audit-service-credential"), HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := auditAccessKeyAuthorizationRequest(t)
	result, err := client.AuthorizeAccessKey(context.Background(), request)
	if err != nil || !result.Decision.Allowed || result.Decision.Subject == nil ||
		result.Decision.Subject.AccessKeyID != "access-key-one" || result.Decision.TenantID != "organization-example" {
		t.Fatalf("access-key authorization=%#v err=%v", result, err)
	}
}

func TestClientReportsConsumedAuditAccessKeyNonceAsConflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	client, err := NewClient(Config{
		Endpoint: server.URL, ServiceCredential: clientSecret(t, "audit-service-credential"), HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AuthorizeAccessKey(context.Background(), auditAccessKeyAuthorizationRequest(t)); !errors.Is(err, auditlog.ErrConflict) {
		t.Fatalf("consumed nonce error=%v", err)
	}
}

func TestClientFailsClosedWithoutFollowingCredentialRedirects(t *testing.T) {
	redirectCalls := 0
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectCalls++
	}))
	defer redirectTarget.Close()
	responseMode := http.StatusTemporaryRedirect
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch responseMode {
		case http.StatusTemporaryRedirect:
			response.Header().Set("Location", redirectTarget.URL)
			response.WriteHeader(http.StatusTemporaryRedirect)
		case http.StatusUnauthorized, http.StatusForbidden:
			response.Header().Set("Content-Type", "application/problem+json")
			response.WriteHeader(responseMode)
			_, _ = response.Write([]byte(`{"detail":"native credential=do-not-leak"}`))
		default:
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"apiVersion":"iam.matrix.xiak.com/v1","kind":"ServiceIdentity","organizationId":"organization-example","principalId":"service-iam","purpose":"IAM","tenantId":"forged"}`))
		}
	}))
	defer server.Close()
	client, err := NewClient(Config{
		Endpoint:          server.URL,
		ServiceCredential: clientSecret(t, "audit-service-credential"),
		HTTPClient:        server.Client(),
	})
	if err != nil {
		t.Fatalf("create IAM HTTP client: %v", err)
	}
	credential := clientSecret(t, "producer-credential")
	request := iamv1.ResolveAuditProducerRequest{Event: clientEvent()}
	if _, err := client.ResolveAuditProducer(context.Background(), credential, request); !errors.Is(err, auditlog.ErrUnavailable) || redirectCalls != 0 {
		t.Fatalf("redirect IAM error=%v redirectCalls=%d", err, redirectCalls)
	}
	responseMode = http.StatusUnauthorized
	if _, err := client.ResolveAuditProducer(context.Background(), credential, request); !errors.Is(err, auditlog.ErrUnauthenticated) || strings.Contains(err.Error(), "do-not-leak") {
		t.Fatalf("unauthorized IAM error=%v", err)
	}
	responseMode = http.StatusForbidden
	if _, err := client.ResolveAuditProducer(context.Background(), credential, request); !errors.Is(err, auditlog.ErrForbidden) || strings.Contains(err.Error(), "do-not-leak") {
		t.Fatalf("forbidden IAM error=%v", err)
	}
	responseMode = http.StatusOK
	if _, err := client.ResolveAuditProducer(context.Background(), credential, request); !errors.Is(err, auditlog.ErrUnavailable) {
		t.Fatalf("ambiguous IAM success error=%v", err)
	}

	for _, endpoint := range []string{
		"http://user:password@example.invalid",
		"http://example.invalid/path",
		"http://example.invalid?tenant=forged",
		"file:///tmp/iam.sock",
	} {
		if _, err := NewClient(Config{
			Endpoint:          endpoint,
			ServiceCredential: clientSecret(t, "audit-service-credential"),
		}); err == nil {
			t.Fatalf("accepted unsafe IAM endpoint %q", endpoint)
		}
	}
}

func clientEvent() auditv1.Event {
	return auditv1.Event{APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: "event-proof",
		TenantID: "organization-second", Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: "principal-example"},
		IAMDecisionID: "decision-proof", Action: auditv1.ActionPaaSApplicationCreated,
		Target: auditv1.TargetReference{Kind: auditv1.TargetApplication, ID: "application-example"}, Result: auditv1.ResultSucceeded,
		RequestDigest: "sha256:" + strings.Repeat("1", 64), RequestID: "request-proof", CorrelationID: "request-proof", OperationID: "operation-proof",
		OccurredAt: time.Date(2026, 8, 26, 17, 18, 19, 123000, time.UTC)}
}

func clientSecret(t *testing.T, value string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(value)
	if err != nil {
		t.Fatalf("create IAM HTTP client secret: %v", err)
	}
	return secret
}

func auditAccessKeyAuthorizationRequest(t *testing.T) iamv1.AccessKeyAuthorizationRequest {
	t.Helper()
	authorization, err := iamv1.NewAuthorizationRequest(
		iamv1.ActionAuditRecordRead,
		iamv1.ResourceReference{Kind: iamv1.ResourceAuditRecord, ID: "collection"},
		iamv1.AuthorizationResourceCollection,
		iamv1.AuthorizationCollectionList,
		"request-audit-key",
		"request-audit-key",
	)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := iamv1.NewSecret(strings.Repeat("A", 22))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := iamv1.NewSecret(strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	return iamv1.AccessKeyAuthorizationRequest{
		Authorization: authorization,
		SignedRequest: iamv1.AccessKeySignedRequest{
			Parameters: iamv1.AccessKeySignatureParameters{
				AccessKeyID: "access-key-one", InstallationID: "installation-one", Audience: iamv1.ProductAudit,
				SignedAt: 1800000000, Nonce: nonce,
			},
			HTTP: iamv1.AccessKeyHTTPRequest{
				Method: http.MethodPost, Scheme: "https", Authority: "api.example.test:443",
				EscapedPath: "/api/audit/v1/records:query", ContentType: "application/json",
				BodyDigest: "sha256:1b5d9794535781df4b24845ab44a56410a3b65371970cab253ba943283e90c00",
			},
			Signature: signature,
		},
	}
}
