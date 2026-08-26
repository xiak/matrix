package audithttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

const testPaaSAuditCredential = "mx1.PaaSAuditCredential00000000000000000000001"

func TestClientRequiresExactAuditReadiness(t *testing.T) {
	state := auditv1.ReadinessReady
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/ready" {
			t.Fatalf("Audit readiness request=%s %s", request.Method, request.URL)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(auditv1.Readiness{
			APIVersion: auditv1.APIVersion, Kind: "Readiness", State: state,
			SchemaVersion: 1, CheckedAt: time.Date(2026, 8, 26, 2, 0, 0, 0, time.UTC),
		})
	}))
	defer server.Close()
	client := newAuditClient(t, server.URL)
	if err := client.Ready(context.Background()); err != nil {
		t.Fatalf("ready Audit client: %v", err)
	}
	state = auditv1.ReadinessNotReady
	if err := client.Ready(context.Background()); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("not-ready Audit error=%v", err)
	}
}

func TestClientAcceptsNewAndEqualReplayUsingClosedAuditEvent(t *testing.T) {
	for _, scenario := range []struct {
		status  int
		outcome auditv1.IngestionOutcome
	}{
		{status: http.StatusCreated, outcome: auditv1.IngestionAccepted},
		{status: http.StatusOK, outcome: auditv1.IngestionDuplicate},
	} {
		t.Run(string(scenario.outcome), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/v1/events" ||
					request.Header.Get("Authorization") != "Bearer "+testPaaSAuditCredential {
					t.Fatalf("Audit request path=%s headers=%#v", request.URL.Path, request.Header)
				}
				var event auditv1.Event
				if auditv1.DecodeRequest(request.Body, &event) != nil ||
					auditv1.ValidateEventForSource(auditv1.SourcePaaS, event) != nil ||
					event.Target.Kind != auditv1.TargetApplication ||
					event.CorrelationID != "audit-paas-flow" {
					t.Fatalf("mapped Audit event=%#v", event)
				}
				response.Header().Set("Content-Type", "application/json")
				response.WriteHeader(scenario.status)
				_ = json.NewEncoder(response).Encode(ingestionResult(event, scenario.outcome))
			}))
			defer server.Close()
			if err := newAuditClient(t, server.URL).Ingest(context.Background(), testPaaSAuditEvent()); err != nil {
				t.Fatalf("ingest PaaS Audit event: %v", err)
			}
		})
	}
}

func TestClientClassifiesTerminalAndRetryableFailures(t *testing.T) {
	for _, scenario := range []struct {
		status int
		want   error
	}{
		{status: http.StatusUnauthorized, want: audit.ErrUnauthenticated},
		{status: http.StatusForbidden, want: audit.ErrUnauthenticated},
		{status: http.StatusBadRequest, want: audit.ErrInvalid},
		{status: http.StatusConflict, want: audit.ErrConflict},
		{status: http.StatusServiceUnavailable, want: audit.ErrUnavailable},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(scenario.status)
		}))
		err := newAuditClient(t, server.URL).Ingest(context.Background(), testPaaSAuditEvent())
		server.Close()
		if !errors.Is(err, scenario.want) {
			t.Fatalf("status %d error=%v want=%v", scenario.status, err, scenario.want)
		}
	}
}

func TestClientRejectsInvalidLocalEventBeforeNetwork(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	event := testPaaSAuditEvent()
	event.Target.Kind = "Deployment"
	if err := newAuditClient(t, server.URL).Ingest(context.Background(), event); !errors.Is(err, audit.ErrInvalid) {
		t.Fatalf("invalid local event error=%v", err)
	}
	if calls != 0 {
		t.Fatalf("invalid local event reached Audit %d times", calls)
	}
}

func TestClientRejectsMismatchedSuccessAsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var event auditv1.Event
		if auditv1.DecodeRequest(request.Body, &event) != nil {
			t.Fatal("decode Audit request")
		}
		event.RequestID = "request-other"
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(ingestionResult(event, auditv1.IngestionAccepted))
	}))
	defer server.Close()
	err := newAuditClient(t, server.URL).Ingest(context.Background(), testPaaSAuditEvent())
	if !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("mismatched success error=%v", err)
	}
}

func newAuditClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	credential, err := iamv1.NewSecret(testPaaSAuditCredential)
	if err != nil {
		t.Fatalf("create PaaS Audit credential: %v", err)
	}
	client, err := NewClient(Config{Endpoint: endpoint, Credential: credential})
	if err != nil {
		t.Fatalf("create PaaS Audit client: %v", err)
	}
	return client
}

func testPaaSAuditEvent() audit.Event {
	return audit.Event{
		SchemaVersion: "v1", EventID: "audit-paas-application", TenantID: "organization-a",
		Actor:         paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "principal-developer"},
		IAMDecisionID: "decision-paas-create", Action: audit.ApplicationCreated,
		Target:        paasv1.ResourceRef{Kind: "Application", ID: "application-a"},
		OperationID:   "operation-paas-create",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Result:        audit.Succeeded, RequestID: "request-paas-create",
		AuditID: "audit-paas-flow", OccurredAt: time.Date(2026, 8, 26, 2, 3, 4, 567_000, time.UTC),
	}
}

func ingestionResult(event auditv1.Event, outcome auditv1.IngestionOutcome) auditv1.IngestionResult {
	return auditv1.IngestionResult{
		APIVersion: auditv1.APIVersion, Kind: "IngestionResult", Outcome: outcome,
		Record: auditv1.AuditRecord{
			APIVersion: auditv1.APIVersion, Kind: "AuditRecord", Source: auditv1.SourcePaaS,
			Sequence: 1, Event: event,
			ContentDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			PreviousHash:  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			RecordHash:    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			IngestedAt:    time.Date(2026, 8, 26, 2, 3, 5, 0, time.UTC),
			Retention:     auditv1.RetentionIndefinite,
		},
	}
}
