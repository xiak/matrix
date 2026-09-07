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
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

const testAuditCredential = "mx1.DevOpsAuditCredential000000000000000000001"

func TestClientAcceptsNewAndEqualReplayForExactDevOpsEvent(t *testing.T) {
	for _, scenario := range []struct {
		status  int
		outcome auditv1.IngestionOutcome
	}{
		{http.StatusCreated, auditv1.IngestionAccepted},
		{http.StatusOK, auditv1.IngestionDuplicate},
	} {
		t.Run(string(scenario.outcome), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/v1/events" ||
					request.Header.Get("Authorization") != "Bearer "+testAuditCredential ||
					request.Header.Get("Matrix-Subject-Credential") != "" {
					t.Fatalf("Audit request path=%s headers=%#v", request.URL.Path, request.Header)
				}
				var event auditv1.Event
				if auditv1.DecodeRequest(request.Body, &event) != nil ||
					auditv1.ValidateEventForSource(auditv1.SourceDevOps, event) != nil {
					t.Fatalf("DevOps Audit event=%#v", event)
				}
				response.Header().Set("Content-Type", "application/json")
				response.WriteHeader(scenario.status)
				_ = json.NewEncoder(response).Encode(ingestionResult(event, scenario.outcome))
			}))
			defer server.Close()
			if err := newAuditClient(t, server.URL).Ingest(context.Background(), testEvent()); err != nil {
				t.Fatalf("ingest DevOps Audit event: %v", err)
			}
		})
	}
}

func TestClientRequiresReadyAuditAndClassifiesFailures(t *testing.T) {
	state := auditv1.ReadinessReady
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/ready" {
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(auditv1.Readiness{
				APIVersion: auditv1.APIVersion, Kind: "Readiness", State: state,
				SchemaVersion: 1, CheckedAt: time.Date(2026, 9, 8, 3, 0, 0, 0, time.UTC),
			})
			return
		}
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := newAuditClient(t, server.URL)
	if err := client.Ready(context.Background()); err != nil {
		t.Fatalf("Audit readiness: %v", err)
	}
	state = auditv1.ReadinessNotReady
	if err := client.Ready(context.Background()); !errors.Is(err, port.ErrAuditUnavailable) {
		t.Fatalf("not-ready error=%v", err)
	}
	if err := client.Ingest(context.Background(), testEvent()); !errors.Is(err, port.ErrAuditUnavailable) {
		t.Fatalf("unavailable ingestion error=%v", err)
	}
}

func TestClientRejectsInvalidEventAndMismatchedSuccess(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		var event auditv1.Event
		_ = auditv1.DecodeRequest(request.Body, &event)
		event.RequestID = "request-other"
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(ingestionResult(event, auditv1.IngestionAccepted))
	}))
	defer server.Close()
	client := newAuditClient(t, server.URL)
	invalid := testEvent()
	invalid.Target.Kind = auditv1.TargetApplication
	if err := client.Ingest(context.Background(), invalid); !errors.Is(err, port.ErrAuditInvalid) || calls != 0 {
		t.Fatalf("invalid event error=%v calls=%d", err, calls)
	}
	if err := client.Ingest(context.Background(), testEvent()); !errors.Is(err, port.ErrAuditUnavailable) {
		t.Fatalf("mismatched success error=%v", err)
	}
}

func newAuditClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	credential, err := iamv1.NewSecret(testAuditCredential)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{Endpoint: endpoint, Credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testEvent() auditv1.Event {
	return auditv1.Event{
		APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: "audit-event-one",
		TenantID: "organization-one", Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: "user-one"},
		IAMDecisionID: "decision-one", Action: auditv1.ActionDevOpsPipelineCreated,
		Target:        auditv1.TargetReference{Kind: auditv1.TargetPipeline, ID: "pipeline-one"},
		Result:        auditv1.ResultSucceeded,
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RequestID:     "request-one", CorrelationID: "correlation-one", OperationID: "operation-one",
		OccurredAt: time.Date(2026, 9, 8, 2, 3, 4, 567_000, time.UTC),
	}
}

func ingestionResult(event auditv1.Event, outcome auditv1.IngestionOutcome) auditv1.IngestionResult {
	return auditv1.IngestionResult{
		APIVersion: auditv1.APIVersion, Kind: "IngestionResult", Outcome: outcome,
		Record: auditv1.AuditRecord{
			APIVersion: auditv1.APIVersion, Kind: "AuditRecord", Source: auditv1.SourceDevOps,
			Sequence: 1, Event: event,
			ContentDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			PreviousHash:  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			RecordHash:    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			IngestedAt:    time.Date(2026, 9, 8, 2, 3, 5, 0, time.UTC), Retention: auditv1.RetentionIndefinite,
		},
	}
}
