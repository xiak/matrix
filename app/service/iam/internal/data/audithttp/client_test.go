package audithttp

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
	"github.com/xiak/matrix/app/service/iam/internal/usecase/auditdispatch"
)

func TestClientDeliversIAMEventAndAcceptsOnlyExactAuditResult(t *testing.T) {
	event, record := auditFixture(t)
	outcome := auditv1.IngestionAccepted
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/events" ||
			request.URL.RawQuery != "" || request.Header.Get("Authorization") != "Bearer iam-producer-credential" ||
			request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Audit ingest request method=%s url=%s headers=%#v", request.Method, request.URL, request.Header)
		}
		var submitted auditv1.Event
		if err := auditv1.DecodeRequest(request.Body, &submitted); err != nil || submitted != event {
			t.Errorf("Audit submitted event=%#v err=%v", submitted, err)
		}
		response.Header().Set("Content-Type", "application/json")
		status := http.StatusCreated
		if outcome == auditv1.IngestionDuplicate {
			status = http.StatusOK
		}
		response.WriteHeader(status)
		_ = json.NewEncoder(response).Encode(auditv1.IngestionResult{
			APIVersion: auditv1.APIVersion,
			Kind:       "IngestionResult",
			Outcome:    outcome,
			Record:     record,
		})
	}))
	defer server.Close()
	client, err := NewClient(Config{
		Endpoint: server.URL, Credential: auditClientSecret(t, "iam-producer-credential"),
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("create Audit HTTP client: %v", err)
	}
	if err := client.Ingest(context.Background(), event); err != nil {
		t.Fatalf("deliver new IAM Audit event: %v", err)
	}
	outcome = auditv1.IngestionDuplicate
	if err := client.Ingest(context.Background(), event); err != nil {
		t.Fatalf("deliver duplicate IAM Audit event: %v", err)
	}
	record.Event.RequestID = "request-substituted"
	if err := client.Ingest(context.Background(), event); !errors.Is(err, auditdispatch.ErrIngestUnavailable) {
		t.Fatalf("substituted Audit result error=%v", err)
	}
}

func TestClientClassifiesAuditFailuresWithoutLeakingResponsesOrRedirecting(t *testing.T) {
	event, _ := auditFixture(t)
	redirectCalls := 0
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectCalls++
	}))
	defer redirectTarget.Close()
	status := http.StatusTemporaryRedirect
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if status == http.StatusTemporaryRedirect {
			response.Header().Set("Location", redirectTarget.URL)
		}
		response.Header().Set("Content-Type", "application/problem+json")
		response.WriteHeader(status)
		_, _ = response.Write([]byte(`{"detail":"native credential=do-not-leak"}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{
		Endpoint: server.URL, Credential: auditClientSecret(t, "iam-producer-credential"),
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("create Audit HTTP client: %v", err)
	}
	tests := []struct {
		status int
		want   error
	}{
		{http.StatusTemporaryRedirect, auditdispatch.ErrIngestUnavailable},
		{http.StatusUnauthorized, auditdispatch.ErrIngestUnauthenticated},
		{http.StatusUnprocessableEntity, auditdispatch.ErrIngestInvalid},
		{http.StatusConflict, auditdispatch.ErrIngestConflict},
		{http.StatusServiceUnavailable, auditdispatch.ErrIngestUnavailable},
	}
	for _, test := range tests {
		status = test.status
		err := client.Ingest(context.Background(), event)
		if !errors.Is(err, test.want) || strings.Contains(err.Error(), "do-not-leak") {
			t.Fatalf("Audit status=%d error=%v want=%v", status, err, test.want)
		}
	}
	if redirectCalls != 0 {
		t.Fatalf("Audit client followed credential redirect %d times", redirectCalls)
	}
}

func auditFixture(t *testing.T) (auditv1.Event, auditv1.AuditRecord) {
	t.Helper()
	now := time.Date(2026, 8, 26, 19, 20, 21, 123000, time.UTC)
	event := auditv1.Event{
		APIVersion: auditv1.APIVersion,
		Kind:       "AuditEvent",
		EventID:    "event-iam-client",
		TenantID:   "organization-example",
		Actor:      auditv1.ActorReference{Type: auditv1.ActorSystem, ID: "iam-bootstrap"},
		Action:     auditv1.ActionIAMBootstrapApplied,
		Target:     auditv1.TargetReference{Kind: auditv1.TargetInstallation, ID: "installation-example"},
		Result:     auditv1.ResultSucceeded,
		RequestDigest: "sha256:0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef",
		RequestID:     "request-iam-client",
		CorrelationID: "request-iam-client",
		OccurredAt:    now,
	}
	record := auditv1.AuditRecord{
		APIVersion:    auditv1.APIVersion,
		Kind:          "AuditRecord",
		Source:        auditv1.SourceIAM,
		Sequence:      1,
		Event:         event,
		ContentDigest: "sha256:" + strings.Repeat("3", 64),
		PreviousHash:  "sha256:" + strings.Repeat("0", 64),
		RecordHash:    "sha256:" + strings.Repeat("4", 64),
		IngestedAt:    now,
		Retention:     auditv1.RetentionIndefinite,
	}
	return event, record
}

func auditClientSecret(t *testing.T, value string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(value)
	if err != nil {
		t.Fatalf("create Audit HTTP client secret: %v", err)
	}
	return secret
}
