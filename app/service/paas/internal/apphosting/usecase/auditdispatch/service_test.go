package auditdispatch

import (
	"context"
	"errors"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

var auditTestTime = time.Date(2026, 8, 25, 18, 0, 0, 123_000, time.UTC)

func TestDispatchOnceDeliversClaimWithStableIdentity(t *testing.T) {
	repository := &fakeAuditRepository{claims: []Claim{auditClaim(1)}}
	ingestor := &fakeAuditIngestor{}
	usecase := mustAuditUsecase(t, repository, ingestor, 3)
	result, err := usecase.DispatchOnce(context.Background())
	if err != nil {
		t.Fatalf("dispatch Audit event: %v", err)
	}
	if !result.Claimed || !result.Delivered || result.Retried || result.DeadLetter {
		t.Fatalf("dispatch result = %#v", result)
	}
	if len(ingestor.events) != 1 || ingestor.events[0].EventID != "audit-event-a" {
		t.Fatalf("ingested events = %#v", ingestor.events)
	}
	if len(repository.completions) != 1 ||
		repository.completions[0].Outcome != OutcomeDelivered ||
		repository.completions[0].FencingToken != 7 {
		t.Fatalf("Audit completion = %#v", repository.completions)
	}
}

func TestDispatchOnceRetriesWithoutPersistingNativeError(t *testing.T) {
	repository := &fakeAuditRepository{claims: []Claim{auditClaim(1)}}
	ingestor := &fakeAuditIngestor{err: errors.New("native response contained credential=do-not-store")}
	usecase := mustAuditUsecase(t, repository, ingestor, 4)
	result, err := usecase.DispatchOnce(context.Background())
	if err != nil {
		t.Fatalf("retry Audit event: %v", err)
	}
	if !result.Retried || len(repository.completions) != 1 {
		t.Fatalf("retry result/completions = %#v / %#v", result, repository.completions)
	}
	completion := repository.completions[0]
	if completion.Outcome != OutcomeRetry || completion.ErrorCode != "" ||
		!completion.RetryAt.Equal(auditTestTime.Add(time.Second)) {
		t.Fatalf("retry completion = %#v", completion)
	}
}

func TestDispatchOnceDeadLettersAfterBoundedAttempts(t *testing.T) {
	repository := &fakeAuditRepository{claims: []Claim{auditClaim(3)}}
	ingestor := &fakeAuditIngestor{err: errors.New("unavailable")}
	result, err := mustAuditUsecase(t, repository, ingestor, 3).DispatchOnce(context.Background())
	if err != nil {
		t.Fatalf("dead-letter Audit event: %v", err)
	}
	if !result.DeadLetter || repository.completions[0].Outcome != OutcomeDeadLetter ||
		repository.completions[0].ErrorCode != "AUDIT_DELIVERY_EXHAUSTED" {
		t.Fatalf("dead-letter result = %#v / %#v", result, repository.completions)
	}
}

func TestDispatchOnceSurfacesStaleFencingCompletion(t *testing.T) {
	repository := &fakeAuditRepository{
		claims: []Claim{auditClaim(1)}, completeErr: ErrStaleLease,
	}
	_, err := mustAuditUsecase(t, repository, &fakeAuditIngestor{}, 3).DispatchOnce(context.Background())
	if !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale completion error = %v", err)
	}
}

func TestDispatchReplayUsesSameEventIDForIdempotentIngestion(t *testing.T) {
	first := auditClaim(1)
	second := auditClaim(2)
	second.FencingToken++
	repository := &fakeAuditRepository{claims: []Claim{first, second}}
	ingestor := &fakeAuditIngestor{}
	usecase := mustAuditUsecase(t, repository, ingestor, 4)
	if _, err := usecase.DispatchOnce(context.Background()); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	if _, err := usecase.DispatchOnce(context.Background()); err != nil {
		t.Fatalf("reclaimed dispatch: %v", err)
	}
	if len(ingestor.events) != 2 || ingestor.events[0].EventID != ingestor.events[1].EventID {
		t.Fatalf("at-least-once event identities = %#v", ingestor.events)
	}
}

type fakeAuditRepository struct {
	claims      []Claim
	completions []Completion
	completeErr error
}

func (repository *fakeAuditRepository) Claim(
	context.Context,
	string,
	time.Duration,
) (Claim, bool, error) {
	if len(repository.claims) == 0 {
		return Claim{}, false, nil
	}
	claim := repository.claims[0]
	repository.claims = repository.claims[1:]
	return claim, true, nil
}

func (repository *fakeAuditRepository) Complete(_ context.Context, completion Completion) error {
	repository.completions = append(repository.completions, completion)
	return repository.completeErr
}

func (repository *fakeAuditRepository) Snapshot(context.Context) (Snapshot, error) {
	return Snapshot{}, nil
}

type fakeAuditIngestor struct {
	events []port.AuditEvent
	err    error
}

func (ingestor *fakeAuditIngestor) Ingest(_ context.Context, event port.AuditEvent) error {
	ingestor.events = append(ingestor.events, event)
	return ingestor.err
}

func mustAuditUsecase(
	t *testing.T,
	repository Repository,
	ingestor port.AuditIngestor,
	maxAttempts int,
) *Usecase {
	t.Helper()
	usecase, err := NewUsecase(repository, ingestor, Config{
		WorkerID: "audit-worker-a", LeaseDuration: 30 * time.Second,
		DeliveryTimeout: 5 * time.Second, InitialBackoff: time.Second,
		MaxBackoff: time.Minute, MaxAttempts: maxAttempts,
		Now: func() time.Time { return auditTestTime },
	})
	if err != nil {
		t.Fatalf("create Audit dispatch use case: %v", err)
	}
	return usecase
}

func auditClaim(attempts int) Claim {
	event := port.AuditEvent{
		SchemaVersion: "v1", EventID: "audit-event-a", TenantID: "tenant-a",
		Actor:         paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-a"},
		IAMDecisionID: "decision-a", Action: port.AuditDeploymentCreated,
		Target:        paasv1.ResourceRef{Kind: "Deployment", ID: "deployment-a"},
		OperationID:   "operation-a",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Result:        port.AuditAccepted, RequestID: "request-a", OccurredAt: auditTestTime,
	}
	return Claim{
		TenantID: "tenant-a", EventID: event.EventID, Attempts: attempts,
		FencingToken: 7, LeaseExpiresAt: auditTestTime.Add(30 * time.Second), Event: event,
	}
}
