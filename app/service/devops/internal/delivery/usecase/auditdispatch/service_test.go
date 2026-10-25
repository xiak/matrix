package auditdispatch

import (
	"context"
	"errors"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
)

var auditTestTime = time.Date(2026, 9, 8, 2, 3, 4, 567_000, time.UTC)

func TestDispatchOnceDeliversClaimWithStableIdentity(t *testing.T) {
	repository := &fakeRepository{claims: []Claim{auditClaim(1)}}
	ingestor := &fakeIngestor{}
	result, err := mustUsecase(t, repository, ingestor, 3).DispatchOnce(context.Background())
	if err != nil || !result.Claimed || !result.Delivered || result.Retried || result.DeadLetter {
		t.Fatalf("dispatch result=%#v err=%v", result, err)
	}
	if len(ingestor.events) != 1 || ingestor.events[0].EventID != "audit-event-one" ||
		len(repository.completions) != 1 || repository.completions[0].Outcome != OutcomeDelivered ||
		repository.completions[0].FencingToken != 7 {
		t.Fatalf("ingestion/completion=%#v / %#v", ingestor.events, repository.completions)
	}
}

func TestDispatchOnceClassifiesRetryAndTerminalOutcomes(t *testing.T) {
	tests := []struct {
		name      string
		attempts  int
		delivery  error
		want      Outcome
		errorCode string
		wantRetry bool
		wantDead  bool
	}{
		{"retry", 1, port.ErrAuditUnavailable, OutcomeRetry, "", true, false},
		{"exhausted", 3, port.ErrAuditUnavailable, OutcomeDeadLetter, "AUDIT_DELIVERY_EXHAUSTED", false, true},
		{"rejected", 1, port.ErrAuditInvalid, OutcomeDeadLetter, "AUDIT_DELIVERY_REJECTED", false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{claims: []Claim{auditClaim(test.attempts)}}
			result, err := mustUsecase(t, repository, &fakeIngestor{err: test.delivery}, 3).DispatchOnce(context.Background())
			if err != nil || result.Retried != test.wantRetry || result.DeadLetter != test.wantDead {
				t.Fatalf("dispatch result=%#v err=%v", result, err)
			}
			completion := repository.completions[0]
			if completion.Outcome != test.want || completion.ErrorCode != test.errorCode {
				t.Fatalf("completion=%#v", completion)
			}
			if test.wantRetry && !completion.RetryAt.Equal(auditTestTime.Add(time.Second)) {
				t.Fatalf("retryAt=%s", completion.RetryAt)
			}
		})
	}
}

func TestDispatchOnceSurfacesStaleFencingCompletion(t *testing.T) {
	repository := &fakeRepository{claims: []Claim{auditClaim(1)}, completeErr: ErrStaleLease}
	_, err := mustUsecase(t, repository, &fakeIngestor{}, 3).DispatchOnce(context.Background())
	if !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale completion error=%v", err)
	}
}

type fakeRepository struct {
	claims      []Claim
	completions []Completion
	completeErr error
	readiness   devopsv1.Readiness
}

func (repository *fakeRepository) Claim(context.Context, string, time.Duration) (Claim, bool, error) {
	if len(repository.claims) == 0 {
		return Claim{}, false, nil
	}
	claim := repository.claims[0]
	repository.claims = repository.claims[1:]
	return claim, true, nil
}
func (repository *fakeRepository) Complete(_ context.Context, completion Completion) error {
	repository.completions = append(repository.completions, completion)
	return repository.completeErr
}
func (*fakeRepository) Snapshot(context.Context) (Snapshot, error) { return Snapshot{}, nil }
func (repository *fakeRepository) Readiness(context.Context) (devopsv1.Readiness, error) {
	return repository.readiness, nil
}

type fakeIngestor struct {
	events []auditv1.Event
	err    error
}

func (*fakeIngestor) Ready(context.Context) error { return nil }
func (ingestor *fakeIngestor) Ingest(_ context.Context, event auditv1.Event) error {
	ingestor.events = append(ingestor.events, event)
	return ingestor.err
}

func mustUsecase(t *testing.T, repository Repository, ingestor port.AuditIngestor, maxAttempts int) *Usecase {
	t.Helper()
	usecase, err := NewUsecase(repository, ingestor, Config{
		WorkerID: "audit-worker-one", LeaseDuration: 30 * time.Second,
		DeliveryTimeout: 5 * time.Second, InitialBackoff: time.Second,
		MaxBackoff: time.Minute, MaxAttempts: maxAttempts, Now: func() time.Time { return auditTestTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	return usecase
}

func auditClaim(attempts int) Claim {
	event := auditv1.Event{
		APIVersion: auditv1.APIVersion, Kind: "AuditEvent", EventID: "audit-event-one",
		TenantID: "tenant-one", Actor: auditv1.ActorReference{Type: auditv1.ActorUser, ID: "user-one"},
		IAMDecisionID: "decision-one", Action: auditv1.ActionDevOpsPipelineCreated,
		Target:        auditv1.TargetReference{Kind: auditv1.TargetPipeline, ID: "pipeline-one"},
		Result:        auditv1.ResultSucceeded,
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RequestID:     "request-one", CorrelationID: "correlation-one", OperationID: "operation-one",
		OccurredAt: auditTestTime,
	}
	return Claim{
		TenantID: "tenant-one", EventID: event.EventID, Attempts: attempts,
		FencingToken: 7, LeaseExpiresAt: auditTestTime.Add(30 * time.Second), Event: event,
	}
}
