package auditdispatch

import (
	"context"
	"errors"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestDispatchClassifiesDeliveryWithoutLosingTheClaim(t *testing.T) {
	tests := []struct {
		name       string
		attempts   int
		delivery   error
		outcome    Outcome
		errorCode  string
		retryDelay time.Duration
	}{
		{name: "delivered", attempts: 1, outcome: OutcomeDelivered},
		{name: "unavailable retries", attempts: 1, delivery: ErrIngestUnavailable, outcome: OutcomeRetry, retryDelay: time.Second},
		{name: "retry exhausts", attempts: 3, delivery: ErrIngestUnavailable, outcome: OutcomeDeadLetter, errorCode: "audit.delivery.exhausted"},
		{name: "authentication is terminal", attempts: 1, delivery: ErrIngestUnauthenticated, outcome: OutcomeDeadLetter, errorCode: "audit.delivery.rejected"},
		{name: "changed replay is terminal", attempts: 1, delivery: ErrIngestConflict, outcome: OutcomeDeadLetter, errorCode: "audit.delivery.rejected"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &dispatchRepository{claim: dispatchClaim(test.attempts)}
			ingestor := &dispatchIngestor{err: test.delivery}
			usecase, err := NewUsecase(repository, ingestor, Config{
				WorkerID:        "iam-audit-worker",
				LeaseDuration:   10 * time.Second,
				DeliveryTimeout: 5 * time.Second,
				InitialBackoff:  time.Second,
				MaxBackoff:      4 * time.Second,
				MaxAttempts:     3,
			})
			if err != nil {
				t.Fatalf("create IAM Audit dispatcher: %v", err)
			}
			result, err := usecase.DispatchOnce(context.Background())
			if err != nil || !result.Claimed || len(repository.completions) != 1 {
				t.Fatalf("dispatch IAM Audit result=%#v completions=%#v err=%v", result, repository.completions, err)
			}
			completion := repository.completions[0]
			if completion.Outcome != test.outcome || completion.ErrorCode != test.errorCode ||
				completion.RetryDelay != test.retryDelay || ingestor.events != 1 {
				t.Fatalf("IAM Audit completion=%#v deliveries=%d", completion, ingestor.events)
			}
		})
	}
}

func TestDispatchLeavesFencingFailuresVisible(t *testing.T) {
	repository := &dispatchRepository{
		claim:       dispatchClaim(1),
		completeErr: ErrStaleLease,
	}
	usecase, err := NewUsecase(repository, &dispatchIngestor{}, Config{
		WorkerID:        "iam-audit-worker",
		LeaseDuration:   10 * time.Second,
		DeliveryTimeout: 5 * time.Second,
		InitialBackoff:  time.Second,
		MaxBackoff:      4 * time.Second,
		MaxAttempts:     3,
	})
	if err != nil {
		t.Fatalf("create IAM Audit dispatcher: %v", err)
	}
	if _, err := usecase.DispatchOnce(context.Background()); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale IAM Audit completion error=%v", err)
	}
}

func TestDispatchBindsTenantAndInstallationChainsToTheStoredOwner(t *testing.T) {
	platform := dispatchClaim(1)
	platform.InstallationID = "installation-example"
	platform.Event.TenantID = ""
	platform.Event.InstallationID = platform.InstallationID
	platform.Event.Action = auditv1.ActionIAMTenantDisabled
	platform.Event.Actor = auditv1.ActorReference{Type: auditv1.ActorUser, ID: "platform-operator"}
	platform.Event.IAMDecisionID = "decision-disable-tenant"
	platform.Event.Target = auditv1.TargetReference{Kind: auditv1.TargetOrganization, ID: "another-tenant"}
	for _, test := range []struct {
		name  string
		claim Claim
		edit  func(*Claim)
		valid bool
	}{
		{name: "tenant fact", claim: dispatchClaim(1), valid: true},
		{name: "installation lifecycle fact", claim: platform, valid: true},
		{name: "wrong tenant owner", claim: dispatchClaim(1), edit: func(claim *Claim) { claim.OrganizationID = "another-tenant" }},
		{name: "unsealed installation", claim: platform, edit: func(claim *Claim) { claim.InstallationID = "" }},
		{name: "wrong installation", claim: platform, edit: func(claim *Claim) { claim.InstallationID = "installation-other" }},
		{name: "missing storage owner", claim: platform, edit: func(claim *Claim) { claim.OrganizationID = "" }},
		{name: "tenant cannot replace installation", claim: platform, edit: func(claim *Claim) { claim.Event.TenantID = "another-tenant"; claim.Event.InstallationID = "" }},
		{name: "mixed chain scopes", claim: platform, edit: func(claim *Claim) { claim.Event.TenantID = "another-tenant" }},
		{name: "wrong action scope", claim: platform, edit: func(claim *Claim) { claim.Event.Action = auditv1.ActionIAMOrganizationCreated }},
		{name: "substituted event", claim: platform, edit: func(claim *Claim) { claim.EventID = "event-other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.edit != nil {
				test.edit(&test.claim)
			}
			repository := &dispatchRepository{claim: test.claim}
			ingestor := &dispatchIngestor{}
			usecase, err := NewUsecase(repository, ingestor, Config{
				WorkerID: "iam-audit-worker", LeaseDuration: 10 * time.Second,
				DeliveryTimeout: 5 * time.Second, InitialBackoff: time.Second,
				MaxBackoff: 4 * time.Second, MaxAttempts: 3,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := usecase.DispatchOnce(context.Background())
			if test.valid {
				if err != nil || !result.Delivered || ingestor.events != 1 || len(repository.completions) != 1 {
					t.Fatalf("valid scoped claim: result=%#v error=%v deliveries=%d", result, err, ingestor.events)
				}
			} else if err == nil || ingestor.events != 0 || len(repository.completions) != 0 {
				t.Fatalf("invalid scope reached delivery: result=%#v error=%v deliveries=%d", result, err, ingestor.events)
			}
		})
	}
}

type dispatchRepository struct {
	claim       Claim
	completeErr error
	completions []Completion
}

func (repository *dispatchRepository) Claim(
	context.Context,
	string,
	time.Duration,
) (Claim, bool, error) {
	return repository.claim, true, nil
}

func (repository *dispatchRepository) Complete(
	_ context.Context,
	completion Completion,
) error {
	repository.completions = append(repository.completions, completion)
	return repository.completeErr
}

func (repository *dispatchRepository) Snapshot(context.Context) (Snapshot, error) {
	return Snapshot{}, nil
}

type dispatchIngestor struct {
	err    error
	events int
}

func (ingestor *dispatchIngestor) Ingest(context.Context, auditv1.Event) error {
	ingestor.events++
	return ingestor.err
}

func dispatchClaim(attempts int) Claim {
	now := time.Date(2026, 8, 26, 18, 19, 20, 123000, time.UTC)
	event := auditv1.Event{
		APIVersion: auditv1.APIVersion,
		Kind:       "AuditEvent",
		EventID:    "event-iam-outbox",
		TenantID:   "organization-example",
		Actor:      auditv1.ActorReference{Type: auditv1.ActorSystem, ID: "iam-bootstrap"},
		Action:     auditv1.ActionIAMBootstrapApplied,
		Target:     auditv1.TargetReference{Kind: auditv1.TargetInstallation, ID: "installation-example"},
		Result:     auditv1.ResultSucceeded,
		RequestDigest: "sha256:0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef",
		RequestID:     "request-iam-outbox",
		CorrelationID: "request-iam-outbox",
		OccurredAt:    now,
	}
	return Claim{
		OrganizationID: iamv1.OrganizationID(event.TenantID), EventID: event.EventID, Attempts: attempts,
		FencingToken: uint64(attempts), LeaseExpiresAt: now.Add(10 * time.Second), Event: event,
	}
}
