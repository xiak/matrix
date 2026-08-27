package authority

import (
	"errors"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

func TestCanonicalEventIsStableSourceBoundAndMicrosecondExact(t *testing.T) {
	event := auditAuthorityEvent("event-one", "organization-example", auditv1.ActionPaaSDeploymentCreated)
	first, err := Canonicalize(auditv1.SourcePaaS, event)
	if err != nil {
		t.Fatalf("canonicalize event: %v", err)
	}
	second, err := Canonicalize(auditv1.SourcePaaS, event)
	if err != nil || first.Document != second.Document || first.ContentDigest != second.ContentDigest {
		t.Fatalf("canonical event is not stable: first=%#v second=%#v err=%v", first, second, err)
	}
	if !strings.Contains(first.Document, `"source":"PAAS"`) ||
		!strings.Contains(first.Document, `"occurredAt":"2026-08-25T05:06:07.000000Z"`) {
		t.Fatalf("canonical envelope omitted source or fixed UTC precision: %s", first.Document)
	}
	if _, err := Canonicalize(auditv1.SourceIAM, event); !errors.Is(err, ErrCanonicalEvent) {
		t.Fatalf("forged source canonicalization error = %v", err)
	}
}

func TestReplayIdentityAcceptsEqualCanonicalContentAndConflictsOnChange(t *testing.T) {
	event := auditAuthorityEvent("event-one", "organization-example", auditv1.ActionPaaSDeploymentCreated)
	outcome, fact, err := ClassifyReplay(nil, auditv1.SourcePaaS, event)
	if err != nil || outcome != ReplayNew {
		t.Fatalf("classify new event: outcome=%q fact=%#v err=%v", outcome, fact, err)
	}
	existing := ReplayState{
		Source: auditv1.SourcePaaS, EventID: event.EventID,
		CanonicalDocument: fact.Document, ContentDigest: fact.ContentDigest,
	}
	outcome, replay, err := ClassifyReplay(&existing, auditv1.SourcePaaS, event)
	if err != nil || outcome != ReplayEqual || replay.ContentDigest != fact.ContentDigest {
		t.Fatalf("classify equal replay: outcome=%q fact=%#v err=%v", outcome, replay, err)
	}
	changed := event
	changed.RequestDigest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	if _, _, err := ClassifyReplay(&existing, auditv1.SourcePaaS, changed); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("changed replay error = %v, want conflict", err)
	}
	corrupt := existing
	corrupt.CanonicalDocument = "!" + corrupt.CanonicalDocument[1:]
	if _, _, err := ClassifyReplay(&corrupt, auditv1.SourcePaaS, event); !errors.Is(err, ErrInvalidReplayState) {
		t.Fatalf("corrupt replay state error = %v", err)
	}
	if strings.Contains(ErrReplayConflict.Error(), fact.Document) {
		t.Fatal("replay conflict exposes canonical event bytes")
	}
}

func auditAuthorityEvent(eventID, tenantID string, action auditv1.Action) auditv1.Event {
	contract, known := auditv1.ContractForAction(action)
	if !known {
		panic("test action has no contract")
	}
	event := auditv1.Event{
		APIVersion:    auditv1.APIVersion,
		Kind:          "AuditEvent",
		EventID:       auditv1.EventID(eventID),
		TenantID:      auditv1.TenantID(tenantID),
		Actor:         auditv1.ActorReference{Type: auditv1.ActorUser, ID: "principal-example"},
		Action:        action,
		Target:        auditv1.TargetReference{Kind: contract.Target, ID: "target-example"},
		Result:        contract.Results[0],
		RequestDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		RequestID:     "request-example",
		CorrelationID: "correlation-example",
		OccurredAt:    time.Date(2026, 8, 25, 5, 6, 7, 0, time.UTC),
	}
	if contract.IAMDecisionRequired {
		event.IAMDecisionID = "decision-example"
	}
	if action == auditv1.ActionIAMAuthorizationDecided {
		event.Target.ID = string(event.IAMDecisionID)
	}
	if contract.OperationRequired {
		event.OperationID = "operation-example"
	}
	if contract.PlatformOnly {
		event.TenantID, event.InstallationID = "", tenantID
	}
	return event
}
