package audit

import (
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

func TestManagedServiceEventsMapToClosedAuditContracts(t *testing.T) {
	now := time.Date(2026, 8, 27, 8, 0, 0, 123_000, time.UTC)
	tests := []struct {
		name          string
		action        string
		targetKind    string
		result        Result
		operationID   OperationID
		wantTarget    auditv1.TargetKind
		wantOperation bool
	}{
		{
			name: "quota activated", action: QuotaEntitlementActivated,
			targetKind: TargetQuotaEntitlement, result: Succeeded,
			wantTarget: auditv1.TargetQuotaEntitlement,
		},
		{
			name: "installation accepted", action: ServiceInstallationCreated,
			targetKind: TargetServiceInstallation, result: Accepted,
			operationID: "operation-example", wantTarget: auditv1.TargetServiceInstallation,
			wantOperation: true,
		},
		{
			name: "installation ready", action: ServiceInstallationReady,
			targetKind: TargetServiceInstallation, result: Succeeded,
			wantTarget: auditv1.TargetServiceInstallation,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := Event{
				SchemaVersion: "v1", EventID: "audit-event-example",
				TenantID:      "organization-example",
				Actor:         ActorReference{Type: ActorUser, ID: "principal-example"},
				IAMDecisionID: "decision-example", Action: test.action,
				Target:        TargetReference{Kind: test.targetKind, ID: "resource-example"},
				OperationID:   test.operationID,
				RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Result:        test.result, RequestID: "request-example", OccurredAt: now,
			}
			if err := ValidateEvent(event); err != nil {
				t.Fatalf("validate managed-service event: %v", err)
			}
			public, err := ToV1(event)
			if err != nil || public.Target.Kind != test.wantTarget ||
				(public.OperationID != "") != test.wantOperation {
				t.Fatalf("mapped event = %#v err=%v", public, err)
			}
		})
	}
}

func TestQuotaAuditRejectsOperationAndProviderTarget(t *testing.T) {
	event := Event{
		SchemaVersion: "v1", EventID: "audit-event-example",
		TenantID:      "organization-example",
		Actor:         ActorReference{Type: ActorUser, ID: "principal-example"},
		IAMDecisionID: "decision-example", Action: QuotaEntitlementActivated,
		Target:        TargetReference{Kind: TargetQuotaEntitlement, ID: "quota-example"},
		OperationID:   "operation-forbidden",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Result:        Succeeded, RequestID: "request-example",
		OccurredAt: time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC),
	}
	if err := ValidateEvent(event); err == nil {
		t.Fatal("quota Audit event accepted a forbidden Operation")
	}
	event.OperationID = ""
	event.Target.Kind = "DockerContainer"
	if err := ValidateEvent(event); err == nil {
		t.Fatal("managed-service Audit event accepted a provider-native target")
	}
}

func TestTerminalLifecycleMapsWithoutAnOperation(t *testing.T) {
	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		action string
		result Result
	}{
		{TerminalSessionCreated, Accepted},
		{TerminalSessionStarted, Succeeded},
		{TerminalSessionEnded, Completed},
		{TerminalSessionEnded, Unsupported},
		{TerminalSessionEnded, Expired},
		{TerminalSessionEnded, Disconnected},
		{TerminalSessionEnded, Revoked},
		{TerminalSessionEnded, Replaced},
		{TerminalSessionEnded, Failed},
	} {
		event := Event{
			SchemaVersion: "v1", EventID: "terminal-event-" + string(test.result),
			TenantID:      "organization-example",
			Actor:         ActorReference{Type: ActorUser, ID: "principal-example"},
			IAMDecisionID: "decision-example", Action: test.action,
			Target:        TargetReference{Kind: TargetTerminalSession, ID: "terminal-session-example"},
			RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Result:        test.result, RequestID: "request-example", OccurredAt: now,
		}
		public, err := ToV1(event)
		if err != nil || ValidateEvent(event) != nil || public.Target.Kind != auditv1.TargetTerminalSession || public.OperationID != "" {
			t.Fatalf("terminal event %s/%s rejected: public=%#v err=%v", test.action, test.result, public, err)
		}
	}
}
