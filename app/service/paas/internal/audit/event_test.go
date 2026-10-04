package audit

import (
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestRoleAuditLineagePreservesExactlyOneOriginalSubject(t *testing.T) {
	for _, actor := range []paasv1.SubjectRef{
		{Type: paasv1.SubjectRole, ID: "role-user", RoleSession: &paasv1.RoleSessionReference{
			SessionID: "session-user", SourceUserID: "user-source",
		}},
		{Type: paasv1.SubjectRole, ID: "role-service", RoleSession: &paasv1.RoleSessionReference{
			SessionID: "session-service", SourceServicePrincipalID: "service-paas",
		}},
	} {
		event := Event{SchemaVersion: "v1", EventID: "audit-event-" + actor.ID,
			TenantID: "organization-example", Actor: actor, IAMDecisionID: "decision-example",
			Action: ApplicationCreated, Target: TargetReference{Kind: "Application", ID: "application-example"},
			OperationID: "operation-example", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Result: Succeeded, RequestID: "request-example", OccurredAt: time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)}
		public, err := ToV1(event)
		if err != nil || public.Actor.RoleSession == nil ||
			string(public.Actor.RoleSession.SessionID) != actor.RoleSession.SessionID ||
			string(public.Actor.RoleSession.SourceUserID) != actor.RoleSession.SourceUserID ||
			string(public.Actor.RoleSession.SourceServicePrincipalID) != actor.RoleSession.SourceServicePrincipalID {
			t.Fatalf("role lineage changed while mapping PaaS Audit: %#v err=%v", public.Actor, err)
		}
	}
}

func TestAccessKeyAuditActorPreservesCredentialAttribution(t *testing.T) {
	event := Event{SchemaVersion: "v1", EventID: "audit-event-key",
		TenantID: "organization-example", Actor: paasv1.SubjectRef{Type: paasv1.SubjectUser, ID: "user-one", AccessKeyID: "key-one"},
		IAMDecisionID: "decision-example", Action: ApplicationCreated,
		Target: TargetReference{Kind: "Application", ID: "application-example"}, OperationID: "operation-example",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Result:        Succeeded, RequestID: "request-example", OccurredAt: time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)}
	public, err := ToV1(event)
	if err != nil || public.Actor.Type != auditv1.ActorUser || public.Actor.ID != "user-one" || public.Actor.AccessKeyID != "key-one" {
		t.Fatalf("access-key attribution changed while mapping PaaS Audit: %#v err=%v", public.Actor, err)
	}
}

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
