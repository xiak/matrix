package auditlog

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/app/service/audit/internal/authority"
)

func TestVerifyInstallationFindsExactPaaSOperationAndVerifiesItsChain(t *testing.T) {
	transaction := newAuditTransaction()
	iam := &auditIAM{now: transaction.now}
	identifier := 0
	service, err := NewService(
		&auditRepository{transaction: transaction},
		iam,
		Config{
			CursorKey: bytes.Repeat([]byte{0x62}, 32),
			NewID: func(prefix string) (string, error) {
				identifier++
				return fmt.Sprintf("%s-installation-%d", prefix, identifier), nil
			},
		},
	)
	if err != nil {
		t.Fatalf("create Audit service: %v", err)
	}
	credential := auditSecret(t, "installation-verifier-credential-1234567890")
	request := auditv1.VerifyInstallationRequest{
		InstallationID: "mxi-0123456789abcdef0123456789abcdef",
		OperationID:    "operation-installation-probe",
		DeploymentID:   "deployment-installation-probe",
	}
	pending, err := service.VerifyInstallation(
		context.Background(), credential, "request-installation-pending", request,
	)
	if err != nil || pending.State != auditv1.InstallationVerificationPending ||
		len(transaction.records[authority.TenantChain("organization-example")]) != 0 {
		t.Fatalf("pending installation Audit verification=%#v records=%d err=%v", pending, len(transaction.records[authority.TenantChain("organization-example")]), err)
	}

	event := auditv1.Event{
		APIVersion: auditv1.APIVersion, Kind: "AuditEvent",
		EventID: "event-installation-probe", TenantID: "organization-example",
		Actor: auditv1.ActorReference{
			Type: auditv1.ActorServiceAccount, ID: "service-installation-verifier",
		},
		IAMDecisionID: "decision-paas-installation-probe",
		Action:        auditv1.ActionPaaSDeploymentCreated,
		Target: auditv1.TargetReference{
			Kind: auditv1.TargetDeployment, ID: request.DeploymentID,
		},
		Result: auditv1.ResultAccepted, RequestDigest: testDigest,
		RequestID:     "request-paas-installation-probe",
		CorrelationID: "request-paas-installation-probe",
		OperationID:   request.OperationID,
		OccurredAt:    transaction.now.Add(-time.Second),
	}
	checkpoint, err := authority.GenesisCheckpoint(authority.TenantChain(event.TenantID))
	if err != nil {
		t.Fatalf("create genesis: %v", err)
	}
	record, fact, err := authority.AppendRecord(
		checkpoint, 1, auditv1.SourcePaaS, event, transaction.now,
	)
	if err != nil {
		t.Fatalf("create PaaS Audit record: %v", err)
	}
	if _, err := transaction.AppendRecord(context.Background(), AppendMutation{Record: record, Fact: fact}); err != nil {
		t.Fatalf("seed PaaS Audit record: %v", err)
	}
	laterEvent := event
	laterEvent.EventID = "event-after-installation-probe"
	laterEvent.Target.ID = "deployment-after-installation-probe"
	laterEvent.OperationID = "operation-after-installation-probe"
	laterEvent.RequestID = "request-after-installation-probe"
	laterEvent.CorrelationID = laterEvent.RequestID
	laterRecord, laterFact, err := authority.AppendRecord(
		authority.Checkpoint{
			ChainID: authority.TenantChain(event.TenantID), Sequence: 1, RecordHash: record.RecordHash,
		},
		2,
		auditv1.SourcePaaS,
		laterEvent,
		transaction.now,
	)
	if err != nil {
		t.Fatalf("create later PaaS Audit record: %v", err)
	}
	if _, err := transaction.AppendRecord(
		context.Background(), AppendMutation{Record: laterRecord, Fact: laterFact},
	); err != nil {
		t.Fatalf("seed later PaaS Audit record: %v", err)
	}

	verified, err := service.VerifyInstallation(
		context.Background(), credential, "request-installation-verified", request,
	)
	if err != nil || verified.State != auditv1.InstallationVerificationVerified ||
		verified.EventID != event.EventID || verified.IAMDecisionID != event.IAMDecisionID ||
		verified.RecordSequence != 1 || verified.FromSequence != 1 ||
		verified.ToSequence != 1 || verified.RecordHash != record.RecordHash {
		t.Fatalf("verified installation Audit result=%#v err=%v", verified, err)
	}
	if transaction.readChainFrom != 1 || transaction.readChainMaximum != 1 {
		t.Fatalf(
			"installation verification chain read = from:%d maximum:%d, want exact target prefix",
			transaction.readChainFrom,
			transaction.readChainMaximum,
		)
	}
	records := transaction.records[authority.TenantChain(event.TenantID)]
	if len(records) != 3 || records[2].Source != auditv1.SourceAudit ||
		records[2].Event.Action != auditv1.ActionAuditIntegrityVerified ||
		records[2].Event.Actor != (auditv1.ActorReference{
			Type: auditv1.ActorServiceAccount, ID: "service-installation-verifier",
		}) {
		t.Fatalf("installation verification access record=%#v", records)
	}
}
