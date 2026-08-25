package authority

import (
	"errors"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

func TestPerTenantSequenceAndHashChainAppendAndVerify(t *testing.T) {
	genesis, err := GenesisCheckpoint("organization-example")
	if err != nil {
		t.Fatalf("create genesis checkpoint: %v", err)
	}
	firstEvent := auditAuthorityEvent("event-one", "organization-example", auditv1.ActionPaaSDeploymentCreated)
	first, _, err := AppendRecord(
		genesis, 1, auditv1.SourcePaaS, firstEvent,
		time.Date(2026, 8, 25, 5, 6, 8, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("append first record: %v", err)
	}
	secondEvent := auditAuthorityEvent("event-two", "organization-example", auditv1.ActionPaaSApplicationCreated)
	secondEvent.OccurredAt = firstEvent.OccurredAt.Add(time.Second)
	secondEvent.Target.ID = "application-example"
	second, _, err := AppendRecord(
		Checkpoint{TenantID: genesis.TenantID, Sequence: first.Sequence, RecordHash: first.RecordHash},
		2,
		auditv1.SourcePaaS,
		secondEvent,
		time.Date(2026, 8, 25, 5, 6, 9, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("append second record: %v", err)
	}
	if first.PreviousHash != GenesisHash || second.PreviousHash != first.RecordHash ||
		first.Retention != auditv1.RetentionIndefinite || second.Retention != auditv1.RetentionIndefinite {
		t.Fatalf("chain linkage or retention is invalid: first=%#v second=%#v", first, second)
	}
	verified, err := VerifyChain(genesis, []auditv1.AuditRecord{first, second})
	if err != nil || verified.Sequence != 2 || verified.RecordHash != second.RecordHash {
		t.Fatalf("verify chain: checkpoint=%#v err=%v", verified, err)
	}
}

func TestHashChainRejectsChangedContentGapPredecessorAndTenant(t *testing.T) {
	genesis, _ := GenesisCheckpoint("organization-example")
	event := auditAuthorityEvent("event-one", "organization-example", auditv1.ActionPaaSDeploymentCreated)
	record, _, err := AppendRecord(
		genesis, 1, auditv1.SourcePaaS, event,
		time.Date(2026, 8, 25, 5, 6, 8, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("append fixture record: %v", err)
	}
	changed := record
	changed.Event.RequestID = "request-changed"
	if _, err := VerifyChain(genesis, []auditv1.AuditRecord{changed}); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("changed content verification error = %v", err)
	}
	gap := record
	gap.Sequence = 2
	if _, err := VerifyChain(genesis, []auditv1.AuditRecord{gap}); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("sequence gap verification error = %v", err)
	}
	predecessor := record
	predecessor.PreviousHash = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
	if _, err := VerifyChain(genesis, []auditv1.AuditRecord{predecessor}); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("changed predecessor verification error = %v", err)
	}
	otherTenant, _ := GenesisCheckpoint("organization-other")
	if _, err := VerifyChain(otherTenant, []auditv1.AuditRecord{record}); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("cross-tenant verification error = %v", err)
	}
	if _, _, err := AppendRecord(genesis, 2, auditv1.SourcePaaS, event, record.IngestedAt); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("non-contiguous append error = %v", err)
	}
}

func TestEachTenantStartsAnIndependentChain(t *testing.T) {
	for _, tenant := range []auditv1.TenantID{"organization-a", "organization-b"} {
		genesis, err := GenesisCheckpoint(tenant)
		if err != nil {
			t.Fatalf("create %s genesis: %v", tenant, err)
		}
		event := auditAuthorityEvent("event-one", string(tenant), auditv1.ActionPaaSDeploymentCreated)
		record, _, err := AppendRecord(
			genesis, 1, auditv1.SourcePaaS, event,
			time.Date(2026, 8, 25, 5, 6, 8, 0, time.UTC),
		)
		if err != nil || record.Sequence != 1 || record.PreviousHash != GenesisHash {
			t.Fatalf("tenant %s first record = %#v err=%v", tenant, record, err)
		}
	}
}
