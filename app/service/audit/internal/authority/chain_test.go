package authority

import (
	"errors"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
)

func TestPerTenantSequenceAndHashChainAppendAndVerify(t *testing.T) {
	genesis, err := GenesisCheckpoint(TenantChain("organization-example"))
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
		Checkpoint{ChainID: genesis.ChainID, Sequence: first.Sequence, RecordHash: first.RecordHash},
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
	genesis, _ := GenesisCheckpoint(TenantChain("organization-example"))
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
	otherTenant, _ := GenesisCheckpoint(TenantChain("organization-other"))
	if _, err := VerifyChain(otherTenant, []auditv1.AuditRecord{record}); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("cross-tenant verification error = %v", err)
	}
	if _, _, err := AppendRecord(genesis, 2, auditv1.SourcePaaS, event, record.IngestedAt); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("non-contiguous append error = %v", err)
	}
}

func TestEachTenantStartsAnIndependentChain(t *testing.T) {
	for _, tenant := range []auditv1.TenantID{"organization-a", "organization-b"} {
		genesis, err := GenesisCheckpoint(TenantChain(tenant))
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

func TestInstallationAndTenantChainsSeparateEqualIdentifiers(t *testing.T) {
	tenant, _ := GenesisCheckpoint(TenantChain("authority-example"))
	platform, _ := GenesisCheckpoint(InstallationChain("authority-example"))
	tenantEvent := auditAuthorityEvent("event-tenant", "authority-example", auditv1.ActionPaaSDeploymentCreated)
	platformEvent := auditAuthorityEvent("event-platform", "authority-example", auditv1.ActionPaaSExecutionPoolCreated)
	now := time.Date(2026, 8, 27, 1, 2, 3, 0, time.UTC)
	tenantRecord, _, err := AppendRecord(tenant, 1, auditv1.SourcePaaS, tenantEvent, now)
	if err != nil {
		t.Fatal(err)
	}
	platformRecord, _, err := AppendRecord(platform, 1, auditv1.SourcePaaS, platformEvent, now)
	if err != nil {
		t.Fatal(err)
	}
	if tenant.ChainID == platform.ChainID || tenantRecord.RecordHash == platformRecord.RecordHash ||
		platformRecord.Event.TenantID != "" || tenantRecord.Event.InstallationID != "" {
		t.Fatal("tenant and installation authorities collapsed")
	}
	for _, pair := range []struct {
		head   Checkpoint
		record auditv1.AuditRecord
	}{{tenant, tenantRecord}, {platform, platformRecord}} {
		if _, err := VerifyChain(pair.head, []auditv1.AuditRecord{pair.record}); err != nil {
			t.Fatalf("verify %s: %v", pair.head.ChainID, err)
		}
	}
	if _, err := VerifyChain(tenant, []auditv1.AuditRecord{platformRecord}); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("installation record verified as tenant: %v", err)
	}
	if _, _, err := AppendRecord(platform, 1, auditv1.SourcePaaS, tenantEvent, now); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("tenant event appended to installation chain: %v", err)
	}
	for _, invalid := range []ChainID{"", "authority-example", "tenant:", "installation:", "Tenant:authority", "tenant:bad space"} {
		if _, err := GenesisCheckpoint(invalid); !errors.Is(err, ErrInvalidChain) {
			t.Fatalf("invalid chain %q accepted: %v", invalid, err)
		}
	}
}
