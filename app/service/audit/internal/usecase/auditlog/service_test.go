package auditlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/audit/internal/authority"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestAuditUsecasesBindIAMAndAuditEveryAuthorizedRead(t *testing.T) {
	transaction := newAuditTransaction()
	repository := &auditRepository{transaction: transaction}
	iam := &auditIAM{
		identity: iamv1.ServiceIdentity{
			APIVersion:     iamv1.APIVersion,
			Kind:           "ServiceIdentity",
			OrganizationID: "organization-example",
			PrincipalID:    "service-iam",
			Purpose:        iamv1.ServiceIAM,
		},
		now: transaction.now,
	}
	identifier := 0
	service, err := NewService(repository, iam, Config{
		CursorKey: bytes.Repeat([]byte{0x42}, 32),
		NewID: func(prefix string) (string, error) {
			identifier++
			return fmt.Sprintf("%s-generated-%d", prefix, identifier), nil
		},
	})
	if err != nil {
		t.Fatalf("create Audit service: %v", err)
	}
	producerCredential := auditSecret(t, "producer-credential-example-1234567890")
	first := auditEvent(
		"event-bootstrap",
		auditv1.ActionIAMBootstrapApplied,
		auditv1.TargetInstallation,
		"installation-example",
		transaction.now.Add(-2*time.Minute),
	)
	accepted, err := service.Ingest(context.Background(), producerCredential, first)
	if err != nil || accepted.Outcome != auditv1.IngestionAccepted || accepted.Record.Sequence != 1 {
		t.Fatalf("ingest first Audit event: result=%#v err=%v", accepted, err)
	}
	replayed, err := service.Ingest(context.Background(), producerCredential, first)
	if err != nil || replayed.Outcome != auditv1.IngestionDuplicate || replayed.Record != accepted.Record {
		t.Fatalf("replay equal Audit event: result=%#v err=%v", replayed, err)
	}
	changed := first
	changed.RequestID = "request-bootstrap-changed"
	if _, err := service.Ingest(context.Background(), producerCredential, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed Audit replay error=%v, want conflict", err)
	}
	second := auditEvent(
		"event-session",
		auditv1.ActionIAMSessionIssued,
		auditv1.TargetSession,
		"session-example",
		transaction.now.Add(-time.Minute),
	)
	accepted, err = service.Ingest(context.Background(), producerCredential, second)
	if err != nil || accepted.Outcome != auditv1.IngestionAccepted || accepted.Record.Sequence != 2 {
		t.Fatalf("ingest second Audit event: result=%#v err=%v", accepted, err)
	}

	subjectCredential := auditSecret(t, "subject-session-example-1234567890")
	firstPage, err := service.QueryRecords(
		context.Background(),
		subjectCredential,
		"request-query-page-one",
		auditv1.QueryRecordsRequest{PageSize: 1},
	)
	if err != nil || len(firstPage.Records) != 1 || firstPage.Records[0].Sequence != 2 ||
		firstPage.NextCursor == "" {
		t.Fatalf("query first Audit page: page=%#v err=%v", firstPage, err)
	}
	assertLastAccessRecord(t, transaction, 3, auditv1.ActionAuditRecordsRead, "decision-1")
	secondPage, err := service.QueryRecords(
		context.Background(),
		subjectCredential,
		"request-query-page-two",
		auditv1.QueryRecordsRequest{PageSize: 1, Cursor: firstPage.NextCursor},
	)
	if err != nil || len(secondPage.Records) != 1 || secondPage.Records[0].Sequence != 1 ||
		secondPage.NextCursor != "" {
		t.Fatalf("query second Audit page: page=%#v err=%v", secondPage, err)
	}
	assertLastAccessRecord(t, transaction, 4, auditv1.ActionAuditRecordsRead, "decision-2")
	actor := auditv1.ActorReference{Type: auditv1.ActorServiceAccount, ID: "service-iam"}
	filtered, err := service.QueryRecords(
		context.Background(),
		subjectCredential,
		"request-query-filtered",
		auditv1.QueryRecordsRequest{
			PageSize: 10,
			Action:   auditv1.ActionIAMBootstrapApplied,
			Actor:    &actor,
		},
	)
	if err != nil || len(filtered.Records) != 1 || filtered.Records[0].Event.EventID != first.EventID {
		t.Fatalf("query filtered Audit records: page=%#v err=%v", filtered, err)
	}
	assertLastAccessRecord(t, transaction, 5, auditv1.ActionAuditRecordsRead, "decision-3")

	verification, err := service.VerifyChain(
		context.Background(),
		subjectCredential,
		"request-verify",
		auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: 5},
	)
	if err != nil || verification.State != auditv1.VerificationVerified ||
		verification.RecordCount != 5 || verification.ToSequence != 5 || !verification.Complete {
		t.Fatalf("verify Audit chain: verification=%#v err=%v", verification, err)
	}
	assertLastAccessRecord(t, transaction, 6, auditv1.ActionAuditIntegrityVerified, "decision-4")
	readiness, err := service.Readiness(context.Background())
	if err != nil || readiness.State != auditv1.ReadinessReady ||
		readiness.CheckedAt != transaction.now || readiness.SchemaVersion != 1 {
		t.Fatalf("read Audit readiness: readiness=%#v err=%v", readiness, err)
	}
}

func TestAuditUsecasesFailClosedBeforeMutation(t *testing.T) {
	transaction := newAuditTransaction()
	iam := &auditIAM{
		identity: iamv1.ServiceIdentity{
			APIVersion:     iamv1.APIVersion,
			Kind:           "ServiceIdentity",
			OrganizationID: "organization-example",
			PrincipalID:    "service-iam",
			Purpose:        iamv1.ServiceIAM,
		},
		now: transaction.now,
	}
	service, err := NewService(
		&auditRepository{transaction: transaction},
		iam,
		Config{
			CursorKey: bytes.Repeat([]byte{0x24}, 32),
			NewID: func(prefix string) (string, error) {
				return prefix + "-generated", nil
			},
		},
	)
	if err != nil {
		t.Fatalf("create Audit service: %v", err)
	}
	producerCredential := auditSecret(t, "producer-credential-example-1234567890")
	event := auditEvent(
		"event-bootstrap",
		auditv1.ActionIAMBootstrapApplied,
		auditv1.TargetInstallation,
		"installation-example",
		transaction.now,
	)
	wrongTenant := event
	wrongTenant.EventID = "event-wrong-tenant"
	wrongTenant.TenantID = "organization-other"
	if _, err := service.Ingest(context.Background(), producerCredential, wrongTenant); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("uncorrelated producer target error=%v, want unavailable", err)
	}
	iam.identity.Purpose = iamv1.ServiceInstallationVerifier
	if _, err := service.Ingest(context.Background(), producerCredential, event); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed producer authorization error=%v, want unavailable", err)
	}
	if len(transaction.records["organization-example"]) != 0 {
		t.Fatal("rejected producer mutated Audit records")
	}
	iam.identity.Purpose = iamv1.ServiceIAM
	if _, err := service.Ingest(context.Background(), producerCredential, event); err != nil {
		t.Fatalf("seed Audit record: %v", err)
	}
	before := len(transaction.records["organization-example"])
	iam.deny = true
	if _, err := service.QueryRecords(
		context.Background(),
		auditSecret(t, "subject-session-example-1234567890"),
		"request-denied",
		auditv1.QueryRecordsRequest{PageSize: 10},
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("denied Audit query error=%v, want forbidden", err)
	}
	if len(transaction.records["organization-example"]) != before {
		t.Fatal("denied Audit query appended an access record")
	}
	iam.deny = false
	iam.malformed = true
	if _, err := service.VerifyChain(
		context.Background(),
		auditSecret(t, "subject-session-example-1234567890"),
		"request-malformed-decision",
		auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: 10},
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed IAM decision error=%v, want unavailable", err)
	}
	if len(transaction.records["organization-example"]) != before {
		t.Fatal("malformed IAM decision appended an access record")
	}
}

func auditEvent(
	eventID auditv1.EventID,
	action auditv1.Action,
	targetKind auditv1.TargetKind,
	targetID string,
	occurredAt time.Time,
) auditv1.Event {
	return auditv1.Event{
		APIVersion:    auditv1.APIVersion,
		Kind:          "AuditEvent",
		EventID:       eventID,
		TenantID:      "organization-example",
		Actor:         auditv1.ActorReference{Type: auditv1.ActorServiceAccount, ID: "service-iam"},
		Action:        action,
		Target:        auditv1.TargetReference{Kind: targetKind, ID: targetID},
		Result:        auditv1.ResultSucceeded,
		RequestDigest: testDigest,
		RequestID:     "request-" + string(eventID),
		CorrelationID: "correlation-" + string(eventID),
		OccurredAt:    occurredAt,
	}
}

func auditSecret(t *testing.T, plaintext string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(plaintext)
	if err != nil {
		t.Fatalf("create test credential: %v", err)
	}
	return secret
}

func assertLastAccessRecord(
	t *testing.T,
	transaction *auditTransaction,
	sequence uint64,
	action auditv1.Action,
	decisionID auditv1.DecisionID,
) {
	t.Helper()
	records := transaction.records["organization-example"]
	if len(records) != int(sequence) {
		t.Fatalf("stored Audit records=%d want=%d", len(records), sequence)
	}
	record := records[len(records)-1]
	if record.Sequence != sequence || record.Source != auditv1.SourceAudit ||
		record.Event.Action != action || record.Event.IAMDecisionID != decisionID ||
		record.Event.Actor.Type != auditv1.ActorUser || record.Event.Actor.ID != "principal-reader" {
		t.Fatalf("last Audit access record=%#v", record)
	}
}

type auditRepository struct {
	transaction *auditTransaction
}

func (repository *auditRepository) WithinTransaction(
	ctx context.Context,
	callback func(context.Context, Transaction) error,
) error {
	return callback(ctx, repository.transaction)
}

type auditIAM struct {
	identity  iamv1.ServiceIdentity
	now       time.Time
	decisions int
	deny      bool
	malformed bool
}

func (client *auditIAM) ResolveAuditProducer(
	_ context.Context,
	_ iamv1.Secret,
	_ iamv1.ResolveAuditProducerRequest,
) (iamv1.AuditProducerAuthorization, error) {
	return iamv1.AuditProducerAuthorization{
		APIVersion: iamv1.APIVersion, Kind: "AuditProducerAuthorization",
		Producer: client.identity, OrganizationID: "organization-example",
	}, nil
}

func (client *auditIAM) Authorize(
	_ context.Context,
	_ iamv1.Secret,
	request iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	client.decisions++
	decision := iamv1.AuthorizationDecision{
		APIVersion: iamv1.APIVersion,
		Kind:       "AuthorizationDecision",
		ID:         iamv1.DecisionID(fmt.Sprintf("decision-%d", client.decisions)),
		Allowed:    !client.deny,
		Reason:     iamv1.DecisionAllowed,
		TenantID:   "organization-example",
		Subject:    &iamv1.Subject{Type: iamv1.PrincipalUser, ID: "principal-reader"},
		Action:     request.Action,
		Resource:   request.Resource,
		RequestID:  request.RequestID,
		DecidedAt:  client.now,
	}
	if client.deny {
		decision.Reason = iamv1.DecisionDenied
		decision.TenantID = ""
		decision.Subject = nil
	}
	if client.malformed {
		decision.RequestID = "request-substituted"
	}
	return decision, nil
}

func (client *auditIAM) VerifyInstallation(
	_ context.Context,
	_ iamv1.Secret,
	request iamv1.AuthorizationRequest,
) (iamv1.AuthorizationDecision, error) {
	client.decisions++
	decision := iamv1.AuthorizationDecision{
		APIVersion: iamv1.APIVersion, Kind: "AuthorizationDecision",
		ID:      iamv1.DecisionID(fmt.Sprintf("decision-%d", client.decisions)),
		Allowed: !client.deny, Reason: iamv1.DecisionAllowed,
		TenantID: "organization-example",
		Subject: &iamv1.Subject{
			Type: iamv1.PrincipalServiceAccount, ID: "service-installation-verifier",
		},
		Action: request.Action, Resource: request.Resource,
		RequestID: request.RequestID, DecidedAt: client.now,
	}
	if client.deny {
		decision.Reason = iamv1.DecisionDenied
		decision.TenantID = ""
		decision.Subject = nil
	}
	return decision, nil
}

type auditTransaction struct {
	now      time.Time
	records  map[auditv1.TenantID][]auditv1.AuditRecord
	registry map[string]StoredRecord
}

func newAuditTransaction() *auditTransaction {
	return &auditTransaction{
		now:      time.Date(2026, 8, 26, 12, 13, 14, 123000, time.UTC),
		records:  make(map[auditv1.TenantID][]auditv1.AuditRecord),
		registry: make(map[string]StoredRecord),
	}
}

func (transaction *auditTransaction) TransactionTime(context.Context) (time.Time, error) {
	return transaction.now, nil
}

func (transaction *auditTransaction) LockEvent(
	context.Context,
	auditv1.Source,
	auditv1.EventID,
) error {
	return nil
}

func (transaction *auditTransaction) LookupRecord(
	_ context.Context,
	source auditv1.Source,
	eventID auditv1.EventID,
) (StoredRecord, bool, error) {
	record, found := transaction.registry[registryKey(source, eventID)]
	return record, found, nil
}

func (transaction *auditTransaction) LockTenantHead(
	_ context.Context,
	tenantID auditv1.TenantID,
) (authority.Checkpoint, time.Time, error) {
	records := transaction.records[tenantID]
	if len(records) == 0 {
		checkpoint, err := authority.GenesisCheckpoint(tenantID)
		return checkpoint, transaction.now, err
	}
	last := records[len(records)-1]
	return authority.Checkpoint{
		TenantID: tenantID, Sequence: last.Sequence, RecordHash: last.RecordHash,
	}, transaction.now, nil
}

func (transaction *auditTransaction) AppendRecord(
	_ context.Context,
	mutation AppendMutation,
) (auditv1.IngestionOutcome, error) {
	key := registryKey(mutation.Record.Source, mutation.Record.Event.EventID)
	if existing, found := transaction.registry[key]; found {
		if existing.Replay.CanonicalDocument == mutation.Fact.Document &&
			existing.Replay.ContentDigest == mutation.Fact.ContentDigest {
			return auditv1.IngestionDuplicate, nil
		}
		return "", ErrConflict
	}
	head, _, err := transaction.LockTenantHead(context.Background(), mutation.Record.Event.TenantID)
	if err != nil {
		return "", err
	}
	if _, err := authority.VerifyChain(head, []auditv1.AuditRecord{mutation.Record}); err != nil {
		return "", ErrUnavailable
	}
	transaction.records[mutation.Record.Event.TenantID] = append(
		transaction.records[mutation.Record.Event.TenantID],
		mutation.Record,
	)
	transaction.registry[key] = StoredRecord{
		Record: mutation.Record,
		Replay: authority.ReplayState{
			Source:            mutation.Record.Source,
			EventID:           mutation.Record.Event.EventID,
			CanonicalDocument: mutation.Fact.Document,
			ContentDigest:     mutation.Fact.ContentDigest,
		},
	}
	return auditv1.IngestionAccepted, nil
}

func (transaction *auditTransaction) ReadRecords(
	_ context.Context,
	query RecordQuery,
) ([]auditv1.AuditRecord, error) {
	stored := transaction.records[query.TenantID]
	result := make([]auditv1.AuditRecord, 0, query.Limit)
	for index := len(stored) - 1; index >= 0 && len(result) < query.Limit; index-- {
		record := stored[index]
		if record.Sequence >= query.BeforeSequence || !recordMatchesQuery(record, query.TenantID, auditv1.QueryRecordsRequest{
			PageSize: query.Limit,
			From:     query.From,
			To:       query.To,
			Action:   query.Action,
			Actor:    query.Actor,
		}) {
			continue
		}
		result = append(result, record)
	}
	return result, nil
}

func (transaction *auditTransaction) ReadCheckpoint(
	_ context.Context,
	tenantID auditv1.TenantID,
	sequence uint64,
) (authority.Checkpoint, bool, error) {
	records := transaction.records[tenantID]
	if sequence == 0 || sequence > uint64(len(records)) {
		return authority.Checkpoint{}, false, nil
	}
	record := records[sequence-1]
	return authority.Checkpoint{
		TenantID: tenantID, Sequence: sequence, RecordHash: record.RecordHash,
	}, true, nil
}

func (transaction *auditTransaction) ReadChain(
	_ context.Context,
	tenantID auditv1.TenantID,
	fromSequence uint64,
	maximumRecords int,
) ([]auditv1.AuditRecord, error) {
	records := transaction.records[tenantID]
	if fromSequence == 0 || fromSequence > uint64(len(records)) {
		return nil, nil
	}
	start := int(fromSequence - 1)
	end := min(start+maximumRecords, len(records))
	return append([]auditv1.AuditRecord(nil), records[start:end]...), nil
}

func (transaction *auditTransaction) LookupPaaSOperationRecord(
	_ context.Context,
	tenantID auditv1.TenantID,
	operationID auditv1.OperationID,
) (auditv1.AuditRecord, bool, error) {
	for _, record := range transaction.records[tenantID] {
		if record.Source == auditv1.SourcePaaS && record.Event.OperationID == operationID {
			return record, true, nil
		}
	}
	return auditv1.AuditRecord{}, false, nil
}

func (transaction *auditTransaction) Readiness(context.Context) (ReadinessSnapshot, error) {
	return ReadinessSnapshot{Ready: true, SchemaVersion: 1, CheckedAt: transaction.now}, nil
}

func registryKey(source auditv1.Source, eventID auditv1.EventID) string {
	return string(source) + "\x00" + string(eventID)
}
