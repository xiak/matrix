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
			InstallationID: "installation-example",
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
		readiness.CheckedAt != transaction.now || readiness.SchemaVersion != 3 {
		t.Fatalf("read Audit readiness: readiness=%#v err=%v", readiness, err)
	}
}

func TestAuditUsecasesFailClosedBeforeMutation(t *testing.T) {
	transaction := newAuditTransaction()
	iam := &auditIAM{
		identity: iamv1.ServiceIdentity{
			InstallationID: "installation-example",
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
	if len(transaction.records[authority.TenantChain("organization-example")]) != 0 {
		t.Fatal("rejected producer mutated Audit records")
	}
	iam.identity.Purpose = iamv1.ServiceIAM
	iam.proofDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	if _, err := service.Ingest(context.Background(), producerCredential, event); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("substituted event digest was accepted: %v", err)
	}
	iam.proofDigest = ""
	if _, err := service.Ingest(context.Background(), producerCredential, event); err != nil {
		t.Fatalf("seed Audit record: %v", err)
	}
	before := len(transaction.records[authority.TenantChain("organization-example")])
	iam.deny = true
	if _, err := service.QueryRecords(
		context.Background(),
		auditSecret(t, "subject-session-example-1234567890"),
		"request-denied",
		auditv1.QueryRecordsRequest{PageSize: 10},
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("denied Audit query error=%v, want forbidden", err)
	}
	if len(transaction.records[authority.TenantChain("organization-example")]) != before {
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
	if len(transaction.records[authority.TenantChain("organization-example")]) != before {
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

func TestPlatformAuditUsesInstallationAuthorityAndCannotReadTenantChain(t *testing.T) {
	transaction := newAuditTransaction()
	iam := &auditIAM{now: transaction.now, identity: iamv1.ServiceIdentity{
		APIVersion: iamv1.APIVersion, Kind: "ServiceIdentity",
		InstallationID: "organization-example", OrganizationID: "organization-example",
		PrincipalID: "service-paas", Purpose: iamv1.ServicePaaS,
	}}
	nextID := 0
	service, err := NewService(&auditRepository{transaction: transaction}, iam, Config{
		CursorKey: bytes.Repeat([]byte{0x53}, 32),
		NewID: func(prefix string) (string, error) {
			nextID++
			return fmt.Sprintf("%s-platform-%d", prefix, nextID), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	credential := auditSecret(t, "test-platform-credential")
	var platformEvent auditv1.Event
	for index := 0; index < 2; index++ {
		for _, platform := range []bool{false, true} {
			event := auditEvent(auditv1.EventID(fmt.Sprintf("event-%t-%d", platform, index)),
				auditv1.ActionPaaSApplicationCreated, auditv1.TargetApplication, "application-example", transaction.now)
			event.Actor = auditv1.ActorReference{Type: auditv1.ActorUser, ID: "principal-reader"}
			event.IAMDecisionID = "decision-original"
			event.OperationID = auditv1.OperationID("operation-" + string(event.EventID))
			if platform {
				event.Action, event.Target.Kind = auditv1.ActionPaaSExecutionPoolCreated, auditv1.TargetExecutionPool
				event.TenantID, event.InstallationID = "", iam.identity.InstallationID
				platformEvent = event
			}
			accepted, err := service.Ingest(ctx, credential, event)
			if err != nil || accepted.Record.Sequence != uint64(index+1) {
				t.Fatalf("seed platform=%t sequence=%d: %v", platform, accepted.Record.Sequence, err)
			}
		}
	}
	wrong := platformEvent
	wrong.InstallationID = "another-installation"
	if _, err := service.Ingest(ctx, credential, wrong); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong-installation producer accepted: %v", err)
	}
	query := auditv1.QueryRecordsRequest{PageSize: 1}
	platformPage, err := service.QueryPlatformRecords(ctx, credential, "request-platform-read", query)
	if err != nil || platformPage.InstallationID != iam.identity.InstallationID || platformPage.TenantID != "" ||
		len(platformPage.Records) != 1 || platformPage.NextCursor == "" || platformPage.Records[0].Event != platformEvent {
		t.Fatalf("platform page failed: %#v %v", platformPage, err)
	}
	tenantPage, err := service.QueryRecords(ctx, credential, "request-tenant-read", query)
	if err != nil || tenantPage.TenantID != "organization-example" || tenantPage.InstallationID != "" || tenantPage.NextCursor == "" {
		t.Fatalf("tenant page failed: %#v %v", tenantPage, err)
	}
	query.Cursor = platformPage.NextCursor
	if _, err := service.QueryRecords(ctx, credential, "request-cross-tenant-cursor", query); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("platform cursor entered tenant chain: %v", err)
	}
	query.Cursor = tenantPage.NextCursor
	if _, err := service.QueryPlatformRecords(ctx, credential, "request-cross-platform-cursor", query); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("tenant cursor entered platform chain: %v", err)
	}
	verification, err := service.VerifyPlatformChain(ctx, credential, "request-platform-verify",
		auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: 10})
	if err != nil || verification.InstallationID != iam.identity.InstallationID || verification.TenantID != "" || verification.RecordCount != 3 {
		t.Fatalf("platform chain verification failed: %#v %v", verification, err)
	}
	platformRecords := transaction.records[authority.InstallationChain(iam.identity.InstallationID)]
	if len(platformRecords) != 4 || platformRecords[2].Event.Action != auditv1.ActionAuditPlatformRecordsRead ||
		platformRecords[3].Event.Action != auditv1.ActionAuditPlatformIntegrityVerified ||
		len(transaction.records[authority.TenantChain("organization-example")]) != 3 {
		t.Fatal("platform access auditing crossed authority boundary")
	}
	iam.deny = true
	if _, err := service.QueryPlatformRecords(ctx, credential, "request-revoked-platform", auditv1.QueryRecordsRequest{PageSize: 10}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked platform query accepted: %v", err)
	}
	if _, err := service.VerifyPlatformChain(ctx, credential, "request-revoked-platform-verify", auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: 10}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked platform verification accepted: %v", err)
	}
	if len(transaction.records[authority.InstallationChain(iam.identity.InstallationID)]) != 4 {
		t.Fatal("denied platform read changed the chain")
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
	records := transaction.records[authority.TenantChain("organization-example")]
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
	identity    iamv1.ServiceIdentity
	now         time.Time
	decisions   int
	deny        bool
	malformed   bool
	proofDigest string
}

func (client *auditIAM) ResolveAuditProducer(
	_ context.Context,
	_ iamv1.Secret,
	request iamv1.ResolveAuditProducerRequest,
) (iamv1.AuditProducerAuthorization, error) {
	source, _ := sourceForIdentity(client.identity)
	_, digest, _ := auditv1.CanonicalizeEvent(source, request.Event)
	if client.proofDigest != "" {
		digest = client.proofDigest
	}
	result := iamv1.AuditProducerAuthorization{
		APIVersion: iamv1.APIVersion, Kind: "AuditProducerAuthorization",
		Producer: client.identity, TenantID: "organization-example", ContentDigest: digest,
	}
	if request.Event.InstallationID != "" {
		result.TenantID, result.InstallationID = "", client.identity.InstallationID
	}
	return result, nil
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
	if iamv1.IsPlatformAction(request.Action) {
		decision.TenantID, decision.InstallationID = "", client.identity.InstallationID
	}
	if client.deny {
		decision.Reason = iamv1.DecisionDenied
		decision.TenantID = ""
		decision.InstallationID = ""
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
	now              time.Time
	records          map[authority.ChainID][]auditv1.AuditRecord
	registry         map[string]StoredRecord
	readChainFrom    uint64
	readChainMaximum int
}

func newAuditTransaction() *auditTransaction {
	return &auditTransaction{
		now:      time.Date(2026, 8, 26, 12, 13, 14, 123000, time.UTC),
		records:  make(map[authority.ChainID][]auditv1.AuditRecord),
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

func (transaction *auditTransaction) LockChainHead(
	_ context.Context,
	chainID authority.ChainID,
) (authority.Checkpoint, time.Time, error) {
	records := transaction.records[chainID]
	if len(records) == 0 {
		checkpoint, err := authority.GenesisCheckpoint(chainID)
		return checkpoint, transaction.now, err
	}
	last := records[len(records)-1]
	return authority.Checkpoint{
		ChainID: chainID, Sequence: last.Sequence, RecordHash: last.RecordHash,
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
	head, _, err := transaction.LockChainHead(context.Background(), authority.ChainFor(mutation.Record.Event.TenantID, mutation.Record.Event.InstallationID))
	if err != nil {
		return "", err
	}
	if _, err := authority.VerifyChain(head, []auditv1.AuditRecord{mutation.Record}); err != nil {
		return "", ErrUnavailable
	}
	transaction.records[authority.ChainFor(mutation.Record.Event.TenantID, mutation.Record.Event.InstallationID)] = append(
		transaction.records[authority.ChainFor(mutation.Record.Event.TenantID, mutation.Record.Event.InstallationID)],
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
	stored := transaction.records[query.ChainID]
	result := make([]auditv1.AuditRecord, 0, query.Limit)
	for index := len(stored) - 1; index >= 0 && len(result) < query.Limit; index-- {
		record := stored[index]
		if record.Sequence >= query.BeforeSequence || !recordMatchesQuery(record, query.ChainID, auditv1.QueryRecordsRequest{
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
	chainID authority.ChainID,
	sequence uint64,
) (authority.Checkpoint, bool, error) {
	records := transaction.records[chainID]
	if sequence == 0 || sequence > uint64(len(records)) {
		return authority.Checkpoint{}, false, nil
	}
	record := records[sequence-1]
	return authority.Checkpoint{
		ChainID: chainID, Sequence: sequence, RecordHash: record.RecordHash,
	}, true, nil
}

func (transaction *auditTransaction) ReadChain(
	_ context.Context,
	chainID authority.ChainID,
	fromSequence uint64,
	maximumRecords int,
) ([]auditv1.AuditRecord, error) {
	transaction.readChainFrom = fromSequence
	transaction.readChainMaximum = maximumRecords
	records := transaction.records[chainID]
	if fromSequence == 0 || fromSequence > uint64(len(records)) {
		return nil, nil
	}
	start := int(fromSequence - 1)
	end := min(start+maximumRecords, len(records))
	return append([]auditv1.AuditRecord(nil), records[start:end]...), nil
}

func (transaction *auditTransaction) LookupPaaSOperationRecord(
	_ context.Context,
	chainID authority.ChainID,
	operationID auditv1.OperationID,
) (auditv1.AuditRecord, bool, error) {
	for _, record := range transaction.records[chainID] {
		if record.Source == auditv1.SourcePaaS && record.Event.OperationID == operationID {
			return record, true, nil
		}
	}
	return auditv1.AuditRecord{}, false, nil
}

func (transaction *auditTransaction) Readiness(context.Context) (ReadinessSnapshot, error) {
	return ReadinessSnapshot{Ready: true, SchemaVersion: 3, CheckedAt: transaction.now}, nil
}

func registryKey(source auditv1.Source, eventID auditv1.EventID) string {
	return string(source) + "\x00" + string(eventID)
}
