package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/app/service/audit/internal/authority"
	"github.com/xiak/matrix/app/service/audit/internal/usecase/auditlog"
)

const maximumAuditSequence = uint64(9007199254740991)

type transaction struct {
	tx pgx.Tx
}

func (value *transaction) TransactionTime(ctx context.Context) (time.Time, error) {
	if value == nil || value.tx == nil {
		return time.Time{}, auditlog.ErrUnavailable
	}
	var databaseTime time.Time
	if err := value.tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&databaseTime); err != nil {
		return time.Time{}, mapDatabaseError("read Audit transaction time", err)
	}
	return databaseTime.UTC(), nil
}

func (value *transaction) LockEvent(
	ctx context.Context,
	source auditv1.Source,
	eventID auditv1.EventID,
) error {
	if _, err := value.tx.Exec(
		ctx,
		"SELECT audit.lock_event($1, $2)",
		string(source),
		string(eventID),
	); err != nil {
		return mapDatabaseError("lock Audit event", err)
	}
	return nil
}

func (value *transaction) LookupRecord(
	ctx context.Context,
	source auditv1.Source,
	eventID auditv1.EventID,
) (auditlog.StoredRecord, bool, error) {
	record, canonicalDocument, err := scanAuditRecord(value.tx.QueryRow(
		ctx,
		`SELECT chain_id, sequence, source, event_id, event_document,
			   canonical_document, content_digest, previous_hash, record_hash,
			   ingested_at, retention
		  FROM audit.lookup_record($1, $2)`,
		string(source),
		string(eventID),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return auditlog.StoredRecord{}, false, nil
	}
	if err != nil {
		return auditlog.StoredRecord{}, false, mapDatabaseError("lookup Audit record", err)
	}
	return auditlog.StoredRecord{
		Record: record,
		Replay: authority.ReplayState{
			Source:            record.Source,
			EventID:           record.Event.EventID,
			CanonicalDocument: canonicalDocument,
			ContentDigest:     record.ContentDigest,
		},
	}, true, nil
}

func (value *transaction) LockChainHead(
	ctx context.Context,
	chainID authority.ChainID,
) (authority.Checkpoint, time.Time, error) {
	var sequence int64
	var recordHash string
	var ingestedAt time.Time
	if err := value.tx.QueryRow(
		ctx,
		"SELECT * FROM audit.lock_chain_head($1)",
		string(chainID),
	).Scan(&sequence, &recordHash, &ingestedAt); err != nil {
		return authority.Checkpoint{}, time.Time{}, mapDatabaseError("lock Audit chain head", err)
	}
	if sequence < 0 || uint64(sequence) > maximumAuditSequence {
		return authority.Checkpoint{}, time.Time{}, auditlog.ErrUnavailable
	}
	return authority.Checkpoint{
		ChainID: chainID, Sequence: uint64(sequence), RecordHash: recordHash,
	}, ingestedAt.UTC(), nil
}

func (value *transaction) AppendRecord(
	ctx context.Context,
	mutation auditlog.AppendMutation,
) (auditv1.IngestionOutcome, error) {
	eventDocument, err := json.Marshal(mutation.Record.Event)
	if err != nil {
		return "", auditlog.ErrUnavailable
	}
	defer clear(eventDocument)
	var outcome string
	var storedSequence int64
	var storedRecordHash string
	err = value.tx.QueryRow(
		ctx,
		`SELECT * FROM audit.append_record(
			$1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10
		)`,
		string(mutation.Record.Source),
		string(mutation.Record.Event.EventID),
		string(authority.ChainFor(mutation.Record.Event.TenantID, mutation.Record.Event.InstallationID)),
		int64(mutation.Record.Sequence),
		eventDocument,
		mutation.Fact.Document,
		mutation.Fact.ContentDigest,
		mutation.Record.PreviousHash,
		mutation.Record.RecordHash,
		mutation.Record.IngestedAt,
	).Scan(&outcome, &storedSequence, &storedRecordHash)
	if err != nil {
		return "", mapDatabaseError("append Audit record", err)
	}
	if storedSequence < 1 || uint64(storedSequence) != mutation.Record.Sequence ||
		storedRecordHash != mutation.Record.RecordHash {
		return "", auditlog.ErrUnavailable
	}
	switch auditv1.IngestionOutcome(outcome) {
	case auditv1.IngestionAccepted:
		return auditv1.IngestionAccepted, nil
	case auditv1.IngestionDuplicate:
		return auditv1.IngestionDuplicate, nil
	default:
		return "", auditlog.ErrUnavailable
	}
}

func (value *transaction) ReadRecords(
	ctx context.Context,
	query auditlog.RecordQuery,
) ([]auditv1.AuditRecord, error) {
	var action any
	if query.Action != "" {
		action = string(query.Action)
	}
	var actorType, actorID any
	if query.Actor != nil {
		actorType = string(query.Actor.Type)
		actorID = string(query.Actor.ID)
	}
	rows, err := value.tx.Query(
		ctx,
		`SELECT chain_id, sequence, source, event_id, event_document,
			   canonical_document, content_digest, previous_hash, record_hash,
			   ingested_at, retention
		  FROM audit.read_records($1, $2, $3, $4, $5, $6, $7, $8)`,
		string(query.ChainID),
		int64(query.BeforeSequence),
		query.Limit,
		query.From,
		query.To,
		action,
		actorType,
		actorID,
	)
	if err != nil {
		return nil, mapDatabaseError("query Audit records", err)
	}
	defer rows.Close()
	records := make([]auditv1.AuditRecord, 0)
	for rows.Next() {
		record, _, err := scanAuditRecord(rows)
		if err != nil {
			return nil, mapDatabaseError("scan Audit query record", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, mapDatabaseError("iterate Audit query records", err)
	}
	return records, nil
}

func (value *transaction) ReadCheckpoint(
	ctx context.Context,
	chainID authority.ChainID,
	sequence uint64,
) (authority.Checkpoint, bool, error) {
	var recordHash string
	err := value.tx.QueryRow(
		ctx,
		"SELECT record_hash FROM audit.read_checkpoint($1, $2)",
		string(chainID),
		int64(sequence),
	).Scan(&recordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.Checkpoint{}, false, nil
	}
	if err != nil {
		return authority.Checkpoint{}, false, mapDatabaseError("read Audit checkpoint", err)
	}
	return authority.Checkpoint{
		ChainID: chainID, Sequence: sequence, RecordHash: recordHash,
	}, true, nil
}

func (value *transaction) ReadChain(
	ctx context.Context,
	chainID authority.ChainID,
	fromSequence uint64,
	maximumRecords int,
) ([]auditv1.AuditRecord, error) {
	rows, err := value.tx.Query(
		ctx,
		`SELECT chain_id, sequence, source, event_id, event_document,
			   canonical_document, content_digest, previous_hash, record_hash,
			   ingested_at, retention
		  FROM audit.read_chain($1, $2, $3)`,
		string(chainID),
		int64(fromSequence),
		maximumRecords,
	)
	if err != nil {
		return nil, mapDatabaseError("read Audit chain", err)
	}
	defer rows.Close()
	records := make([]auditv1.AuditRecord, 0)
	for rows.Next() {
		record, _, err := scanAuditRecord(rows)
		if err != nil {
			return nil, mapDatabaseError("scan Audit chain record", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, mapDatabaseError("iterate Audit chain records", err)
	}
	return records, nil
}

func (value *transaction) LookupPaaSOperationRecord(
	ctx context.Context,
	chainID authority.ChainID,
	operationID auditv1.OperationID,
) (auditv1.AuditRecord, bool, error) {
	record, _, err := scanAuditRecord(value.tx.QueryRow(
		ctx,
		`SELECT chain_id, sequence, source, event_id, event_document,
			   canonical_document, content_digest, previous_hash, record_hash,
			   ingested_at, retention
		  FROM audit.lookup_paas_operation_record($1, $2)`,
		string(chainID),
		string(operationID),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return auditv1.AuditRecord{}, false, nil
	}
	if err != nil {
		return auditv1.AuditRecord{}, false, mapDatabaseError("lookup PaaS Audit operation", err)
	}
	return record, true, nil
}

func (value *transaction) Readiness(
	ctx context.Context,
) (auditlog.ReadinessSnapshot, error) {
	var snapshot auditlog.ReadinessSnapshot
	if err := value.tx.QueryRow(ctx, "SELECT * FROM audit.readiness()").Scan(
		&snapshot.Ready,
		&snapshot.SchemaVersion,
		&snapshot.CheckedAt,
	); err != nil {
		return auditlog.ReadinessSnapshot{}, mapDatabaseError("read Audit readiness", err)
	}
	snapshot.CheckedAt = snapshot.CheckedAt.UTC()
	if snapshot.SchemaVersion != 4 || snapshot.CheckedAt.IsZero() {
		return auditlog.ReadinessSnapshot{}, auditlog.ErrUnavailable
	}
	return snapshot, nil
}

type auditRecordScanner interface {
	Scan(...any) error
}

func scanAuditRecord(scanner auditRecordScanner) (auditv1.AuditRecord, string, error) {
	var chainID, source, eventID, canonicalDocument string
	var eventDocument []byte
	var sequence int64
	var record auditv1.AuditRecord
	if err := scanner.Scan(
		&chainID,
		&sequence,
		&source,
		&eventID,
		&eventDocument,
		&canonicalDocument,
		&record.ContentDigest,
		&record.PreviousHash,
		&record.RecordHash,
		&record.IngestedAt,
		&record.Retention,
	); err != nil {
		return auditv1.AuditRecord{}, "", err
	}
	defer clear(eventDocument)
	if sequence < 1 || uint64(sequence) > maximumAuditSequence ||
		auditv1.DecodeRequest(bytes.NewReader(eventDocument), &record.Event) != nil ||
		authority.ChainFor(record.Event.TenantID, record.Event.InstallationID) != authority.ChainID(chainID) ||
		record.Event.EventID != auditv1.EventID(eventID) {
		return auditv1.AuditRecord{}, "", auditlog.ErrUnavailable
	}
	record.APIVersion = auditv1.APIVersion
	record.Kind = "AuditRecord"
	record.Source = auditv1.Source(source)
	record.Sequence = uint64(sequence)
	record.IngestedAt = record.IngestedAt.UTC()
	fact, err := authority.Canonicalize(record.Source, record.Event)
	if err != nil || fact.Document != canonicalDocument ||
		fact.ContentDigest != record.ContentDigest {
		return auditv1.AuditRecord{}, "", auditlog.ErrUnavailable
	}
	return record, canonicalDocument, nil
}
