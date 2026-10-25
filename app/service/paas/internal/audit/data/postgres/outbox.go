package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
	"github.com/xiak/matrix/app/service/paas/internal/audit/usecase/auditdispatch"
)

var _ auditdispatch.Repository = (*AuditOutboxRepository)(nil)

type AuditOutboxRepository struct {
	pool          *pgxpool.Pool
	claimSequence atomic.Uint64
}

func NewAuditOutboxRepository(pool *pgxpool.Pool) (*AuditOutboxRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &AuditOutboxRepository{pool: pool}, nil
}

func (repository *AuditOutboxRepository) Claim(
	ctx context.Context,
	workerID string,
	leaseDuration time.Duration,
) (auditdispatch.Claim, bool, error) {
	if repository == nil || repository.pool == nil {
		return auditdispatch.Claim{}, false, errors.New("Audit outbox repository is nil")
	}
	if ctx == nil {
		return auditdispatch.Claim{}, false, errors.New("Audit claim context is nil")
	}
	if err := paasv1.ValidateID("audit.workerId", workerID); err != nil {
		return auditdispatch.Claim{}, false, err
	}
	if leaseDuration < time.Second || leaseDuration > 5*time.Minute ||
		leaseDuration%time.Second != 0 {
		return auditdispatch.Claim{}, false, errors.New("Audit lease duration must use whole seconds")
	}
	streams := []auditdispatch.Stream{
		auditdispatch.StreamAppHosting,
		auditdispatch.StreamManagedService,
	}
	if repository.claimSequence.Add(1)%2 == 0 {
		streams[0], streams[1] = streams[1], streams[0]
	}
	for _, stream := range streams {
		claim, found, err := repository.claimStream(ctx, stream, workerID, leaseDuration)
		if err != nil || found {
			return claim, found, err
		}
	}
	return auditdispatch.Claim{}, false, nil
}

func (repository *AuditOutboxRepository) claimStream(
	ctx context.Context,
	stream auditdispatch.Stream,
	workerID string,
	leaseDuration time.Duration,
) (auditdispatch.Claim, bool, error) {
	function, err := auditFunction(stream, "claim_audit_event")
	if err != nil {
		return auditdispatch.Claim{}, false, err
	}
	var claim auditdispatch.Claim
	var document []byte
	installationColumn := "''::text"
	if stream == auditdispatch.StreamAppHosting {
		installationColumn = "COALESCE(installation_id, '')"
	}
	err = repository.pool.QueryRow(ctx, `SELECT COALESCE(tenant_id, ''), `+installationColumn+`, event_id, attempts,
		fencing_token, lease_expires_at, document FROM `+function+`($1, $2)`,
		workerID, int(leaseDuration/time.Second)).Scan(
		&claim.TenantID, &claim.InstallationID, &claim.EventID, &claim.Attempts, &claim.FencingToken,
		&claim.LeaseExpiresAt, &document,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return auditdispatch.Claim{}, false, nil
	}
	if err != nil {
		return auditdispatch.Claim{}, false, fmt.Errorf("claim %s Audit event: %w", stream, err)
	}
	claim.Stream = stream
	claim.LeaseExpiresAt = normalizeTime(claim.LeaseExpiresAt)
	event, decodeErr := decodeAuditEvent(document)
	if decodeErr != nil {
		completionErr := repository.Complete(ctx, auditdispatch.Completion{
			TenantID: claim.TenantID, InstallationID: claim.InstallationID,
			EventID: claim.EventID, Stream: stream, WorkerID: workerID,
			FencingToken: claim.FencingToken, Outcome: auditdispatch.OutcomeDeadLetter,
			ErrorCode: "CORRUPT_AUDIT_EVENT",
		})
		return auditdispatch.Claim{}, false,
			errors.Join(fmt.Errorf("decode claimed Audit event: %w", decodeErr), completionErr)
	}
	claim.Event = event
	return claim, true, nil
}

func (repository *AuditOutboxRepository) Complete(
	ctx context.Context,
	completion auditdispatch.Completion,
) error {
	if repository == nil || repository.pool == nil {
		return errors.New("Audit outbox repository is nil")
	}
	if ctx == nil {
		return errors.New("Audit completion context is nil")
	}
	if err := validateAuditCompletion(completion); err != nil {
		return err
	}
	var retryAt any
	if completion.Outcome == auditdispatch.OutcomeRetry {
		retryAt = completion.RetryAt.UTC()
	}
	var errorCode any
	if completion.Outcome == auditdispatch.OutcomeDeadLetter {
		errorCode = completion.ErrorCode
	}
	function, err := auditFunction(completion.Stream, "complete_audit_event")
	if err != nil {
		return err
	}
	arguments := []any{completion.TenantID}
	parameters := "($1, $2, $3, $4, $5, $6, $7)"
	if completion.Stream == auditdispatch.StreamAppHosting {
		arguments = append(arguments, completion.InstallationID)
		parameters = "($1, $2, $3, $4, $5, $6, $7, $8)"
	}
	arguments = append(arguments, completion.EventID, completion.WorkerID,
		completion.FencingToken, completion.Outcome, retryAt, errorCode)
	_, err = repository.pool.Exec(ctx, `SELECT `+function+parameters, arguments...)
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "MX412" {
			return fmt.Errorf("complete Audit event: %w", auditdispatch.ErrStaleLease)
		}
		return fmt.Errorf("complete Audit event: %w", err)
	}
	return nil
}

func (repository *AuditOutboxRepository) Snapshot(
	ctx context.Context,
) (auditdispatch.Snapshot, error) {
	if repository == nil || repository.pool == nil {
		return auditdispatch.Snapshot{}, errors.New("Audit outbox repository is nil")
	}
	if ctx == nil {
		return auditdispatch.Snapshot{}, errors.New("Audit snapshot context is nil")
	}
	var value auditdispatch.Snapshot
	for _, stream := range []auditdispatch.Stream{
		auditdispatch.StreamAppHosting,
		auditdispatch.StreamManagedService,
	} {
		function, err := auditFunction(stream, "audit_outbox_snapshot")
		if err != nil {
			return auditdispatch.Snapshot{}, err
		}
		var current auditdispatch.Snapshot
		if err := repository.pool.QueryRow(ctx, `SELECT pending_count, leased_count,
			retry_count, delivered_count, dead_letter_count, expired_lease_count FROM `+function+`()`).Scan(
			&current.Pending, &current.Leased, &current.Retry, &current.Delivered,
			&current.DeadLetter, &current.ExpiredLease,
		); err != nil {
			return auditdispatch.Snapshot{}, fmt.Errorf("read %s Audit outbox snapshot: %w", stream, err)
		}
		value.Pending += current.Pending
		value.Leased += current.Leased
		value.Retry += current.Retry
		value.Delivered += current.Delivered
		value.DeadLetter += current.DeadLetter
		value.ExpiredLease += current.ExpiredLease
	}
	if value.Pending < 0 || value.Leased < 0 || value.Retry < 0 ||
		value.Delivered < 0 || value.DeadLetter < 0 || value.ExpiredLease < 0 {
		return auditdispatch.Snapshot{}, errors.New("Audit outbox snapshot contains a negative count")
	}
	return value, nil
}

func decodeAuditEvent(document []byte) (audit.Event, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value audit.Event
	if err := decoder.Decode(&value); err != nil {
		return audit.Event{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return audit.Event{}, errors.New("stored Audit event contains trailing data")
	}
	if err := audit.ValidateEvent(value); err != nil {
		return audit.Event{}, err
	}
	return value, nil
}

func normalizeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func auditFunction(stream auditdispatch.Stream, name string) (string, error) {
	if name != "claim_audit_event" && name != "complete_audit_event" && name != "audit_outbox_snapshot" {
		return "", errors.New("Audit database function name is invalid")
	}
	switch stream {
	case auditdispatch.StreamAppHosting:
		return "paas." + name, nil
	case auditdispatch.StreamManagedService:
		return "managedservice." + name, nil
	default:
		return "", errors.New("Audit stream is invalid")
	}
}

func validateAuditCompletion(value auditdispatch.Completion) error {
	var problems []error
	problems = append(problems,
		auditv1.ValidateAuthority(auditv1.TenantID(value.TenantID), value.InstallationID),
		paasv1.ValidateID("audit.eventId", value.EventID),
		paasv1.ValidateID("audit.workerId", value.WorkerID),
	)
	if value.Stream != auditdispatch.StreamAppHosting &&
		value.Stream != auditdispatch.StreamManagedService {
		problems = append(problems, errors.New("Audit completion stream is invalid"))
	}
	if value.Stream == auditdispatch.StreamManagedService && value.InstallationID != "" {
		problems = append(problems, errors.New("managed-service Audit completion must be tenant-scoped"))
	}
	if value.FencingToken < 1 {
		problems = append(problems, errors.New("Audit completion fencing token is invalid"))
	}
	switch value.Outcome {
	case auditdispatch.OutcomeDelivered:
		if !value.RetryAt.IsZero() || value.ErrorCode != "" {
			problems = append(problems, errors.New("delivered Audit completion contains retry data"))
		}
	case auditdispatch.OutcomeRetry:
		if value.RetryAt.IsZero() || value.ErrorCode != "" {
			problems = append(problems, errors.New("retry Audit completion is invalid"))
		}
	case auditdispatch.OutcomeDeadLetter:
		if !value.RetryAt.IsZero() ||
			value.ErrorCode != "AUDIT_DELIVERY_REJECTED" &&
				value.ErrorCode != "AUDIT_DELIVERY_EXHAUSTED" &&
				value.ErrorCode != "CORRUPT_AUDIT_EVENT" {
			problems = append(problems, errors.New("dead-letter Audit completion is invalid"))
		}
	default:
		problems = append(problems, fmt.Errorf("unknown Audit completion outcome %q", value.Outcome))
	}
	return errors.Join(problems...)
}
