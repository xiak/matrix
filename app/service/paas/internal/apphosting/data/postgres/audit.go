package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/auditdispatch"
)

var _ auditdispatch.Repository = (*AuditOutboxRepository)(nil)

type AuditOutboxRepository struct {
	pool *pgxpool.Pool
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
	var claim auditdispatch.Claim
	var document []byte
	err := repository.pool.QueryRow(
		ctx,
		`SELECT tenant_id,
		        event_id,
		        attempts,
		        fencing_token,
		        lease_expires_at,
		        document
		   FROM paas.claim_audit_event($1, $2)`,
		workerID,
		int(leaseDuration/time.Second),
	).Scan(
		&claim.TenantID,
		&claim.EventID,
		&claim.Attempts,
		&claim.FencingToken,
		&claim.LeaseExpiresAt,
		&document,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return auditdispatch.Claim{}, false, nil
	}
	if err != nil {
		return auditdispatch.Claim{}, false, fmt.Errorf("claim Audit outbox event: %w", err)
	}
	claim.LeaseExpiresAt = databaseTime(claim.LeaseExpiresAt)
	event, decodeErr := decodeAuditEvent(document)
	if decodeErr != nil {
		completionErr := repository.Complete(ctx, auditdispatch.Completion{
			TenantID: claim.TenantID, EventID: claim.EventID, WorkerID: workerID,
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
	_, err := repository.pool.Exec(
		ctx,
		`SELECT paas.complete_audit_event($1, $2, $3, $4, $5, $6, $7)`,
		completion.TenantID,
		completion.EventID,
		completion.WorkerID,
		completion.FencingToken,
		completion.Outcome,
		retryAt,
		errorCode,
	)
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
	if err := repository.pool.QueryRow(
		ctx,
		`SELECT pending_count,
		        leased_count,
		        retry_count,
		        delivered_count,
		        dead_letter_count,
		        expired_lease_count
		   FROM paas.audit_outbox_snapshot()`,
	).Scan(
		&value.Pending,
		&value.Leased,
		&value.Retry,
		&value.Delivered,
		&value.DeadLetter,
		&value.ExpiredLease,
	); err != nil {
		return auditdispatch.Snapshot{}, fmt.Errorf("read Audit outbox snapshot: %w", err)
	}
	if value.Pending < 0 || value.Leased < 0 || value.Retry < 0 ||
		value.Delivered < 0 || value.DeadLetter < 0 || value.ExpiredLease < 0 {
		return auditdispatch.Snapshot{}, errors.New("Audit outbox snapshot contains a negative count")
	}
	return value, nil
}

func decodeAuditEvent(document []byte) (port.AuditEvent, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value port.AuditEvent
	if err := decoder.Decode(&value); err != nil {
		return port.AuditEvent{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return port.AuditEvent{}, errors.New("stored Audit event contains trailing data")
	}
	if err := port.ValidateAuditEvent(value); err != nil {
		return port.AuditEvent{}, err
	}
	return value, nil
}

func validateAuditCompletion(value auditdispatch.Completion) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("audit.tenantId", string(value.TenantID)),
		paasv1.ValidateID("audit.eventId", value.EventID),
		paasv1.ValidateID("audit.workerId", value.WorkerID),
	)
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
		if !value.RetryAt.IsZero() || value.ErrorCode == "" {
			problems = append(problems, errors.New("dead-letter Audit completion is invalid"))
		}
	default:
		problems = append(problems, fmt.Errorf("unknown Audit completion outcome %q", value.Outcome))
	}
	return errors.Join(problems...)
}
