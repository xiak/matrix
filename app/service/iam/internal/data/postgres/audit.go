package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/auditdispatch"
)

var _ auditdispatch.Repository = (*AuditOutboxRepository)(nil)

type AuditOutboxRepository struct {
	pool *pgxpool.Pool
}

func NewAuditOutboxRepository(pool *pgxpool.Pool) (*AuditOutboxRepository, error) {
	if pool == nil {
		return nil, errors.New("IAM Audit PostgreSQL pool is required")
	}
	return &AuditOutboxRepository{pool: pool}, nil
}

func (repository *AuditOutboxRepository) Claim(
	ctx context.Context,
	workerID string,
	leaseDuration time.Duration,
) (auditdispatch.Claim, bool, error) {
	if repository == nil || repository.pool == nil {
		return auditdispatch.Claim{}, false, errors.New("IAM Audit outbox repository is nil")
	}
	if ctx == nil || auditv1.ValidateID("workerId", workerID) != nil ||
		leaseDuration < time.Second || leaseDuration > 5*time.Minute ||
		leaseDuration%time.Second != 0 {
		return auditdispatch.Claim{}, false, errors.New("IAM Audit claim input is invalid")
	}
	var claim auditdispatch.Claim
	var document []byte
	var fencingToken int64
	err := repository.pool.QueryRow(
		ctx,
		`SELECT tenant_id, event_id, event_document, attempts,
		        fencing_token, lease_expires_at
		   FROM iam.claim_audit_event($1, $2)`,
		workerID,
		int(leaseDuration/time.Second),
	).Scan(
		&claim.TenantID,
		&claim.EventID,
		&document,
		&claim.Attempts,
		&fencingToken,
		&claim.LeaseExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return auditdispatch.Claim{}, false, nil
	}
	if err != nil {
		return auditdispatch.Claim{}, false, fmt.Errorf("claim IAM Audit outbox event: %w", err)
	}
	claim.LeaseExpiresAt = claim.LeaseExpiresAt.UTC()
	if fencingToken < 1 || fencingToken > 9007199254740991 {
		return auditdispatch.Claim{}, false, errors.New("IAM Audit outbox fencing token is invalid")
	}
	claim.FencingToken = uint64(fencingToken)
	if auditv1.DecodeRequest(bytes.NewReader(document), &claim.Event) != nil ||
		auditv1.ValidateEventForSource(auditv1.SourceIAM, claim.Event) != nil ||
		claim.Event.TenantID != claim.TenantID || claim.Event.EventID != claim.EventID {
		clear(document)
		completionErr := repository.Complete(ctx, auditdispatch.Completion{
			EventID: claim.EventID, WorkerID: workerID, FencingToken: claim.FencingToken,
			Outcome: auditdispatch.OutcomeDeadLetter, ErrorCode: "audit.event.corrupt",
		})
		return auditdispatch.Claim{}, false,
			errors.Join(errors.New("claimed IAM Audit event is corrupt"), completionErr)
	}
	clear(document)
	return claim, true, nil
}

func (repository *AuditOutboxRepository) Complete(
	ctx context.Context,
	completion auditdispatch.Completion,
) error {
	if repository == nil || repository.pool == nil {
		return errors.New("IAM Audit outbox repository is nil")
	}
	if ctx == nil || validateAuditCompletion(completion) != nil {
		return errors.New("IAM Audit completion input is invalid")
	}
	retrySeconds := 0
	var errorCode any
	if completion.Outcome == auditdispatch.OutcomeRetry {
		retrySeconds = int(completion.RetryDelay / time.Second)
	}
	if completion.Outcome == auditdispatch.OutcomeDeadLetter {
		errorCode = completion.ErrorCode
	}
	_, err := repository.pool.Exec(
		ctx,
		"SELECT iam.complete_audit_event($1, $2, $3, $4, $5, $6)",
		string(completion.EventID),
		completion.WorkerID,
		int64(completion.FencingToken),
		string(completion.Outcome),
		retrySeconds,
		errorCode,
	)
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "40001" {
			return fmt.Errorf("complete IAM Audit event: %w", auditdispatch.ErrStaleLease)
		}
		return fmt.Errorf("complete IAM Audit event: %w", err)
	}
	return nil
}

func (repository *AuditOutboxRepository) Snapshot(
	ctx context.Context,
) (auditdispatch.Snapshot, error) {
	if repository == nil || repository.pool == nil {
		return auditdispatch.Snapshot{}, errors.New("IAM Audit outbox repository is nil")
	}
	if ctx == nil {
		return auditdispatch.Snapshot{}, errors.New("IAM Audit snapshot context is nil")
	}
	var snapshot auditdispatch.Snapshot
	if err := repository.pool.QueryRow(
		ctx,
		`SELECT pending_count, leased_count, retry_count, delivered_count,
		        dead_letter_count, expired_lease_count
		   FROM iam.audit_outbox_snapshot()`,
	).Scan(
		&snapshot.Pending,
		&snapshot.Leased,
		&snapshot.Retry,
		&snapshot.Delivered,
		&snapshot.DeadLetter,
		&snapshot.ExpiredLease,
	); err != nil {
		return auditdispatch.Snapshot{}, fmt.Errorf("read IAM Audit outbox snapshot: %w", err)
	}
	if snapshot.Pending < 0 || snapshot.Leased < 0 || snapshot.Retry < 0 ||
		snapshot.Delivered < 0 || snapshot.DeadLetter < 0 || snapshot.ExpiredLease < 0 {
		return auditdispatch.Snapshot{}, errors.New("IAM Audit outbox snapshot is invalid")
	}
	return snapshot, nil
}

func validateAuditCompletion(completion auditdispatch.Completion) error {
	var problems []error
	problems = append(problems,
		auditv1.ValidateID("eventId", string(completion.EventID)),
		auditv1.ValidateID("workerId", completion.WorkerID),
	)
	if completion.FencingToken < 1 || completion.FencingToken > 9007199254740991 {
		problems = append(problems, errors.New("IAM Audit completion fencing token is invalid"))
	}
	switch completion.Outcome {
	case auditdispatch.OutcomeDelivered:
		if completion.RetryDelay != 0 || completion.ErrorCode != "" {
			problems = append(problems, errors.New("delivered IAM Audit completion contains failure data"))
		}
	case auditdispatch.OutcomeRetry:
		if completion.RetryDelay < time.Second || completion.RetryDelay > 24*time.Hour ||
			completion.RetryDelay%time.Second != 0 || completion.ErrorCode != "" {
			problems = append(problems, errors.New("retry IAM Audit completion is invalid"))
		}
	case auditdispatch.OutcomeDeadLetter:
		if completion.RetryDelay != 0 ||
			completion.ErrorCode != "audit.delivery.rejected" &&
				completion.ErrorCode != "audit.delivery.exhausted" &&
				completion.ErrorCode != "audit.event.corrupt" {
			problems = append(problems, errors.New("dead-letter IAM Audit completion is invalid"))
		}
	default:
		problems = append(problems, errors.New("IAM Audit completion outcome is invalid"))
	}
	return errors.Join(problems...)
}
