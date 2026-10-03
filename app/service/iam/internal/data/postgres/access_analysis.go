package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/accessanalysis"
)

type AccessAnalysisRepository struct{ pool *pgxpool.Pool }
type accessAnalysisTransaction struct{ tx pgx.Tx }

func NewAccessAnalysisRepository(pool *pgxpool.Pool) (*AccessAnalysisRepository, error) {
	if pool == nil {
		return nil, accessanalysis.ErrUnavailable
	}
	return &AccessAnalysisRepository{pool: pool}, nil
}

func (repository *AccessAnalysisRepository) Ready(ctx context.Context) error {
	if repository == nil || repository.pool == nil || ctx == nil {
		return accessanalysis.ErrUnavailable
	}
	var ready bool
	if err := repository.pool.QueryRow(ctx, "SELECT iam.access_analysis_worker_ready()").Scan(&ready); err != nil || !ready {
		return accessanalysis.ErrUnavailable
	}
	return nil
}

func (repository *AccessAnalysisRepository) WithinTransaction(ctx context.Context, callback func(context.Context, accessanalysis.Transaction) error) error {
	if repository == nil || repository.pool == nil || ctx == nil || callback == nil {
		return accessanalysis.ErrUnavailable
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite})
	if err != nil {
		return mapAccessAnalysisError(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return mapAccessAnalysisError(err)
	}
	if err = callback(ctx, &accessAnalysisTransaction{tx: tx}); err != nil {
		return err
	}
	return mapAccessAnalysisError(tx.Commit(ctx))
}

func (value *accessAnalysisTransaction) Claim(ctx context.Context, worker, attempt string) (accessanalysis.Claim, bool, error) {
	var claim accessanalysis.Claim
	var encoded []byte
	err := value.tx.QueryRow(ctx, `SELECT attempt_id,worker_id,fence,lease_expires_at,snapshot_digest,snapshot_document
		FROM iam.claim_access_analysis($1,$2)`, worker, attempt).Scan(&claim.AttemptID, &claim.WorkerID, &claim.Fence,
		&claim.LeaseExpiresAt, &claim.SnapshotDigest, &encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return claim, false, nil
	}
	if err != nil {
		return accessanalysis.Claim{}, false, mapAccessAnalysisError(err)
	}
	if contractjson.DecodeObjectBytes(encoded, 2*1024*1024, &claim.Snapshot) != nil {
		return accessanalysis.Claim{}, false, accessanalysis.ErrUnavailable
	}
	claim.LeaseExpiresAt = claim.LeaseExpiresAt.UTC()
	normalizeAnalysisSnapshot(&claim.Snapshot)
	if _, err := accessanalysis.Evaluate(claim.Snapshot); err != nil {
		return accessanalysis.Claim{}, false, accessanalysis.ErrUnavailable
	}
	return claim, true, nil
}

func (value *accessAnalysisTransaction) Complete(ctx context.Context, claim accessanalysis.Claim, completion accessanalysis.Completion) error {
	encoded, err := json.Marshal(completion)
	if err != nil || len(encoded) > 2*1024*1024 {
		return accessanalysis.ErrUnavailable
	}
	defer clear(encoded)
	_, err = value.tx.Exec(ctx, "SELECT iam.complete_access_analysis($1,$2,$3,$4,$5::jsonb)",
		claim.AttemptID, claim.WorkerID, claim.Fence, claim.Snapshot.Analyzer.AccountID, encoded)
	return mapAccessAnalysisError(err)
}

func normalizeAnalysisSnapshot(snapshot *accessanalysis.Snapshot) {
	snapshot.ObservedAt = snapshot.ObservedAt.UTC()
	snapshot.Analyzer.CreatedAt, snapshot.Analyzer.UpdatedAt = snapshot.Analyzer.CreatedAt.UTC(), snapshot.Analyzer.UpdatedAt.UTC()
	if snapshot.RecoveryCompletedAt != nil {
		value := snapshot.RecoveryCompletedAt.UTC()
		snapshot.RecoveryCompletedAt = &value
	}
	for index := range snapshot.Coverage {
		if snapshot.Coverage[index].ObservedFrom != nil {
			value := snapshot.Coverage[index].ObservedFrom.UTC()
			snapshot.Coverage[index].ObservedFrom = &value
		}
		if snapshot.Coverage[index].ObservedThrough != nil {
			value := snapshot.Coverage[index].ObservedThrough.UTC()
			snapshot.Coverage[index].ObservedThrough = &value
		}
	}
	for index := range snapshot.Candidates {
		snapshot.Candidates[index].CreatedAt = snapshot.Candidates[index].CreatedAt.UTC()
		if snapshot.Candidates[index].LastActivityAt != nil {
			value := snapshot.Candidates[index].LastActivityAt.UTC()
			snapshot.Candidates[index].LastActivityAt = &value
		}
	}
	for index := range snapshot.Findings {
		normalizeAccessFinding(&snapshot.Findings[index])
	}
}

func normalizeAccessFinding(item *iamv1.AccessFinding) {
	item.WindowStartedAt, item.ObservedAt = item.WindowStartedAt.UTC(), item.ObservedAt.UTC()
	item.CreatedAt, item.UpdatedAt = item.CreatedAt.UTC(), item.UpdatedAt.UTC()
	if item.LastActivityAt != nil {
		value := item.LastActivityAt.UTC()
		item.LastActivityAt = &value
	}
	if item.RecoveryCompletedAt != nil {
		value := item.RecoveryCompletedAt.UTC()
		item.RecoveryCompletedAt = &value
	}
	if item.ResolvedAt != nil {
		value := item.ResolvedAt.UTC()
		item.ResolvedAt = &value
	}
}

func mapAccessAnalysisError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var failure *pgconn.PgError
	if errors.As(err, &failure) {
		switch failure.Code {
		case "40001", "40P01":
			return accessanalysis.ErrRetryableTransaction
		case "P0002", "23505":
			return accessanalysis.ErrStaleLease
		}
	}
	return fmt.Errorf("IAM access analysis database: %w", accessanalysis.ErrUnavailable)
}
