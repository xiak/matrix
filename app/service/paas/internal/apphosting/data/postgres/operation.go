package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
)

var _ operationqueue.Repository = (*OperationQueueRepository)(nil)

type OperationQueueRepository struct {
	pool *pgxpool.Pool
}

func NewOperationQueueRepository(pool *pgxpool.Pool) (*OperationQueueRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &OperationQueueRepository{pool: pool}, nil
}

func (repository *OperationQueueRepository) ClaimOperation(
	ctx context.Context,
	workerID string,
	leaseDuration time.Duration,
) (operationqueue.Lease, bool, error) {
	if repository == nil || repository.pool == nil {
		return operationqueue.Lease{}, false, errors.New("Operation queue repository is nil")
	}
	if ctx == nil {
		return operationqueue.Lease{}, false, errors.New("Operation claim context is nil")
	}
	if err := paasv1.ValidateID("workerId", workerID); err != nil {
		return operationqueue.Lease{}, false, err
	}
	if leaseDuration < time.Second ||
		leaseDuration > 5*time.Minute ||
		leaseDuration%time.Second != 0 {
		return operationqueue.Lease{}, false, errors.New("Operation lease duration is invalid")
	}
	var (
		tenantID       string
		operationID    string
		state          string
		attempt        uint64
		fencingToken   uint64
		leaseExpiresAt time.Time
		document       []byte
	)
	err := repository.pool.QueryRow(
		ctx,
		`SELECT tenant_id,
		        operation_id,
		        operation_state,
		        attempt,
		        fencing_token,
		        lease_expires_at,
		        document
		   FROM paas.claim_operation($1, $2)`,
		workerID,
		int(leaseDuration/time.Second),
	).Scan(
		&tenantID,
		&operationID,
		&state,
		&attempt,
		&fencingToken,
		&leaseExpiresAt,
		&document,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return operationqueue.Lease{}, false, nil
	}
	if err != nil {
		return operationqueue.Lease{}, false, fmt.Errorf("claim Operation: %w", err)
	}
	var operation paasv1.Operation
	if err := decodeDocument("Operation", document, &operation); err != nil {
		return operationqueue.Lease{}, false, err
	}
	if err := paasv1.ValidateOperation(operation); err != nil {
		return operationqueue.Lease{}, false, fmt.Errorf("validate claimed Operation: %w", err)
	}
	if string(operation.Scope.TenantID) != tenantID ||
		string(operation.ID) != operationID ||
		string(operation.State) != state ||
		uint64(operation.Attempt) != attempt {
		return operationqueue.Lease{}, false, errors.New("claimed Operation relational identity mismatch")
	}
	return operationqueue.Lease{
		TenantID:       paasv1.TenantID(tenantID),
		Operation:      operation,
		WorkerID:       workerID,
		FencingToken:   fencingToken,
		LeaseExpiresAt: databaseTime(leaseExpiresAt),
	}, true, nil
}

func (repository *OperationQueueRepository) AdvanceOperation(
	ctx context.Context,
	transition operationqueue.Transition,
) (paasv1.Operation, error) {
	if repository == nil || repository.pool == nil {
		return paasv1.Operation{}, errors.New("Operation queue repository is nil")
	}
	if ctx == nil {
		return paasv1.Operation{}, errors.New("Operation transition context is nil")
	}
	var problemDocument any
	if transition.Problem != nil {
		encoded, err := json.Marshal(transition.Problem)
		if err != nil {
			return paasv1.Operation{}, fmt.Errorf("encode Operation Problem: %w", err)
		}
		problemDocument = encoded
	}
	var nextAttemptAt any
	if transition.NextAttemptAt != nil {
		nextAttemptAt = *transition.NextAttemptAt
	}
	var document []byte
	err := withinTenantTransaction(
		ctx,
		repository.pool,
		transition.Lease.TenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite},
		func(tx pgx.Tx) error {
			return tx.QueryRow(
				ctx,
				`SELECT paas.advance_operation($1, $2, $3, $4, $5::jsonb, $6, $7)`,
				transition.Lease.Operation.ID,
				transition.Lease.WorkerID,
				int64(transition.Lease.FencingToken),
				transition.State,
				problemDocument,
				nextAttemptAt,
				transition.ReleaseLease,
			).Scan(&document)
		},
	)
	if err != nil {
		return paasv1.Operation{}, mapOperationQueueError(err)
	}
	var operation paasv1.Operation
	if err := decodeDocument("Operation", document, &operation); err != nil {
		return paasv1.Operation{}, err
	}
	if err := paasv1.ValidateOperation(operation); err != nil {
		return paasv1.Operation{}, fmt.Errorf("validate transitioned Operation: %w", err)
	}
	return operation, nil
}

func (repository *OperationQueueRepository) ReleaseOperation(
	ctx context.Context,
	lease operationqueue.Lease,
	nextAttemptAt time.Time,
) (paasv1.Operation, error) {
	if repository == nil || repository.pool == nil {
		return paasv1.Operation{}, errors.New("Operation queue repository is nil")
	}
	if ctx == nil {
		return paasv1.Operation{}, errors.New("Operation lease release context is nil")
	}
	var document []byte
	err := withinTenantTransaction(
		ctx,
		repository.pool,
		lease.TenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite},
		func(tx pgx.Tx) error {
			return tx.QueryRow(
				ctx,
				`SELECT paas.release_operation_lease($1, $2, $3, $4)`,
				lease.Operation.ID,
				lease.WorkerID,
				int64(lease.FencingToken),
				nextAttemptAt,
			).Scan(&document)
		},
	)
	if err != nil {
		return paasv1.Operation{}, mapOperationQueueError(err)
	}
	var operation paasv1.Operation
	if err := decodeDocument("Operation", document, &operation); err != nil {
		return paasv1.Operation{}, err
	}
	if err := paasv1.ValidateOperation(operation); err != nil {
		return paasv1.Operation{}, fmt.Errorf("validate released Operation: %w", err)
	}
	return operation, nil
}

func mapOperationQueueError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "P0002":
			return fmt.Errorf("advance Operation: %w", operationqueue.ErrNotFound)
		case "MX412":
			return fmt.Errorf("advance Operation: %w", operationqueue.ErrStaleLease)
		case "55000":
			return fmt.Errorf("advance Operation: %w", operationqueue.ErrInvalidTransition)
		}
	}
	return fmt.Errorf("advance Operation: %w", err)
}
