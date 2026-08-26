package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase"
)

var _ usecase.Repository = (*Repository)(nil)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) (*Repository, error) {
	if pool == nil {
		return nil, errors.New("managed-service PostgreSQL pool is required")
	}
	return &Repository{pool: pool}, nil
}

func (repository *Repository) Begin(
	ctx context.Context,
	tenantID string,
	mode usecase.TransactionMode,
) (usecase.Transaction, error) {
	if repository == nil || repository.pool == nil || ctx == nil ||
		managedservicev1.ValidateID("tenantId", tenantID) != nil {
		return nil, usecase.ErrInvalidArgument
	}
	options := pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
	if mode == usecase.ReadWrite {
		options = pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite}
	} else if mode != usecase.ReadOnly {
		return nil, usecase.ErrInvalidArgument
	}
	tx, err := repository.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, databaseError(ctx, err)
	}
	if _, err := tx.Exec(
		ctx,
		"SELECT pg_catalog.set_config('matrix.tenant_id', $1, true)",
		tenantID,
	); err != nil {
		_ = tx.Rollback(context.Background())
		return nil, databaseError(ctx, err)
	}
	return &transaction{tx: tx}, nil
}

func databaseError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var database *pgconn.PgError
	if errors.As(err, &database) {
		switch database.Code {
		case "40001", "40P01":
			return usecase.ErrTransactionRetry
		case "23505":
			if database.ConstraintName == "service_installations_pkey" {
				return usecase.ErrAlreadyExists
			}
			return usecase.ErrTransactionRetry
		case "23503":
			return usecase.ErrNotFound
		case "23514", "22023":
			return usecase.ErrInvalidArgument
		}
	}
	return usecase.ErrRepositoryUnavailable
}
