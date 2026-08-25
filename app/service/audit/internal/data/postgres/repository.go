package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xiak/matrix/app/service/audit/internal/usecase/auditlog"
)

var (
	_ auditlog.Repository  = (*Repository)(nil)
	_ auditlog.Transaction = (*transaction)(nil)
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) (*Repository, error) {
	if pool == nil {
		return nil, errors.New("Audit PostgreSQL pool is required")
	}
	return &Repository{pool: pool}, nil
}

func (repository *Repository) WithinTransaction(
	ctx context.Context,
	callback func(context.Context, auditlog.Transaction) error,
) error {
	if repository == nil || repository.pool == nil {
		return auditlog.ErrUnavailable
	}
	if ctx == nil || callback == nil {
		return auditlog.ErrInvalidArgument
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.Serializable,
		AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return mapDatabaseError("begin Audit transaction", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return mapDatabaseError("set Audit transaction timezone", err)
	}
	if err := callback(ctx, &transaction{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return mapDatabaseError("commit Audit transaction", err)
	}
	return nil
}

func mapDatabaseError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "40001", "40P01":
			return fmt.Errorf("%s: %w", operation, auditlog.ErrRetryableTransaction)
		case "23505":
			return fmt.Errorf("%s: %w", operation, auditlog.ErrConflict)
		}
	}
	return fmt.Errorf("%s: %w", operation, auditlog.ErrUnavailable)
}
