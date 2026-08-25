package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

var (
	_ identityaccess.Repository  = (*Repository)(nil)
	_ identityaccess.Transaction = (*transaction)(nil)
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) (*Repository, error) {
	if pool == nil {
		return nil, errors.New("IAM PostgreSQL pool is required")
	}
	return &Repository{pool: pool}, nil
}

func (repository *Repository) WithinTransaction(
	ctx context.Context,
	callback func(context.Context, identityaccess.Transaction) error,
) error {
	if repository == nil || repository.pool == nil {
		return identityaccess.ErrUnavailable
	}
	if ctx == nil || callback == nil {
		return identityaccess.ErrInvalidArgument
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.Serializable,
		AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return mapDatabaseError("begin IAM transaction", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return mapDatabaseError("set IAM transaction timezone", err)
	}
	if err := callback(ctx, &transaction{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return mapDatabaseError("commit IAM transaction", err)
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
			return fmt.Errorf("%s: %w", operation, identityaccess.ErrRetryableTransaction)
		case "23505":
			return fmt.Errorf("%s: %w", operation, identityaccess.ErrConflict)
		}
	}
	return fmt.Errorf("%s: %w", operation, identityaccess.ErrUnavailable)
}

func mapSubjectDatabaseError(operation string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "42501" {
		return fmt.Errorf("%s: %w", operation, identityaccess.ErrUnauthenticated)
	}
	return mapDatabaseError(operation, err)
}

func mapAuthorizationDatabaseError(operation string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "42501" {
		return fmt.Errorf("%s: %w", operation, identityaccess.ErrForbidden)
	}
	return mapDatabaseError(operation, err)
}
