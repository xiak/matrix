package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
)

var _ createplacement.Repository = (*PlacementRepository)(nil)

// PlacementRepository implements the exact persistence boundary required by
// the CreatePlacement use case.
type PlacementRepository struct {
	pool *pgxpool.Pool
}

func NewPlacementRepository(pool *pgxpool.Pool) (*PlacementRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &PlacementRepository{pool: pool}, nil
}

func (repository *PlacementRepository) WithinTransaction(
	ctx context.Context,
	tenantID paasv1.TenantID,
	guard operationqueue.LeaseGuard,
	callback func(context.Context, createplacement.Transaction) error,
) error {
	if repository == nil || repository.pool == nil {
		return errors.New("placement repository is nil")
	}
	if ctx == nil {
		return errors.New("placement transaction context is nil")
	}
	if callback == nil {
		return errors.New("placement transaction callback is required")
	}
	if err := paasv1.ValidateID("tenantId", string(tenantID)); err != nil {
		return err
	}
	if err := operationqueue.ValidateLeaseGuard(guard); err != nil {
		return err
	}
	if guard.TenantID != tenantID {
		return errors.New("placement tenant and Operation lease tenant differ")
	}
	return mapTransactionError(
		"execute placement transaction",
		withinTenantTransaction(
			ctx,
			repository.pool,
			tenantID,
			pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite},
			func(tx pgx.Tx) error {
				return callback(ctx, &placementTransaction{
					tx: tx, tenantID: tenantID, leaseGuard: guard,
				})
			},
		),
	)
}

func withinTenantTransaction(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID paasv1.TenantID,
	options pgx.TxOptions,
	callback func(pgx.Tx) error,
) error {
	tx, err := pool.BeginTx(ctx, options)
	if err != nil {
		return fmt.Errorf("begin tenant transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return fmt.Errorf("set tenant transaction timezone: %w", err)
	}
	var configuredTenant string
	if err := tx.QueryRow(
		ctx,
		"SELECT set_config('matrix.tenant_id', $1, true)",
		string(tenantID),
	).Scan(&configuredTenant); err != nil {
		return fmt.Errorf("set tenant transaction context: %w", err)
	}
	var effectiveTenant string
	if err := tx.QueryRow(ctx, "SELECT paas.current_tenant_id()").Scan(&effectiveTenant); err != nil {
		return fmt.Errorf("verify tenant transaction context: %w", err)
	}
	if configuredTenant != string(tenantID) || effectiveTenant != string(tenantID) {
		return errors.New("PostgreSQL tenant context verification failed")
	}

	if err := callback(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant transaction: %w", err)
	}
	return nil
}

func mapTransactionError(action string, err error) error {
	if err == nil {
		return nil
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		if postgresError.Code == "MX412" {
			return fmt.Errorf("%s: %w", action, createplacement.ErrStaleLease)
		}
		if postgresError.Code == "40001" || postgresError.Code == "40P01" ||
			(postgresError.Code == "23505" &&
				postgresError.ConstraintName == "placement_decisions_operation_uq") {
			return fmt.Errorf(
				"%s: %w: PostgreSQL transaction conflict",
				action,
				createplacement.ErrRetryableTransaction,
			)
		}
	}
	return fmt.Errorf("%s: %w", action, err)
}
