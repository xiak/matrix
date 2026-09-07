// Package postgres implements delivery-owned persistence boundaries.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
)

var (
	_ pipelineconfiguration.Repository  = (*ConfigurationRepository)(nil)
	_ pipelineconfiguration.Transaction = (*configurationTransaction)(nil)
)

// ConfigurationRepository owns the atomic API mutation boundary. Worker
// effects use the distinct matrix_devops_worker database role.
type ConfigurationRepository struct {
	pool *pgxpool.Pool
}

func NewConfigurationRepository(pool *pgxpool.Pool) (*ConfigurationRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &ConfigurationRepository{pool: pool}, nil
}

func (repository *ConfigurationRepository) WithinTransaction(
	ctx context.Context,
	tenantID devopsv1.TenantID,
	callback func(context.Context, pipelineconfiguration.Transaction) error,
) error {
	if repository == nil || repository.pool == nil {
		return errors.New("delivery configuration repository is nil")
	}
	if ctx == nil {
		return errors.New("delivery configuration transaction context is nil")
	}
	if callback == nil {
		return errors.New("delivery configuration transaction callback is required")
	}
	if err := devopsv1.ValidateID("tenantId", string(tenantID)); err != nil {
		return err
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return fmt.Errorf("begin delivery configuration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return fmt.Errorf("set delivery transaction timezone: %w", err)
	}
	var configuredTenant string
	if err := tx.QueryRow(
		ctx,
		"SELECT set_config('matrix.devops_tenant_id', $1, true)",
		string(tenantID),
	).Scan(&configuredTenant); err != nil {
		return fmt.Errorf("set delivery tenant context: %w", err)
	}
	var effectiveTenant string
	if err := tx.QueryRow(ctx, "SELECT delivery.current_tenant_id()").Scan(&effectiveTenant); err != nil {
		return fmt.Errorf("verify delivery tenant context: %w", err)
	}
	if configuredTenant != string(tenantID) || effectiveTenant != string(tenantID) {
		return errors.New("PostgreSQL delivery tenant context verification failed")
	}
	if err := callback(ctx, &configurationTransaction{tx: tx, tenantID: tenantID}); err != nil {
		return mapTransactionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapTransactionError(fmt.Errorf("commit delivery configuration transaction: %w", err))
	}
	return nil
}

func mapTransactionError(err error) error {
	if err == nil {
		return nil
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "MX409":
			return fmt.Errorf("execute delivery configuration transaction: %w", pipelineconfiguration.ErrResourceVersionConflict)
		case "40001", "40P01", "23505":
			return fmt.Errorf("execute delivery configuration transaction: %w", pipelineconfiguration.ErrRetryableTransaction)
		case "23503":
			return fmt.Errorf("execute delivery configuration transaction: %w", pipelineconfiguration.ErrPreconditionFailed)
		}
	}
	return fmt.Errorf("execute delivery configuration transaction: %w", err)
}

type configurationTransaction struct {
	tx       pgx.Tx
	tenantID devopsv1.TenantID
}
