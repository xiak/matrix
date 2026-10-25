package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
)

func (repository *ControlPlaneRepository) WithinAdmissionTransaction(
	ctx context.Context,
	tenantID devopsv1.TenantID,
	callback func(context.Context, runadmission.Transaction) error,
) error {
	if repository == nil || repository.pool == nil {
		return errors.New("delivery control-plane repository is nil")
	}
	if ctx == nil {
		return errors.New("run admission transaction context is nil")
	}
	if callback == nil {
		return errors.New("run admission transaction callback is required")
	}
	if err := devopsv1.ValidateID("tenantId", string(tenantID)); err != nil {
		return err
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return fmt.Errorf("begin run admission transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return fmt.Errorf("set run admission transaction timezone: %w", err)
	}
	var configuredTenant string
	if err := tx.QueryRow(
		ctx,
		"SELECT set_config('matrix.devops_tenant_id', $1, true)",
		string(tenantID),
	).Scan(&configuredTenant); err != nil {
		return fmt.Errorf("set run admission tenant context: %w", err)
	}
	var effectiveTenant string
	if err := tx.QueryRow(ctx, "SELECT delivery.current_tenant_id()").Scan(&effectiveTenant); err != nil {
		return fmt.Errorf("verify run admission tenant context: %w", err)
	}
	if configuredTenant != string(tenantID) || effectiveTenant != string(tenantID) {
		return errors.New("PostgreSQL run admission tenant context verification failed")
	}
	admissionTx := &admissionTransaction{configurationTransaction: configurationTransaction{
		tx: tx, tenantID: tenantID,
	}}
	if err := callback(ctx, admissionTx); err != nil {
		return mapAdmissionTransactionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapAdmissionTransactionError(fmt.Errorf("commit run admission transaction: %w", err))
	}
	return nil
}

func mapAdmissionTransactionError(err error) error {
	if err == nil {
		return nil
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "MX429":
			return fmt.Errorf("execute run admission transaction: %w", runadmission.ErrQueueCapacityExceeded)
		case "40001", "40P01", "23505":
			return fmt.Errorf("execute run admission transaction: %w", runadmission.ErrRetryableTransaction)
		case "23503":
			return fmt.Errorf("execute run admission transaction: %w", runadmission.ErrPreconditionFailed)
		}
	}
	return fmt.Errorf("execute run admission transaction: %w", err)
}

type admissionTransaction struct {
	configurationTransaction
}
