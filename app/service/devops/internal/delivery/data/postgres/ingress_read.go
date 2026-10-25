package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func (repository *ControlPlaneRepository) ReadSourceConnection(
	ctx context.Context,
	scope devopsv1.ResourceScope,
	id devopsv1.ResourceID,
) (devopsv1.SourceConnection, bool, error) {
	if repository == nil || repository.pool == nil {
		return devopsv1.SourceConnection{}, false, errors.New("delivery control-plane repository is nil")
	}
	if ctx == nil {
		return devopsv1.SourceConnection{}, false, errors.New("source ingress read context is nil")
	}
	if err := errors.Join(
		devopsv1.ValidateResourceScope(scope),
		devopsv1.ValidateID("sourceConnectionId", string(id)),
	); err != nil {
		return devopsv1.SourceConnection{}, false, err
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return devopsv1.SourceConnection{}, false, fmt.Errorf("begin source ingress read: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var configuredTenant string
	if err := tx.QueryRow(
		ctx,
		"SELECT set_config('matrix.devops_tenant_id', $1, true)",
		string(scope.TenantID),
	).Scan(&configuredTenant); err != nil {
		return devopsv1.SourceConnection{}, false, fmt.Errorf("set source ingress tenant context: %w", err)
	}
	var effectiveTenant string
	if err := tx.QueryRow(ctx, "SELECT delivery.current_tenant_id()").Scan(&effectiveTenant); err != nil {
		return devopsv1.SourceConnection{}, false, fmt.Errorf("verify source ingress tenant context: %w", err)
	}
	if configuredTenant != string(scope.TenantID) || effectiveTenant != string(scope.TenantID) {
		return devopsv1.SourceConnection{}, false, errors.New("source ingress tenant context verification failed")
	}
	value, found, err := (&configurationTransaction{
		tx: tx, tenantID: scope.TenantID,
	}).LoadSourceConnection(ctx, id)
	if err != nil {
		return devopsv1.SourceConnection{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return devopsv1.SourceConnection{}, false, fmt.Errorf("commit source ingress read: %w", err)
	}
	return value, found, nil
}
