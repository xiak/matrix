package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
)

var _ port.EnrolledNodeConnectionReader = (*EnrolledNodeConnectionRepository)(nil)

// EnrolledNodeConnectionRepository exposes only the non-secret route committed
// with an accepted target. Every read is installation-scoped through forced
// RLS; controller and node private keys remain filesystem-owned input.
type EnrolledNodeConnectionRepository struct {
	pool *pgxpool.Pool
}

func NewEnrolledNodeConnectionRepository(pool *pgxpool.Pool) (*EnrolledNodeConnectionRepository, error) {
	if pool == nil {
		return nil, errors.New("enrolled node connection database pool is required")
	}
	return &EnrolledNodeConnectionRepository{pool: pool}, nil
}

func (repository *EnrolledNodeConnectionRepository) LoadEnrolledNodeConnection(
	ctx context.Context,
	installationID string,
	targetID paasv1.ResourceID,
) (port.EnrolledNodeConnection, bool, error) {
	if repository == nil || repository.pool == nil || ctx == nil ||
		paasv1.ValidateID("installationId", installationID) != nil ||
		paasv1.ValidateID("executionTargetId", string(targetID)) != nil {
		return port.EnrolledNodeConnection{}, false, errors.New("enrolled node connection read is invalid")
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return port.EnrolledNodeConnection{}, false, connectionReadError(ctx)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return port.EnrolledNodeConnection{}, false, connectionReadError(ctx)
	}
	var configuredInstallation string
	if err := tx.QueryRow(
		ctx,
		"SELECT set_config('matrix.installation_id', $1, true)",
		installationID,
	).Scan(&configuredInstallation); err != nil || configuredInstallation != installationID {
		return port.EnrolledNodeConnection{}, false, connectionReadError(ctx)
	}
	value := port.EnrolledNodeConnection{}
	err = tx.QueryRow(ctx, `SELECT installation_id, execution_target_id,
		controller_id, binding_ref, endpoint, identity_fingerprint, enabled
		FROM paas.enrolled_node_connections
		WHERE installation_id = $1 AND execution_target_id = $2`,
		installationID, targetID,
	).Scan(
		&value.InstallationID, &value.ExecutionTargetID,
		&value.ControllerID, &value.BindingRef, &value.Endpoint,
		&value.IdentityFingerprint, &value.Enabled,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return port.EnrolledNodeConnection{}, false, connectionReadError(ctx)
		}
		return port.EnrolledNodeConnection{}, false, nil
	}
	if err != nil || port.ValidateEnrolledNodeConnection(value) != nil ||
		value.InstallationID != installationID || value.ExecutionTargetID != targetID {
		return port.EnrolledNodeConnection{}, false, connectionReadError(ctx)
	}
	if err := tx.Commit(ctx); err != nil {
		return port.EnrolledNodeConnection{}, false, connectionReadError(ctx)
	}
	return value, true, nil
}

func connectionReadError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("enrolled node connection storage is unavailable")
}
