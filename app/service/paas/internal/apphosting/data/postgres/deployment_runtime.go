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
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/refreshdeploymentruntime"
)

var _ refreshdeploymentruntime.Repository = (*DeploymentRuntimeRepository)(nil)

type DeploymentRuntimeRepository struct {
	pool *pgxpool.Pool
}

func NewDeploymentRuntimeRepository(pool *pgxpool.Pool) (*DeploymentRuntimeRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &DeploymentRuntimeRepository{pool: pool}, nil
}

func (repository *DeploymentRuntimeRepository) Next(
	ctx context.Context,
	cursor refreshdeploymentruntime.Cursor,
) (refreshdeploymentruntime.Candidate, bool, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return refreshdeploymentruntime.Candidate{}, false, errors.New("Deployment runtime repository is unavailable")
	}
	var afterTenant, afterDeployment any
	if cursor.TenantID != "" || cursor.DeploymentID != "" {
		if paasv1.ValidateID("tenantId", string(cursor.TenantID)) != nil ||
			paasv1.ValidateID("deploymentId", string(cursor.DeploymentID)) != nil {
			return refreshdeploymentruntime.Candidate{}, false, errors.New("Deployment runtime cursor is invalid")
		}
		afterTenant, afterDeployment = string(cursor.TenantID), string(cursor.DeploymentID)
	}
	var value refreshdeploymentruntime.Candidate
	err := repository.pool.QueryRow(
		ctx,
		`SELECT tenant_id,
		        deployment_id,
		        deployment_generation,
		        application_revision_id,
		        execution_target_id,
		        placement_decision_id,
		        content_digest
		   FROM paas.next_deployment_runtime_candidate($1, $2)`,
		afterTenant,
		afterDeployment,
	).Scan(
		&value.TenantID,
		&value.DeploymentID,
		&value.Generation,
		&value.ApplicationRevisionID,
		&value.ExecutionTargetID,
		&value.PlacementDecisionID,
		&value.ContentDigest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return refreshdeploymentruntime.Candidate{}, false, nil
	}
	if err != nil {
		return refreshdeploymentruntime.Candidate{}, false, fmt.Errorf("select Deployment runtime candidate: %w", err)
	}
	return value, true, nil
}

func (repository *DeploymentRuntimeRepository) Store(
	ctx context.Context,
	tenantID paasv1.TenantID,
	placementDecisionID paasv1.ResourceID,
	observation paasv1.DeploymentRuntimeObservation,
	validUntil time.Time,
) (bool, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return false, errors.New("Deployment runtime repository is unavailable")
	}
	if paasv1.ValidateID("tenantId", string(tenantID)) != nil ||
		paasv1.ValidateID("placementDecisionId", string(placementDecisionID)) != nil ||
		paasv1.ValidateDeploymentRuntimeObservation(observation) != nil ||
		validUntil.Location() != time.UTC || !validUntil.After(observation.ObservedAt) {
		return false, errors.New("Deployment runtime snapshot is invalid")
	}
	document, err := json.Marshal(observation)
	if err != nil {
		return false, fmt.Errorf("encode Deployment runtime observation: %w", err)
	}
	var stored bool
	err = repository.pool.QueryRow(
		ctx,
		`SELECT paas.store_deployment_runtime_snapshot(
		    $1, $2, $3, $4, $5, $6, $7, $8, $9
		)`,
		string(tenantID),
		string(observation.DeploymentID),
		observation.Generation,
		string(observation.ApplicationRevisionID),
		string(observation.ExecutionTargetID),
		string(placementDecisionID),
		observation.ObservedAt,
		validUntil,
		document,
	).Scan(&stored)
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "MX409" {
			return false, fmt.Errorf(
				"store Deployment runtime snapshot: %w",
				refreshdeploymentruntime.ErrSnapshotRejected,
			)
		}
		return false, fmt.Errorf("store Deployment runtime snapshot: %w", err)
	}
	return stored, nil
}
