package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func (transaction *applicationTransaction) ListDeployments(
	ctx context.Context,
	after paasv1.ResourceID,
	limit int,
) ([]paasv1.Deployment, paasv1.ResourceID, error) {
	if ctx == nil || limit < 1 || limit > paasv1.MaximumDeploymentListItems ||
		(after != "" && paasv1.ValidateID("after", string(after)) != nil) {
		return nil, "", errors.New("Deployment list query is invalid")
	}
	rows, err := transaction.tx.Query(
		ctx,
		`SELECT id, generation, application_revision_id, policy_id, resource_version, document
		   FROM paas.deployments
		  WHERE tenant_id = $1
		    AND ($2 = '' OR id > $2 COLLATE "C")
		  ORDER BY id COLLATE "C"
		  LIMIT $3`,
		string(transaction.tenantID),
		string(after),
		limit+1,
	)
	if err != nil {
		return nil, "", fmt.Errorf("list Deployments: %w", err)
	}
	defer rows.Close()
	items := make([]paasv1.Deployment, 0, limit+1)
	for rows.Next() {
		var (
			id                    string
			generation            uint64
			applicationRevisionID string
			policyID              string
			resourceVersion       uint64
			document              []byte
		)
		if err := rows.Scan(
			&id,
			&generation,
			&applicationRevisionID,
			&policyID,
			&resourceVersion,
			&document,
		); err != nil {
			return nil, "", fmt.Errorf("scan Deployment list: %w", err)
		}
		var deployment paasv1.Deployment
		if err := decodeDocument("Deployment", document, &deployment); err != nil {
			return nil, "", err
		}
		if paasv1.ValidateDeployment(deployment) != nil ||
			string(deployment.Metadata.ID) != id ||
			deployment.Metadata.Scope.TenantID != transaction.tenantID ||
			deployment.Generation != generation ||
			deployment.Metadata.ResourceVersion != resourceVersion ||
			string(deployment.Spec.ApplicationRevisionID) != applicationRevisionID ||
			string(deployment.Spec.PlacementPolicyID) != policyID {
			return nil, "", errors.New("stored Deployment list identity mismatch")
		}
		items = append(items, deployment)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate Deployment list: %w", err)
	}
	nextAfter := paasv1.ResourceID("")
	if len(items) > limit {
		items = items[:limit]
		nextAfter = items[len(items)-1].Metadata.ID
	}
	return items, nextAfter, nil
}

func (transaction *applicationTransaction) LoadDeploymentRuntime(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.DeploymentRuntimeSnapshot, bool, error) {
	deployment, found, err := transaction.findDeployment(ctx, id)
	if err != nil || !found {
		return paasv1.DeploymentRuntimeSnapshot{}, found, err
	}
	base := paasv1.DeploymentRuntimeSnapshot{
		APIVersion: paasv1.APIVersion,
		Kind:       "DeploymentRuntimeSnapshot",
		Scope:      deployment.Metadata.Scope,
		State:      paasv1.MeasurementUnavailable,
		Resources:  paasv1.DeploymentResourceSnapshot{State: paasv1.MeasurementUnavailable},
	}
	if deployment.Spec.DesiredState != paasv1.DeploymentDesiredRunning ||
		deployment.Status.PlacementDecisionID == "" {
		return base, true, nil
	}
	var (
		generation            uint64
		applicationRevisionID string
		executionTargetID     string
		observedAt            time.Time
		validUntil            time.Time
		document              []byte
	)
	err = transaction.tx.QueryRow(
		ctx,
		`SELECT snapshot.deployment_generation,
		        snapshot.application_revision_id,
		        snapshot.execution_target_id,
		        snapshot.observed_at,
		        snapshot.valid_until,
		        snapshot.document
		   FROM paas.deployment_runtime_snapshots AS snapshot
		  WHERE snapshot.tenant_id = $1
		    AND snapshot.deployment_id = $2
		    AND snapshot.placement_decision_id = $3
		    AND snapshot.deployment_generation = $4
		    AND snapshot.application_revision_id = $5`,
		string(transaction.tenantID),
		string(id),
		string(deployment.Status.PlacementDecisionID),
		deployment.Generation,
		string(deployment.Spec.ApplicationRevisionID),
	).Scan(
		&generation,
		&applicationRevisionID,
		&executionTargetID,
		&observedAt,
		&validUntil,
		&document,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return base, true, nil
	}
	if err != nil {
		return paasv1.DeploymentRuntimeSnapshot{}, false, fmt.Errorf("load Deployment runtime: %w", err)
	}
	var observation paasv1.DeploymentRuntimeObservation
	if err := decodeDocument("DeploymentRuntimeObservation", document, &observation); err != nil {
		return paasv1.DeploymentRuntimeSnapshot{}, false, err
	}
	if paasv1.ValidateDeploymentRuntimeObservation(observation) != nil ||
		observation.DeploymentID != deployment.Metadata.ID ||
		observation.Generation != generation || generation != deployment.Generation ||
		string(observation.ApplicationRevisionID) != applicationRevisionID ||
		observation.ApplicationRevisionID != deployment.Spec.ApplicationRevisionID ||
		string(observation.ExecutionTargetID) != executionTargetID ||
		!observation.ObservedAt.Equal(databaseTime(observedAt)) {
		return paasv1.DeploymentRuntimeSnapshot{}, false, errors.New("stored Deployment runtime identity mismatch")
	}
	base.State = paasv1.MeasurementAvailable
	base.Value = &paasv1.DeploymentRuntimeValue{
		Observation: observation,
		ValidUntil:  databaseTime(validUntil),
	}
	resourceObservation, resourceValidUntil, found, err := transaction.loadDeploymentResources(
		ctx,
		deployment,
		observation,
	)
	if err != nil {
		return paasv1.DeploymentRuntimeSnapshot{}, false, err
	}
	if found {
		base.Resources = paasv1.DeploymentResourceSnapshot{
			State: paasv1.MeasurementAvailable,
			Value: &paasv1.DeploymentResourceValue{
				Observation: resourceObservation,
				ValidUntil:  resourceValidUntil,
			},
		}
	}
	now, err := transaction.TransactionTime(ctx)
	if err != nil {
		return paasv1.DeploymentRuntimeSnapshot{}, false, err
	}
	base = base.Snapshot(now)
	if paasv1.ValidateDeploymentRuntimeSnapshot(base) != nil {
		return paasv1.DeploymentRuntimeSnapshot{}, false, errors.New("stored Deployment runtime snapshot is invalid")
	}
	return base, true, nil
}

func (transaction *applicationTransaction) loadDeploymentResources(
	ctx context.Context,
	deployment paasv1.Deployment,
	runtime paasv1.DeploymentRuntimeObservation,
) (paasv1.DeploymentResourceObservation, time.Time, bool, error) {
	var (
		generation            uint64
		applicationRevisionID string
		executionTargetID     string
		observedAt            time.Time
		validUntil            time.Time
		document              []byte
	)
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT snapshot.deployment_generation,
		        snapshot.application_revision_id,
		        snapshot.execution_target_id,
		        snapshot.observed_at,
		        snapshot.valid_until,
		        snapshot.document
		   FROM paas.deployment_resource_snapshots AS snapshot
		  WHERE snapshot.tenant_id = $1
		    AND snapshot.deployment_id = $2
		    AND snapshot.placement_decision_id = $3
		    AND snapshot.deployment_generation = $4
		    AND snapshot.application_revision_id = $5
		    AND snapshot.execution_target_id = $6`,
		string(transaction.tenantID),
		string(deployment.Metadata.ID),
		string(deployment.Status.PlacementDecisionID),
		deployment.Generation,
		string(deployment.Spec.ApplicationRevisionID),
		string(runtime.ExecutionTargetID),
	).Scan(
		&generation,
		&applicationRevisionID,
		&executionTargetID,
		&observedAt,
		&validUntil,
		&document,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.DeploymentResourceObservation{}, time.Time{}, false, nil
	}
	if err != nil {
		return paasv1.DeploymentResourceObservation{}, time.Time{}, false,
			fmt.Errorf("load Deployment resources: %w", err)
	}
	var observation paasv1.DeploymentResourceObservation
	if err := decodeDocument("DeploymentResourceObservation", document, &observation); err != nil {
		return paasv1.DeploymentResourceObservation{}, time.Time{}, false, err
	}
	if paasv1.ValidateDeploymentResourceObservation(observation) != nil ||
		observation.DeploymentID != deployment.Metadata.ID ||
		observation.DeploymentID != runtime.DeploymentID ||
		observation.Generation != generation || generation != deployment.Generation ||
		observation.Generation != runtime.Generation ||
		string(observation.ApplicationRevisionID) != applicationRevisionID ||
		observation.ApplicationRevisionID != deployment.Spec.ApplicationRevisionID ||
		observation.ApplicationRevisionID != runtime.ApplicationRevisionID ||
		string(observation.ExecutionTargetID) != executionTargetID ||
		observation.ExecutionTargetID != runtime.ExecutionTargetID ||
		!observation.ObservedAt.Equal(databaseTime(observedAt)) ||
		!sameDeploymentInstanceIDs(runtime.Instances, observation.Instances) {
		return paasv1.DeploymentResourceObservation{}, time.Time{}, false,
			errors.New("stored Deployment resource identity mismatch")
	}
	return observation, databaseTime(validUntil), true, nil
}

func sameDeploymentInstanceIDs(
	runtime []paasv1.DeploymentRuntimeInstance,
	resources []paasv1.DeploymentResourceInstance,
) bool {
	if len(runtime) != len(resources) {
		return false
	}
	for index := range runtime {
		if runtime[index].ID != resources[index].ID {
			return false
		}
	}
	return true
}
