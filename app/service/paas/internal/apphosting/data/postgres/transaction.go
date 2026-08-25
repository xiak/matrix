package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/createplacement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
)

var _ createplacement.Transaction = (*placementTransaction)(nil)

type placementTransaction struct {
	tx         pgx.Tx
	tenantID   paasv1.TenantID
	leaseGuard operationqueue.LeaseGuard
}

func (transaction *placementTransaction) TransactionTime(ctx context.Context) (time.Time, error) {
	var value time.Time
	if err := transaction.tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&value); err != nil {
		return time.Time{}, fmt.Errorf("read PostgreSQL transaction time: %w", err)
	}
	return databaseTime(value), nil
}

func (transaction *placementTransaction) FindDecisionByOperation(
	ctx context.Context,
	operationID paasv1.OperationID,
) (createplacement.StoredDecision, bool, error) {
	if err := paasv1.ValidateID("operationId", string(operationID)); err != nil {
		return createplacement.StoredDecision{}, false, err
	}
	var requestDigest string
	var document []byte
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT request_digest, document
           FROM paas.placement_decisions
          WHERE tenant_id = $1
            AND operation_id = $2`,
		string(transaction.tenantID),
		string(operationID),
	).Scan(&requestDigest, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return createplacement.StoredDecision{}, false, nil
	}
	if err != nil {
		return createplacement.StoredDecision{}, false, fmt.Errorf("find placement decision replay: %w", err)
	}
	var decision paasv1.PlacementDecision
	if err := decodeDocument("PlacementDecision", document, &decision); err != nil {
		return createplacement.StoredDecision{}, false, err
	}
	if err := paasv1.ValidatePlacementDecision(decision); err != nil {
		return createplacement.StoredDecision{}, false, fmt.Errorf("validate stored PlacementDecision: %w", err)
	}
	if decision.Metadata.Scope.TenantID != transaction.tenantID {
		return createplacement.StoredDecision{}, false, errors.New("stored PlacementDecision tenant mismatch")
	}
	return createplacement.StoredDecision{
		RequestDigest: requestDigest,
		Decision:      decision,
	}, true, nil
}

func (transaction *placementTransaction) LoadAndLockSnapshot(
	ctx context.Context,
	deploymentID paasv1.ResourceID,
) (placement.Snapshot, error) {
	if err := paasv1.ValidateID("deploymentId", string(deploymentID)); err != nil {
		return placement.Snapshot{}, err
	}

	deployment, err := transaction.loadDeployment(ctx, deploymentID)
	if err != nil {
		return placement.Snapshot{}, err
	}
	revision, err := transaction.loadApplicationRevision(
		ctx,
		deployment.Spec.ApplicationRevisionID,
	)
	if err != nil {
		return placement.Snapshot{}, err
	}
	policy, err := transaction.loadPolicy(ctx, deployment.Spec.PlacementPolicyID)
	if err != nil {
		return placement.Snapshot{}, err
	}
	poolIDs := make([]string, len(policy.Spec.EligibleExecutionPoolIDs))
	for index, poolID := range policy.Spec.EligibleExecutionPoolIDs {
		poolIDs[index] = string(poolID)
	}
	pools, err := transaction.loadPools(ctx, poolIDs)
	if err != nil {
		return placement.Snapshot{}, err
	}
	lockedTargets, err := transaction.lockTargetAllocations(ctx, poolIDs)
	if err != nil {
		return placement.Snapshot{}, err
	}
	targets, err := transaction.loadTargets(ctx, poolIDs)
	if err != nil {
		return placement.Snapshot{}, err
	}
	targetIDs := make([]string, len(targets))
	for index, target := range targets {
		targetIDs[index] = string(target.Metadata.ID)
	}
	if !equalStrings(lockedTargets, targetIDs) {
		return placement.Snapshot{}, errors.New(
			"execution target inventory is missing a canonical allocation lock row",
		)
	}
	claims, err := transaction.loadCapacityClaims(ctx, targetIDs)
	if err != nil {
		return placement.Snapshot{}, err
	}
	return placement.Snapshot{
		Deployment:          deployment,
		ApplicationRevision: revision,
		Policy:              policy,
		Pools:               pools,
		Targets:             targets,
		CapacityClaims:      claims,
	}, nil
}

func (transaction *placementTransaction) loadDeployment(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.Deployment, error) {
	deployment, found, err := transaction.findDeployment(ctx, id)
	if err != nil {
		return paasv1.Deployment{}, err
	}
	if !found {
		return paasv1.Deployment{}, errors.New("deployment not found in tenant scope")
	}
	return deployment, nil
}

func (transaction *placementTransaction) findDeployment(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.Deployment, bool, error) {
	if err := paasv1.ValidateID("deploymentId", string(id)); err != nil {
		return paasv1.Deployment{}, false, err
	}
	var generation uint64
	var applicationRevisionID string
	var policyID string
	var resourceVersion uint64
	var document []byte
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT generation, application_revision_id, policy_id, resource_version, document
		   FROM paas.deployments
		  WHERE tenant_id = $1
		    AND id = $2`,
		string(transaction.tenantID),
		string(id),
	).Scan(&generation, &applicationRevisionID, &policyID, &resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.Deployment{}, false, nil
	}
	if err != nil {
		return paasv1.Deployment{}, false, fmt.Errorf("load Deployment: %w", err)
	}
	var deployment paasv1.Deployment
	if err := decodeDocument("Deployment", document, &deployment); err != nil {
		return paasv1.Deployment{}, false, err
	}
	if err := paasv1.ValidateDeployment(deployment); err != nil {
		return paasv1.Deployment{}, false, fmt.Errorf("validate stored Deployment: %w", err)
	}
	if deployment.Metadata.ID != id ||
		deployment.Metadata.Scope.TenantID != transaction.tenantID ||
		deployment.Generation != generation ||
		deployment.Metadata.ResourceVersion != resourceVersion ||
		string(deployment.Spec.ApplicationRevisionID) != applicationRevisionID ||
		string(deployment.Spec.PlacementPolicyID) != policyID {
		return paasv1.Deployment{}, false, errors.New("stored Deployment relational identity mismatch")
	}
	return deployment, true, nil
}

func (transaction *placementTransaction) loadApplicationRevision(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.ApplicationRevision, error) {
	revision, found, err := transaction.findApplicationRevision(ctx, id)
	if err != nil {
		return paasv1.ApplicationRevision{}, err
	}
	if !found {
		return paasv1.ApplicationRevision{}, errors.New(
			"application revision not found in tenant scope",
		)
	}
	return revision, nil
}

func (transaction *placementTransaction) findApplicationRevision(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.ApplicationRevision, bool, error) {
	if err := paasv1.ValidateID("applicationRevisionId", string(id)); err != nil {
		return paasv1.ApplicationRevision{}, false, err
	}
	var applicationID string
	var contentDigest string
	var resourceVersion uint64
	var document []byte
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT application_id, content_digest, resource_version, document
		   FROM paas.application_revisions
		  WHERE tenant_id = $1
		    AND id = $2`,
		string(transaction.tenantID),
		string(id),
	).Scan(&applicationID, &contentDigest, &resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.ApplicationRevision{}, false, nil
	}
	if err != nil {
		return paasv1.ApplicationRevision{}, false, fmt.Errorf("load ApplicationRevision: %w", err)
	}
	var revision paasv1.ApplicationRevision
	if err := decodeDocument("ApplicationRevision", document, &revision); err != nil {
		return paasv1.ApplicationRevision{}, false, err
	}
	if err := paasv1.ValidateApplicationRevision(revision); err != nil {
		return paasv1.ApplicationRevision{}, false, fmt.Errorf(
			"validate stored ApplicationRevision: %w",
			err,
		)
	}
	if revision.Metadata.ID != id ||
		revision.Metadata.Scope.TenantID != transaction.tenantID ||
		revision.Metadata.ResourceVersion != resourceVersion ||
		string(revision.Spec.ApplicationID) != applicationID ||
		revision.Spec.ContentDigest != contentDigest {
		return paasv1.ApplicationRevision{}, false, errors.New(
			"stored ApplicationRevision relational identity mismatch",
		)
	}
	return revision, true, nil
}

func (transaction *placementTransaction) loadPolicy(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.PlacementPolicy, error) {
	policy, found, err := transaction.findPolicy(ctx, id)
	if err != nil {
		return paasv1.PlacementPolicy{}, err
	}
	if !found {
		return paasv1.PlacementPolicy{}, errors.New("placement policy not found in tenant scope")
	}
	return policy, nil
}

func (transaction *placementTransaction) findPolicy(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.PlacementPolicy, bool, error) {
	if err := paasv1.ValidateID("placementPolicyId", string(id)); err != nil {
		return paasv1.PlacementPolicy{}, false, err
	}
	var resourceVersion uint64
	var document []byte
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT resource_version, document
           FROM paas.placement_policies
          WHERE tenant_id = $1
            AND id = $2`,
		string(transaction.tenantID),
		string(id),
	).Scan(&resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.PlacementPolicy{}, false, nil
	}
	if err != nil {
		return paasv1.PlacementPolicy{}, false, fmt.Errorf("load PlacementPolicy: %w", err)
	}
	var policy paasv1.PlacementPolicy
	if err := decodeDocument("PlacementPolicy", document, &policy); err != nil {
		return paasv1.PlacementPolicy{}, false, err
	}
	if err := paasv1.ValidatePlacementPolicy(policy); err != nil {
		return paasv1.PlacementPolicy{}, false, fmt.Errorf("validate stored PlacementPolicy: %w", err)
	}
	if policy.Metadata.ID != id ||
		policy.Metadata.Scope.TenantID != transaction.tenantID ||
		policy.Metadata.ResourceVersion != resourceVersion {
		return paasv1.PlacementPolicy{}, false, errors.New("stored PlacementPolicy relational identity mismatch")
	}
	return policy, true, nil
}

func (transaction *placementTransaction) loadPools(
	ctx context.Context,
	poolIDs []string,
) ([]paasv1.ExecutionPool, error) {
	rows, err := transaction.tx.Query(
		ctx,
		`SELECT id, resource_version, document
		   FROM paas.execution_pools
          WHERE id = ANY($1::text[])
          ORDER BY id COLLATE "C"`,
		poolIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("load ExecutionPools: %w", err)
	}
	defer rows.Close()
	pools := make([]paasv1.ExecutionPool, 0, len(poolIDs))
	for rows.Next() {
		var id string
		var resourceVersion uint64
		var document []byte
		if err := rows.Scan(&id, &resourceVersion, &document); err != nil {
			return nil, fmt.Errorf("scan ExecutionPool: %w", err)
		}
		var pool paasv1.ExecutionPool
		if err := decodeDocument("ExecutionPool", document, &pool); err != nil {
			return nil, err
		}
		if err := paasv1.ValidateExecutionPool(pool); err != nil {
			return nil, fmt.Errorf("validate stored ExecutionPool: %w", err)
		}
		if string(pool.Metadata.ID) != id || pool.Metadata.ResourceVersion != resourceVersion {
			return nil, errors.New("stored ExecutionPool relational identity mismatch")
		}
		pools = append(pools, pool)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ExecutionPools: %w", err)
	}
	if len(pools) != len(poolIDs) {
		return nil, errors.New("one or more policy ExecutionPools are missing")
	}
	return pools, nil
}

func (transaction *placementTransaction) lockTargetAllocations(
	ctx context.Context,
	poolIDs []string,
) ([]string, error) {
	rows, err := transaction.tx.Query(
		ctx,
		`WITH candidates AS MATERIALIZED (
		     SELECT allocation.execution_target_id
		       FROM paas.execution_target_allocations AS allocation
		       JOIN paas.execution_targets AS target
		         ON target.id = allocation.execution_target_id
		      WHERE target.execution_pool_id = ANY($1::text[])
		      ORDER BY allocation.execution_target_id COLLATE "C"
		      FOR UPDATE OF allocation
		 )
		 UPDATE paas.execution_target_allocations AS allocation
		    SET lock_version = allocation.lock_version + 1
		   FROM candidates
		  WHERE allocation.execution_target_id = candidates.execution_target_id
	  RETURNING allocation.execution_target_id`,
		poolIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("lock execution target allocations: %w", err)
	}
	defer rows.Close()
	var targetIDs []string
	for rows.Next() {
		var targetID string
		if err := rows.Scan(&targetID); err != nil {
			return nil, fmt.Errorf("scan locked execution target allocation: %w", err)
		}
		targetIDs = append(targetIDs, targetID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate locked execution target allocations: %w", err)
	}
	sort.Strings(targetIDs)
	return targetIDs, nil
}

func (transaction *placementTransaction) loadTargets(
	ctx context.Context,
	poolIDs []string,
) ([]paasv1.ExecutionTarget, error) {
	rows, err := transaction.tx.Query(
		ctx,
		`SELECT id, execution_pool_id, resource_version, document
		   FROM paas.execution_targets
		  WHERE execution_pool_id = ANY($1::text[])
          ORDER BY id COLLATE "C"`,
		poolIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("load ExecutionTargets: %w", err)
	}
	defer rows.Close()
	var targets []paasv1.ExecutionTarget
	for rows.Next() {
		var id string
		var poolID string
		var resourceVersion uint64
		var document []byte
		if err := rows.Scan(&id, &poolID, &resourceVersion, &document); err != nil {
			return nil, fmt.Errorf("scan ExecutionTarget: %w", err)
		}
		var target paasv1.ExecutionTarget
		if err := decodeDocument("ExecutionTarget", document, &target); err != nil {
			return nil, err
		}
		if err := paasv1.ValidateExecutionTarget(target); err != nil {
			return nil, fmt.Errorf("validate stored ExecutionTarget: %w", err)
		}
		if string(target.Metadata.ID) != id ||
			string(target.Spec.ExecutionPoolID) != poolID ||
			target.Metadata.ResourceVersion != resourceVersion {
			return nil, errors.New("stored ExecutionTarget relational identity mismatch")
		}
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ExecutionTargets: %w", err)
	}
	return targets, nil
}

func (transaction *placementTransaction) loadCapacityClaims(
	ctx context.Context,
	targetIDs []string,
) ([]placement.CapacityClaim, error) {
	if len(targetIDs) == 0 {
		return nil, nil
	}
	rows, err := transaction.tx.Query(
		ctx,
		`SELECT id::text,
		        execution_target_id,
                isolation,
                cpu_millis,
                memory_bytes,
                workload_slots,
                state,
                lease_expires_at,
                resource_version
           FROM paas.capacity_claims
		  WHERE execution_target_id = ANY($1::text[])
            AND (
                state = 'ACTIVE'
                OR (state = 'PENDING' AND lease_expires_at > transaction_timestamp())
            )
		  ORDER BY execution_target_id COLLATE "C", id`,
		targetIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("load capacity claims: %w", err)
	}
	defer rows.Close()
	var claims []placement.CapacityClaim
	for rows.Next() {
		var claim placement.CapacityClaim
		var claimID string
		var targetID string
		var isolation string
		var state string
		var leaseExpiresAt *time.Time
		if err := rows.Scan(
			&claimID,
			&targetID,
			&isolation,
			&claim.Resources.CPUMillis,
			&claim.Resources.MemoryBytes,
			&claim.Resources.WorkloadSlots,
			&state,
			&leaseExpiresAt,
			&claim.ResourceVersion,
		); err != nil {
			return nil, fmt.Errorf("scan capacity claim: %w", err)
		}
		claim.ID = paasv1.ResourceID(claimID)
		claim.ExecutionTargetID = paasv1.ResourceID(targetID)
		claim.Isolation = paasv1.IsolationGuarantee(isolation)
		claim.State = placement.CapacityClaimState(state)
		if leaseExpiresAt != nil {
			claim.LeaseExpiresAt = databaseTime(*leaseExpiresAt)
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate capacity claims: %w", err)
	}
	return claims, nil
}

func databaseTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
