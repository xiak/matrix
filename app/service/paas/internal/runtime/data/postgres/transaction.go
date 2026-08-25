package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	paasv1 "matrix/api/paas/v1"
	"matrix/app/service/paas/internal/runtime/domain/placement"
	"matrix/app/service/paas/internal/runtime/usecase/createplacement"
)

var _ createplacement.Transaction = (*placementTransaction)(nil)

type placementTransaction struct {
	tx       pgx.Tx
	tenantID paasv1.TenantID
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
	releaseID paasv1.ResourceID,
	policyID paasv1.ResourceID,
) (placement.Snapshot, error) {
	if err := paasv1.ValidateID("workloadReleaseId", string(releaseID)); err != nil {
		return placement.Snapshot{}, err
	}
	if err := paasv1.ValidateID("placementPolicyId", string(policyID)); err != nil {
		return placement.Snapshot{}, err
	}

	release, err := transaction.loadRelease(ctx, releaseID)
	if err != nil {
		return placement.Snapshot{}, err
	}
	policy, err := transaction.loadPolicy(ctx, policyID)
	if err != nil {
		return placement.Snapshot{}, err
	}
	poolIDs := make([]string, len(policy.Spec.EligibleResourcePools))
	for index, poolID := range policy.Spec.EligibleResourcePools {
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
			"runtime target inventory is missing a canonical allocation lock row",
		)
	}
	claims, err := transaction.loadCapacityClaims(ctx, targetIDs)
	if err != nil {
		return placement.Snapshot{}, err
	}
	return placement.Snapshot{
		Release:        release,
		Policy:         policy,
		Pools:          pools,
		Targets:        targets,
		CapacityClaims: claims,
	}, nil
}

func (transaction *placementTransaction) loadRelease(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.WorkloadRelease, error) {
	var resourceVersion uint64
	var document []byte
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT resource_version, document
           FROM paas.tenant_releases
          WHERE tenant_id = $1
            AND id = $2`,
		string(transaction.tenantID),
		string(id),
	).Scan(&resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.WorkloadRelease{}, errors.New("workload release not found in tenant scope")
	}
	if err != nil {
		return paasv1.WorkloadRelease{}, fmt.Errorf("load WorkloadRelease: %w", err)
	}
	var release paasv1.WorkloadRelease
	if err := decodeDocument("WorkloadRelease", document, &release); err != nil {
		return paasv1.WorkloadRelease{}, err
	}
	if err := paasv1.ValidateWorkloadRelease(release); err != nil {
		return paasv1.WorkloadRelease{}, fmt.Errorf("validate stored WorkloadRelease: %w", err)
	}
	if release.Metadata.ID != id ||
		release.Metadata.Scope.TenantID != transaction.tenantID ||
		release.Metadata.ResourceVersion != resourceVersion {
		return paasv1.WorkloadRelease{}, errors.New("stored WorkloadRelease relational identity mismatch")
	}
	return release, nil
}

func (transaction *placementTransaction) loadPolicy(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.PlacementPolicy, error) {
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
		return paasv1.PlacementPolicy{}, errors.New("placement policy not found in tenant scope")
	}
	if err != nil {
		return paasv1.PlacementPolicy{}, fmt.Errorf("load PlacementPolicy: %w", err)
	}
	var policy paasv1.PlacementPolicy
	if err := decodeDocument("PlacementPolicy", document, &policy); err != nil {
		return paasv1.PlacementPolicy{}, err
	}
	if err := paasv1.ValidatePlacementPolicy(policy); err != nil {
		return paasv1.PlacementPolicy{}, fmt.Errorf("validate stored PlacementPolicy: %w", err)
	}
	if policy.Metadata.ID != id ||
		policy.Metadata.Scope.TenantID != transaction.tenantID ||
		policy.Metadata.ResourceVersion != resourceVersion {
		return paasv1.PlacementPolicy{}, errors.New("stored PlacementPolicy relational identity mismatch")
	}
	return policy, nil
}

func (transaction *placementTransaction) loadPools(
	ctx context.Context,
	poolIDs []string,
) ([]paasv1.ResourcePool, error) {
	rows, err := transaction.tx.Query(
		ctx,
		`SELECT id, resource_version, document
           FROM paas.resource_pools
          WHERE id = ANY($1::text[])
          ORDER BY id COLLATE "C"`,
		poolIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("load ResourcePools: %w", err)
	}
	defer rows.Close()
	pools := make([]paasv1.ResourcePool, 0, len(poolIDs))
	for rows.Next() {
		var id string
		var resourceVersion uint64
		var document []byte
		if err := rows.Scan(&id, &resourceVersion, &document); err != nil {
			return nil, fmt.Errorf("scan ResourcePool: %w", err)
		}
		var pool paasv1.ResourcePool
		if err := decodeDocument("ResourcePool", document, &pool); err != nil {
			return nil, err
		}
		if err := paasv1.ValidateResourcePool(pool); err != nil {
			return nil, fmt.Errorf("validate stored ResourcePool: %w", err)
		}
		if string(pool.Metadata.ID) != id || pool.Metadata.ResourceVersion != resourceVersion {
			return nil, errors.New("stored ResourcePool relational identity mismatch")
		}
		pools = append(pools, pool)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ResourcePools: %w", err)
	}
	if len(pools) != len(poolIDs) {
		return nil, errors.New("one or more policy ResourcePools are missing")
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
             SELECT allocation.target_id
               FROM paas.runtime_target_allocations AS allocation
               JOIN paas.runtime_targets AS target
                 ON target.id = allocation.target_id
              WHERE target.resource_pool_id = ANY($1::text[])
              ORDER BY allocation.target_id COLLATE "C"
              FOR UPDATE OF allocation
         )
         UPDATE paas.runtime_target_allocations AS allocation
            SET lock_version = allocation.lock_version + 1
           FROM candidates
          WHERE allocation.target_id = candidates.target_id
      RETURNING allocation.target_id`,
		poolIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("lock runtime target allocations: %w", err)
	}
	defer rows.Close()
	var targetIDs []string
	for rows.Next() {
		var targetID string
		if err := rows.Scan(&targetID); err != nil {
			return nil, fmt.Errorf("scan locked runtime target allocation: %w", err)
		}
		targetIDs = append(targetIDs, targetID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate locked runtime target allocations: %w", err)
	}
	sort.Strings(targetIDs)
	return targetIDs, nil
}

func (transaction *placementTransaction) loadTargets(
	ctx context.Context,
	poolIDs []string,
) ([]paasv1.RuntimeTarget, error) {
	rows, err := transaction.tx.Query(
		ctx,
		`SELECT id, resource_pool_id, resource_version, document
           FROM paas.runtime_targets
          WHERE resource_pool_id = ANY($1::text[])
          ORDER BY id COLLATE "C"`,
		poolIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("load RuntimeTargets: %w", err)
	}
	defer rows.Close()
	var targets []paasv1.RuntimeTarget
	for rows.Next() {
		var id string
		var poolID string
		var resourceVersion uint64
		var document []byte
		if err := rows.Scan(&id, &poolID, &resourceVersion, &document); err != nil {
			return nil, fmt.Errorf("scan RuntimeTarget: %w", err)
		}
		var target paasv1.RuntimeTarget
		if err := decodeDocument("RuntimeTarget", document, &target); err != nil {
			return nil, err
		}
		if err := paasv1.ValidateRuntimeTarget(target); err != nil {
			return nil, fmt.Errorf("validate stored RuntimeTarget: %w", err)
		}
		if string(target.Metadata.ID) != id ||
			string(target.Spec.ResourcePoolID) != poolID ||
			target.Metadata.ResourceVersion != resourceVersion {
			return nil, errors.New("stored RuntimeTarget relational identity mismatch")
		}
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate RuntimeTargets: %w", err)
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
                runtime_target_id,
                isolation,
                cpu_millis,
                memory_bytes,
                workload_slots,
                state,
                lease_expires_at,
                resource_version
           FROM paas.capacity_claims
          WHERE runtime_target_id = ANY($1::text[])
            AND (
                state = 'ACTIVE'
                OR (state = 'PENDING' AND lease_expires_at > transaction_timestamp())
            )
          ORDER BY runtime_target_id COLLATE "C", id`,
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
		claim.RuntimeTargetID = paasv1.ResourceID(targetID)
		claim.Isolation = paasv1.IsolationClass(isolation)
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
