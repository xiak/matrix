package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	managedserviceadapterv1 "github.com/xiak/matrix/api/adapter/managedservice/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase/reconcileinstallation"
)

var _ reconcileinstallation.Queue = (*Repository)(nil)

func (repository *Repository) Claim(
	ctx context.Context,
	workerID string,
	leaseDuration time.Duration,
) (reconcileinstallation.WorkItem, bool, error) {
	leaseSeconds, err := boundedSeconds(leaseDuration)
	if repository == nil || repository.pool == nil || ctx == nil ||
		managedservicev1.ValidateID("workerId", workerID) != nil || err != nil {
		return reconcileinstallation.WorkItem{}, false, reconcileinstallation.ErrQueueUnavailable
	}
	var result reconcileinstallation.WorkItem
	var fencingToken int64
	var attempt int32
	err = repository.pool.QueryRow(ctx, `
SELECT tenant_id, operation_id, installation_id, installation_name,
       offering_id, engine_version, quota_entitlement_id, region_id,
       quota_shape_id, fencing_token, attempt, created_at, observed_at
  FROM managedservice.claim_operation($1, $2)`, workerID, leaseSeconds).Scan(
		&result.TenantID, &result.OperationID,
		&result.Installation.ID, &result.Installation.Name,
		&result.Installation.OfferingID, &result.Installation.EngineVersion,
		&result.Installation.QuotaEntitlementID, &result.Installation.RegionID,
		&result.QuotaShapeID, &fencingToken, &attempt,
		&result.Installation.CreatedAt, &result.Installation.Operation.ObservedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return reconcileinstallation.WorkItem{}, false, nil
	}
	if err != nil || fencingToken < 1 || attempt < 1 {
		return reconcileinstallation.WorkItem{}, false, reconcileinstallation.ErrQueueUnavailable
	}
	result.FencingToken = uint64(fencingToken)
	result.Attempt = uint32(attempt)
	result.WorkerID = workerID
	result.Installation.Phase = managedservicev1.InstallationProvisioning
	result.Installation.Operation.ID = result.OperationID
	result.Installation.Operation.Phase = managedservicev1.InstallationProvisioning
	result.Installation.CreatedAt = normalizeTime(result.Installation.CreatedAt)
	result.Installation.Operation.ObservedAt = normalizeTime(result.Installation.Operation.ObservedAt)
	if managedservicev1.ValidateID("tenantId", result.TenantID) != nil ||
		managedservicev1.ValidateID("quotaShapeId", result.QuotaShapeID) != nil ||
		managedservicev1.ValidateServiceInstallation(result.Installation) != nil {
		return reconcileinstallation.WorkItem{}, false, reconcileinstallation.ErrQueueUnavailable
	}
	return result, true, nil
}

func (repository *Repository) Complete(
	ctx context.Context,
	work reconcileinstallation.WorkItem,
	result managedserviceadapterv1.ProvisionResult,
) error {
	if repository == nil || repository.pool == nil || ctx == nil || validateWork(work) != nil ||
		managedserviceadapterv1.ValidateProvisionResult(result) != nil {
		return reconcileinstallation.ErrQueueUnavailable
	}
	_, err := repository.pool.Exec(ctx, `
SELECT managedservice.complete_operation($1, $2, $3, $4, $5, $6)`,
		work.TenantID, work.OperationID, work.WorkerID,
		work.FencingToken, result.Endpoint, result.CredentialReference,
	)
	if err != nil {
		return reconcileinstallation.ErrQueueUnavailable
	}
	return nil
}

func (repository *Repository) Retry(
	ctx context.Context,
	work reconcileinstallation.WorkItem,
	delay time.Duration,
) error {
	delaySeconds, err := boundedSeconds(delay)
	if repository == nil || repository.pool == nil || ctx == nil || validateWork(work) != nil || err != nil {
		return reconcileinstallation.ErrQueueUnavailable
	}
	_, err = repository.pool.Exec(ctx, `
SELECT managedservice.retry_operation($1, $2, $3, $4, $5)`,
		work.TenantID, work.OperationID, work.WorkerID,
		work.FencingToken, delaySeconds,
	)
	if err != nil {
		return reconcileinstallation.ErrQueueUnavailable
	}
	return nil
}

func (repository *Repository) Fail(
	ctx context.Context,
	work reconcileinstallation.WorkItem,
	failureCode string,
) error {
	if repository == nil || repository.pool == nil || ctx == nil || validateWork(work) != nil ||
		failureCode == "" {
		return reconcileinstallation.ErrQueueUnavailable
	}
	_, err := repository.pool.Exec(ctx, `
SELECT managedservice.fail_operation($1, $2, $3, $4, $5)`,
		work.TenantID, work.OperationID, work.WorkerID,
		work.FencingToken, failureCode,
	)
	if err != nil {
		return reconcileinstallation.ErrQueueUnavailable
	}
	return nil
}

func validateWork(work reconcileinstallation.WorkItem) error {
	return errors.Join(
		managedservicev1.ValidateID("work.tenantId", work.TenantID),
		managedservicev1.ValidateID("work.operationId", work.OperationID),
		managedservicev1.ValidateID("work.workerId", work.WorkerID),
	)
}

func boundedSeconds(value time.Duration) (int32, error) {
	if value < time.Second || value > 5*time.Minute || value%time.Second != 0 {
		return 0, errors.New("managed-service duration is invalid")
	}
	return int32(value / time.Second), nil
}
