package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase"
)

type transaction struct {
	tx pgx.Tx
}

type scanner interface {
	Scan(...any) error
}

const quotaColumns = `id, offering_id, quota_shape_id, purchased_count,
       reserved_count, consumed_count, resource_version, activated_at`

const installationColumns = `installation.id, installation.name,
       installation.offering_id, installation.engine_version,
       installation.quota_entitlement_id, installation.region_id,
       installation.phase, installation.endpoint,
       installation.credential_reference, installation.created_at,
       operation.id, operation.phase, operation.safe_failure_code,
       operation.observed_at`

func (value *transaction) ListQuotaEntitlements(
	ctx context.Context,
) ([]managedservicev1.QuotaEntitlement, error) {
	rows, err := value.tx.Query(ctx, `
SELECT `+quotaColumns+`
  FROM managedservice.quota_entitlements
 ORDER BY activated_at DESC, id COLLATE "C"`)
	if err != nil {
		return nil, databaseError(ctx, err)
	}
	defer rows.Close()
	result := make([]managedservicev1.QuotaEntitlement, 0)
	for rows.Next() {
		item, scanErr := scanQuota(rows)
		if scanErr != nil {
			return nil, databaseError(ctx, scanErr)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError(ctx, err)
	}
	return result, nil
}

func (value *transaction) GetQuotaEntitlement(
	ctx context.Context,
	id string,
) (managedservicev1.QuotaEntitlement, error) {
	item, err := scanQuota(value.tx.QueryRow(ctx, `
SELECT `+quotaColumns+`
  FROM managedservice.quota_entitlements
 WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return managedservicev1.QuotaEntitlement{}, usecase.ErrNotFound
	}
	if err != nil {
		return managedservicev1.QuotaEntitlement{}, databaseError(ctx, err)
	}
	return item, nil
}

func (value *transaction) FindQuotaReplay(
	ctx context.Context,
	idempotencyKey string,
) (managedservicev1.QuotaEntitlement, string, bool, error) {
	row := value.tx.QueryRow(ctx, `
SELECT `+quotaColumns+`, request_digest
  FROM managedservice.quota_entitlements
 WHERE idempotency_key = $1`, idempotencyKey)
	item, digest, err := scanQuotaWithDigest(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return managedservicev1.QuotaEntitlement{}, "", false, nil
	}
	if err != nil {
		return managedservicev1.QuotaEntitlement{}, "", false, databaseError(ctx, err)
	}
	return item, digest, true, nil
}

func (value *transaction) InsertQuotaEntitlement(
	ctx context.Context,
	draft usecase.QuotaDraft,
) (managedservicev1.QuotaEntitlement, error) {
	row := value.tx.QueryRow(ctx, `
INSERT INTO managedservice.quota_entitlements (
    tenant_id, id, offering_id, quota_shape_id, purchased_count,
    idempotency_key, request_digest, activated_by_type, activated_by_id,
    iam_decision_id, request_id
) VALUES (
    managedservice.current_tenant_id(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
RETURNING `+quotaColumns,
		draft.ID, draft.OfferingID, draft.QuotaShapeID, draft.PurchasedCount,
		draft.IdempotencyKey, draft.RequestDigest, draft.ActorType, draft.ActorID,
		draft.IAMDecisionID, draft.RequestID,
	)
	item, err := scanQuota(row)
	if err != nil {
		return managedservicev1.QuotaEntitlement{}, databaseError(ctx, err)
	}
	return item, nil
}

func (value *transaction) FindInstallationReplay(
	ctx context.Context,
	idempotencyKey string,
) (managedservicev1.ServiceInstallation, string, bool, error) {
	row := value.tx.QueryRow(ctx, `
SELECT `+installationColumns+`, operation.request_digest
  FROM managedservice.service_installations AS installation
  JOIN managedservice.operations AS operation
    ON operation.tenant_id = installation.tenant_id
   AND operation.installation_id = installation.id
 WHERE operation.idempotency_key = $1`, idempotencyKey)
	item, digest, err := scanInstallationWithDigest(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return managedservicev1.ServiceInstallation{}, "", false, nil
	}
	if err != nil {
		return managedservicev1.ServiceInstallation{}, "", false, databaseError(ctx, err)
	}
	return item, digest, true, nil
}

func (value *transaction) GetQuotaEntitlementForUpdate(
	ctx context.Context,
	id string,
) (managedservicev1.QuotaEntitlement, error) {
	item, err := scanQuota(value.tx.QueryRow(ctx, `
SELECT `+quotaColumns+`
  FROM managedservice.quota_entitlements
 WHERE id = $1
 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return managedservicev1.QuotaEntitlement{}, usecase.ErrNotFound
	}
	if err != nil {
		return managedservicev1.QuotaEntitlement{}, databaseError(ctx, err)
	}
	return item, nil
}

func (value *transaction) ReserveInstallation(
	ctx context.Context,
	draft usecase.InstallationDraft,
	expectedQuotaVersion uint64,
) (managedservicev1.ServiceInstallation, error) {
	tag, err := value.tx.Exec(ctx, `
UPDATE managedservice.quota_entitlements
   SET reserved_count = reserved_count + 1,
       resource_version = resource_version + 1
 WHERE id = $1
   AND resource_version = $2
   AND reserved_count + consumed_count < purchased_count`,
		draft.QuotaEntitlementID, expectedQuotaVersion,
	)
	if err != nil {
		return managedservicev1.ServiceInstallation{}, databaseError(ctx, err)
	}
	if tag.RowsAffected() != 1 {
		return managedservicev1.ServiceInstallation{}, usecase.ErrQuotaExhausted
	}
	var createdAt, observedAt time.Time
	err = value.tx.QueryRow(ctx, `
INSERT INTO managedservice.service_installations (
    tenant_id, id, name, offering_id, engine_version,
    quota_entitlement_id, region_id
) VALUES (
    managedservice.current_tenant_id(), $1, $2, $3, $4, $5, $6
)
RETURNING created_at, observed_at`,
		draft.ID, draft.Name, draft.OfferingID, draft.EngineVersion,
		draft.QuotaEntitlementID, draft.RegionID,
	).Scan(&createdAt, &observedAt)
	if err != nil {
		return managedservicev1.ServiceInstallation{}, databaseError(ctx, err)
	}
	err = value.tx.QueryRow(ctx, `
INSERT INTO managedservice.operations (
    tenant_id, id, installation_id, idempotency_key, request_digest,
    requested_by_type, requested_by_id, iam_decision_id, request_id
) VALUES (
    managedservice.current_tenant_id(), $1, $2, $3, $4, $5, $6, $7, $8
)
RETURNING observed_at`,
		draft.OperationID, draft.ID, draft.IdempotencyKey, draft.RequestDigest,
		draft.ActorType, draft.ActorID, draft.IAMDecisionID, draft.RequestID,
	).Scan(&observedAt)
	if err != nil {
		return managedservicev1.ServiceInstallation{}, databaseError(ctx, err)
	}
	result := managedservicev1.ServiceInstallation{
		ID: draft.ID, Name: draft.Name, OfferingID: draft.OfferingID,
		EngineVersion: draft.EngineVersion, QuotaEntitlementID: draft.QuotaEntitlementID,
		RegionID: draft.RegionID, Phase: managedservicev1.InstallationPending,
		CreatedAt: normalizeTime(createdAt),
		Operation: managedservicev1.InstallationOperation{
			ID: draft.OperationID, Phase: managedservicev1.InstallationPending,
			ObservedAt: normalizeTime(observedAt),
		},
	}
	if managedservicev1.ValidateServiceInstallation(result) != nil {
		return managedservicev1.ServiceInstallation{}, usecase.ErrRepositoryUnavailable
	}
	return result, nil
}

func (value *transaction) AppendAuditEvent(ctx context.Context, event audit.Event) error {
	if audit.ValidateEvent(event) != nil {
		return usecase.ErrRepositoryUnavailable
	}
	document, err := json.Marshal(event)
	if err != nil {
		return usecase.ErrRepositoryUnavailable
	}
	defer clear(document)
	if _, err := value.tx.Exec(
		ctx,
		`SELECT managedservice.append_audit_outbox($1::jsonb)`,
		document,
	); err != nil {
		return databaseError(ctx, err)
	}
	return nil
}

func (value *transaction) ListServiceInstallations(
	ctx context.Context,
) ([]managedservicev1.ServiceInstallation, error) {
	rows, err := value.tx.Query(ctx, `
SELECT `+installationColumns+`
  FROM managedservice.service_installations AS installation
  JOIN managedservice.operations AS operation
    ON operation.tenant_id = installation.tenant_id
   AND operation.installation_id = installation.id
 ORDER BY installation.created_at DESC, installation.id COLLATE "C"`)
	if err != nil {
		return nil, databaseError(ctx, err)
	}
	defer rows.Close()
	result := make([]managedservicev1.ServiceInstallation, 0)
	for rows.Next() {
		item, scanErr := scanInstallation(rows)
		if scanErr != nil {
			return nil, databaseError(ctx, scanErr)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError(ctx, err)
	}
	return result, nil
}

func (value *transaction) GetServiceInstallation(
	ctx context.Context,
	id string,
) (managedservicev1.ServiceInstallation, error) {
	item, err := scanInstallation(value.tx.QueryRow(ctx, `
SELECT `+installationColumns+`
  FROM managedservice.service_installations AS installation
  JOIN managedservice.operations AS operation
    ON operation.tenant_id = installation.tenant_id
   AND operation.installation_id = installation.id
 WHERE installation.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return managedservicev1.ServiceInstallation{}, usecase.ErrNotFound
	}
	if err != nil {
		return managedservicev1.ServiceInstallation{}, databaseError(ctx, err)
	}
	return item, nil
}

func (value *transaction) Commit(ctx context.Context) error {
	return databaseErrorIfPresent(ctx, value.tx.Commit(ctx))
}

func (value *transaction) Rollback(ctx context.Context) error {
	err := value.tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return databaseErrorIfPresent(ctx, err)
}

func scanQuota(row scanner) (managedservicev1.QuotaEntitlement, error) {
	var result managedservicev1.QuotaEntitlement
	var purchased, reserved, consumed int64
	err := row.Scan(
		&result.ID, &result.OfferingID, &result.QuotaShapeID,
		&purchased, &reserved, &consumed, &result.ResourceVersion, &result.ActivatedAt,
	)
	if err != nil {
		return managedservicev1.QuotaEntitlement{}, err
	}
	if purchased < 0 || reserved < 0 || consumed < 0 ||
		purchased > int64(^uint32(0)) || reserved > int64(^uint32(0)) || consumed > int64(^uint32(0)) {
		return managedservicev1.QuotaEntitlement{}, usecase.ErrRepositoryUnavailable
	}
	result.PurchasedCount = uint32(purchased)
	result.ReservedCount = uint32(reserved)
	result.ConsumedCount = uint32(consumed)
	result.ActivatedAt = normalizeTime(result.ActivatedAt)
	if managedservicev1.ValidateQuotaEntitlement(result) != nil {
		return managedservicev1.QuotaEntitlement{}, usecase.ErrRepositoryUnavailable
	}
	return result, nil
}

func scanQuotaWithDigest(row scanner) (managedservicev1.QuotaEntitlement, string, error) {
	var result managedservicev1.QuotaEntitlement
	var purchased, reserved, consumed int64
	var digest string
	err := row.Scan(
		&result.ID, &result.OfferingID, &result.QuotaShapeID,
		&purchased, &reserved, &consumed, &result.ResourceVersion, &result.ActivatedAt,
		&digest,
	)
	if err != nil {
		return managedservicev1.QuotaEntitlement{}, "", err
	}
	result.PurchasedCount = uint32(purchased)
	result.ReservedCount = uint32(reserved)
	result.ConsumedCount = uint32(consumed)
	result.ActivatedAt = normalizeTime(result.ActivatedAt)
	if managedservicev1.ValidateQuotaEntitlement(result) != nil {
		return managedservicev1.QuotaEntitlement{}, "", usecase.ErrRepositoryUnavailable
	}
	return result, digest, nil
}

func scanInstallation(row scanner) (managedservicev1.ServiceInstallation, error) {
	result, _, err := scanInstallationValues(row, false)
	return result, err
}

func scanInstallationWithDigest(row scanner) (managedservicev1.ServiceInstallation, string, error) {
	return scanInstallationValues(row, true)
}

func scanInstallationValues(
	row scanner,
	withDigest bool,
) (managedservicev1.ServiceInstallation, string, error) {
	var result managedservicev1.ServiceInstallation
	var digest string
	destinations := []any{
		&result.ID, &result.Name, &result.OfferingID, &result.EngineVersion,
		&result.QuotaEntitlementID, &result.RegionID, &result.Phase,
		&result.Endpoint, &result.CredentialReference, &result.CreatedAt,
		&result.Operation.ID, &result.Operation.Phase,
		&result.Operation.SafeFailureCode, &result.Operation.ObservedAt,
	}
	if withDigest {
		destinations = append(destinations, &digest)
	}
	if err := row.Scan(destinations...); err != nil {
		return managedservicev1.ServiceInstallation{}, "", err
	}
	result.CreatedAt = normalizeTime(result.CreatedAt)
	result.Operation.ObservedAt = normalizeTime(result.Operation.ObservedAt)
	if managedservicev1.ValidateServiceInstallation(result) != nil {
		return managedservicev1.ServiceInstallation{}, "", usecase.ErrRepositoryUnavailable
	}
	return result, digest, nil
}

func normalizeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func databaseErrorIfPresent(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	return databaseError(ctx, err)
}
