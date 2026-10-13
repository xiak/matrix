package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase"
)

type transaction struct {
	tx pgx.Tx
}

type scanner interface {
	Scan(...any) error
}

const serviceActivationColumns = `service_id, service_revision, service_digest,
       resource_version, activated_at`

const quotaColumns = `id, offering_id, quota_shape_id, purchased_count,
       reserved_count, consumed_count, resource_version, activated_at`

const installationColumns = `installation.id, installation.name,
       installation.offering_id, installation.engine_version,
       installation.quota_entitlement_id, installation.region_id,
       installation.phase, installation.endpoint,
       installation.credential_reference, installation.resource_version,
       installation.created_at,
       operation.id, operation.kind, operation.phase, operation.safe_failure_code,
       operation.observed_at`

func (value *transaction) ListCommandResults(
	ctx context.Context,
	read usecase.CommandResultRead,
) ([]managedservicev1.CommandResult, error) {
	if managedservicev1.ValidateCommandType(read.CommandType) != nil ||
		(read.Subject.Type != port.SubjectUser && read.Subject.Type != port.SubjectRole) ||
		read.RetentionSeconds < 1 || read.RetentionSeconds > 30*24*60*60 {
		return nil, usecase.ErrInvalidArgument
	}
	sourceUser, sourceService := "", ""
	if read.Subject.RoleSession != nil {
		sourceUser = read.Subject.RoleSession.SourceUserID
		sourceService = read.Subject.RoleSession.SourceServicePrincipalID
	}
	rows, err := value.tx.Query(ctx, `
SELECT idempotency_key, request_digest, target_id,
       operation_id, operation_kind, operation_phase,
       operation_safe_failure_code, operation_observed_at, completed_at
  FROM managedservice.list_command_results($1, $2, $3, $4, $5, $6, $7)`,
		read.CommandType, read.Subject.Type, read.Subject.ID, sourceUser, sourceService,
		read.RetentionSeconds, managedservicev1.MaxCommandResultItems,
	)
	if err != nil {
		return nil, databaseError(ctx, err)
	}
	defer rows.Close()
	results := make([]managedservicev1.CommandResult, 0)
	for rows.Next() {
		var idempotencyKey, digest, targetID string
		var operationID, operationKind, operationPhase, safeFailureCode *string
		var operationObservedAt, completedAt *time.Time
		if err := rows.Scan(&idempotencyKey, &digest, &targetID, &operationID, &operationKind,
			&operationPhase, &safeFailureCode, &operationObservedAt, &completedAt); err != nil {
			return nil, databaseError(ctx, err)
		}
		result := managedservicev1.CommandResult{
			Kind: "ManagedServiceCommandResult", IdempotencyKey: idempotencyKey,
			CommandType: read.CommandType, InputDigest: digest,
			Target: managedservicev1.CommandTargetReference{ID: targetID},
		}
		if completedAt != nil {
			normalized := normalizeTime(*completedAt)
			result.CompletedAt = &normalized
		}
		switch read.CommandType {
		case managedservicev1.CommandQuotaActivate:
			if operationID != nil || operationKind != nil || operationPhase != nil ||
				safeFailureCode != nil || operationObservedAt != nil || completedAt == nil {
				return nil, usecase.ErrRepositoryUnavailable
			}
			result.State = managedservicev1.CommandSucceeded
			result.Target.Kind = managedservicev1.CommandTargetQuotaEntitlement
		case managedservicev1.CommandInstallationCreate, managedservicev1.CommandInstallationTerminate:
			if operationID == nil || operationKind == nil || operationPhase == nil || operationObservedAt == nil {
				return nil, usecase.ErrRepositoryUnavailable
			}
			operation := managedservicev1.InstallationOperation{
				ID: *operationID, Kind: managedservicev1.InstallationOperationKind(*operationKind),
				Phase: managedservicev1.InstallationPhase(*operationPhase), SafeFailureCode: safeFailureCode,
				ObservedAt: normalizeTime(*operationObservedAt),
			}
			result.State = commandResultState(operation)
			result.Target.Kind = managedservicev1.CommandTargetServiceInstallation
			result.Operation = &operation
			if (result.State == managedservicev1.CommandInProgress) != (completedAt == nil) ||
				(completedAt != nil && !result.CompletedAt.Equal(operation.ObservedAt)) {
				return nil, usecase.ErrRepositoryUnavailable
			}
		default:
			return nil, usecase.ErrInvalidArgument
		}
		if managedservicev1.ValidateCommandResult(result) != nil {
			return nil, usecase.ErrRepositoryUnavailable
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError(ctx, err)
	}
	return results, nil
}

func commandResultState(operation managedservicev1.InstallationOperation) managedservicev1.CommandState {
	switch operation.Phase {
	case managedservicev1.InstallationPending, managedservicev1.InstallationProvisioning:
		return managedservicev1.CommandInProgress
	case managedservicev1.InstallationReady:
		return managedservicev1.CommandSucceeded
	case managedservicev1.InstallationFailed:
		return managedservicev1.CommandFailed
	default:
		return ""
	}
}

func (value *transaction) ListServiceActivations(
	ctx context.Context,
) ([]managedservicev1.ServiceActivation, error) {
	rows, err := value.tx.Query(ctx, `
SELECT `+serviceActivationColumns+`
  FROM managedservice.service_activations
 ORDER BY activated_at DESC, service_id COLLATE "C"`)
	if err != nil {
		return nil, databaseError(ctx, err)
	}
	defer rows.Close()
	result := make([]managedservicev1.ServiceActivation, 0)
	for rows.Next() {
		item, scanErr := scanServiceActivation(rows)
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

func (value *transaction) GetServiceActivation(
	ctx context.Context,
	serviceID string,
) (managedservicev1.ServiceActivation, error) {
	item, err := scanServiceActivation(value.tx.QueryRow(ctx, `
SELECT `+serviceActivationColumns+`
  FROM managedservice.service_activations
 WHERE service_id = $1`, serviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return managedservicev1.ServiceActivation{}, usecase.ErrNotFound
	}
	if err != nil {
		return managedservicev1.ServiceActivation{}, databaseError(ctx, err)
	}
	return item, nil
}

func (value *transaction) FindServiceActivationReplay(
	ctx context.Context,
	idempotencyKey string,
) (managedservicev1.ServiceActivation, string, bool, error) {
	row := value.tx.QueryRow(ctx, `
SELECT `+serviceActivationColumns+`, request_digest
  FROM managedservice.service_activations
 WHERE idempotency_key = $1`, idempotencyKey)
	item, digest, err := scanServiceActivationWithDigest(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return managedservicev1.ServiceActivation{}, "", false, nil
	}
	if err != nil {
		return managedservicev1.ServiceActivation{}, "", false, databaseError(ctx, err)
	}
	return item, digest, true, nil
}

func (value *transaction) InsertServiceActivation(
	ctx context.Context,
	draft usecase.ServiceActivationDraft,
) (managedservicev1.ServiceActivation, error) {
	row := value.tx.QueryRow(ctx, `
INSERT INTO managedservice.service_activations (
    tenant_id, service_id, service_revision, service_digest,
    idempotency_key, request_digest, activated_by_type, activated_by_id,
    iam_decision_id, request_id
) VALUES (
    managedservice.current_tenant_id(), $1, $2, $3,
    $4, $5, $6, $7, $8, $9
)
RETURNING `+serviceActivationColumns,
		draft.Service.ID, draft.Service.Revision, draft.Service.ContentDigest,
		draft.IdempotencyKey, draft.RequestDigest, draft.ActorType, draft.ActorID,
		draft.IAMDecisionID, draft.RequestID,
	)
	item, err := scanServiceActivation(row)
	if err != nil {
		return managedservicev1.ServiceActivation{}, databaseError(ctx, err)
	}
	return item, nil
}

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
SELECT `+installationColumns+`,
       CASE WHEN requested.kind = 'PROVISION' THEN requested.request_digest ELSE '' END
  FROM managedservice.operations AS requested
  JOIN managedservice.service_installations AS installation
    ON installation.tenant_id = requested.tenant_id
   AND installation.id = requested.installation_id
  JOIN managedservice.operations AS operation
    ON operation.tenant_id = installation.tenant_id
   AND operation.id = installation.current_operation_id
 WHERE requested.idempotency_key = $1`, idempotencyKey)
	item, digest, err := scanInstallationWithDigest(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return managedservicev1.ServiceInstallation{}, "", false, nil
	}
	if err != nil {
		return managedservicev1.ServiceInstallation{}, "", false, databaseError(ctx, err)
	}
	return item, digest, true, nil
}

func (value *transaction) FindTerminationReplay(
	ctx context.Context,
	idempotencyKey string,
) (managedservicev1.ServiceInstallation, string, bool, error) {
	row := value.tx.QueryRow(ctx, `
SELECT `+installationColumns+`,
       CASE WHEN requested.kind = 'TERMINATE' THEN requested.request_digest ELSE '' END
  FROM managedservice.operations AS requested
  JOIN managedservice.service_installations AS installation
    ON installation.tenant_id = requested.tenant_id
   AND installation.id = requested.installation_id
  JOIN managedservice.operations AS operation
    ON operation.tenant_id = installation.tenant_id
   AND operation.id = installation.current_operation_id
 WHERE requested.idempotency_key = $1`, idempotencyKey)
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
	var resourceVersion uint64
	err = value.tx.QueryRow(ctx, `
INSERT INTO managedservice.service_installations (
    tenant_id, id, name, offering_id, engine_version,
    quota_entitlement_id, region_id, current_operation_id
) VALUES (
    managedservice.current_tenant_id(), $1, $2, $3, $4, $5, $6, $7
)
RETURNING created_at, observed_at, resource_version`,
		draft.ID, draft.Name, draft.OfferingID, draft.EngineVersion,
		draft.QuotaEntitlementID, draft.RegionID, draft.OperationID,
	).Scan(&createdAt, &observedAt, &resourceVersion)
	if err != nil {
		return managedservicev1.ServiceInstallation{}, databaseError(ctx, err)
	}
	err = value.tx.QueryRow(ctx, `
INSERT INTO managedservice.operations (
    tenant_id, id, installation_id, kind, quota_release,
    idempotency_key, request_digest,
    requested_by_type, requested_by_id, iam_decision_id, request_id
) VALUES (
    managedservice.current_tenant_id(), $1, $2, 'PROVISION', 'NONE',
    $3, $4, $5, $6, $7, $8
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
		ResourceVersion: resourceVersion, CreatedAt: normalizeTime(createdAt),
		Operation: managedservicev1.InstallationOperation{
			ID: draft.OperationID, Kind: managedservicev1.InstallationOperationProvision,
			Phase:      managedservicev1.InstallationPending,
			ObservedAt: normalizeTime(observedAt),
		},
	}
	if managedservicev1.ValidateServiceInstallation(result) != nil {
		return managedservicev1.ServiceInstallation{}, usecase.ErrRepositoryUnavailable
	}
	return result, nil
}

func (value *transaction) StartTermination(
	ctx context.Context,
	draft usecase.TerminationDraft,
) (managedservicev1.ServiceInstallation, error) {
	_, err := value.tx.Exec(ctx, `
SELECT managedservice.start_termination($1, $2, $3, $4, $5, $6, $7, $8)`,
		draft.InstallationID, draft.OperationID, draft.IdempotencyKey,
		draft.RequestDigest, draft.ActorType, draft.ActorID,
		draft.IAMDecisionID, draft.RequestID)
	if err != nil {
		return managedservicev1.ServiceInstallation{}, databaseError(ctx, err)
	}
	return value.GetServiceInstallation(ctx, draft.InstallationID)
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
   AND operation.id = installation.current_operation_id
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
   AND operation.id = installation.current_operation_id
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

func scanServiceActivation(row scanner) (managedservicev1.ServiceActivation, error) {
	var result managedservicev1.ServiceActivation
	err := row.Scan(
		&result.Service.ID, &result.Service.Revision, &result.Service.ContentDigest,
		&result.ResourceVersion, &result.ActivatedAt,
	)
	if err != nil {
		return managedservicev1.ServiceActivation{}, err
	}
	result.ActivatedAt = normalizeTime(result.ActivatedAt)
	if managedservicev1.ValidateServiceActivation(result) != nil {
		return managedservicev1.ServiceActivation{}, usecase.ErrRepositoryUnavailable
	}
	return result, nil
}

func scanServiceActivationWithDigest(row scanner) (managedservicev1.ServiceActivation, string, error) {
	var result managedservicev1.ServiceActivation
	var digest string
	err := row.Scan(
		&result.Service.ID, &result.Service.Revision, &result.Service.ContentDigest,
		&result.ResourceVersion, &result.ActivatedAt, &digest,
	)
	if err != nil {
		return managedservicev1.ServiceActivation{}, "", err
	}
	result.ActivatedAt = normalizeTime(result.ActivatedAt)
	if managedservicev1.ValidateServiceActivation(result) != nil {
		return managedservicev1.ServiceActivation{}, "", usecase.ErrRepositoryUnavailable
	}
	return result, digest, nil
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
		&result.Endpoint, &result.CredentialReference, &result.ResourceVersion,
		&result.CreatedAt,
		&result.Operation.ID, &result.Operation.Kind, &result.Operation.Phase,
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
