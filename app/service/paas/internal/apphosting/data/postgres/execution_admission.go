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
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

var _ executionadmission.Repository = (*ExecutionAdmissionRepository)(nil)
var _ executionadmission.Transaction = (*executionAdmissionTransaction)(nil)

type ExecutionAdmissionRepository struct{ pool *pgxpool.Pool }

func NewExecutionAdmissionRepository(pool *pgxpool.Pool) (*ExecutionAdmissionRepository, error) {
	if pool == nil {
		return nil, errors.New("execution admission database pool is required")
	}
	return &ExecutionAdmissionRepository{pool: pool}, nil
}

func (repository *ExecutionAdmissionRepository) WithinTransaction(ctx context.Context, installationID string, callback func(context.Context, executionadmission.Transaction) error) error {
	if repository == nil || repository.pool == nil || ctx == nil || callback == nil || paasv1.ValidateID("installationId", installationID) != nil {
		return errors.New("execution admission transaction input is invalid")
	}
	err := func() error {
		tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT set_config('matrix.installation_id', $1, true)", installationID); err != nil {
			return err
		}
		var effectiveInstallation string
		if err := tx.QueryRow(ctx, "SELECT paas.current_installation_id()").Scan(&effectiveInstallation); err != nil || effectiveInstallation != installationID {
			return errors.New("execution admission authority context is invalid")
		}
		if err := callback(ctx, &executionAdmissionTransaction{tx: tx, installationID: installationID}); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}()
	if err == nil {
		return nil
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "40001", "40P01":
			return executionadmission.ErrRetryableTransaction
		case "23505":
			return errors.Join(executionadmission.ErrRetryableTransaction, executionadmission.ErrConflict)
		case "23503", "MX409":
			return executionadmission.ErrConflict
		case "MX404":
			return executionadmission.ErrNotFound
		case "22023", "23514":
			return executionadmission.ErrInvalidArgument
		}
	}
	return fmt.Errorf("execution admission transaction: %w", err)
}

type executionAdmissionTransaction struct {
	tx             pgx.Tx
	installationID string
}

func (transaction *executionAdmissionTransaction) TransactionTime(ctx context.Context) (time.Time, error) {
	var now time.Time
	err := transaction.tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now)
	return databaseTime(now), err
}

func (transaction *executionAdmissionTransaction) FindOperationByFingerprint(ctx context.Context, fingerprint string) (paasv1.Operation, bool, error) {
	if paasv1.ValidateDigest("idempotencyFingerprint", fingerprint) != nil {
		return paasv1.Operation{}, false, executionadmission.ErrInvalidArgument
	}
	return transaction.loadOperation(ctx, "idempotency_fingerprint", fingerprint)
}

func (transaction *executionAdmissionTransaction) LoadOperation(ctx context.Context, id paasv1.OperationID) (paasv1.Operation, bool, error) {
	if paasv1.ValidateID("operationId", string(id)) != nil {
		return paasv1.Operation{}, false, executionadmission.ErrInvalidArgument
	}
	return transaction.loadOperation(ctx, "id", string(id))
}

func (transaction *executionAdmissionTransaction) loadOperation(ctx context.Context, column, selector string) (paasv1.Operation, bool, error) {
	if column != "id" && column != "idempotency_fingerprint" {
		return paasv1.Operation{}, false, executionadmission.ErrInvalidArgument
	}
	var id, fingerprint string
	var document []byte
	err := transaction.tx.QueryRow(ctx, `SELECT id, idempotency_fingerprint, document FROM paas.operations
		WHERE authority_key = 'installation:' || $1 AND `+column+` = $2`, transaction.installationID, selector).Scan(&id, &fingerprint, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.Operation{}, false, nil
	}
	if err != nil {
		return paasv1.Operation{}, false, err
	}
	var value paasv1.Operation
	if decodeDocument("Operation", document, &value) != nil || paasv1.ValidateOperation(value) != nil || value.InstallationID != transaction.installationID ||
		string(value.ID) != id || value.IdempotencyFingerprint != fingerprint {
		return paasv1.Operation{}, false, errors.New("stored installation Operation is invalid")
	}
	return value, true, nil
}

func (transaction *executionAdmissionTransaction) LoadPool(ctx context.Context, id paasv1.ResourceID) (paasv1.ExecutionPool, bool, error) {
	var version uint64
	var document []byte
	err := transaction.tx.QueryRow(ctx, `SELECT resource_version, document FROM paas.execution_pools WHERE installation_id = $1 AND id = $2`, transaction.installationID, id).Scan(&version, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.ExecutionPool{}, false, nil
	}
	if err != nil {
		return paasv1.ExecutionPool{}, false, err
	}
	var value paasv1.ExecutionPool
	if decodeDocument("ExecutionPool", document, &value) != nil || paasv1.ValidateExecutionPool(value) != nil || value.Metadata.ID != id || value.Metadata.ResourceVersion != version {
		return paasv1.ExecutionPool{}, false, errors.New("stored execution pool is invalid")
	}
	return value, true, nil
}

func (transaction *executionAdmissionTransaction) LoadTarget(ctx context.Context, id paasv1.ResourceID) (executionadmission.Registration, bool, error) {
	value, err := scanExecutionRegistration(transaction.tx.QueryRow(ctx, `SELECT id, execution_pool_id, resource_version, binding_ref, identity_fingerprint, document
		FROM paas.execution_targets WHERE installation_id = $1 AND id = $2 AND binding_ref IS NOT NULL`, transaction.installationID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return executionadmission.Registration{}, false, nil
	}
	return value, err == nil, err
}

func (transaction *executionAdmissionTransaction) LoadPoolTarget(ctx context.Context, id paasv1.ResourceID) (paasv1.ExecutionTarget, bool, error) {
	if paasv1.ValidateID("targetId", string(id)) != nil {
		return paasv1.ExecutionTarget{}, false, executionadmission.ErrInvalidArgument
	}
	var storedID, poolID string
	var version uint64
	var document []byte
	err := transaction.tx.QueryRow(ctx, `SELECT id, execution_pool_id, resource_version, document
		FROM paas.execution_targets WHERE installation_id = $1 AND id = $2`, transaction.installationID, id).Scan(
		&storedID, &poolID, &version, &document,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.ExecutionTarget{}, false, nil
	}
	if err != nil {
		return paasv1.ExecutionTarget{}, false, err
	}
	var value paasv1.ExecutionTarget
	if decodeDocument("ExecutionTarget", document, &value) != nil ||
		paasv1.ValidateExecutionTarget(value) != nil || string(value.Metadata.ID) != storedID ||
		string(value.Spec.ExecutionPoolID) != poolID || value.Metadata.ResourceVersion != version {
		return paasv1.ExecutionTarget{}, false, errors.New("stored execution target is invalid")
	}
	return value, true, nil
}

func (transaction *executionAdmissionTransaction) ListTargets(ctx context.Context) ([]executionadmission.Registration, error) {
	rows, err := transaction.tx.Query(ctx, `SELECT id, execution_pool_id, resource_version, binding_ref, identity_fingerprint, document
		FROM paas.execution_targets WHERE installation_id = $1 AND binding_ref IS NOT NULL ORDER BY id COLLATE "C" LIMIT $2`, transaction.installationID, executionadmission.MaximumTargets+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []executionadmission.Registration{}
	for rows.Next() {
		value, err := scanExecutionRegistration(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if len(values) > executionadmission.MaximumTargets {
		return nil, executionadmission.ErrConflict
	}
	return values, rows.Err()
}

func (transaction *executionAdmissionTransaction) ListPoolTargets(ctx context.Context, poolID paasv1.ResourceID) ([]paasv1.ExecutionTarget, error) {
	if paasv1.ValidateID("poolId", string(poolID)) != nil {
		return nil, executionadmission.ErrInvalidArgument
	}
	rows, err := transaction.tx.Query(ctx, `SELECT id, execution_pool_id, resource_version, document
		FROM paas.execution_targets WHERE installation_id = $1 AND execution_pool_id = $2
		ORDER BY id COLLATE "C" LIMIT $3`, transaction.installationID, poolID, executionadmission.MaximumTargets+2)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]paasv1.ExecutionTarget, 0)
	for rows.Next() {
		var id, storedPoolID string
		var version uint64
		var document []byte
		if err := rows.Scan(&id, &storedPoolID, &version, &document); err != nil {
			return nil, err
		}
		var value paasv1.ExecutionTarget
		if decodeDocument("ExecutionTarget", document, &value) != nil ||
			paasv1.ValidateExecutionTarget(value) != nil || string(value.Metadata.ID) != id ||
			string(value.Spec.ExecutionPoolID) != storedPoolID || value.Spec.ExecutionPoolID != poolID ||
			value.Metadata.ResourceVersion != version {
			return nil, errors.New("stored pool execution target is invalid")
		}
		values = append(values, value)
	}
	if len(values) > executionadmission.MaximumTargets+1 {
		return nil, executionadmission.ErrConflict
	}
	return values, rows.Err()
}

func scanExecutionRegistration(row interface{ Scan(...any) error }) (executionadmission.Registration, error) {
	var value executionadmission.Registration
	var id, poolID string
	var version uint64
	var document []byte
	if err := row.Scan(&id, &poolID, &version, &value.BindingRef, &value.IdentityFingerprint, &document); err != nil {
		return value, err
	}
	if decodeDocument("ExecutionTarget", document, &value.Target) != nil || paasv1.ValidateExecutionTarget(value.Target) != nil ||
		paasv1.ValidateID("bindingRef", value.BindingRef) != nil || paasv1.ValidateDigest("identityFingerprint", value.IdentityFingerprint) != nil ||
		string(value.Target.Metadata.ID) != id || string(value.Target.Spec.ExecutionPoolID) != poolID || value.Target.Metadata.ResourceVersion != version ||
		value.Target.Metadata.Labels["matrix-machine-fingerprint"] != value.IdentityFingerprint {
		return executionadmission.Registration{}, errors.New("stored node registration is invalid")
	}
	return value, nil
}

func (transaction *executionAdmissionTransaction) CreatePool(ctx context.Context, pool paasv1.ExecutionPool, submission executionadmission.Submission) error {
	if paasv1.ValidateExecutionPool(pool) != nil {
		return executionadmission.ErrInvalidArgument
	}
	return transaction.admit(ctx, pool, submission, nil, nil, nil, nil)
}

func (transaction *executionAdmissionTransaction) RegisterTarget(ctx context.Context, registration executionadmission.Registration, expectedPoolVersion uint64, pool paasv1.ExecutionPool, submission executionadmission.Submission) error {
	if paasv1.ValidateExecutionTarget(registration.Target) != nil || paasv1.ValidateExecutionPool(pool) != nil ||
		registration.Target.Spec.ExecutionPoolID != pool.Metadata.ID || expectedPoolVersion < 1 || expectedPoolVersion > 9007199254740991 {
		return executionadmission.ErrInvalidArgument
	}
	poolDocument, err := json.Marshal(pool)
	if err != nil {
		return err
	}
	return transaction.admit(ctx, registration.Target, submission, registration.BindingRef, registration.IdentityFingerprint, int64(expectedPoolVersion), poolDocument)
}

func (transaction *executionAdmissionTransaction) admit(ctx context.Context, resource any, submission executionadmission.Submission, bindingRef, fingerprint, poolVersion, poolDocument any) error {
	if paasv1.ValidateOperation(submission.Operation) != nil || audit.ValidateEvent(submission.AuditEvent) != nil ||
		submission.Operation.InstallationID != transaction.installationID || submission.AuditEvent.InstallationID != transaction.installationID {
		return executionadmission.ErrInvalidArgument
	}
	document, err := json.Marshal(resource)
	if err != nil {
		return err
	}
	operationDocument, err := json.Marshal(submission.Operation)
	if err != nil {
		return err
	}
	eventDocument, err := json.Marshal(submission.AuditEvent)
	if err != nil {
		return err
	}
	_, err = transaction.tx.Exec(ctx, `SELECT paas.admit_execution_resource($1::jsonb,$2::jsonb,$3::jsonb,$4,$5,$6,$7::jsonb)`,
		document, operationDocument, eventDocument, bindingRef, fingerprint, poolVersion, poolDocument)
	return err
}

func (transaction *executionAdmissionTransaction) RefreshTarget(ctx context.Context, expectedTargetVersion uint64, target paasv1.ExecutionTarget, expectedPoolVersion uint64, pool paasv1.ExecutionPool) error {
	if paasv1.ValidateExecutionTarget(target) != nil || paasv1.ValidateExecutionPool(pool) != nil ||
		expectedTargetVersion < 1 || expectedTargetVersion > 9007199254740991 || expectedPoolVersion < 1 || expectedPoolVersion > 9007199254740991 {
		return executionadmission.ErrInvalidArgument
	}
	targetDocument, err := json.Marshal(target)
	if err != nil {
		return err
	}
	poolDocument, err := json.Marshal(pool)
	if err != nil {
		return err
	}
	_, err = transaction.tx.Exec(ctx, `SELECT paas.refresh_execution_target($1,$2::jsonb,$3,$4::jsonb)`, int64(expectedTargetVersion), targetDocument, int64(expectedPoolVersion), poolDocument)
	return err
}
