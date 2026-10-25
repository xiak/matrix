package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/refreshexecutionprofile"
)

var (
	_ refreshexecutionprofile.Repository  = (*ExecutionProfileRepository)(nil)
	_ refreshexecutionprofile.Transaction = (*executionProfileTransaction)(nil)
)

type ExecutionProfileRepository struct {
	pool *pgxpool.Pool
}

func NewExecutionProfileRepository(pool *pgxpool.Pool) (*ExecutionProfileRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &ExecutionProfileRepository{pool: pool}, nil
}

func (repository *ExecutionProfileRepository) WithinTransaction(
	ctx context.Context,
	tenantID paasv1.TenantID,
	installationID string,
	callback func(context.Context, refreshexecutionprofile.Transaction) error,
) error {
	if repository == nil || repository.pool == nil || ctx == nil || callback == nil {
		return errors.New("execution profile transaction input is invalid")
	}
	if err := paasv1.ValidateID("tenantId", string(tenantID)); err != nil {
		return err
	}
	if err := paasv1.ValidateID("installationId", installationID); err != nil {
		return err
	}
	err := withinTenantTransaction(
		ctx,
		repository.pool,
		tenantID,
		pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite},
		func(tx pgx.Tx) error {
			return callback(ctx, &executionProfileTransaction{
				tx: tx, tenantID: tenantID, installationID: installationID,
			})
		},
	)
	if err == nil {
		return nil
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "40001", "40P01":
			return fmt.Errorf(
				"reconcile execution profile: %w",
				refreshexecutionprofile.ErrRetryableTransaction,
			)
		case "MX409":
			return fmt.Errorf(
				"reconcile execution profile: %w",
				refreshexecutionprofile.ErrConflict,
			)
		}
	}
	return fmt.Errorf("reconcile execution profile: %w", err)
}

type executionProfileTransaction struct {
	tx             pgx.Tx
	tenantID       paasv1.TenantID
	installationID string
}

func (transaction *executionProfileTransaction) Load(
	ctx context.Context,
	ids refreshexecutionprofile.IDs,
) (refreshexecutionprofile.Snapshot, error) {
	if transaction == nil || transaction.tx == nil || ctx == nil {
		return refreshexecutionprofile.Snapshot{}, errors.New("execution profile load input is invalid")
	}
	if err := validateExecutionProfileIDs(ids); err != nil {
		return refreshexecutionprofile.Snapshot{}, err
	}
	var transactionTime time.Time
	if err := transaction.tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(
		&transactionTime,
	); err != nil {
		return refreshexecutionprofile.Snapshot{}, errors.New("execution profile database time is unavailable")
	}
	pool, err := transaction.loadPool(ctx, ids.PoolID)
	if err != nil {
		return refreshexecutionprofile.Snapshot{}, err
	}
	target, err := transaction.loadTarget(ctx, ids.TargetID)
	if err != nil {
		return refreshexecutionprofile.Snapshot{}, err
	}
	policy, err := transaction.loadPolicy(ctx, ids.PolicyID)
	if err != nil {
		return refreshexecutionprofile.Snapshot{}, err
	}
	targets, err := transaction.loadTargets(ctx, ids.PoolID, ids.TargetID)
	if err != nil {
		return refreshexecutionprofile.Snapshot{}, err
	}
	return refreshexecutionprofile.Snapshot{
		TransactionTime: databaseTime(transactionTime),
		Pool:            pool,
		Target:          target,
		Policy:          policy,
		Targets:         targets,
	}, nil
}

func (transaction *executionProfileTransaction) Save(
	ctx context.Context,
	versions refreshexecutionprofile.Versions,
	profile refreshexecutionprofile.Profile,
) error {
	if transaction == nil || transaction.tx == nil || ctx == nil ||
		paasv1.ValidateExecutionPool(profile.Pool) != nil ||
		paasv1.ValidateExecutionTarget(profile.Target) != nil ||
		paasv1.ValidatePlacementPolicy(profile.Policy) != nil ||
		profile.Policy.Metadata.Scope.TenantID != transaction.tenantID ||
		profile.Target.Spec.ExecutionPoolID != profile.Pool.Metadata.ID {
		return errors.New("execution profile save input is invalid")
	}
	poolDocument, err := json.Marshal(profile.Pool)
	if err != nil {
		return errors.New("execution profile pool cannot be encoded")
	}
	targetDocument, err := json.Marshal(profile.Target)
	if err != nil {
		return errors.New("execution profile target cannot be encoded")
	}
	policyDocument, err := json.Marshal(profile.Policy)
	if err != nil {
		return errors.New("execution profile policy cannot be encoded")
	}
	var reconciled bool
	if err := transaction.tx.QueryRow(
		ctx,
		`SELECT paas.reconcile_local_execution_profile(
		     $1, $2, $3::jsonb, $4, $5::jsonb, $6, $7::jsonb
		 )`,
		transaction.installationID,
		int64(versions.Pool),
		poolDocument,
		int64(versions.Target),
		targetDocument,
		int64(versions.Policy),
		policyDocument,
	).Scan(&reconciled); err != nil {
		return err
	}
	if !reconciled {
		return errors.New("execution profile was not reconciled")
	}
	return nil
}

func (transaction *executionProfileTransaction) loadPool(
	ctx context.Context,
	id paasv1.ResourceID,
) (*paasv1.ExecutionPool, error) {
	var installationID pgtype.Text
	var resourceVersion uint64
	var document []byte
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT installation_id, resource_version, document
		   FROM paas.execution_pools
		  WHERE id = $1`,
		string(id),
	).Scan(&installationID, &resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("execution profile pool cannot be loaded")
	}
	if installationID.Valid && installationID.String != transaction.installationID {
		return nil, refreshexecutionprofile.ErrConflict
	}
	var value paasv1.ExecutionPool
	if decodeDocument("ExecutionPool", document, &value) != nil ||
		paasv1.ValidateExecutionPool(value) != nil || value.Metadata.ID != id ||
		value.Metadata.ResourceVersion != resourceVersion {
		return nil, errors.New("stored execution profile pool is invalid")
	}
	return &value, nil
}

func (transaction *executionProfileTransaction) loadTarget(
	ctx context.Context,
	id paasv1.ResourceID,
) (*paasv1.ExecutionTarget, error) {
	var installationID pgtype.Text
	var poolID string
	var resourceVersion uint64
	var document []byte
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT installation_id, execution_pool_id, resource_version, document
		   FROM paas.execution_targets
		  WHERE id = $1`,
		string(id),
	).Scan(&installationID, &poolID, &resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("execution profile target cannot be loaded")
	}
	if installationID.Valid && installationID.String != transaction.installationID {
		return nil, refreshexecutionprofile.ErrConflict
	}
	var value paasv1.ExecutionTarget
	if decodeDocument("ExecutionTarget", document, &value) != nil ||
		paasv1.ValidateExecutionTarget(value) != nil || value.Metadata.ID != id ||
		string(value.Spec.ExecutionPoolID) != poolID ||
		value.Metadata.ResourceVersion != resourceVersion {
		return nil, errors.New("stored execution profile target is invalid")
	}
	return &value, nil
}

func (transaction *executionProfileTransaction) loadTargets(
	ctx context.Context,
	poolID paasv1.ResourceID,
	localTargetID paasv1.ResourceID,
) ([]paasv1.ExecutionTarget, error) {
	rows, err := transaction.tx.Query(
		ctx,
		`SELECT id, installation_id, resource_version, document
		   FROM paas.execution_targets
		  WHERE execution_pool_id = $1
		  ORDER BY id COLLATE "C"`,
		string(poolID),
	)
	if err != nil {
		return nil, errors.New("execution profile targets cannot be loaded")
	}
	defer rows.Close()
	values := make([]paasv1.ExecutionTarget, 0)
	for rows.Next() {
		var id string
		var installationID pgtype.Text
		var resourceVersion uint64
		var document []byte
		if err := rows.Scan(&id, &installationID, &resourceVersion, &document); err != nil {
			return nil, errors.New("execution profile target cannot be scanned")
		}
		if (installationID.Valid && installationID.String != transaction.installationID) ||
			(!installationID.Valid && paasv1.ResourceID(id) != localTargetID) {
			return nil, refreshexecutionprofile.ErrConflict
		}
		var value paasv1.ExecutionTarget
		if decodeDocument("ExecutionTarget", document, &value) != nil ||
			paasv1.ValidateExecutionTarget(value) != nil || string(value.Metadata.ID) != id ||
			value.Spec.ExecutionPoolID != poolID || value.Metadata.ResourceVersion != resourceVersion {
			return nil, errors.New("stored execution profile target is invalid")
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("execution profile targets cannot be iterated")
	}
	return values, nil
}

func (transaction *executionProfileTransaction) loadPolicy(
	ctx context.Context,
	id paasv1.ResourceID,
) (*paasv1.PlacementPolicy, error) {
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
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("execution profile policy cannot be loaded")
	}
	var value paasv1.PlacementPolicy
	if decodeDocument("PlacementPolicy", document, &value) != nil ||
		paasv1.ValidatePlacementPolicy(value) != nil || value.Metadata.ID != id ||
		value.Metadata.Scope.TenantID != transaction.tenantID ||
		value.Metadata.ResourceVersion != resourceVersion {
		return nil, errors.New("stored execution profile policy is invalid")
	}
	return &value, nil
}

func validateExecutionProfileIDs(ids refreshexecutionprofile.IDs) error {
	return errors.Join(
		paasv1.ValidateID("executionPoolId", string(ids.PoolID)),
		paasv1.ValidateID("executionTargetId", string(ids.TargetID)),
		paasv1.ValidateID("placementPolicyId", string(ids.PolicyID)),
	)
}
