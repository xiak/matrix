package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/applicationlifecycle"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
)

var (
	_ applicationlifecycle.Repository  = (*ApplicationRepository)(nil)
	_ applicationlifecycle.Transaction = (*applicationTransaction)(nil)
)

// ApplicationRepository owns the atomic desired-state submission boundary.
// Worker execution state uses a separate repository and database role.
type ApplicationRepository struct {
	pool *pgxpool.Pool
}

func NewApplicationRepository(pool *pgxpool.Pool) (*ApplicationRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &ApplicationRepository{pool: pool}, nil
}

func (repository *ApplicationRepository) WithinTransaction(
	ctx context.Context,
	tenantID paasv1.TenantID,
	callback func(context.Context, applicationlifecycle.Transaction) error,
) error {
	if repository == nil || repository.pool == nil {
		return errors.New("application repository is nil")
	}
	if ctx == nil {
		return errors.New("application transaction context is nil")
	}
	if callback == nil {
		return errors.New("application transaction callback is required")
	}
	if err := paasv1.ValidateID("tenantId", string(tenantID)); err != nil {
		return err
	}
	err := withinTenantTransaction(
		ctx,
		repository.pool,
		tenantID,
		pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite},
		func(tx pgx.Tx) error {
			transaction := &applicationTransaction{placementTransaction: &placementTransaction{
				tx:       tx,
				tenantID: tenantID,
			}}
			return callback(ctx, transaction)
		},
	)
	return mapApplicationTransactionError(err)
}

type applicationTransaction struct {
	*placementTransaction
}

func (transaction *applicationTransaction) FindOperationByFingerprint(
	ctx context.Context,
	fingerprint string,
) (paasv1.Operation, bool, error) {
	if err := paasv1.ValidateDigest("idempotencyFingerprint", fingerprint); err != nil {
		return paasv1.Operation{}, false, err
	}
	var (
		id            string
		action        string
		targetKind    string
		targetID      string
		requestDigest string
		state         string
		attempt       uint64
		createdAt     time.Time
		updatedAt     time.Time
		document      []byte
	)
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT id,
		        action,
		        target_kind,
		        target_id,
		        request_digest,
		        state,
		        attempt,
		        created_at,
		        updated_at,
		        document
		   FROM paas.operations
		  WHERE tenant_id = $1
		    AND idempotency_fingerprint = $2`,
		string(transaction.tenantID),
		fingerprint,
	).Scan(
		&id,
		&action,
		&targetKind,
		&targetID,
		&requestDigest,
		&state,
		&attempt,
		&createdAt,
		&updatedAt,
		&document,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.Operation{}, false, nil
	}
	if err != nil {
		return paasv1.Operation{}, false, fmt.Errorf("find Operation replay: %w", err)
	}
	var operation paasv1.Operation
	if err := decodeDocument("Operation", document, &operation); err != nil {
		return paasv1.Operation{}, false, err
	}
	if err := paasv1.ValidateOperation(operation); err != nil {
		return paasv1.Operation{}, false, fmt.Errorf("validate stored Operation: %w", err)
	}
	if string(operation.ID) != id ||
		operation.Scope.TenantID != transaction.tenantID ||
		string(operation.Action) != action ||
		operation.Target.Kind != targetKind ||
		string(operation.Target.ID) != targetID ||
		operation.IdempotencyFingerprint != fingerprint ||
		operation.RequestDigest != requestDigest ||
		string(operation.State) != state ||
		uint64(operation.Attempt) != attempt ||
		!operation.CreatedAt.Equal(databaseTime(createdAt)) ||
		!operation.UpdatedAt.Equal(databaseTime(updatedAt)) {
		return paasv1.Operation{}, false, errors.New("stored Operation relational identity mismatch")
	}
	return operation, true, nil
}

func (transaction *applicationTransaction) LoadDeployment(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.Deployment, bool, error) {
	return transaction.findDeployment(ctx, id)
}

func (transaction *applicationTransaction) LoadApplicationRevision(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.ApplicationRevision, error) {
	revision, found, err := transaction.findApplicationRevision(ctx, id)
	if err != nil {
		return paasv1.ApplicationRevision{}, err
	}
	if !found {
		return paasv1.ApplicationRevision{}, applicationlifecycle.ErrNotFound
	}
	return revision, nil
}

func (transaction *applicationTransaction) LoadPlacementPolicy(
	ctx context.Context,
	id paasv1.ResourceID,
) (paasv1.PlacementPolicy, error) {
	policy, found, err := transaction.findPolicy(ctx, id)
	if err != nil {
		return paasv1.PlacementPolicy{}, err
	}
	if !found {
		return paasv1.PlacementPolicy{}, applicationlifecycle.ErrNotFound
	}
	return policy, nil
}

func (transaction *applicationTransaction) ValidateConfigurationBindings(
	ctx context.Context,
	spec paasv1.DeploymentSpec,
	applicationID paasv1.ResourceID,
) error {
	revisionSet := make(map[string]struct{})
	for _, component := range spec.Components {
		for _, binding := range component.Bindings {
			if binding.ConfigurationRevisionID != "" {
				revisionSet[string(binding.ConfigurationRevisionID)] = struct{}{}
			}
		}
	}
	if len(revisionSet) == 0 {
		return nil
	}
	revisionIDs := make([]string, 0, len(revisionSet))
	for revisionID := range revisionSet {
		revisionIDs = append(revisionIDs, revisionID)
	}
	slices.Sort(revisionIDs)
	rows, err := transaction.tx.Query(
		ctx,
		`SELECT revision.id,
		        revision.configuration_id,
		        revision.content_digest,
		        revision.resource_version,
		        configuration.application_id,
		        revision.document
		   FROM paas.configuration_revisions AS revision
		   JOIN paas.configurations AS configuration
		     ON configuration.tenant_id = revision.tenant_id
		    AND configuration.id = revision.configuration_id
		  WHERE revision.tenant_id = $1
		    AND revision.id = ANY($2::text[])
		  ORDER BY revision.id COLLATE "C"`,
		string(transaction.tenantID),
		revisionIDs,
	)
	if err != nil {
		return fmt.Errorf("load ConfigurationRevision bindings: %w", err)
	}
	defer rows.Close()
	loaded := 0
	for rows.Next() {
		var (
			id              string
			configurationID string
			contentDigest   string
			resourceVersion uint64
			ownerID         string
			document        []byte
		)
		if err := rows.Scan(
			&id,
			&configurationID,
			&contentDigest,
			&resourceVersion,
			&ownerID,
			&document,
		); err != nil {
			return fmt.Errorf("scan ConfigurationRevision binding: %w", err)
		}
		var revision paasv1.ConfigurationRevision
		if err := decodeDocument("ConfigurationRevision", document, &revision); err != nil {
			return err
		}
		if err := paasv1.ValidateConfigurationRevision(revision); err != nil {
			return fmt.Errorf("validate stored ConfigurationRevision: %w", err)
		}
		if string(revision.Metadata.ID) != id ||
			revision.Metadata.Scope.TenantID != transaction.tenantID ||
			string(revision.Spec.ConfigurationID) != configurationID ||
			revision.Spec.ContentDigest != contentDigest ||
			revision.Metadata.ResourceVersion != resourceVersion ||
			ownerID != string(applicationID) {
			return errors.New("ConfigurationRevision binding ownership or relational identity mismatch")
		}
		loaded++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate ConfigurationRevision bindings: %w", err)
	}
	if loaded != len(revisionIDs) {
		return applicationlifecycle.ErrNotFound
	}
	return nil
}

func (transaction *applicationTransaction) LoadAcceptedGeneration(
	ctx context.Context,
	deploymentID paasv1.ResourceID,
	generation uint64,
) (paasv1.DeploymentGeneration, error) {
	if err := paasv1.ValidateID("deploymentId", string(deploymentID)); err != nil {
		return paasv1.DeploymentGeneration{}, err
	}
	if generation == 0 || generation > 9007199254740991 {
		return paasv1.DeploymentGeneration{}, errors.New("Deployment generation is invalid")
	}
	return transaction.loadGeneration(
		ctx,
		`SELECT deployment_id,
		        generation,
		        application_revision_id,
		        policy_id,
		        content_digest,
		        created_by_operation_id,
		        created_at,
		        document
		   FROM paas.deployment_generations
		  WHERE tenant_id = $1
		    AND deployment_id = $2
		    AND generation = $3`,
		string(transaction.tenantID),
		string(deploymentID),
		int64(generation),
	)
}

func (transaction *applicationTransaction) LoadGenerationByOperation(
	ctx context.Context,
	operationID paasv1.OperationID,
) (paasv1.DeploymentGeneration, error) {
	if err := paasv1.ValidateID("operationId", string(operationID)); err != nil {
		return paasv1.DeploymentGeneration{}, err
	}
	return transaction.loadGeneration(
		ctx,
		`SELECT deployment_id,
		        generation,
		        application_revision_id,
		        policy_id,
		        content_digest,
		        created_by_operation_id,
		        created_at,
		        document
		   FROM paas.deployment_generations
		  WHERE tenant_id = $1
		    AND created_by_operation_id = $2`,
		string(transaction.tenantID),
		string(operationID),
	)
}

func (transaction *applicationTransaction) loadGeneration(
	ctx context.Context,
	query string,
	arguments ...any,
) (paasv1.DeploymentGeneration, error) {
	var (
		deploymentID          string
		generation            uint64
		applicationRevisionID string
		policyID              string
		contentDigest         string
		operationID           string
		createdAt             time.Time
		document              []byte
	)
	err := transaction.tx.QueryRow(ctx, query, arguments...).Scan(
		&deploymentID,
		&generation,
		&applicationRevisionID,
		&policyID,
		&contentDigest,
		&operationID,
		&createdAt,
		&document,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return paasv1.DeploymentGeneration{}, applicationlifecycle.ErrNotFound
	}
	if err != nil {
		return paasv1.DeploymentGeneration{}, fmt.Errorf("load DeploymentGeneration: %w", err)
	}
	var value paasv1.DeploymentGeneration
	if err := decodeDocument("DeploymentGeneration", document, &value); err != nil {
		return paasv1.DeploymentGeneration{}, err
	}
	if err := paasv1.ValidateDeploymentGeneration(value); err != nil {
		return paasv1.DeploymentGeneration{}, fmt.Errorf("validate stored DeploymentGeneration: %w", err)
	}
	if value.Scope.TenantID != transaction.tenantID ||
		string(value.DeploymentID) != deploymentID ||
		value.Generation != generation ||
		string(value.Spec.ApplicationRevisionID) != applicationRevisionID ||
		string(value.Spec.PlacementPolicyID) != policyID ||
		value.ContentDigest != contentDigest ||
		string(value.CreatedByOperationID) != operationID ||
		!value.CreatedAt.Equal(databaseTime(createdAt)) {
		return paasv1.DeploymentGeneration{}, errors.New(
			"stored DeploymentGeneration relational identity mismatch",
		)
	}
	return value, nil
}

func (transaction *applicationTransaction) SubmitDeployment(
	ctx context.Context,
	submission applicationlifecycle.Submission,
) error {
	if err := validateApplicationSubmission(transaction.tenantID, submission); err != nil {
		return err
	}
	deploymentDocument, err := json.Marshal(submission.Deployment)
	if err != nil {
		return fmt.Errorf("encode Deployment document: %w", err)
	}
	generationDocument, err := json.Marshal(submission.Generation)
	if err != nil {
		return fmt.Errorf("encode DeploymentGeneration document: %w", err)
	}
	operationDocument, err := json.Marshal(submission.Operation)
	if err != nil {
		return fmt.Errorf("encode Operation document: %w", err)
	}
	auditDocument, err := json.Marshal(submission.AuditEvent)
	if err != nil {
		return fmt.Errorf("encode Audit event: %w", err)
	}
	if _, err := transaction.tx.Exec(
		ctx,
		`SELECT paas.submit_deployment($1::jsonb, $2::jsonb, $3::jsonb, $4::jsonb, $5)`,
		deploymentDocument,
		generationDocument,
		operationDocument,
		auditDocument,
		int64(submission.ExpectedResourceVersion),
	); err != nil {
		return fmt.Errorf("submit Deployment generation and Operation: %w", err)
	}
	return nil
}

func validateApplicationSubmission(
	tenantID paasv1.TenantID,
	submission applicationlifecycle.Submission,
) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateDeployment(submission.Deployment),
		paasv1.ValidateDeploymentGeneration(submission.Generation),
		paasv1.ValidateOperation(submission.Operation),
		audit.ValidateEvent(submission.AuditEvent),
	)
	deployment := submission.Deployment
	generation := submission.Generation
	operation := submission.Operation
	auditEvent := submission.AuditEvent
	if deployment.Metadata.Scope.TenantID != tenantID ||
		generation.Scope.TenantID != tenantID ||
		operation.Scope.TenantID != tenantID ||
		generation.DeploymentID != deployment.Metadata.ID ||
		generation.Generation != deployment.Generation ||
		generation.CreatedByOperationID != operation.ID ||
		operation.Target.Kind != "Deployment" ||
		operation.Target.ID != deployment.Metadata.ID ||
		auditEvent.TenantID != tenantID ||
		auditEvent.Target != operation.Target ||
		auditEvent.OperationID != operation.ID ||
		auditEvent.Actor != operation.RequestedBy ||
		auditEvent.RequestDigest != operation.RequestDigest ||
		!auditEvent.OccurredAt.Equal(operation.CreatedAt) ||
		generation.ContentDigest != paasv1.DeploymentSpecContentDigest(deployment.Spec) {
		problems = append(problems, errors.New("application submission identities do not match"))
	}
	if submission.ExpectedResourceVersion > 9007199254740991 ||
		(submission.ExpectedResourceVersion == 0 &&
			(deployment.Metadata.ResourceVersion != 1 || deployment.Generation != 1)) ||
		(submission.ExpectedResourceVersion > 0 &&
			deployment.Metadata.ResourceVersion != submission.ExpectedResourceVersion+1) {
		problems = append(problems, errors.New("application submission resource version is invalid"))
	}
	return errors.Join(problems...)
}

func mapApplicationTransactionError(err error) error {
	if err == nil {
		return nil
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "MX409":
			return fmt.Errorf(
				"execute application transaction: %w",
				applicationlifecycle.ErrResourceVersionConflict,
			)
		case "40001", "40P01", "23505":
			return fmt.Errorf(
				"execute application transaction: %w",
				applicationlifecycle.ErrRetryableTransaction,
			)
		}
	}
	return fmt.Errorf("execute application transaction: %w", err)
}
