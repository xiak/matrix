package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/pipelineconfiguration"
)

func (transaction *configurationTransaction) TransactionTime(ctx context.Context) (time.Time, error) {
	var value time.Time
	if err := transaction.tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&value); err != nil {
		return time.Time{}, fmt.Errorf("read PostgreSQL transaction time: %w", err)
	}
	return value.UTC(), nil
}

func (transaction *configurationTransaction) FindMutation(
	ctx context.Context,
	fingerprint string,
) (pipelineconfiguration.StoredMutation, bool, error) {
	if err := devopsv1.ValidateDigest("idempotencyFingerprint", fingerprint); err != nil {
		return pipelineconfiguration.StoredMutation{}, false, err
	}
	var (
		id, kind, commandTargetID, requestDigest, resultKind string
		createdAt                                            time.Time
		recordDocument, resultDocument                       []byte
	)
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT id, mutation_kind, command_target_id, request_digest,
		        result_kind, created_at, document, result_document
		   FROM delivery.mutations
		  WHERE tenant_id = $1 AND idempotency_fingerprint = $2`,
		string(transaction.tenantID), fingerprint,
	).Scan(&id, &kind, &commandTargetID, &requestDigest, &resultKind, &createdAt, &recordDocument, &resultDocument)
	if errors.Is(err, pgx.ErrNoRows) {
		return pipelineconfiguration.StoredMutation{}, false, nil
	}
	if err != nil {
		return pipelineconfiguration.StoredMutation{}, false, fmt.Errorf("find delivery mutation replay: %w", err)
	}
	var stored pipelineconfiguration.StoredMutation
	if err := decodeDocument("MutationRecord", recordDocument, &stored.Record); err != nil {
		return pipelineconfiguration.StoredMutation{}, false, err
	}
	if err := decodeDocument("MutationResult", resultDocument, &stored.Result); err != nil {
		return pipelineconfiguration.StoredMutation{}, false, err
	}
	if err := pipelineconfiguration.ValidateStoredMutation(stored); err != nil {
		return pipelineconfiguration.StoredMutation{}, false, fmt.Errorf("validate stored delivery mutation: %w", err)
	}
	if stored.Record.ID != id || stored.Record.TenantID != transaction.tenantID ||
		string(stored.Record.Kind) != kind || string(stored.Record.CommandTargetID) != commandTargetID ||
		stored.Record.IdempotencyFingerprint != fingerprint || stored.Record.RequestDigest != requestDigest ||
		string(stored.Record.ResultKind) != resultKind || !stored.Record.CreatedAt.Equal(createdAt.UTC()) {
		return pipelineconfiguration.StoredMutation{}, false, errors.New("stored delivery mutation relational identity mismatch")
	}
	return stored, true, nil
}

func (transaction *configurationTransaction) LoadProject(
	ctx context.Context,
	id devopsv1.ResourceID,
) (devopsv1.DevOpsProject, bool, error) {
	var resourceVersion uint64
	var document []byte
	err := transaction.queryResource(ctx, "projects", id, &resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return devopsv1.DevOpsProject{}, false, nil
	}
	if err != nil {
		return devopsv1.DevOpsProject{}, false, fmt.Errorf("load DevOpsProject: %w", err)
	}
	var value devopsv1.DevOpsProject
	if err := decodeDocument("DevOpsProject", document, &value); err != nil {
		return value, false, err
	}
	if err := devopsv1.ValidateDevOpsProject(value); err != nil {
		return value, false, fmt.Errorf("validate stored DevOpsProject: %w", err)
	}
	if value.Metadata.ID != id || value.Metadata.Scope.TenantID != transaction.tenantID || value.Metadata.ResourceVersion != resourceVersion {
		return value, false, errors.New("stored DevOpsProject relational identity mismatch")
	}
	return value, true, nil
}

func (transaction *configurationTransaction) LoadSourceConnection(
	ctx context.Context,
	id devopsv1.ResourceID,
) (devopsv1.SourceConnection, bool, error) {
	if err := devopsv1.ValidateID("sourceConnectionId", string(id)); err != nil {
		return devopsv1.SourceConnection{}, false, err
	}
	var adapterID string
	var resourceVersion uint64
	var document []byte
	err := transaction.tx.QueryRow(ctx,
		`SELECT adapter_id, resource_version, document FROM delivery.source_connections
		  WHERE tenant_id = $1 AND id = $2`, string(transaction.tenantID), string(id),
	).Scan(&adapterID, &resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return devopsv1.SourceConnection{}, false, nil
	}
	if err != nil {
		return devopsv1.SourceConnection{}, false, fmt.Errorf("load SourceConnection: %w", err)
	}
	var value devopsv1.SourceConnection
	if err := decodeDocument("SourceConnection", document, &value); err != nil {
		return value, false, err
	}
	if err := devopsv1.ValidateSourceConnection(value); err != nil {
		return value, false, fmt.Errorf("validate stored SourceConnection: %w", err)
	}
	if value.Metadata.ID != id || value.Metadata.Scope.TenantID != transaction.tenantID ||
		value.Metadata.ResourceVersion != resourceVersion || string(value.Spec.AdapterID) != adapterID {
		return value, false, errors.New("stored SourceConnection relational identity mismatch")
	}
	return value, true, nil
}

func (transaction *configurationTransaction) LoadRepositoryBinding(
	ctx context.Context,
	id devopsv1.ResourceID,
) (devopsv1.RepositoryBinding, bool, error) {
	if err := devopsv1.ValidateID("repositoryBindingId", string(id)); err != nil {
		return devopsv1.RepositoryBinding{}, false, err
	}
	var projectID, connectionID, contentDigest string
	var resourceVersion uint64
	var document []byte
	err := transaction.tx.QueryRow(ctx,
		`SELECT project_id, source_connection_id, content_digest, resource_version, document
		   FROM delivery.repository_bindings WHERE tenant_id = $1 AND id = $2`,
		string(transaction.tenantID), string(id),
	).Scan(&projectID, &connectionID, &contentDigest, &resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return devopsv1.RepositoryBinding{}, false, nil
	}
	if err != nil {
		return devopsv1.RepositoryBinding{}, false, fmt.Errorf("load RepositoryBinding: %w", err)
	}
	var value devopsv1.RepositoryBinding
	if err := decodeDocument("RepositoryBinding", document, &value); err != nil {
		return value, false, err
	}
	if err := devopsv1.ValidateRepositoryBinding(value); err != nil {
		return value, false, fmt.Errorf("validate stored RepositoryBinding: %w", err)
	}
	if value.Metadata.ID != id || value.Metadata.Scope.TenantID != transaction.tenantID ||
		value.Metadata.ResourceVersion != resourceVersion || string(value.ProjectID) != projectID ||
		string(value.Spec.SourceConnectionID) != connectionID || value.ContentDigest != contentDigest {
		return value, false, errors.New("stored RepositoryBinding relational identity mismatch")
	}
	return value, true, nil
}

func (transaction *configurationTransaction) LoadPipeline(
	ctx context.Context,
	id devopsv1.ResourceID,
) (devopsv1.Pipeline, bool, error) {
	if err := devopsv1.ValidateID("pipelineId", string(id)); err != nil {
		return devopsv1.Pipeline{}, false, err
	}
	var projectID, bindingID, draftDigest string
	var resourceVersion uint64
	var document []byte
	err := transaction.tx.QueryRow(ctx,
		`SELECT project_id, repository_binding_id, draft_digest, resource_version, document
		   FROM delivery.pipelines WHERE tenant_id = $1 AND id = $2`,
		string(transaction.tenantID), string(id),
	).Scan(&projectID, &bindingID, &draftDigest, &resourceVersion, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return devopsv1.Pipeline{}, false, nil
	}
	if err != nil {
		return devopsv1.Pipeline{}, false, fmt.Errorf("load Pipeline: %w", err)
	}
	var value devopsv1.Pipeline
	if err := decodeDocument("Pipeline", document, &value); err != nil {
		return value, false, err
	}
	if err := devopsv1.ValidatePipeline(value); err != nil {
		return value, false, fmt.Errorf("validate stored Pipeline: %w", err)
	}
	if value.Metadata.ID != id || value.Metadata.Scope.TenantID != transaction.tenantID ||
		value.Metadata.ResourceVersion != resourceVersion || string(value.ProjectID) != projectID ||
		string(value.Draft.Spec.RepositoryBindingID) != bindingID || value.Draft.ContentDigest != draftDigest {
		return value, false, errors.New("stored Pipeline relational identity mismatch")
	}
	return value, true, nil
}

func (transaction *configurationTransaction) queryResource(
	ctx context.Context,
	table string,
	id devopsv1.ResourceID,
	resourceVersion *uint64,
	document *[]byte,
) error {
	if err := devopsv1.ValidateID("resourceId", string(id)); err != nil {
		return err
	}
	if table != "projects" {
		return errors.New("unsupported delivery resource table")
	}
	return transaction.tx.QueryRow(ctx,
		`SELECT resource_version, document FROM delivery.projects WHERE tenant_id = $1 AND id = $2`,
		string(transaction.tenantID), string(id),
	).Scan(resourceVersion, document)
}

func decodeDocument[T any](kind string, document []byte, target *T) error {
	if len(document) == 0 {
		return fmt.Errorf("stored %s document is empty", kind)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode stored %s document: %w", kind, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("stored %s document contains trailing JSON", kind)
		}
		return fmt.Errorf("decode stored %s document trailer: %w", kind, err)
	}
	return nil
}
