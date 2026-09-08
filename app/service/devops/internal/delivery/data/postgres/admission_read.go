package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runadmission"
)

func (transaction *admissionTransaction) LoadAdmission(
	ctx context.Context,
	id devopsv1.ResourceID,
) (runadmission.Admission, bool, error) {
	if err := devopsv1.ValidateID("sourceEventId", string(id)); err != nil {
		return runadmission.Admission{}, false, err
	}
	var connectionID, bindingID, bindingDigest, externalRepositoryID, deliveryID string
	var contentDigest, payloadDigest string
	var receivedAt time.Time
	var document []byte
	err := transaction.tx.QueryRow(ctx,
		`SELECT source_connection_id, repository_binding_id,
		        repository_binding_digest, external_repository_id, delivery_id,
		        content_digest, canonical_payload_digest, received_at, document
		   FROM delivery.source_events
		  WHERE tenant_id = $1 AND id = $2`,
		string(transaction.tenantID), string(id),
	).Scan(
		&connectionID, &bindingID, &bindingDigest, &externalRepositoryID,
		&deliveryID, &contentDigest, &payloadDigest, &receivedAt, &document,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return runadmission.Admission{}, false, nil
	}
	if err != nil {
		return runadmission.Admission{}, false, fmt.Errorf("load SourceEvent: %w", err)
	}
	var event devopsv1.SourceEvent
	if err := decodeDocument("SourceEvent", document, &event); err != nil {
		return runadmission.Admission{}, false, err
	}
	if err := devopsv1.ValidateSourceEvent(event); err != nil {
		return runadmission.Admission{}, false, fmt.Errorf("validate stored SourceEvent: %w", err)
	}
	if event.ID != id || event.Scope.TenantID != transaction.tenantID ||
		string(event.Spec.SourceConnectionID) != connectionID ||
		string(event.Spec.RepositoryBindingID) != bindingID ||
		event.Spec.RepositoryBindingDigest != bindingDigest ||
		string(event.Spec.ExternalRepositoryID) != externalRepositoryID ||
		event.Spec.DeliveryID != deliveryID || event.ContentDigest != contentDigest ||
		event.Spec.CanonicalPayloadDigest != payloadDigest ||
		!event.ReceivedAt.Equal(receivedAt.UTC()) {
		return runadmission.Admission{}, false, errors.New("stored SourceEvent relational identity mismatch")
	}

	runs, err := transaction.loadPipelineRunsForEvent(ctx, event)
	if err != nil {
		return runadmission.Admission{}, false, err
	}
	admission := runadmission.Admission{Event: event, Runs: runs}
	if err := runadmission.ValidateAdmission(admission); err != nil {
		return runadmission.Admission{}, false, fmt.Errorf("validate stored run admission: %w", err)
	}
	return admission, true, nil
}

func (transaction *admissionTransaction) loadPipelineRunsForEvent(
	ctx context.Context,
	event devopsv1.SourceEvent,
) ([]devopsv1.PipelineRun, error) {
	rows, err := transaction.tx.Query(ctx,
		`SELECT id, pipeline_id, project_id, source_event_digest,
		        pipeline_revision_id, pipeline_revision_digest,
		        repository_binding_id, repository_binding_digest,
		        state, stage, reason, resource_version, created_at, updated_at, document
		   FROM delivery.pipeline_runs
		  WHERE tenant_id = $1 AND source_event_id = $2
		    AND replay_of_run_id IS NULL
		  ORDER BY pipeline_id COLLATE "C"`,
		string(transaction.tenantID), string(event.ID),
	)
	if err != nil {
		return nil, fmt.Errorf("load PipelineRuns: %w", err)
	}
	defer rows.Close()
	var runs []devopsv1.PipelineRun
	for rows.Next() {
		var id, pipelineID, projectID, eventDigest, revisionID, revisionDigest string
		var bindingID, bindingDigest, state, stage, reason string
		var resourceVersion uint64
		var createdAt, updatedAt time.Time
		var document []byte
		if err := rows.Scan(
			&id, &pipelineID, &projectID, &eventDigest, &revisionID, &revisionDigest,
			&bindingID, &bindingDigest, &state, &stage, &reason, &resourceVersion,
			&createdAt, &updatedAt, &document,
		); err != nil {
			return nil, fmt.Errorf("scan PipelineRun: %w", err)
		}
		var run devopsv1.PipelineRun
		if err := decodeDocument("PipelineRun", document, &run); err != nil {
			return nil, err
		}
		if err := devopsv1.ValidatePipelineRun(run); err != nil {
			return nil, fmt.Errorf("validate stored PipelineRun: %w", err)
		}
		if string(run.ID) != id || run.Scope.TenantID != transaction.tenantID ||
			string(run.PipelineID) != pipelineID || string(run.ProjectID) != projectID ||
			run.Input.SourceEventID != event.ID || run.Input.SourceEventDigest != eventDigest ||
			string(run.Input.PipelineRevisionID) != revisionID || run.Input.PipelineRevisionDigest != revisionDigest ||
			string(run.Input.RepositoryBindingID) != bindingID || run.Input.RepositoryBindingDigest != bindingDigest ||
			string(run.Status.State) != state || string(run.Status.Stage) != stage ||
			string(run.Status.Reason) != reason || run.Status.ResourceVersion != resourceVersion ||
			!run.CreatedAt.Equal(createdAt.UTC()) || !run.UpdatedAt.Equal(updatedAt.UTC()) {
			return nil, errors.New("stored PipelineRun relational identity mismatch")
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate PipelineRuns: %w", err)
	}
	return runs, nil
}

func (transaction *admissionTransaction) LoadRepositoryBindingForSource(
	ctx context.Context,
	connectionID devopsv1.ResourceID,
	externalRepositoryID devopsv1.ResourceID,
) (devopsv1.RepositoryBinding, bool, error) {
	if err := errors.Join(
		devopsv1.ValidateID("sourceConnectionId", string(connectionID)),
		devopsv1.ValidateID("externalRepositoryId", string(externalRepositoryID)),
	); err != nil {
		return devopsv1.RepositoryBinding{}, false, err
	}
	var bindingID devopsv1.ResourceID
	err := transaction.tx.QueryRow(ctx,
		`SELECT id FROM delivery.repository_bindings
		  WHERE tenant_id = $1 AND source_connection_id = $2
		    AND external_repository_id = $3`,
		string(transaction.tenantID), string(connectionID), string(externalRepositoryID),
	).Scan(&bindingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return devopsv1.RepositoryBinding{}, false, nil
	}
	if err != nil {
		return devopsv1.RepositoryBinding{}, false, fmt.Errorf("resolve RepositoryBinding for source: %w", err)
	}
	return transaction.LoadRepositoryBinding(ctx, bindingID)
}

func (transaction *admissionTransaction) LoadMatchingActiveRevisions(
	ctx context.Context,
	bindingID devopsv1.ResourceID,
	bindingDigest string,
) ([]devopsv1.PipelineActivation, error) {
	if err := errors.Join(
		devopsv1.ValidateID("repositoryBindingId", string(bindingID)),
		devopsv1.ValidateDigest("repositoryBindingDigest", bindingDigest),
	); err != nil {
		return nil, err
	}
	rows, err := transaction.tx.Query(ctx,
		`SELECT pipeline.document, revision.document
		   FROM delivery.pipelines AS pipeline
		   JOIN delivery.pipeline_revisions AS revision
		     ON revision.tenant_id = pipeline.tenant_id
		    AND revision.id = pipeline.active_revision_id
		    AND revision.pipeline_id = pipeline.id
		    AND revision.revision = pipeline.active_revision
		    AND revision.content_digest = pipeline.active_revision_digest
		  WHERE pipeline.tenant_id = $1
		    AND revision.repository_binding_id = $2
		    AND revision.repository_binding_digest = $3
		  ORDER BY pipeline.id COLLATE "C"`,
		string(transaction.tenantID), string(bindingID), bindingDigest,
	)
	if err != nil {
		return nil, fmt.Errorf("load matching active Pipeline revisions: %w", err)
	}
	defer rows.Close()
	var values []devopsv1.PipelineActivation
	for rows.Next() {
		var pipelineDocument, revisionDocument []byte
		if err := rows.Scan(&pipelineDocument, &revisionDocument); err != nil {
			return nil, fmt.Errorf("scan active Pipeline revision: %w", err)
		}
		var value devopsv1.PipelineActivation
		value.APIVersion = devopsv1.APIVersion
		value.Kind = "PipelineActivation"
		if err := decodeDocument("Pipeline", pipelineDocument, &value.Pipeline); err != nil {
			return nil, err
		}
		if err := decodeDocument("PipelineRevision", revisionDocument, &value.Revision); err != nil {
			return nil, err
		}
		if err := devopsv1.ValidatePipelineActivation(value); err != nil {
			return nil, fmt.Errorf("validate matching active Pipeline revision: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active Pipeline revisions: %w", err)
	}
	return values, nil
}

func (transaction *admissionTransaction) QueuedRunCount(ctx context.Context) (uint64, error) {
	var count int64
	if err := transaction.tx.QueryRow(ctx,
		`SELECT count(*) FROM delivery.pipeline_runs
		  WHERE tenant_id = $1 AND state = 'QUEUED'`,
		string(transaction.tenantID),
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count queued PipelineRuns: %w", err)
	}
	if count < 0 {
		return 0, errors.New("queued PipelineRun count is negative")
	}
	return uint64(count), nil
}
