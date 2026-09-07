package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runcontrol"
)

type runControlTransaction struct {
	configurationTransaction
}

func (transaction *runControlTransaction) FindCancellation(
	ctx context.Context,
	fingerprint string,
) (runcontrol.StoredCancellation, bool, error) {
	if err := devopsv1.ValidateDigest("idempotencyFingerprint", fingerprint); err != nil {
		return runcontrol.StoredCancellation{}, false, err
	}
	var (
		id, kind, commandTargetID, targetKind, targetID string
		requestDigest, resultKind                       string
		createdAt                                       time.Time
		operationDocument, resultDocument               []byte
	)
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT id, mutation_kind, command_target_id, target_kind, target_id,
		        request_digest, result_kind, created_at, document, result_document
		   FROM delivery.mutations
		  WHERE tenant_id = $1 AND idempotency_fingerprint = $2`,
		string(transaction.tenantID), fingerprint,
	).Scan(
		&id, &kind, &commandTargetID, &targetKind, &targetID,
		&requestDigest, &resultKind, &createdAt, &operationDocument, &resultDocument,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return runcontrol.StoredCancellation{}, false, nil
	}
	if err != nil {
		return runcontrol.StoredCancellation{}, false, fmt.Errorf("find PipelineRun cancellation replay: %w", err)
	}
	if kind != "CANCEL_PIPELINE_RUN" {
		return runcontrol.StoredCancellation{}, false, runcontrol.ErrIdempotencyConflict
	}
	var stored runcontrol.StoredCancellation
	if err := decodeDocument("CancellationOperation", operationDocument, &stored.Operation); err != nil {
		return runcontrol.StoredCancellation{}, false, err
	}
	if err := decodeDocument("PipelineRun cancellation result", resultDocument, &stored.Result); err != nil {
		return runcontrol.StoredCancellation{}, false, err
	}
	if err := runcontrol.ValidateStoredCancellation(stored); err != nil {
		return runcontrol.StoredCancellation{}, false, fmt.Errorf("validate stored PipelineRun cancellation: %w", err)
	}
	operation := stored.Operation
	if operation.ID != id || operation.TenantID != transaction.tenantID ||
		operation.Kind != kind || string(operation.CommandTargetID) != commandTargetID ||
		string(operation.Target.Kind) != targetKind || operation.Target.ID != targetID ||
		operation.IdempotencyFingerprint != fingerprint || operation.RequestDigest != requestDigest ||
		operation.ResultKind != resultKind || !operation.CreatedAt.Equal(createdAt.UTC()) {
		return runcontrol.StoredCancellation{}, false, errors.New("stored PipelineRun cancellation relational identity mismatch")
	}
	return stored, true, nil
}

func (transaction *runControlTransaction) LoadPipelineRun(
	ctx context.Context,
	id devopsv1.ResourceID,
) (devopsv1.PipelineRun, bool, error) {
	if err := devopsv1.ValidateID("runId", string(id)); err != nil {
		return devopsv1.PipelineRun{}, false, err
	}
	var (
		state, stage string
		reason       *string
		version      uint64
		cancelledAt  *time.Time
		completedAt  *time.Time
		updatedAt    time.Time
		document     []byte
	)
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT state, stage, reason, resource_version,
		        cancellation_requested_at, completed_at, updated_at, document
		   FROM delivery.pipeline_runs
		  WHERE tenant_id = $1 AND id = $2`,
		string(transaction.tenantID), string(id),
	).Scan(&state, &stage, &reason, &version, &cancelledAt, &completedAt, &updatedAt, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return devopsv1.PipelineRun{}, false, nil
	}
	if err != nil {
		return devopsv1.PipelineRun{}, false, fmt.Errorf("load PipelineRun: %w", err)
	}
	run, err := decodePipelineRun(document)
	if err != nil {
		return devopsv1.PipelineRun{}, false, err
	}
	reasonValue := ""
	if reason != nil {
		reasonValue = *reason
	}
	if run.ID != id || run.Scope.TenantID != transaction.tenantID ||
		string(run.Status.State) != state || string(run.Status.Stage) != stage ||
		string(run.Status.Reason) != reasonValue || run.Status.ResourceVersion != version ||
		!run.UpdatedAt.Equal(updatedAt.UTC()) ||
		!equalOptionalTime(run.Status.CancellationRequestedAt, cancelledAt) ||
		!equalOptionalTime(run.Status.CompletedAt, completedAt) {
		return devopsv1.PipelineRun{}, false, errors.New("stored PipelineRun relational identity mismatch")
	}
	return run, true, nil
}

func (transaction *runControlTransaction) LockPipelineRunForCancellation(
	ctx context.Context,
	id devopsv1.ResourceID,
) (devopsv1.PipelineRun, bool, bool, error) {
	if err := devopsv1.ValidateID("runId", string(id)); err != nil {
		return devopsv1.PipelineRun{}, false, false, err
	}
	var document []byte
	var effectMayExist bool
	err := transaction.tx.QueryRow(
		ctx,
		`SELECT run_document, effect_may_exist
		   FROM delivery.lock_pipeline_run_for_cancellation($1)`,
		string(id),
	).Scan(&document, &effectMayExist)
	if errors.Is(err, pgx.ErrNoRows) {
		return devopsv1.PipelineRun{}, false, false, nil
	}
	if err != nil {
		return devopsv1.PipelineRun{}, false, false, fmt.Errorf("lock PipelineRun for cancellation: %w", err)
	}
	run, err := decodePipelineRun(document)
	if err != nil {
		return devopsv1.PipelineRun{}, false, false, err
	}
	if run.ID != id || run.Scope.TenantID != transaction.tenantID {
		return devopsv1.PipelineRun{}, false, false, errors.New("locked PipelineRun identity mismatch")
	}
	return run, effectMayExist, true, nil
}

func (transaction *runControlTransaction) CommitPipelineRunCancellation(
	ctx context.Context,
	expectedResourceVersion uint64,
	submission runcontrol.Submission,
) error {
	if expectedResourceVersion == 0 || expectedResourceVersion > devopsv1.MaximumContractInteger {
		return errors.New("PipelineRun cancellation expected resource version is invalid")
	}
	if err := runcontrol.ValidateSubmission(submission); err != nil {
		return fmt.Errorf("validate PipelineRun cancellation submission: %w", err)
	}
	if submission.Operation.TenantID != transaction.tenantID ||
		submission.Operation.ExpectedResourceVersion != expectedResourceVersion {
		return errors.New("PipelineRun cancellation differs from transaction identity")
	}
	runDocument, err := json.Marshal(submission.Result)
	if err != nil {
		return fmt.Errorf("encode PipelineRun cancellation result: %w", err)
	}
	operationDocument, err := json.Marshal(submission.Operation)
	if err != nil {
		return fmt.Errorf("encode PipelineRun cancellation Operation: %w", err)
	}
	cancellationEventDocument, err := json.Marshal(submission.CancellationEvent)
	if err != nil {
		return fmt.Errorf("encode PipelineRun cancellation Audit fact: %w", err)
	}
	var terminalEventDocument any
	if submission.TerminalEvent != nil {
		terminalEventDocument, err = json.Marshal(*submission.TerminalEvent)
		if err != nil {
			return fmt.Errorf("encode PipelineRun cancellation terminal Audit fact: %w", err)
		}
	}
	if _, err := transaction.tx.Exec(
		ctx,
		`SELECT delivery.commit_pipeline_run_cancellation(
		    $1, $2::jsonb, $3::jsonb, $4::jsonb, $5::jsonb
		)`,
		int64(expectedResourceVersion), runDocument, operationDocument,
		cancellationEventDocument, terminalEventDocument,
	); err != nil {
		return fmt.Errorf("commit PipelineRun cancellation: %w", err)
	}
	return nil
}

func equalOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(right.UTC())
}
