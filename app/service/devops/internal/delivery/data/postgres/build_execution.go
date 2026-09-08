package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/buildexecution"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

var _ buildexecution.Repository = (*BuildExecutionRepository)(nil)

// BuildExecutionRepository is the table-blind PostgreSQL boundary for fenced
// VERIFY commands and their normalized executor receipts.
type BuildExecutionRepository struct {
	pool *pgxpool.Pool
}

func NewBuildExecutionRepository(
	pool *pgxpool.Pool,
) (*BuildExecutionRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &BuildExecutionRepository{pool: pool}, nil
}

func (repository *BuildExecutionRepository) Heartbeat(
	ctx context.Context,
	workerID string,
) (time.Time, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return time.Time{}, errors.New("build worker heartbeat repository is unavailable")
	}
	if devopsv1.ValidateID("buildWorker.workerId", workerID) != nil {
		return time.Time{}, errors.New("build worker heartbeat identity is invalid")
	}
	var observedAt time.Time
	if err := repository.pool.QueryRow(
		ctx, `SELECT delivery.record_build_worker_heartbeat($1)`, workerID,
	).Scan(&observedAt); err != nil {
		return time.Time{}, fmt.Errorf("record build worker heartbeat: %w", err)
	}
	return observedAt.UTC(), nil
}

func (repository *BuildExecutionRepository) Claim(
	ctx context.Context,
	workerID string,
	leaseDuration time.Duration,
) (buildexecution.Command, bool, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return buildexecution.Command{}, false,
			errors.New("build execution repository is unavailable")
	}
	if devopsv1.ValidateID("buildWorker.workerId", workerID) != nil ||
		leaseDuration != buildexecution.LeaseDuration {
		return buildexecution.Command{}, false,
			errors.New("build execution claim is invalid")
	}

	var (
		command          buildexecution.Command
		runID            string
		commandID        string
		inputDigest      string
		stage            string
		mode             string
		runDocument      []byte
		revisionDocument []byte
		archiveDocument  []byte
	)
	err := repository.pool.QueryRow(
		ctx,
		`SELECT tenant_id, run_id, command_id, input_digest, stage, attempt,
		        claim_mode, fencing_token, lease_expires_at,
		        reconciliation_attempts, run_document,
		        pipeline_revision_document, source_archive_document,
		        started_at, deadline_at
		   FROM delivery.claim_build_task($1, $2)`,
		workerID,
		int(leaseDuration/time.Second),
	).Scan(
		&command.Lease.TenantID,
		&runID,
		&commandID,
		&inputDigest,
		&stage,
		&command.Lease.Intent.Attempt,
		&mode,
		&command.Lease.FencingToken,
		&command.Lease.LeaseExpiresAt,
		&command.Lease.ReconciliationAttempts,
		&runDocument,
		&revisionDocument,
		&archiveDocument,
		&command.StartedAt,
		&command.DeadlineAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return buildexecution.Command{}, false, nil
	}
	if err != nil {
		return buildexecution.Command{}, false,
			fmt.Errorf("claim build task: %w", err)
	}

	command.Lease.WorkerID = workerID
	command.Lease.Mode = runlifecycle.ClaimMode(mode)
	command.Lease.LeaseExpiresAt = command.Lease.LeaseExpiresAt.UTC()
	command.Lease.Intent.CommandID = commandID
	command.Lease.Intent.RunID = devopsv1.ResourceID(runID)
	command.Lease.Intent.InputDigest = inputDigest
	command.Lease.Intent.Stage = devopsv1.PipelineRunStage(stage)
	command.StartedAt = command.StartedAt.UTC()
	command.DeadlineAt = command.DeadlineAt.UTC()
	if err := decodeDocument("PipelineRun", runDocument, &command.Lease.Run); err != nil {
		return buildexecution.Command{}, false, err
	}
	if err := decodeDocument(
		"PipelineRevision", revisionDocument, &command.Revision,
	); err != nil {
		return buildexecution.Command{}, false, err
	}
	if err := decodeDocument(
		"source archive receipt", archiveDocument, &command.Archive,
	); err != nil {
		return buildexecution.Command{}, false, err
	}
	if err := buildexecution.ValidateCommand(command); err != nil {
		return buildexecution.Command{}, false,
			fmt.Errorf("validate claimed build task: %w", err)
	}
	return command, true, nil
}

func (repository *BuildExecutionRepository) Renew(
	ctx context.Context,
	guard runlifecycle.LeaseGuard,
	leaseDuration time.Duration,
) (time.Time, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return time.Time{}, errors.New("build execution repository is unavailable")
	}
	if err := runlifecycle.ValidateLeaseGuard(guard); err != nil {
		return time.Time{}, err
	}
	if leaseDuration != buildexecution.LeaseDuration {
		return time.Time{}, errors.New("build execution lease duration is invalid")
	}
	var expiresAt time.Time
	err := repository.pool.QueryRow(
		ctx,
		`SELECT delivery.renew_build_task($1, $2, $3, $4, $5, $6)`,
		guard.TenantID,
		guard.RunID,
		guard.CommandID,
		guard.WorkerID,
		int64(guard.FencingToken),
		int(leaseDuration/time.Second),
	).Scan(&expiresAt)
	if err != nil {
		return time.Time{}, mapRunLifecycleError("renew build task", err)
	}
	return expiresAt.UTC(), nil
}

func (repository *BuildExecutionRepository) Complete(
	ctx context.Context,
	completion buildexecution.Completion,
) (devopsv1.PipelineRun, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return devopsv1.PipelineRun{}, errors.New("build execution repository is unavailable")
	}
	if err := buildexecution.ValidateCompletion(completion); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("begin build completion: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	_, runDocument, auditDocument, reason, err := prepareRunTransition(
		ctx,
		tx,
		completion.Command.Lease,
		completion.State,
		completion.Reason,
	)
	if err != nil {
		return devopsv1.PipelineRun{}, err
	}
	var receiptDocument any
	if completion.Receipt != nil {
		receiptDocument, err = json.Marshal(completion.Receipt)
		if err != nil {
			return devopsv1.PipelineRun{}, fmt.Errorf("encode build receipt: %w", err)
		}
	}
	lease := completion.Command.Lease
	var storedDocument []byte
	err = tx.QueryRow(
		ctx,
		`SELECT delivery.complete_build_task(
		    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)`,
		lease.TenantID,
		lease.Run.ID,
		lease.Intent.CommandID,
		lease.WorkerID,
		int64(lease.FencingToken),
		completion.State,
		reason,
		receiptDocument,
		runDocument,
		auditDocument,
	).Scan(&storedDocument)
	if err != nil {
		return devopsv1.PipelineRun{}, mapRunLifecycleError("complete build task", err)
	}
	updated, err := decodePipelineRun(storedDocument)
	if err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return devopsv1.PipelineRun{}, mapRunLifecycleError("commit build completion", err)
	}
	return updated, nil
}

func (repository *BuildExecutionRepository) Readiness(
	ctx context.Context,
) (devopsv1.Readiness, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return devopsv1.Readiness{}, errors.New("build worker readiness repository is unavailable")
	}
	return readReadiness(
		ctx,
		repository.pool,
		"SELECT * FROM delivery.build_worker_readiness()",
	)
}
