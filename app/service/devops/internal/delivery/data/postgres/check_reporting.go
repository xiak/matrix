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
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/checkreporting"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

var _ checkreporting.Repository = (*CheckReportingRepository)(nil)

// CheckReportingRepository is the table-blind PostgreSQL boundary for fenced
// REPORT commands and normalized provider receipts.
type CheckReportingRepository struct {
	pool *pgxpool.Pool
}

func NewCheckReportingRepository(
	pool *pgxpool.Pool,
) (*CheckReportingRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &CheckReportingRepository{pool: pool}, nil
}

func (repository *CheckReportingRepository) Heartbeat(
	ctx context.Context,
	workerID string,
) (time.Time, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return time.Time{}, errors.New("check reporter heartbeat repository is unavailable")
	}
	if devopsv1.ValidateID("checkReporter.workerId", workerID) != nil {
		return time.Time{}, errors.New("check reporter heartbeat identity is invalid")
	}
	var observedAt time.Time
	if err := repository.pool.QueryRow(
		ctx, `SELECT delivery.record_check_reporter_heartbeat($1)`, workerID,
	).Scan(&observedAt); err != nil {
		return time.Time{}, fmt.Errorf("record check reporter heartbeat: %w", err)
	}
	return observedAt.UTC(), nil
}

func (repository *CheckReportingRepository) Claim(
	ctx context.Context,
	workerID string,
	leaseDuration time.Duration,
) (checkreporting.Command, bool, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return checkreporting.Command{}, false,
			errors.New("check reporting repository is unavailable")
	}
	if devopsv1.ValidateID("checkReporter.workerId", workerID) != nil ||
		leaseDuration != checkreporting.LeaseDuration {
		return checkreporting.Command{}, false,
			errors.New("check reporting claim is invalid")
	}

	var (
		command          checkreporting.Command
		runID            string
		commandID        string
		inputDigest      string
		stage            string
		mode             string
		runDocument      []byte
		connection       []byte
		bindingRevision  []byte
		pipelineRevision []byte
		buildReceipt     []byte
	)
	err := repository.pool.QueryRow(
		ctx,
		`SELECT tenant_id, run_id, command_id, input_digest, stage, attempt,
		        claim_mode, fencing_token, lease_expires_at,
		        reconciliation_attempts, run_document, connection_document,
		        binding_revision_document, pipeline_revision_document,
		        build_receipt_document
		   FROM delivery.claim_check_report_task($1, $2)`,
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
		&connection,
		&bindingRevision,
		&pipelineRevision,
		&buildReceipt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return checkreporting.Command{}, false, nil
	}
	if err != nil {
		return checkreporting.Command{}, false,
			fmt.Errorf("claim check report task: %w", err)
	}

	command.Lease.WorkerID = workerID
	command.Lease.Mode = runlifecycle.ClaimMode(mode)
	command.Lease.LeaseExpiresAt = command.Lease.LeaseExpiresAt.UTC()
	command.Lease.Intent.CommandID = commandID
	command.Lease.Intent.RunID = devopsv1.ResourceID(runID)
	command.Lease.Intent.InputDigest = inputDigest
	command.Lease.Intent.Stage = devopsv1.PipelineRunStage(stage)
	if err := decodeDocument("PipelineRun", runDocument, &command.Lease.Run); err != nil {
		return checkreporting.Command{}, false, err
	}
	if err := decodeDocument("SourceConnection", connection, &command.Connection); err != nil {
		return checkreporting.Command{}, false, err
	}
	if err := decodeDocument(
		"RepositoryBinding", bindingRevision, &command.BindingRevision,
	); err != nil {
		return checkreporting.Command{}, false, err
	}
	if err := decodeDocument(
		"PipelineRevision", pipelineRevision, &command.Revision,
	); err != nil {
		return checkreporting.Command{}, false, err
	}
	if err := decodeDocument(
		"build receipt", buildReceipt, &command.BuildReceipt,
	); err != nil {
		return checkreporting.Command{}, false, err
	}
	if err := checkreporting.ValidateCommand(command); err != nil {
		return checkreporting.Command{}, false,
			fmt.Errorf("validate claimed check report task: %w", err)
	}
	return command, true, nil
}

func (repository *CheckReportingRepository) Complete(
	ctx context.Context,
	completion checkreporting.Completion,
) (devopsv1.PipelineRun, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return devopsv1.PipelineRun{}, errors.New("check reporting repository is unavailable")
	}
	if err := checkreporting.ValidateCompletion(completion); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("begin check report completion: %w", err)
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
			return devopsv1.PipelineRun{}, fmt.Errorf("encode check receipt: %w", err)
		}
	}
	lease := completion.Command.Lease
	var storedDocument []byte
	err = tx.QueryRow(
		ctx,
		`SELECT delivery.complete_check_report_task(
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
		return devopsv1.PipelineRun{}, mapRunLifecycleError("complete check report task", err)
	}
	updated, err := decodePipelineRun(storedDocument)
	if err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return devopsv1.PipelineRun{},
			mapRunLifecycleError("commit check report completion", err)
	}
	return updated, nil
}

func (repository *CheckReportingRepository) MarkUncertain(
	ctx context.Context,
	reconciliation runlifecycle.Reconciliation,
) (devopsv1.PipelineRun, error) {
	if err := repository.validateReconciliation(ctx, reconciliation); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	var document []byte
	err := repository.pool.QueryRow(
		ctx,
		`SELECT delivery.mark_pipeline_run_report_uncertain($1, $2, $3, $4, $5, $6)`,
		reconciliation.Lease.TenantID,
		reconciliation.Lease.Run.ID,
		reconciliation.Lease.Intent.CommandID,
		reconciliation.Lease.WorkerID,
		int64(reconciliation.Lease.FencingToken),
		reconciliation.NextAttemptAt,
	).Scan(&document)
	if err != nil {
		return devopsv1.PipelineRun{}, mapRunLifecycleError("mark check report uncertain", err)
	}
	return decodePipelineRun(document)
}

func (repository *CheckReportingRepository) Defer(
	ctx context.Context,
	reconciliation runlifecycle.Reconciliation,
) (uint64, error) {
	if err := repository.validateReconciliation(ctx, reconciliation); err != nil {
		return 0, err
	}
	var attempts uint64
	err := repository.pool.QueryRow(
		ctx,
		`SELECT delivery.defer_pipeline_run_reconciliation($1, $2, $3, $4, $5, $6)`,
		reconciliation.Lease.TenantID,
		reconciliation.Lease.Run.ID,
		reconciliation.Lease.Intent.CommandID,
		reconciliation.Lease.WorkerID,
		int64(reconciliation.Lease.FencingToken),
		reconciliation.NextAttemptAt,
	).Scan(&attempts)
	if err != nil {
		return 0, mapRunLifecycleError("defer check report reconciliation", err)
	}
	return attempts, nil
}

func (repository *CheckReportingRepository) Readiness(
	ctx context.Context,
) (devopsv1.Readiness, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return devopsv1.Readiness{}, errors.New("check reporter readiness repository is unavailable")
	}
	return readReadiness(
		ctx,
		repository.pool,
		"SELECT * FROM delivery.check_reporter_readiness()",
	)
}

func (repository *CheckReportingRepository) validateReconciliation(
	ctx context.Context,
	reconciliation runlifecycle.Reconciliation,
) error {
	if repository == nil || repository.pool == nil || ctx == nil {
		return errors.New("check reporting repository is unavailable")
	}
	if err := runlifecycle.ValidateLease(reconciliation.Lease); err != nil {
		return err
	}
	return validateDatabaseDeferral(reconciliation.NextAttemptAt)
}
