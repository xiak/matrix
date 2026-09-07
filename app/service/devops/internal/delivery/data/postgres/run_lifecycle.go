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

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runaudit"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

var _ runlifecycle.Repository = (*RunTaskRepository)(nil)

type RunTaskRepository struct {
	pool *pgxpool.Pool
}

func NewRunTaskRepository(pool *pgxpool.Pool) (*RunTaskRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &RunTaskRepository{pool: pool}, nil
}

func (repository *RunTaskRepository) Claim(
	ctx context.Context,
	workerID string,
	leaseDuration time.Duration,
) (runlifecycle.Lease, bool, error) {
	if repository == nil || repository.pool == nil {
		return runlifecycle.Lease{}, false, errors.New("PipelineRun task repository is nil")
	}
	if ctx == nil {
		return runlifecycle.Lease{}, false, errors.New("PipelineRun task claim context is nil")
	}
	if err := devopsv1.ValidateID("workerId", workerID); err != nil {
		return runlifecycle.Lease{}, false, err
	}
	if leaseDuration < time.Second || leaseDuration > 5*time.Minute ||
		leaseDuration%time.Second != 0 {
		return runlifecycle.Lease{}, false, errors.New("PipelineRun task lease duration is invalid")
	}

	var (
		lease       runlifecycle.Lease
		runID       string
		commandID   string
		inputDigest string
		stage       string
		mode        string
		document    []byte
	)
	err := repository.pool.QueryRow(
		ctx,
		`SELECT tenant_id, run_id, command_id, input_digest, stage, attempt,
		        claim_mode, fencing_token, lease_expires_at,
		        reconciliation_attempts, run_document
		   FROM delivery.claim_pipeline_run_task($1, $2)`,
		workerID,
		int(leaseDuration/time.Second),
	).Scan(
		&lease.TenantID,
		&runID,
		&commandID,
		&inputDigest,
		&stage,
		&lease.Intent.Attempt,
		&mode,
		&lease.FencingToken,
		&lease.LeaseExpiresAt,
		&lease.ReconciliationAttempts,
		&document,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return runlifecycle.Lease{}, false, nil
	}
	if err != nil {
		return runlifecycle.Lease{}, false, fmt.Errorf("claim PipelineRun task: %w", err)
	}
	lease.WorkerID = workerID
	lease.Mode = runlifecycle.ClaimMode(mode)
	lease.LeaseExpiresAt = lease.LeaseExpiresAt.UTC()
	lease.Intent.CommandID = commandID
	lease.Intent.RunID = devopsv1.ResourceID(runID)
	lease.Intent.InputDigest = inputDigest
	lease.Intent.Stage = devopsv1.PipelineRunStage(stage)
	if err := decodeDocument("PipelineRun", document, &lease.Run); err != nil {
		return runlifecycle.Lease{}, false, err
	}
	if err := runlifecycle.ValidateLease(lease); err != nil {
		return runlifecycle.Lease{}, false, fmt.Errorf("validate claimed PipelineRun task: %w", err)
	}
	return lease, true, nil
}

func (repository *RunTaskRepository) Renew(
	ctx context.Context,
	guard runlifecycle.LeaseGuard,
	leaseDuration time.Duration,
) (time.Time, error) {
	if repository == nil || repository.pool == nil {
		return time.Time{}, errors.New("PipelineRun task repository is nil")
	}
	if ctx == nil {
		return time.Time{}, errors.New("PipelineRun task renewal context is nil")
	}
	if err := runlifecycle.ValidateLeaseGuard(guard); err != nil {
		return time.Time{}, err
	}
	if leaseDuration < time.Second || leaseDuration > 5*time.Minute ||
		leaseDuration%time.Second != 0 {
		return time.Time{}, errors.New("PipelineRun task lease duration is invalid")
	}
	var expiresAt time.Time
	err := repository.pool.QueryRow(
		ctx,
		`SELECT delivery.renew_pipeline_run_task($1, $2, $3, $4, $5, $6)`,
		guard.TenantID,
		guard.RunID,
		guard.CommandID,
		guard.WorkerID,
		int64(guard.FencingToken),
		int(leaseDuration/time.Second),
	).Scan(&expiresAt)
	if err != nil {
		return time.Time{}, mapRunLifecycleError("renew PipelineRun task", err)
	}
	return expiresAt.UTC(), nil
}

func (repository *RunTaskRepository) Advance(
	ctx context.Context,
	transition runlifecycle.Transition,
) (devopsv1.PipelineRun, error) {
	if err := repository.validateMutation(ctx, transition.Lease); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if err := domain.ValidatePipelineRunTransition(
		transition.Lease.Run.Status.State,
		transition.State,
		transition.Reason,
	); err != nil || transition.State == devopsv1.PipelineRunReconciling {
		return devopsv1.PipelineRun{}, fmt.Errorf("advance PipelineRun task: %w", runlifecycle.ErrInvalidTransition)
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("begin PipelineRun task transition: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var effectiveNow time.Time
	if err := tx.QueryRow(
		ctx,
		`SELECT greatest(transaction_timestamp(), $1::timestamptz + interval '1 microsecond')`,
		transition.Lease.Run.UpdatedAt,
	).Scan(&effectiveNow); err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("read PipelineRun transition time: %w", err)
	}
	effectiveNow = effectiveNow.UTC()
	expected, err := domain.AdvancePipelineRun(
		transition.Lease.Run, transition.State, transition.Reason, effectiveNow,
	)
	if err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("advance PipelineRun task: %w", runlifecycle.ErrInvalidTransition)
	}
	runDocument, err := json.Marshal(expected)
	if err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("encode PipelineRun transition: %w", err)
	}
	var auditDocument any
	if expected.Status.CompletedAt != nil {
		event, eventErr := runaudit.NewTerminalEvent(
			expected, transition.Lease.Intent.CommandID, runaudit.WorkerActorID,
		)
		if eventErr != nil {
			return devopsv1.PipelineRun{}, fmt.Errorf("build PipelineRun terminal Audit fact: %w", eventErr)
		}
		auditDocument, err = json.Marshal(event)
		if err != nil {
			return devopsv1.PipelineRun{}, fmt.Errorf("encode PipelineRun terminal Audit fact: %w", err)
		}
	}
	var reason any
	if transition.Reason != "" {
		reason = transition.Reason
	}
	var document []byte
	err = tx.QueryRow(
		ctx,
		`SELECT delivery.advance_pipeline_run_task($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		transition.Lease.TenantID,
		transition.Lease.Run.ID,
		transition.Lease.Intent.CommandID,
		transition.Lease.WorkerID,
		int64(transition.Lease.FencingToken),
		transition.State,
		reason,
		runDocument,
		auditDocument,
	).Scan(&document)
	if err != nil {
		return devopsv1.PipelineRun{}, mapRunLifecycleError("advance PipelineRun task", err)
	}
	updated, err := decodePipelineRun(document)
	if err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return devopsv1.PipelineRun{}, mapRunLifecycleError("commit PipelineRun task transition", err)
	}
	return updated, nil
}

func (repository *RunTaskRepository) MarkReportUncertain(
	ctx context.Context,
	reconciliation runlifecycle.Reconciliation,
) (devopsv1.PipelineRun, error) {
	if err := repository.validateMutation(ctx, reconciliation.Lease); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if err := validateDatabaseDeferral(reconciliation.NextAttemptAt); err != nil {
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
		return devopsv1.PipelineRun{}, mapRunLifecycleError("mark PipelineRun report uncertain", err)
	}
	return decodePipelineRun(document)
}

func (repository *RunTaskRepository) DeferReconciliation(
	ctx context.Context,
	reconciliation runlifecycle.Reconciliation,
) (uint64, error) {
	if err := repository.validateMutation(ctx, reconciliation.Lease); err != nil {
		return 0, err
	}
	if err := validateDatabaseDeferral(reconciliation.NextAttemptAt); err != nil {
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
		return 0, mapRunLifecycleError("defer PipelineRun reconciliation", err)
	}
	return attempts, nil
}

func (repository *RunTaskRepository) validateMutation(ctx context.Context, lease runlifecycle.Lease) error {
	if repository == nil || repository.pool == nil {
		return errors.New("PipelineRun task repository is nil")
	}
	if ctx == nil {
		return errors.New("PipelineRun task mutation context is nil")
	}
	return runlifecycle.ValidateLease(lease)
}

func decodePipelineRun(document []byte) (devopsv1.PipelineRun, error) {
	var run devopsv1.PipelineRun
	if err := decodeDocument("PipelineRun", document, &run); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if err := devopsv1.ValidatePipelineRun(run); err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("validate stored PipelineRun: %w", err)
	}
	return run, nil
}

func validateDatabaseDeferral(value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return errors.New("PipelineRun next observation time is invalid")
	}
	return nil
}

func mapRunLifecycleError(action string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "MX412":
			return fmt.Errorf("%s: %w", action, runlifecycle.ErrStaleLease)
		case "MX410":
			return fmt.Errorf("%s: %w", action, runlifecycle.ErrReconciliationExhausted)
		case "55000":
			return fmt.Errorf("%s: %w", action, runlifecycle.ErrInvalidTransition)
		}
	}
	return fmt.Errorf("%s: %w", action, err)
}
