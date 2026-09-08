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
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceacquisition"
)

var _ sourceacquisition.Repository = (*SourceAcquisitionRepository)(nil)

// SourceAcquisitionRepository is the table-blind PostgreSQL boundary used by
// the dedicated source-fetcher login. It can coordinate only FETCH commands.
type SourceAcquisitionRepository struct {
	pool *pgxpool.Pool
}

func NewSourceAcquisitionRepository(
	pool *pgxpool.Pool,
) (*SourceAcquisitionRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &SourceAcquisitionRepository{pool: pool}, nil
}

func (repository *SourceAcquisitionRepository) Heartbeat(
	ctx context.Context,
	workerID string,
) (time.Time, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return time.Time{}, errors.New("source fetcher heartbeat repository is unavailable")
	}
	if devopsv1.ValidateID("sourceFetcher.workerId", workerID) != nil {
		return time.Time{}, errors.New("source fetcher heartbeat identity is invalid")
	}
	var observedAt time.Time
	if err := repository.pool.QueryRow(
		ctx, `SELECT delivery.record_source_fetcher_heartbeat($1)`, workerID,
	).Scan(&observedAt); err != nil {
		return time.Time{}, fmt.Errorf("record source fetcher heartbeat: %w", err)
	}
	return observedAt.UTC(), nil
}

func (repository *SourceAcquisitionRepository) Claim(
	ctx context.Context,
	workerID string,
	leaseDuration time.Duration,
) (sourceacquisition.Command, bool, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return sourceacquisition.Command{}, false,
			errors.New("source acquisition repository is unavailable")
	}
	if devopsv1.ValidateID("sourceFetcher.workerId", workerID) != nil ||
		leaseDuration != sourceacquisition.LeaseDuration {
		return sourceacquisition.Command{}, false,
			errors.New("source acquisition claim is invalid")
	}

	var (
		command          sourceacquisition.Command
		runID            string
		commandID        string
		inputDigest      string
		stage            string
		mode             string
		runDocument      []byte
		connection       []byte
		bindingRevision  []byte
		pipelineRevision []byte
		sourceEvent      []byte
	)
	err := repository.pool.QueryRow(
		ctx,
		`SELECT tenant_id, run_id, command_id, input_digest, stage, attempt,
		        claim_mode, fencing_token, lease_expires_at,
		        reconciliation_attempts, run_document, connection_document,
		        binding_revision_document, pipeline_revision_document,
		        source_event_document
		   FROM delivery.claim_source_fetch_task($1, $2)`,
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
		&sourceEvent,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return sourceacquisition.Command{}, false, nil
	}
	if err != nil {
		return sourceacquisition.Command{}, false,
			fmt.Errorf("claim source fetch task: %w", err)
	}

	command.Lease.WorkerID = workerID
	command.Lease.Mode = runlifecycle.ClaimMode(mode)
	command.Lease.LeaseExpiresAt = command.Lease.LeaseExpiresAt.UTC()
	command.Lease.Intent.CommandID = commandID
	command.Lease.Intent.RunID = devopsv1.ResourceID(runID)
	command.Lease.Intent.InputDigest = inputDigest
	command.Lease.Intent.Stage = devopsv1.PipelineRunStage(stage)
	if err := decodeDocument("PipelineRun", runDocument, &command.Lease.Run); err != nil {
		return sourceacquisition.Command{}, false, err
	}
	if err := decodeDocument("SourceConnection", connection, &command.Connection); err != nil {
		return sourceacquisition.Command{}, false, err
	}
	if err := decodeDocument(
		"RepositoryBinding", bindingRevision, &command.BindingRevision,
	); err != nil {
		return sourceacquisition.Command{}, false, err
	}
	if err := decodeDocument(
		"PipelineRevision", pipelineRevision, &command.Revision,
	); err != nil {
		return sourceacquisition.Command{}, false, err
	}
	if err := decodeDocument("SourceEvent", sourceEvent, &command.Event); err != nil {
		return sourceacquisition.Command{}, false, err
	}
	if err := sourceacquisition.ValidateCommand(command); err != nil {
		return sourceacquisition.Command{}, false,
			fmt.Errorf("validate claimed source fetch task: %w", err)
	}
	return command, true, nil
}

func (repository *SourceAcquisitionRepository) Renew(
	ctx context.Context,
	guard runlifecycle.LeaseGuard,
	leaseDuration time.Duration,
) (time.Time, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return time.Time{}, errors.New("source acquisition repository is unavailable")
	}
	if err := runlifecycle.ValidateLeaseGuard(guard); err != nil {
		return time.Time{}, err
	}
	if leaseDuration != sourceacquisition.LeaseDuration {
		return time.Time{}, errors.New("source acquisition lease duration is invalid")
	}
	var expiresAt time.Time
	err := repository.pool.QueryRow(
		ctx,
		`SELECT delivery.renew_source_fetch_task($1, $2, $3, $4, $5, $6)`,
		guard.TenantID,
		guard.RunID,
		guard.CommandID,
		guard.WorkerID,
		int64(guard.FencingToken),
		int(leaseDuration/time.Second),
	).Scan(&expiresAt)
	if err != nil {
		return time.Time{}, mapRunLifecycleError("renew source fetch task", err)
	}
	return expiresAt.UTC(), nil
}

func (repository *SourceAcquisitionRepository) Complete(
	ctx context.Context,
	completion sourceacquisition.Completion,
) (devopsv1.PipelineRun, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return devopsv1.PipelineRun{}, errors.New("source acquisition repository is unavailable")
	}
	if err := sourceacquisition.ValidateCompletion(completion); err != nil {
		return devopsv1.PipelineRun{}, err
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return devopsv1.PipelineRun{}, fmt.Errorf("begin source fetch completion: %w", err)
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
			return devopsv1.PipelineRun{}, fmt.Errorf("encode source archive receipt: %w", err)
		}
	}
	lease := completion.Command.Lease
	var storedDocument []byte
	err = tx.QueryRow(
		ctx,
		`SELECT delivery.complete_source_fetch_task(
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
		return devopsv1.PipelineRun{}, mapRunLifecycleError("complete source fetch task", err)
	}
	updated, err := decodePipelineRun(storedDocument)
	if err != nil {
		return devopsv1.PipelineRun{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return devopsv1.PipelineRun{},
			mapRunLifecycleError("commit source fetch completion", err)
	}
	return updated, nil
}

func (repository *SourceAcquisitionRepository) Readiness(
	ctx context.Context,
) (devopsv1.Readiness, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return devopsv1.Readiness{}, errors.New("source fetcher readiness repository is unavailable")
	}
	return readReadiness(
		ctx,
		repository.pool,
		"SELECT * FROM delivery.source_fetcher_readiness()",
	)
}
