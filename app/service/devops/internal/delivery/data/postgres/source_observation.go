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
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceobservation"
)

var _ sourceobservation.Repository = (*SourceObservationRepository)(nil)

type SourceObservationRepository struct {
	pool *pgxpool.Pool
}

func NewSourceObservationRepository(pool *pgxpool.Pool) (*SourceObservationRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &SourceObservationRepository{pool: pool}, nil
}

func (repository *SourceObservationRepository) Heartbeat(
	ctx context.Context,
	workerID string,
) (time.Time, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return time.Time{}, errors.New("source observer heartbeat repository is unavailable")
	}
	if devopsv1.ValidateID("sourceObserver.workerId", workerID) != nil {
		return time.Time{}, errors.New("source observer heartbeat identity is invalid")
	}
	var observedAt time.Time
	if err := repository.pool.QueryRow(
		ctx, `SELECT delivery.record_source_observer_heartbeat($1)`, workerID,
	).Scan(&observedAt); err != nil {
		return time.Time{}, fmt.Errorf("record source observer heartbeat: %w", err)
	}
	return observedAt.UTC(), nil
}

func (repository *SourceObservationRepository) Claim(
	ctx context.Context,
	workerID string,
	leaseDuration time.Duration,
) (sourceobservation.Lease, bool, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return sourceobservation.Lease{}, false, errors.New("source observation repository is unavailable")
	}
	if devopsv1.ValidateID("sourceObserver.workerId", workerID) != nil ||
		leaseDuration != sourceobservation.LeaseDuration {
		return sourceobservation.Lease{}, false, errors.New("source observation claim is invalid")
	}
	var (
		lease              sourceobservation.Lease
		kind               string
		connectionDocument []byte
		bindingDocument    []byte
	)
	err := repository.pool.QueryRow(
		ctx,
		`SELECT tenant_id, resource_kind, resource_id, resource_version,
		        fencing_token, claimed_at, lease_expires_at,
		        connection_document, binding_document
		   FROM delivery.claim_source_observation($1, $2)`,
		workerID, int(leaseDuration/time.Second),
	).Scan(
		&lease.TenantID,
		&kind,
		&lease.ResourceID,
		&lease.ResourceVersion,
		&lease.FencingToken,
		&lease.ClaimedAt,
		&lease.LeaseExpiresAt,
		&connectionDocument,
		&bindingDocument,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return sourceobservation.Lease{}, false, nil
	}
	if err != nil {
		return sourceobservation.Lease{}, false, fmt.Errorf("claim source observation: %w", err)
	}
	lease.Kind = sourceobservation.WorkKind(kind)
	lease.WorkerID = workerID
	lease.ClaimedAt = lease.ClaimedAt.UTC()
	lease.LeaseExpiresAt = lease.LeaseExpiresAt.UTC()
	if err := decodeDocument("SourceConnection", connectionDocument, &lease.Connection); err != nil {
		return sourceobservation.Lease{}, false, err
	}
	if len(bindingDocument) != 0 {
		var binding devopsv1.RepositoryBinding
		if err := decodeDocument("RepositoryBinding", bindingDocument, &binding); err != nil {
			return sourceobservation.Lease{}, false, err
		}
		lease.Binding = &binding
	}
	if err := sourceobservation.ValidateLease(lease); err != nil {
		return sourceobservation.Lease{}, false,
			fmt.Errorf("validate claimed source observation: %w", err)
	}
	return lease, true, nil
}

func (repository *SourceObservationRepository) CompleteSourceConnection(
	ctx context.Context,
	lease sourceobservation.Lease,
	observation domain.SourceConnectionHealthObservation,
) (devopsv1.SourceConnection, error) {
	if lease.Kind != sourceobservation.WorkSourceConnection || lease.Binding != nil {
		return devopsv1.SourceConnection{}, sourceobservation.ErrInvalidLease
	}
	updated, err := repository.complete(
		ctx, lease,
		func(observedAt time.Time) (any, bool, error) {
			return domain.ObserveSourceConnectionHealth(
				lease.Connection, lease.ResourceVersion, observation, observedAt,
			)
		},
		func(value any) ([]byte, error) {
			event, err := sourceobservation.NewSourceConnectionHealthEvent(
				value.(devopsv1.SourceConnection),
			)
			if err != nil {
				return nil, err
			}
			return json.Marshal(event)
		},
	)
	if err != nil {
		return devopsv1.SourceConnection{}, err
	}
	connection, ok := updated.(devopsv1.SourceConnection)
	if !ok {
		return devopsv1.SourceConnection{}, errors.New("source observation result type is invalid")
	}
	return connection, nil
}

func (repository *SourceObservationRepository) CompleteRepositoryBinding(
	ctx context.Context,
	lease sourceobservation.Lease,
	observation domain.RepositoryBindingHealthObservation,
) (devopsv1.RepositoryBinding, error) {
	if lease.Kind != sourceobservation.WorkRepositoryBinding || lease.Binding == nil {
		return devopsv1.RepositoryBinding{}, sourceobservation.ErrInvalidLease
	}
	updated, err := repository.complete(
		ctx, lease,
		func(observedAt time.Time) (any, bool, error) {
			return domain.ObserveRepositoryBindingHealth(
				*lease.Binding, lease.ResourceVersion, observation, observedAt,
			)
		},
		func(value any) ([]byte, error) {
			event, err := sourceobservation.NewRepositoryBindingHealthEvent(
				value.(devopsv1.RepositoryBinding),
			)
			if err != nil {
				return nil, err
			}
			return json.Marshal(event)
		},
	)
	if err != nil {
		return devopsv1.RepositoryBinding{}, err
	}
	binding, ok := updated.(devopsv1.RepositoryBinding)
	if !ok {
		return devopsv1.RepositoryBinding{}, errors.New("source observation result type is invalid")
	}
	return binding, nil
}

func (repository *SourceObservationRepository) complete(
	ctx context.Context,
	lease sourceobservation.Lease,
	observe func(time.Time) (any, bool, error),
	buildAudit func(any) ([]byte, error),
) (any, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return nil, errors.New("source observation repository is unavailable")
	}
	if err := sourceobservation.ValidateLease(lease); err != nil {
		return nil, err
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin source observation completion: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	targetUpdatedAt := lease.Connection.Metadata.UpdatedAt
	if lease.Binding != nil {
		targetUpdatedAt = lease.Binding.Metadata.UpdatedAt
	}
	var effectiveNow time.Time
	if err := tx.QueryRow(
		ctx,
		`SELECT greatest(transaction_timestamp(), $1::timestamptz + interval '1 microsecond')`,
		targetUpdatedAt,
	).Scan(&effectiveNow); err != nil {
		return nil, fmt.Errorf("read source observation completion time: %w", err)
	}
	effectiveNow = effectiveNow.UTC()
	updated, transitioned, err := observe(effectiveNow)
	if err != nil {
		return nil, fmt.Errorf("apply source health observation: %w", err)
	}
	resourceDocument, err := json.Marshal(updated)
	if err != nil {
		return nil, fmt.Errorf("encode source health observation: %w", err)
	}
	var auditDocument any
	if transitioned {
		auditDocument, err = buildAudit(updated)
		if err != nil {
			return nil, fmt.Errorf("build source health Audit fact: %w", err)
		}
	}
	var storedDocument []byte
	err = tx.QueryRow(
		ctx,
		`SELECT delivery.complete_source_observation(
		    $1, $2, $3, $4, $5, $6, $7, $8
		)`,
		lease.TenantID,
		lease.Kind,
		lease.ResourceID,
		lease.ResourceVersion,
		lease.WorkerID,
		lease.FencingToken,
		resourceDocument,
		auditDocument,
	).Scan(&storedDocument)
	if err != nil {
		return nil, mapSourceObservationError("complete source observation", err)
	}
	switch lease.Kind {
	case sourceobservation.WorkSourceConnection:
		var connection devopsv1.SourceConnection
		if err := decodeDocument("SourceConnection", storedDocument, &connection); err != nil {
			return nil, err
		}
		updated = connection
	case sourceobservation.WorkRepositoryBinding:
		var binding devopsv1.RepositoryBinding
		if err := decodeDocument("RepositoryBinding", storedDocument, &binding); err != nil {
			return nil, err
		}
		updated = binding
	default:
		return nil, sourceobservation.ErrInvalidLease
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapSourceObservationError("commit source observation", err)
	}
	return updated, nil
}

func (repository *SourceObservationRepository) Readiness(
	ctx context.Context,
) (devopsv1.Readiness, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return devopsv1.Readiness{}, errors.New("source observer readiness repository is unavailable")
	}
	return readReadiness(ctx, repository.pool, "SELECT * FROM delivery.source_observer_readiness()")
}

func mapSourceObservationError(action string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "MX412" {
		return fmt.Errorf("%s: %w", action, sourceobservation.ErrStaleLease)
	}
	return fmt.Errorf("%s: %w", action, err)
}
