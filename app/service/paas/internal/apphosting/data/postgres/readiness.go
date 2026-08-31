package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

// The deployment-runtime objects are an additive expansion of the published
// PaaS schema-2 compatibility floor. Revision-4 binaries ignore them and keep
// accepting the same readiness tuple during an exact rollback; this binary
// separately verifies the new object and function shapes in its migration.
const paasDatabaseSchemaVersion = 3

func (repository *ApplicationRepository) Readiness(
	ctx context.Context,
) (paasv1.Readiness, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return paasv1.Readiness{}, errors.New("PaaS readiness repository is unavailable")
	}
	return readReadiness(ctx, repository.pool, "SELECT * FROM paas.readiness()")
}

func (repository *OperationQueueRepository) Readiness(
	ctx context.Context,
) (paasv1.Readiness, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return paasv1.Readiness{}, errors.New("PaaS worker readiness repository is unavailable")
	}
	return readReadiness(ctx, repository.pool, "SELECT * FROM paas.worker_readiness()")
}

func readReadiness(
	ctx context.Context,
	pool *pgxpool.Pool,
	query string,
) (paasv1.Readiness, error) {
	var (
		ready         bool
		schemaVersion int64
		checkedAt     time.Time
	)
	if err := pool.QueryRow(ctx, query).Scan(
		&ready,
		&schemaVersion,
		&checkedAt,
	); err != nil {
		return paasv1.Readiness{}, fmt.Errorf("read PaaS readiness: %w", err)
	}
	checkedAt = databaseTime(checkedAt)
	if schemaVersion != paasDatabaseSchemaVersion || checkedAt.IsZero() ||
		checkedAt.Location() != time.UTC || checkedAt.Nanosecond()%1_000 != 0 {
		return paasv1.Readiness{}, errors.New("PaaS readiness state is invalid")
	}
	state := paasv1.ReadinessNotReady
	if ready {
		state = paasv1.ReadinessReady
	}
	result := paasv1.Readiness{
		APIVersion: paasv1.APIVersion, Kind: "Readiness", State: state,
		SchemaVersion: uint64(schemaVersion), CheckedAt: checkedAt,
	}
	if paasv1.ValidateReadiness(result) != nil {
		return paasv1.Readiness{}, errors.New("PaaS readiness state is invalid")
	}
	return result, nil
}
