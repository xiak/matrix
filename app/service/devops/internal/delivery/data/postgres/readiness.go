package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func (repository *ControlPlaneRepository) Readiness(ctx context.Context) (devopsv1.Readiness, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return devopsv1.Readiness{}, errors.New("DevOps readiness repository is unavailable")
	}
	return readReadiness(ctx, repository.pool, "SELECT * FROM delivery.readiness()")
}

func readReadiness(ctx context.Context, pool *pgxpool.Pool, query string) (devopsv1.Readiness, error) {
	var ready bool
	var schemaVersion int64
	var checkedAt time.Time
	if err := pool.QueryRow(ctx, query).Scan(&ready, &schemaVersion, &checkedAt); err != nil {
		return devopsv1.Readiness{}, fmt.Errorf("read DevOps readiness: %w", err)
	}
	checkedAt = checkedAt.UTC()
	if schemaVersion != 1 || checkedAt.IsZero() || checkedAt.Nanosecond()%1_000 != 0 {
		return devopsv1.Readiness{}, errors.New("DevOps readiness state is invalid")
	}
	state := devopsv1.ReadinessNotReady
	if ready {
		state = devopsv1.ReadinessReady
	}
	result := devopsv1.Readiness{
		APIVersion: devopsv1.APIVersion, Kind: "Readiness", State: state,
		SchemaVersion: uint64(schemaVersion), CheckedAt: checkedAt,
	}
	if devopsv1.ValidateReadiness(result) != nil {
		return devopsv1.Readiness{}, errors.New("DevOps readiness state is invalid")
	}
	return result, nil
}
