package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func (repository *ApplicationRepository) Readiness(
	ctx context.Context,
) (paasv1.Readiness, error) {
	if repository == nil || repository.pool == nil || ctx == nil {
		return paasv1.Readiness{}, errors.New("PaaS readiness repository is unavailable")
	}
	var (
		ready         bool
		schemaVersion int64
		checkedAt     time.Time
	)
	if err := repository.pool.QueryRow(ctx, "SELECT * FROM paas.readiness()").Scan(
		&ready,
		&schemaVersion,
		&checkedAt,
	); err != nil {
		return paasv1.Readiness{}, fmt.Errorf("read PaaS readiness: %w", err)
	}
	checkedAt = databaseTime(checkedAt)
	if schemaVersion != 1 || checkedAt.IsZero() ||
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
