package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/transitionreservation"
)

var _ transitionreservation.Repository = (*CapacityReservationRepository)(nil)

type CapacityReservationRepository struct {
	pool *pgxpool.Pool
}

func NewCapacityReservationRepository(
	pool *pgxpool.Pool,
) (*CapacityReservationRepository, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL connection pool is required")
	}
	return &CapacityReservationRepository{pool: pool}, nil
}

func (repository *CapacityReservationRepository) TransitionCapacityReservation(
	ctx context.Context,
	tenantID paasv1.TenantID,
	reservationID paasv1.ResourceID,
	action transitionreservation.Action,
	expectedResourceVersion uint64,
) (transitionreservation.StoredTransition, error) {
	if repository == nil || repository.pool == nil {
		return transitionreservation.StoredTransition{}, errors.New(
			"capacity reservation repository is nil",
		)
	}
	if ctx == nil {
		return transitionreservation.StoredTransition{}, errors.New(
			"capacity reservation transition context is nil",
		)
	}
	var result transitionreservation.StoredTransition
	err := withinTenantTransaction(
		ctx,
		repository.pool,
		tenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite},
		func(tx pgx.Tx) error {
			var state string
			if err := tx.QueryRow(
				ctx,
				`SELECT claim_state, claim_resource_version, changed
				   FROM paas.transition_capacity_reservation($1, $2, $3)`,
				string(reservationID),
				string(action),
				int64(expectedResourceVersion),
			).Scan(&state, &result.ResourceVersion, &result.Changed); err != nil {
				return err
			}
			result.State = placement.CapacityClaimState(state)
			return nil
		},
	)
	if err != nil {
		return transitionreservation.StoredTransition{}, mapReservationTransitionError(err)
	}
	return result, nil
}

func mapReservationTransitionError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "P0002":
			return fmt.Errorf("transition capacity reservation: %w", transitionreservation.ErrNotFound)
		case "40001":
			return fmt.Errorf(
				"transition capacity reservation: %w",
				transitionreservation.ErrResourceVersionConflict,
			)
		case "55000":
			return fmt.Errorf(
				"transition capacity reservation: %w",
				transitionreservation.ErrInvalidTransition,
			)
		}
	}
	return fmt.Errorf("transition capacity reservation: %w", err)
}
