package transitionreservation

import (
	"context"
	"errors"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
)

type Action string

const (
	ActionActivate Action = "ACTIVATE"
	ActionRelease  Action = "RELEASE"
	ActionExpire   Action = "EXPIRE"
)

var (
	ErrNotFound                = errors.New("capacity reservation not found")
	ErrResourceVersionConflict = errors.New("capacity reservation resource version conflict")
	ErrInvalidTransition       = errors.New("capacity reservation transition is invalid")
)

type Command struct {
	TenantID                paasv1.TenantID
	ReservationID           paasv1.ResourceID
	Action                  Action
	ExpectedResourceVersion uint64
}

type Result struct {
	State           placement.CapacityClaimState
	ResourceVersion uint64
	Replayed        bool
}

type StoredTransition struct {
	State           placement.CapacityClaimState
	ResourceVersion uint64
	Changed         bool
}

type Repository interface {
	TransitionCapacityReservation(
		context.Context,
		paasv1.TenantID,
		paasv1.ResourceID,
		Action,
		uint64,
	) (StoredTransition, error)
}

type Usecase struct {
	repository Repository
}
