package transitionreservation

import (
	"context"
	"errors"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
)

const maxResourceVersion = 9_007_199_254_740_991

func NewUsecase(repository Repository) (*Usecase, error) {
	if repository == nil {
		return nil, errors.New("capacity reservation repository is required")
	}
	return &Usecase{repository: repository}, nil
}

func (usecase *Usecase) Transition(
	ctx context.Context,
	command Command,
	guard operationqueue.LeaseGuard,
) (Result, error) {
	if usecase == nil || usecase.repository == nil {
		return Result{}, errors.New("capacity reservation transition use case is nil")
	}
	if ctx == nil {
		return Result{}, errors.New("capacity reservation transition context is nil")
	}
	if err := validateCommand(command); err != nil {
		return Result{}, err
	}
	if err := operationqueue.ValidateLeaseGuard(guard); err != nil {
		return Result{}, err
	}
	if guard.TenantID != command.TenantID {
		return Result{}, errors.New("capacity reservation and Operation lease tenants differ")
	}
	stored, err := usecase.repository.TransitionCapacityReservation(
		ctx,
		guard,
		command.ReservationID,
		command.Action,
		command.ExpectedResourceVersion,
	)
	if err != nil {
		return Result{}, err
	}
	return Result{
		State:           stored.State,
		ResourceVersion: stored.ResourceVersion,
		Replayed:        !stored.Changed,
	}, nil
}

func validateCommand(command Command) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("tenantId", string(command.TenantID)),
		paasv1.ValidateID("reservationId", string(command.ReservationID)),
	)
	if command.Action != ActionActivate &&
		command.Action != ActionRelease &&
		command.Action != ActionExpire {
		problems = append(problems, errors.New("capacity reservation action is invalid"))
	}
	if command.ExpectedResourceVersion == 0 ||
		command.ExpectedResourceVersion > maxResourceVersion {
		problems = append(problems, errors.New("expected resource version is invalid"))
	}
	return errors.Join(problems...)
}
