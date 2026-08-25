package transitionreservation

import (
	"context"
	"errors"
	"testing"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/operationqueue"
)

type fakeRepository struct {
	result  StoredTransition
	err     error
	command Command
	guard   operationqueue.LeaseGuard
}

func (repository *fakeRepository) TransitionCapacityReservation(
	_ context.Context,
	guard operationqueue.LeaseGuard,
	reservationID paasv1.ResourceID,
	action Action,
	expectedResourceVersion uint64,
) (StoredTransition, error) {
	repository.command = Command{
		TenantID:                guard.TenantID,
		ReservationID:           reservationID,
		Action:                  action,
		ExpectedResourceVersion: expectedResourceVersion,
	}
	repository.guard = guard
	return repository.result, repository.err
}

func reservationGuard(tenantID paasv1.TenantID) operationqueue.LeaseGuard {
	return operationqueue.LeaseGuard{
		TenantID: tenantID, OperationID: "operation-a",
		WorkerID: "worker-a", FencingToken: 1,
	}
}

func TestTransitionReturnsPersistedStateAndReplayFact(t *testing.T) {
	repository := &fakeRepository{result: StoredTransition{
		State:           placement.CapacityClaimActive,
		ResourceVersion: 2,
		Changed:         false,
	}}
	usecase, err := NewUsecase(repository)
	if err != nil {
		t.Fatalf("new transition use case: %v", err)
	}
	command := Command{
		TenantID:                "tenant-a",
		ReservationID:           "reservation-a",
		Action:                  ActionActivate,
		ExpectedResourceVersion: 1,
	}
	guard := reservationGuard(command.TenantID)
	result, err := usecase.Transition(context.Background(), command, guard)
	if err != nil {
		t.Fatalf("transition reservation: %v", err)
	}
	if result.State != placement.CapacityClaimActive ||
		result.ResourceVersion != 2 ||
		!result.Replayed {
		t.Fatalf("result = %#v", result)
	}
	if repository.command != command {
		t.Fatalf("repository command = %#v, want %#v", repository.command, command)
	}
	if repository.guard != guard {
		t.Fatalf("repository guard = %#v, want %#v", repository.guard, guard)
	}
}

func TestTransitionValidatesCommandBeforeRepository(t *testing.T) {
	repository := &fakeRepository{}
	usecase, err := NewUsecase(repository)
	if err != nil {
		t.Fatalf("new transition use case: %v", err)
	}
	command := Command{
		TenantID:                "tenant-a",
		ReservationID:           "reservation-a",
		Action:                  "INVALID",
		ExpectedResourceVersion: 0,
	}
	_, err = usecase.Transition(
		context.Background(), command, reservationGuard(command.TenantID),
	)
	if err == nil {
		t.Fatal("invalid transition command unexpectedly succeeded")
	}
	if repository.command != (Command{}) {
		t.Fatalf("repository received invalid command: %#v", repository.command)
	}
}

func TestTransitionPreservesRepositoryErrorIdentity(t *testing.T) {
	repository := &fakeRepository{err: ErrResourceVersionConflict}
	usecase, err := NewUsecase(repository)
	if err != nil {
		t.Fatalf("new transition use case: %v", err)
	}
	command := Command{
		TenantID:                "tenant-a",
		ReservationID:           "reservation-a",
		Action:                  ActionRelease,
		ExpectedResourceVersion: 1,
	}
	_, err = usecase.Transition(
		context.Background(), command, reservationGuard(command.TenantID),
	)
	if !errors.Is(err, ErrResourceVersionConflict) {
		t.Fatalf("error = %v, want resource version conflict", err)
	}
}
