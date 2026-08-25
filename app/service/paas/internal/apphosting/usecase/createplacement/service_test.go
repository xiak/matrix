package createplacement

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain/placement"
)

func TestCreatePlacementCommitsDecisionAndPendingReservation(t *testing.T) {
	transaction := &fakeTransaction{
		time:     createPlacementTime,
		snapshot: createPlacementSnapshot(),
	}
	repository := &fakeRepository{transaction: transaction}
	usecase := mustUsecase(t, repository)
	command := createPlacementCommand()

	output, err := usecase.CreatePlacement(context.Background(), command)
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	if output.Replayed {
		t.Fatal("new placement cannot be marked replayed")
	}
	if output.Decision.Outcome != paasv1.PlacementScheduled ||
		output.Decision.ExecutionTargetID != "target-a" ||
		output.Decision.ExecutionTargetResourceVersion != 7 {
		t.Fatalf("decision = %#v", output.Decision)
	}
	if !output.Decision.DecidedAt.Equal(createPlacementTime) {
		t.Fatalf("decidedAt = %s, want database time %s", output.Decision.DecidedAt, createPlacementTime)
	}
	if repository.tenantID != command.TenantID || repository.calls != 1 {
		t.Fatalf("repository tenant/calls = %q/%d", repository.tenantID, repository.calls)
	}
	if transaction.timeCalls != 1 || transaction.loadCalls != 1 || transaction.insertCalls != 1 {
		t.Fatalf(
			"transaction calls time/load/insert = %d/%d/%d",
			transaction.timeCalls,
			transaction.loadCalls,
			transaction.insertCalls,
		)
	}
	creation := transaction.creation
	if creation.OperationID != command.OperationID || creation.RequestDigest != command.RequestDigest {
		t.Fatalf("decision creation identity = %#v", creation)
	}
	if creation.Reservation == nil {
		t.Fatal("scheduled placement must create a reservation")
	}
	reservation := creation.Reservation
	if reservation.TenantID != command.TenantID ||
		reservation.DecisionID != command.DecisionID ||
		reservation.DeploymentID != command.DeploymentID ||
		reservation.ExecutionTargetID != output.Decision.ExecutionTargetID ||
		reservation.State != placement.CapacityClaimPending ||
		reservation.ResourceVersion != 1 {
		t.Fatalf("reservation = %#v", reservation)
	}
	if want := createPlacementTime.Add(10 * time.Minute); !reservation.LeaseExpiresAt.Equal(want) {
		t.Fatalf("lease expiry = %s, want %s", reservation.LeaseExpiresAt, want)
	}
	if reservation.Resources != (placement.Resources{
		CPUMillis:     250,
		MemoryBytes:   64 * 1024 * 1024,
		WorkloadSlots: 1,
	}) {
		t.Fatalf("reserved resources = %#v", reservation.Resources)
	}
}

func TestCreatePlacementExactReplaySkipsPlanningAndMutation(t *testing.T) {
	command := createPlacementCommand()
	decision := scheduledDecision(command)
	transaction := &fakeTransaction{
		found: true,
		stored: StoredDecision{
			RequestDigest: command.RequestDigest,
			Decision:      decision,
		},
	}
	repository := &fakeRepository{transaction: transaction}
	output, err := mustUsecase(t, repository).CreatePlacement(context.Background(), command)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !output.Replayed || !reflect.DeepEqual(output.Decision, decision) {
		t.Fatalf("replay output = %#v", output)
	}
	if transaction.timeCalls != 0 || transaction.loadCalls != 0 || transaction.insertCalls != 0 {
		t.Fatalf("replay performed new work: %#v", transaction)
	}
}

func TestCreatePlacementRejectsSemanticIdempotencyConflicts(t *testing.T) {
	baseCommand := createPlacementCommand()
	baseDecision := scheduledDecision(baseCommand)
	tests := []struct {
		name   string
		mutate func(*StoredDecision)
	}{
		{
			name: "request digest",
			mutate: func(stored *StoredDecision) {
				stored.RequestDigest = createDigest('f')
			},
		},
		{
			name: "tenant",
			mutate: func(stored *StoredDecision) {
				stored.Decision.Metadata.Scope.TenantID = "tenant-b"
			},
		},
		{
			name: "deployment",
			mutate: func(stored *StoredDecision) {
				stored.Decision.DeploymentID = "deployment-other"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stored := StoredDecision{
				RequestDigest: baseCommand.RequestDigest,
				Decision:      baseDecision,
			}
			test.mutate(&stored)
			transaction := &fakeTransaction{found: true, stored: stored}
			_, err := mustUsecase(t, &fakeRepository{transaction: transaction}).CreatePlacement(
				context.Background(),
				baseCommand,
			)
			if !errors.Is(err, ErrIdempotencyConflict) {
				t.Fatalf("error = %v, want idempotency conflict", err)
			}
		})
	}
}

func TestCreatePlacementRetriesOnlyRetryableTransactions(t *testing.T) {
	t.Run("eventual commit", func(t *testing.T) {
		transaction := &fakeTransaction{
			time:     createPlacementTime,
			snapshot: createPlacementSnapshot(),
		}
		repository := &fakeRepository{
			transaction: transaction,
			afterCallbackErrors: []error{
				ErrRetryableTransaction,
				ErrRetryableTransaction,
			},
		}
		output, err := mustUsecase(t, repository).CreatePlacement(
			context.Background(),
			createPlacementCommand(),
		)
		if err != nil {
			t.Fatalf("place after retries: %v", err)
		}
		if repository.calls != 3 || output.Decision.Outcome != paasv1.PlacementScheduled {
			t.Fatalf("calls/output = %d/%#v", repository.calls, output)
		}
	})

	t.Run("attempts exhausted", func(t *testing.T) {
		transaction := &fakeTransaction{
			time:     createPlacementTime,
			snapshot: createPlacementSnapshot(),
		}
		repository := &fakeRepository{
			transaction: transaction,
			afterCallbackErrors: []error{
				ErrRetryableTransaction,
				ErrRetryableTransaction,
				ErrRetryableTransaction,
			},
		}
		_, err := mustUsecase(t, repository).CreatePlacement(context.Background(), createPlacementCommand())
		if !errors.Is(err, ErrRetryableTransaction) ||
			!strings.Contains(err.Error(), "attempts exhausted") ||
			repository.calls != 3 {
			t.Fatalf("error/calls = %v/%d", err, repository.calls)
		}
	})

	t.Run("non retryable", func(t *testing.T) {
		terminal := errors.New("terminal store failure")
		repository := &fakeRepository{
			transaction: &fakeTransaction{
				time:     createPlacementTime,
				snapshot: createPlacementSnapshot(),
			},
			afterCallbackErrors: []error{terminal},
		}
		_, err := mustUsecase(t, repository).CreatePlacement(context.Background(), createPlacementCommand())
		if !errors.Is(err, terminal) || repository.calls != 1 {
			t.Fatalf("error/calls = %v/%d", err, repository.calls)
		}
	})
}

func TestUnschedulableDecisionHasNoReservation(t *testing.T) {
	snapshot := createPlacementSnapshot()
	snapshot.Policy.Spec.RequiredIsolationGuarantee = paasv1.IsolationHost
	snapshot.Pools[0].Spec.AllowedIsolationGuarantees = []paasv1.IsolationGuarantee{
		paasv1.IsolationHost,
	}
	snapshot.Targets[0].Status.SupportedIsolationGuarantees = []paasv1.IsolationGuarantee{
		paasv1.IsolationHost,
	}
	transaction := &fakeTransaction{time: createPlacementTime, snapshot: snapshot}
	output, err := mustUsecase(t, &fakeRepository{transaction: transaction}).CreatePlacement(
		context.Background(),
		createPlacementCommand(),
	)
	if err != nil {
		t.Fatalf("place: %v", err)
	}
	if output.Decision.Outcome != paasv1.PlacementUnschedulable ||
		output.Decision.Reason == nil ||
		output.Decision.Reason.Code != paasv1.ErrorCapabilityUnsupported {
		t.Fatalf("decision = %#v", output.Decision)
	}
	if transaction.creation.Reservation != nil {
		t.Fatalf("unschedulable decision reserved capacity: %#v", transaction.creation)
	}
}

func TestCreatePlacementValidatesBeforeOpeningTransaction(t *testing.T) {
	repository := &fakeRepository{transaction: &fakeTransaction{}}
	command := createPlacementCommand()
	command.RequestDigest = "not-a-digest"
	if _, err := mustUsecase(t, repository).CreatePlacement(context.Background(), command); err == nil {
		t.Fatal("invalid command must fail")
	}
	if repository.calls != 0 {
		t.Fatalf("invalid command opened %d transactions", repository.calls)
	}
}

func TestNewRejectsUnsafeTransactionConfiguration(t *testing.T) {
	planner, err := placement.NewV1Planner(5 * time.Minute)
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	repository := &fakeRepository{}
	for _, config := range []Config{
		{PendingReservationTTL: 0, MaxTransactionAttempts: 1},
		{PendingReservationTTL: time.Nanosecond, MaxTransactionAttempts: 1},
		{PendingReservationTTL: 25 * time.Hour, MaxTransactionAttempts: 1},
		{PendingReservationTTL: time.Minute, MaxTransactionAttempts: 0},
		{PendingReservationTTL: time.Minute, MaxTransactionAttempts: 11},
	} {
		if _, err := NewUsecase(planner, repository, config); err == nil {
			t.Fatalf("config %#v must fail", config)
		}
	}
}
