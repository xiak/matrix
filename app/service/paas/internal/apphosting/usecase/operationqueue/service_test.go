package operationqueue

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/domain"
)

var queueTime = time.Date(2026, 8, 25, 17, 0, 0, 123_000, time.UTC)

func TestClaimNextReturnsValidatedFencedLease(t *testing.T) {
	repository := &fakeQueueRepository{lease: queueLease(), found: true}
	queue := mustQueue(t, repository)
	lease, found, err := queue.ClaimNext(context.Background(), "worker-a")
	if err != nil {
		t.Fatalf("claim Operation: %v", err)
	}
	if !found || lease.WorkerID != "worker-a" || lease.FencingToken != 7 ||
		lease.Operation.State != paasv1.OperationAccepted {
		t.Fatalf("claimed lease = %#v", lease)
	}
	if repository.leaseDuration != 30*time.Second {
		t.Fatalf("claim lease duration = %s", repository.leaseDuration)
	}
}

func TestAdvanceUsesExactStateMachineAndRetainsLease(t *testing.T) {
	repository := &fakeQueueRepository{}
	queue := mustQueue(t, repository)
	lease, err := queue.Advance(context.Background(), Transition{
		Lease: queueLease(),
		State: paasv1.OperationPlanning,
	})
	if err != nil {
		t.Fatalf("advance Operation: %v", err)
	}
	if lease.Operation.State != paasv1.OperationPlanning ||
		lease.WorkerID != "worker-a" || lease.FencingToken != 7 {
		t.Fatalf("advanced lease = %#v", lease)
	}
	if repository.advanceCalls != 1 {
		t.Fatalf("repository advance calls = %d", repository.advanceCalls)
	}
}

func TestAdvanceTerminalFailureRequiresProblemAndReleasesLease(t *testing.T) {
	problem := queueProblem()
	repository := &fakeQueueRepository{}
	lease, err := mustQueue(t, repository).Advance(context.Background(), Transition{
		Lease:        queueLease(),
		State:        paasv1.OperationFailed,
		Problem:      &problem,
		ReleaseLease: true,
	})
	if err != nil {
		t.Fatalf("fail Operation: %v", err)
	}
	if lease.Operation.State != paasv1.OperationFailed ||
		lease.Operation.Error == nil || lease.Operation.TerminalAt == nil ||
		lease.WorkerID != "" || lease.FencingToken != 0 || !lease.LeaseExpiresAt.IsZero() {
		t.Fatalf("terminal lease = %#v", lease)
	}
}

func TestAdvanceCanReleaseNonTerminalLeaseForScheduledRetry(t *testing.T) {
	nextAttemptAt := queueTime.Add(2 * time.Minute)
	lease, err := mustQueue(t, &fakeQueueRepository{}).Advance(
		context.Background(),
		Transition{
			Lease:         queueLease(),
			State:         paasv1.OperationPlanning,
			NextAttemptAt: &nextAttemptAt,
			ReleaseLease:  true,
		},
	)
	if err != nil {
		t.Fatalf("schedule Operation retry: %v", err)
	}
	if lease.WorkerID != "" || lease.Operation.State != paasv1.OperationPlanning {
		t.Fatalf("released retry lease = %#v", lease)
	}
}

func TestAdvanceRejectsIllegalOrIncompleteTransitionBeforePersistence(t *testing.T) {
	tests := []Transition{
		{Lease: queueLease(), State: paasv1.OperationExecuting},
		{Lease: queueLease(), State: paasv1.OperationFailed, ReleaseLease: true},
		{Lease: queueLease(), State: paasv1.OperationPlanning, ReleaseLease: true},
	}
	for _, transition := range tests {
		repository := &fakeQueueRepository{}
		if _, err := mustQueue(t, repository).Advance(context.Background(), transition); err == nil {
			t.Fatalf("transition %#v must fail", transition)
		}
		if repository.advanceCalls != 0 {
			t.Fatalf("invalid transition reached persistence: %#v", transition)
		}
	}
}

func TestAdvancePropagatesStaleFencingFailure(t *testing.T) {
	repository := &fakeQueueRepository{advanceError: ErrStaleLease}
	_, err := mustQueue(t, repository).Advance(context.Background(), Transition{
		Lease: queueLease(),
		State: paasv1.OperationPlanning,
	})
	if !errors.Is(err, ErrStaleLease) {
		t.Fatalf("advance error = %v, want stale lease", err)
	}
}

func TestReleaseSchedulesSameStateReconciliationWithoutTransition(t *testing.T) {
	lease := queueLease()
	lease.Operation.State = paasv1.OperationReconciling
	nextAttemptAt := queueTime.Add(2 * time.Minute)
	repository := &fakeQueueRepository{}
	released, err := mustQueue(t, repository).Release(
		context.Background(), lease, nextAttemptAt,
	)
	if err != nil {
		t.Fatalf("release reconciliation lease: %v", err)
	}
	if released.Operation.State != paasv1.OperationReconciling ||
		released.WorkerID != "" || released.FencingToken != 0 ||
		!released.LeaseExpiresAt.IsZero() || repository.releaseCalls != 1 {
		t.Fatalf("released reconciliation lease = %#v", released)
	}
}

type fakeQueueRepository struct {
	lease         Lease
	found         bool
	leaseDuration time.Duration
	advanceError  error
	advanceCalls  int
	releaseCalls  int
}

func (repository *fakeQueueRepository) ClaimOperation(
	_ context.Context,
	_ string,
	leaseDuration time.Duration,
) (Lease, bool, error) {
	repository.leaseDuration = leaseDuration
	return repository.lease, repository.found, nil
}

func (repository *fakeQueueRepository) AdvanceOperation(
	_ context.Context,
	transition Transition,
) (paasv1.Operation, error) {
	repository.advanceCalls++
	if repository.advanceError != nil {
		return paasv1.Operation{}, repository.advanceError
	}
	operation := transition.Lease.Operation
	operation.State = transition.State
	operation.UpdatedAt = queueTime.Add(time.Second)
	operation.Error = transition.Problem
	if domain.IsTerminalOperationState(transition.State) {
		terminalAt := operation.UpdatedAt
		operation.TerminalAt = &terminalAt
	}
	return operation, nil
}

func (repository *fakeQueueRepository) ReleaseOperation(
	_ context.Context,
	lease Lease,
	_ time.Time,
) (paasv1.Operation, error) {
	repository.releaseCalls++
	if repository.advanceError != nil {
		return paasv1.Operation{}, repository.advanceError
	}
	operation := lease.Operation
	operation.UpdatedAt = queueTime.Add(time.Second)
	return operation, nil
}

func mustQueue(t *testing.T, repository Repository) *Queue {
	t.Helper()
	queue, err := NewQueue(repository, Config{LeaseDuration: 30 * time.Second})
	if err != nil {
		t.Fatalf("new Operation queue: %v", err)
	}
	return queue
}

func queueLease() Lease {
	return Lease{
		TenantID: "tenant-a",
		Operation: paasv1.Operation{
			APIVersion: paasv1.APIVersion,
			Kind:       "Operation",
			ID:         "operation-a",
			Scope: paasv1.ResourceScope{
				Kind:     paasv1.AuthorityTenant,
				TenantID: "tenant-a",
			},
			Action: paasv1.OperationDeploy,
			Target: paasv1.ResourceRef{Kind: "Deployment", ID: "deployment-a"},
			RequestedBy: paasv1.SubjectRef{
				Type: paasv1.SubjectUser,
				ID:   "user-a",
			},
			IdempotencyFingerprint: queueDigest('a'),
			RequestDigest:          queueDigest('b'),
			State:                  paasv1.OperationAccepted,
			Attempt:                1,
			CreatedAt:              queueTime.Add(-time.Minute),
			UpdatedAt:              queueTime,
		},
		WorkerID:       "worker-a",
		FencingToken:   7,
		LeaseExpiresAt: queueTime.Add(time.Minute),
	}
}

func queueProblem() paasv1.Problem {
	return paasv1.Problem{
		Type:      "urn:matrix:operation-failed",
		Title:     "Operation failed",
		Status:    500,
		Code:      paasv1.ErrorOperationFailed,
		Detail:    "The deployment effect failed before completion.",
		TraceID:   "trace-a",
		Retryable: false,
	}
}

func queueDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
