package placement

import (
	"testing"
	"time"

	paasv1 "matrix/api/paas/v1"
)

func TestPendingExpiryAndReleasedReservationsDoNotConsumeCapacity(t *testing.T) {
	planner := mustPlanner(t)
	withoutReservation := singleTargetInput()
	withoutReservation.Snapshot.Targets[0].Status.Allocatable.CPUMillis = 500
	baseline, err := planner.Plan(withoutReservation)
	if err != nil {
		t.Fatalf("baseline plan: %v", err)
	}

	tests := []struct {
		name          string
		state         ReservationState
		expiresAt     time.Time
		wantScheduled bool
	}{
		{name: "expired pending", state: ReservationPending, expiresAt: fixtureTime.Add(-time.Microsecond), wantScheduled: true},
		{name: "boundary pending", state: ReservationPending, expiresAt: fixtureTime, wantScheduled: true},
		{name: "live pending", state: ReservationPending, expiresAt: fixtureTime.Add(time.Microsecond)},
		{name: "active", state: ReservationActive},
		{name: "released", state: ReservationReleased, wantScheduled: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneInput(withoutReservation)
			reservation := testReservation(
				"reservation-capacity",
				"tenant-b",
				"target-a",
				Resources{CPUMillis: 200, WorkloadSlots: 1},
			)
			reservation.State = test.state
			reservation.LeaseExpiresAt = test.expiresAt
			input.Snapshot.Reservations = []Reservation{reservation}
			result, err := planner.Plan(input)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if test.wantScheduled && result.Decision.Outcome != paasv1.PlacementScheduled {
				t.Fatalf("outcome = %q, want scheduled", result.Decision.Outcome)
			}
			if !test.wantScheduled && result.Decision.Outcome != paasv1.PlacementUnschedulable {
				t.Fatalf("outcome = %q, want unschedulable", result.Decision.Outcome)
			}
			if (test.state == ReservationReleased ||
				test.state == ReservationPending && !test.expiresAt.After(fixtureTime)) &&
				result.Decision.CandidateSetDigest != baseline.Decision.CandidateSetDigest {
				t.Fatalf("non-consuming reservation changed digest: %q", result.Decision.CandidateSetDigest)
			}
		})
	}
}
