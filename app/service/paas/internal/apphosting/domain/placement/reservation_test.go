package placement

import (
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestPendingExpiryAndReleasedCapacityClaimsDoNotConsumeCapacity(t *testing.T) {
	planner := mustPlanner(t)
	withoutClaim := singleTargetInput()
	withoutClaim.Snapshot.Targets[0].Status.Allocatable.CPUMillis = 500
	baseline, err := planner.Plan(withoutClaim)
	if err != nil {
		t.Fatalf("baseline plan: %v", err)
	}

	tests := []struct {
		name          string
		state         CapacityClaimState
		expiresAt     time.Time
		wantScheduled bool
	}{
		{name: "expired pending", state: CapacityClaimPending, expiresAt: fixtureTime.Add(-time.Microsecond), wantScheduled: true},
		{name: "boundary pending", state: CapacityClaimPending, expiresAt: fixtureTime, wantScheduled: true},
		{name: "live pending", state: CapacityClaimPending, expiresAt: fixtureTime.Add(time.Microsecond)},
		{name: "active", state: CapacityClaimActive},
		{name: "released", state: CapacityClaimReleased, wantScheduled: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneInput(withoutClaim)
			claim := testCapacityClaim(
				"claim-capacity",
				"target-a",
				Resources{CPUMillis: 200, WorkloadSlots: 1},
			)
			claim.State = test.state
			claim.LeaseExpiresAt = test.expiresAt
			input.Snapshot.CapacityClaims = []CapacityClaim{claim}
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
			if (test.state == CapacityClaimReleased ||
				test.state == CapacityClaimPending && !test.expiresAt.After(fixtureTime)) &&
				result.Decision.CandidateSetDigest != baseline.Decision.CandidateSetDigest {
				t.Fatalf("non-consuming capacity claim changed digest: %q", result.Decision.CandidateSetDigest)
			}
		})
	}
}
