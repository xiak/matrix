package placement

import "testing"

func FuzzPlanOrderInvariant(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte{255, 7, 19, 23})
	f.Fuzz(func(t *testing.T, order []byte) {
		planner := mustPlanner(t)
		input := baseInput()
		input.Snapshot.CapacityClaims = []CapacityClaim{
			testCapacityClaim("claim-a", "target-a", Resources{
				CPUMillis: 100, WorkloadSlots: 1,
			}),
			testCapacityClaim("claim-b", "target-b", Resources{
				CPUMillis: 200, WorkloadSlots: 1,
			}),
		}
		baseline, err := planner.Plan(input)
		if err != nil {
			t.Fatalf("baseline plan: %v", err)
		}
		candidate := cloneInput(input)
		for index, value := range order {
			if value%2 == 0 {
				candidate.Snapshot.Pools[0], candidate.Snapshot.Pools[1] =
					candidate.Snapshot.Pools[1], candidate.Snapshot.Pools[0]
			}
			if value%3 == 0 {
				candidate.Snapshot.Targets[0], candidate.Snapshot.Targets[1] =
					candidate.Snapshot.Targets[1], candidate.Snapshot.Targets[0]
			}
			if value%5 == 0 {
				candidate.Snapshot.CapacityClaims[0], candidate.Snapshot.CapacityClaims[1] =
					candidate.Snapshot.CapacityClaims[1], candidate.Snapshot.CapacityClaims[0]
			}
			candidate.Snapshot.Targets[index%2].Metadata.Labels = reorderedLabels(
				candidate.Snapshot.Targets[index%2].Metadata.Labels,
				value%7 == 0,
			)
		}
		result, err := planner.Plan(candidate)
		if err != nil {
			t.Fatalf("plan reordered snapshot: %v", err)
		}
		if result.Decision.ExecutionTargetID != baseline.Decision.ExecutionTargetID ||
			result.Decision.CandidateSetDigest != baseline.Decision.CandidateSetDigest {
			t.Fatalf("reordering changed placement decision")
		}
	})
}
