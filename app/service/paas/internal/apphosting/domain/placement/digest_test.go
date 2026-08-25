package placement

import (
	"math/rand"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestPlanningIsInvariantToCollectionAndMapOrder(t *testing.T) {
	input := baseInput()
	input.Snapshot.CapacityClaims = []CapacityClaim{
		testCapacityClaim("claim-a", "target-a", Resources{
			CPUMillis: 100, MemoryBytes: 1024, WorkloadSlots: 1,
		}),
		testCapacityClaim("claim-b", "target-b", Resources{
			CPUMillis: 200, MemoryBytes: 2048, WorkloadSlots: 1,
		}),
	}
	planner := mustPlanner(t)
	baseline, err := planner.Plan(input)
	if err != nil {
		t.Fatalf("baseline plan: %v", err)
	}

	for iteration := 0; iteration < 100; iteration++ {
		candidate := cloneInput(input)
		random := rand.New(rand.NewSource(int64(iteration + 1)))
		random.Shuffle(len(candidate.Snapshot.Pools), func(left, right int) {
			candidate.Snapshot.Pools[left], candidate.Snapshot.Pools[right] =
				candidate.Snapshot.Pools[right], candidate.Snapshot.Pools[left]
		})
		random.Shuffle(len(candidate.Snapshot.Targets), func(left, right int) {
			candidate.Snapshot.Targets[left], candidate.Snapshot.Targets[right] =
				candidate.Snapshot.Targets[right], candidate.Snapshot.Targets[left]
		})
		random.Shuffle(len(candidate.Snapshot.CapacityClaims), func(left, right int) {
			candidate.Snapshot.CapacityClaims[left], candidate.Snapshot.CapacityClaims[right] =
				candidate.Snapshot.CapacityClaims[right], candidate.Snapshot.CapacityClaims[left]
		})
		random.Shuffle(
			len(candidate.Snapshot.Policy.Spec.EligibleExecutionPoolIDs),
			func(left, right int) {
				candidate.Snapshot.Policy.Spec.EligibleExecutionPoolIDs[left],
					candidate.Snapshot.Policy.Spec.EligibleExecutionPoolIDs[right] =
					candidate.Snapshot.Policy.Spec.EligibleExecutionPoolIDs[right],
					candidate.Snapshot.Policy.Spec.EligibleExecutionPoolIDs[left]
			},
		)
		for index := range candidate.Snapshot.Pools {
			random.Shuffle(
				len(candidate.Snapshot.Pools[index].Spec.AllowedIsolationGuarantees),
				func(left, right int) {
					classes := candidate.Snapshot.Pools[index].Spec.AllowedIsolationGuarantees
					classes[left], classes[right] = classes[right], classes[left]
				},
			)
		}
		for index := range candidate.Snapshot.Targets {
			random.Shuffle(
				len(candidate.Snapshot.Targets[index].Status.SupportedIsolationGuarantees),
				func(left, right int) {
					classes := candidate.Snapshot.Targets[index].Status.SupportedIsolationGuarantees
					classes[left], classes[right] = classes[right], classes[left]
				},
			)
			candidate.Snapshot.Targets[index].Metadata.Labels = reorderedLabels(
				candidate.Snapshot.Targets[index].Metadata.Labels,
				iteration%2 == 0,
			)
		}

		result, err := planner.Plan(candidate)
		if err != nil {
			t.Fatalf("iteration %d: %v", iteration, err)
		}
		if result.Decision.ExecutionTargetID != baseline.Decision.ExecutionTargetID ||
			result.Decision.CandidateSetDigest != baseline.Decision.CandidateSetDigest {
			t.Fatalf(
				"iteration %d changed decision: target=%q digest=%q",
				iteration,
				result.Decision.ExecutionTargetID,
				result.Decision.CandidateSetDigest,
			)
		}
	}
}

func TestCandidateDigestGoldenAndDecisionRelevantSensitivity(t *testing.T) {
	input := baseInput()
	claim := testCapacityClaim(
		"claim-a",
		"target-b",
		Resources{CPUMillis: 100, MemoryBytes: 1024, WorkloadSlots: 1},
	)
	claim.State = CapacityClaimPending
	claim.LeaseExpiresAt = fixtureTime.Add(10 * time.Minute)
	input.Snapshot.CapacityClaims = []CapacityClaim{claim}
	planner := mustPlanner(t)
	baseline, err := planner.Plan(input)
	if err != nil {
		t.Fatalf("baseline plan: %v", err)
	}
	const golden = "sha256:be0e44069d5e8cffb23e3ecf5a1927964cafbe70e5f1f9a8df4473b6bfae9b47"
	if baseline.Decision.CandidateSetDigest != golden {
		t.Fatalf(
			"candidate digest = %q, update golden %q",
			baseline.Decision.CandidateSetDigest,
			golden,
		)
	}

	tests := []struct {
		name   string
		mutate func(*Input)
	}{
		{name: "deployment resource version", mutate: func(value *Input) { value.Snapshot.Deployment.Metadata.ResourceVersion++ }},
		{name: "deployment replicas", mutate: func(value *Input) { value.Snapshot.Deployment.Spec.Components[0].Replicas++ }},
		{name: "application revision identity", mutate: func(value *Input) {
			value.Snapshot.ApplicationRevision.Metadata.ID = "revision-b"
			value.Snapshot.Deployment.Spec.ApplicationRevisionID = "revision-b"
		}},
		{name: "application revision content", mutate: func(value *Input) { value.Snapshot.ApplicationRevision.Spec.ContentDigest = testDigest('b') }},
		{name: "requirements", mutate: func(value *Input) { value.Snapshot.ApplicationRevision.Spec.Components[0].Resources.CPUMillis++ }},
		{name: "policy resource version", mutate: func(value *Input) { value.Snapshot.Policy.Metadata.ResourceVersion++ }},
		{name: "policy isolation", mutate: func(value *Input) {
			value.Snapshot.Policy.Spec.RequiredIsolationGuarantee = paasv1.IsolationTenant
		}},
		{name: "policy strategy", mutate: func(value *Input) { value.Snapshot.Policy.Spec.Strategy = paasv1.PlacementSpread }},
		{name: "policy pools", mutate: func(value *Input) {
			value.Snapshot.Policy.Spec.EligibleExecutionPoolIDs = []paasv1.ResourceID{"pool-a"}
		}},
		{name: "policy selector", mutate: func(value *Input) { value.Snapshot.Policy.Spec.ExecutionTargetSelector.MatchLabels["site"] = "local" }},
		{name: "pool resource version", mutate: func(value *Input) { value.Snapshot.Pools[0].Metadata.ResourceVersion++ }},
		{name: "pool phase", mutate: func(value *Input) { value.Snapshot.Pools[0].Status.Phase = paasv1.ExecutionPoolDegraded }},
		{name: "pool selector", mutate: func(value *Input) { value.Snapshot.Pools[0].Spec.ExecutionTargetSelector.MatchLabels["site"] = "other" }},
		{name: "pool isolation", mutate: func(value *Input) {
			value.Snapshot.Pools[0].Spec.AllowedIsolationGuarantees = []paasv1.IsolationGuarantee{paasv1.IsolationWorkload, paasv1.IsolationTenant}
		}},
		{name: "target resource version", mutate: func(value *Input) { value.Snapshot.Targets[0].Metadata.ResourceVersion++ }},
		{name: "target desired state", mutate: func(value *Input) { value.Snapshot.Targets[0].Spec.DesiredState = paasv1.ExecutionTargetDraining }},
		{name: "target health", mutate: func(value *Input) { value.Snapshot.Targets[0].Status.Health = paasv1.ExecutionTargetHealthDegraded }},
		{name: "target observation", mutate: func(value *Input) {
			value.Snapshot.Targets[0].Status.ObservedAt = value.Snapshot.Targets[0].Status.ObservedAt.Add(-time.Microsecond)
		}},
		{name: "target labels", mutate: func(value *Input) { value.Snapshot.Targets[0].Metadata.Labels["capacity-class"] = "large" }},
		{name: "target allocatable", mutate: func(value *Input) { value.Snapshot.Targets[0].Status.Allocatable.CPUMillis-- }},
		{name: "target isolation", mutate: func(value *Input) {
			value.Snapshot.Targets[0].Status.SupportedIsolationGuarantees = []paasv1.IsolationGuarantee{paasv1.IsolationWorkload, paasv1.IsolationTenant}
		}},
		{name: "capacity claim resources", mutate: func(value *Input) { value.Snapshot.CapacityClaims[0].Resources.CPUMillis++ }},
		{name: "capacity claim version", mutate: func(value *Input) { value.Snapshot.CapacityClaims[0].ResourceVersion++ }},
		{name: "capacity claim expiry", mutate: func(value *Input) {
			value.Snapshot.CapacityClaims[0].LeaseExpiresAt = value.Snapshot.CapacityClaims[0].LeaseExpiresAt.Add(time.Microsecond)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneInput(input)
			test.mutate(&candidate)
			result, err := planner.Plan(candidate)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if result.Decision.CandidateSetDigest == baseline.Decision.CandidateSetDigest {
				t.Fatalf("decision-relevant change did not change candidate digest")
			}
		})
	}

	differentAge, err := NewV1Planner(6 * time.Minute)
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	withDifferentAge, err := differentAge.Plan(input)
	if err != nil {
		t.Fatalf("plan with different age: %v", err)
	}
	if withDifferentAge.Decision.CandidateSetDigest == baseline.Decision.CandidateSetDigest {
		t.Fatal("observation-age configuration did not change candidate digest")
	}

	versionedPolicy := mustPlanner(t)
	versionedPolicy.policies[paasv1.IsolationWorkload] = testIsolationPolicy{
		class:   paasv1.IsolationWorkload,
		version: "compose-workload-v2",
		admit:   true,
	}
	withDifferentPolicyVersion, err := versionedPolicy.Plan(input)
	if err != nil {
		t.Fatalf("plan with different isolation policy version: %v", err)
	}
	if withDifferentPolicyVersion.Decision.CandidateSetDigest == baseline.Decision.CandidateSetDigest {
		t.Fatal("isolation policy version did not change candidate digest")
	}
}

func TestCandidateDigestExcludesOperationAndWallClockMetadata(t *testing.T) {
	input := baseInput()
	planner := mustPlanner(t)
	baseline, err := planner.Plan(input)
	if err != nil {
		t.Fatalf("baseline plan: %v", err)
	}
	candidate := cloneInput(input)
	candidate.OperationID = "operation-other"
	candidate.DecisionID = "decision-other"
	candidate.RequestDigest = testDigest('d')
	candidate.TraceID = "trace-other"
	candidate.DecidedAt = candidate.DecidedAt.Add(time.Second)
	result, err := planner.Plan(candidate)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if result.Decision.CandidateSetDigest != baseline.Decision.CandidateSetDigest {
		t.Fatalf(
			"non-candidate metadata changed digest: got %q want %q",
			result.Decision.CandidateSetDigest,
			baseline.Decision.CandidateSetDigest,
		)
	}
}
