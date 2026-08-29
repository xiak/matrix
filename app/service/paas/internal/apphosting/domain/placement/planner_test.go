package placement

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var fixtureTime = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func TestPlanFirstFitBuildsValidVersionBoundDecision(t *testing.T) {
	planner := mustPlanner(t)
	input := baseInput()
	result, err := planner.Plan(input)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if result.Decision.Outcome != paasv1.PlacementScheduled {
		t.Fatalf("outcome = %q", result.Decision.Outcome)
	}
	if result.Decision.ExecutionTargetID != "target-a" {
		t.Fatalf("target = %q, want target-a", result.Decision.ExecutionTargetID)
	}
	if result.Decision.ExecutionTargetResourceVersion != 3 {
		t.Fatalf(
			"target resource version = %d, want 3",
			result.Decision.ExecutionTargetResourceVersion,
		)
	}
	wantResources := Resources{
		CPUMillis:     400,
		MemoryBytes:   512 * 1024 * 1024,
		WorkloadSlots: 3,
	}
	if result.Requirements != wantResources {
		t.Fatalf("requirements = %#v, want %#v", result.Requirements, wantResources)
	}
	if err := paasv1.ValidatePlacementDecision(result.Decision); err != nil {
		t.Fatalf("public decision is invalid: %v", err)
	}
	if !strings.HasPrefix(result.Decision.CandidateSetDigest, "sha256:") {
		t.Fatalf("candidate digest = %q", result.Decision.CandidateSetDigest)
	}
}

func TestUpdateReplacesActiveCapacityOnItsBoundTarget(t *testing.T) {
	planner := mustPlanner(t)
	input := baseInput()
	input.Snapshot.Deployment.Generation = 2
	input.Snapshot.Deployment.Status = paasv1.DeploymentStatus{
		Phase:                         paasv1.DeploymentPending,
		ObservedGeneration:            1,
		ObservedApplicationRevisionID: input.Snapshot.ApplicationRevision.Metadata.ID,
		PlacementDecisionID:           "decision-active",
		CurrentOperationID:            input.OperationID,
		ReadyComponents:               2,
		ObservedAt:                    fixtureTime.Add(-time.Minute),
	}
	input.Snapshot.Targets[0].Status.Allocatable = paasv1.Capacity{
		CPUMillis: 400, MemoryBytes: 512 * 1024 * 1024, WorkloadSlots: 3,
	}
	input.Snapshot.CapacityClaims = []CapacityClaim{
		testCapacityClaim("claim-active", "target-b", Resources{
			CPUMillis: 400, MemoryBytes: 512 * 1024 * 1024, WorkloadSlots: 3,
		}),
	}
	input.Snapshot.ActivePlacement = &ActivePlacement{
		DecisionID: "decision-active", ExecutionTargetID: "target-b", CapacityClaimID: "claim-active",
	}

	result, err := planner.Plan(input)
	if err != nil {
		t.Fatalf("plan replacement: %v", err)
	}
	if result.Decision.Outcome != paasv1.PlacementScheduled ||
		result.Decision.ExecutionTargetID != "target-b" {
		t.Fatalf("replacement decision = %#v", result.Decision)
	}
}

func TestCandidateFiltersFailClosed(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Input)
		planner func(*testing.T) *Planner
	}{
		{
			name: "pool not eligible",
			mutate: func(input *Input) {
				input.Snapshot.Pools = append(input.Snapshot.Pools, testPool("pool-other"))
				input.Snapshot.Policy.Spec.EligibleExecutionPoolIDs = []paasv1.ResourceID{"pool-other"}
			},
		},
		{
			name: "pool not ready",
			mutate: func(input *Input) {
				input.Snapshot.Pools[0].Status.Phase = paasv1.ExecutionPoolDegraded
			},
		},
		{
			name: "target not active",
			mutate: func(input *Input) {
				input.Snapshot.Targets[0].Spec.DesiredState = paasv1.ExecutionTargetDraining
			},
		},
		{
			name: "target not ready",
			mutate: func(input *Input) {
				input.Snapshot.Targets[0].Status.Health = paasv1.ExecutionTargetHealthDegraded
			},
		},
		{
			name: "pool selector mismatch",
			mutate: func(input *Input) {
				input.Snapshot.Pools[0].Spec.ExecutionTargetSelector.MatchLabels["site"] = "remote"
			},
		},
		{
			name: "policy selector mismatch",
			mutate: func(input *Input) {
				input.Snapshot.Policy.Spec.ExecutionTargetSelector.MatchLabels["executor"] = "other"
			},
		},
		{
			name: "stale observation",
			mutate: func(input *Input) {
				input.Snapshot.Targets[0].Status.ObservedAt = fixtureTime.Add(-5*time.Minute - time.Microsecond)
			},
		},
		{
			name: "pool isolation unsupported",
			mutate: func(input *Input) {
				input.Snapshot.Pools[0].Spec.AllowedIsolationGuarantees = []paasv1.IsolationGuarantee{
					paasv1.IsolationTenant,
				}
			},
		},
		{
			name: "target isolation unsupported",
			mutate: func(input *Input) {
				input.Snapshot.Targets[0].Status.SupportedIsolationGuarantees = []paasv1.IsolationGuarantee{
					paasv1.IsolationTenant,
				}
			},
		},
		{
			name:   "isolation policy rejected",
			mutate: func(*Input) {},
			planner: func(t *testing.T) *Planner {
				planner := mustPlanner(t)
				planner.policies[paasv1.IsolationWorkload] = testIsolationPolicy{
					class:   paasv1.IsolationWorkload,
					version: "reject-workload-v1",
					admit:   false,
				}
				return planner
			},
		},
		{
			name: "insufficient cpu",
			mutate: func(input *Input) {
				input.Snapshot.Targets[0].Status.Allocatable.CPUMillis = 399
			},
		},
		{
			name: "insufficient memory",
			mutate: func(input *Input) {
				input.Snapshot.Targets[0].Status.Allocatable.MemoryBytes = 512*1024*1024 - 1
			},
		},
		{
			name: "insufficient slots",
			mutate: func(input *Input) {
				input.Snapshot.Targets[0].Status.Allocatable.WorkloadSlots = 2
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := singleTargetInput()
			test.mutate(&input)
			planner := mustPlanner(t)
			if test.planner != nil {
				planner = test.planner(t)
			}
			result, err := planner.Plan(input)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			assertUnschedulable(t, result.Decision, paasv1.ErrorUnschedulable, true)
		})
	}
}

func TestUnsupportedIsolationNeverDowngradesToCompose(t *testing.T) {
	planner := mustPlanner(t)
	for _, isolation := range []paasv1.IsolationGuarantee{
		paasv1.IsolationTenant,
		paasv1.IsolationHost,
	} {
		t.Run(string(isolation), func(t *testing.T) {
			input := singleTargetInput()
			input.Snapshot.Policy.Spec.RequiredIsolationGuarantee = isolation
			input.Snapshot.Pools[0].Spec.AllowedIsolationGuarantees = []paasv1.IsolationGuarantee{isolation}
			input.Snapshot.Targets[0].Status.SupportedIsolationGuarantees = []paasv1.IsolationGuarantee{isolation}
			result, err := planner.Plan(input)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			assertUnschedulable(
				t,
				result.Decision,
				paasv1.ErrorCapabilityUnsupported,
				false,
			)
			if result.Decision.ExecutionTargetID != "" ||
				result.Decision.ExecutionTargetResourceVersion != 0 ||
				result.Decision.GrantedIsolationGuarantee != "" {
				t.Fatalf("unsupported isolation selected a target: %#v", result.Decision)
			}
		})
	}
}

func TestPlacementStrategiesUseExactReservedUtilization(t *testing.T) {
	input := baseInput()
	input.Snapshot.CapacityClaims = []CapacityClaim{
		testCapacityClaim("claim-a", "target-a", Resources{
			CPUMillis: 800, WorkloadSlots: 1,
		}),
		testCapacityClaim("claim-b", "target-b", Resources{
			CPUMillis: 100, WorkloadSlots: 1,
		}),
	}
	tests := []struct {
		strategy paasv1.PlacementStrategy
		want     paasv1.ResourceID
	}{
		{strategy: paasv1.PlacementFirstFit, want: "target-a"},
		{strategy: paasv1.PlacementSpread, want: "target-b"},
		{strategy: paasv1.PlacementBinPack, want: "target-a"},
	}
	for _, test := range tests {
		t.Run(string(test.strategy), func(t *testing.T) {
			candidate := cloneInput(input)
			candidate.Snapshot.Policy.Spec.Strategy = test.strategy
			result, err := mustPlanner(t).Plan(candidate)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if result.Decision.ExecutionTargetID != test.want {
				t.Fatalf("target = %q, want %q", result.Decision.ExecutionTargetID, test.want)
			}
		})
	}
}

func TestScoredStrategyTieBreaksByOpaqueTargetID(t *testing.T) {
	for _, strategy := range []paasv1.PlacementStrategy{
		paasv1.PlacementSpread,
		paasv1.PlacementBinPack,
	} {
		t.Run(string(strategy), func(t *testing.T) {
			input := baseInput()
			input.Snapshot.Policy.Spec.Strategy = strategy
			result, err := mustPlanner(t).Plan(input)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if result.Decision.ExecutionTargetID != "target-a" {
				t.Fatalf("tie selected %q, want target-a", result.Decision.ExecutionTargetID)
			}
		})
	}
}

func TestExactRationalComparisonDoesNotRound(t *testing.T) {
	left := utilization{
		numerator:   9_007_199_254_740_990,
		denominator: 9_007_199_254_740_991,
	}
	right := utilization{
		numerator:   9_007_199_254_740_989,
		denominator: 9_007_199_254_740_990,
	}
	if comparison := compareUtilization(left, right); comparison <= 0 {
		t.Fatalf("exact comparison = %d, want left greater", comparison)
	}
	if comparison := compareUtilization(
		utilization{denominator: 1},
		utilization{infinite: true},
	); comparison >= 0 {
		t.Fatalf("zero utilization must be below infinity, got %d", comparison)
	}
}

func TestPlannerDoesNotMutateCallerOwnedInput(t *testing.T) {
	input := baseInput()
	input.Snapshot.CapacityClaims = []CapacityClaim{
		testCapacityClaim("claim-a", "target-a", Resources{
			CPUMillis: 100, MemoryBytes: 1024, WorkloadSlots: 1,
		}),
	}
	want := cloneInput(input)
	planner := mustPlanner(t)
	planner.policies[paasv1.IsolationWorkload] = testIsolationPolicy{
		class:   paasv1.IsolationWorkload,
		version: "mutation-probe-v1",
		admit:   true,
		mutate:  true,
	}
	if _, err := planner.Plan(input); err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !reflect.DeepEqual(input, want) {
		t.Fatal("planner or isolation policy mutated caller-owned input")
	}
}

func TestV1PlannerIsSafeForConcurrentPlanning(t *testing.T) {
	planner := mustPlanner(t)
	input := baseInput()
	baseline, err := planner.Plan(input)
	if err != nil {
		t.Fatalf("baseline plan: %v", err)
	}

	const workers = 64
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := planner.Plan(input)
			if err != nil {
				errorsByWorker <- err
				return
			}
			if !reflect.DeepEqual(result, baseline) {
				errorsByWorker <- errors.New("concurrent result differs from baseline")
			}
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		t.Error(err)
	}
}

func TestOpaqueDecisionIDProducesPortableMetadataName(t *testing.T) {
	input := baseInput()
	input.DecisionID = "DECISION:Opaque.1"
	result, err := mustPlanner(t).Plan(input)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if err := paasv1.ValidatePlacementDecision(result.Decision); err != nil {
		t.Fatalf("decision derived from opaque id is invalid: %v", err)
	}
}
