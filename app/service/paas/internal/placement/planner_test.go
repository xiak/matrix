package placement

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	paasv1 "matrix/api/paas/v1"
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
	if result.Decision.RuntimeTargetID != "target-a" {
		t.Fatalf("target = %q, want target-a", result.Decision.RuntimeTargetID)
	}
	if result.Decision.RuntimeTargetResourceVersion != 3 {
		t.Fatalf(
			"target resource version = %d, want 3",
			result.Decision.RuntimeTargetResourceVersion,
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
				input.Snapshot.Policy.Spec.EligibleResourcePools = []paasv1.ResourceID{"pool-other"}
			},
		},
		{
			name: "pool not ready",
			mutate: func(input *Input) {
				input.Snapshot.Pools[0].Status.Phase = paasv1.ResourcePoolDegraded
			},
		},
		{
			name: "target not active",
			mutate: func(input *Input) {
				input.Snapshot.Targets[0].Spec.DesiredState = paasv1.TargetDraining
			},
		},
		{
			name: "target not ready",
			mutate: func(input *Input) {
				input.Snapshot.Targets[0].Status.Health = paasv1.TargetHealthDegraded
			},
		},
		{
			name: "pool selector mismatch",
			mutate: func(input *Input) {
				input.Snapshot.Pools[0].Spec.TargetSelector.MatchLabels["site"] = "remote"
			},
		},
		{
			name: "policy selector mismatch",
			mutate: func(input *Input) {
				input.Snapshot.Policy.Spec.TargetSelector.MatchLabels["runtime"] = "other"
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
				input.Snapshot.Pools[0].Spec.AllowedIsolationClasses = []paasv1.IsolationClass{
					paasv1.IsolationDedicatedCompose,
				}
			},
		},
		{
			name: "target isolation unsupported",
			mutate: func(input *Input) {
				input.Snapshot.Targets[0].Status.SupportedIsolationClasses = []paasv1.IsolationClass{
					paasv1.IsolationDedicatedCompose,
				}
			},
		},
		{
			name:   "isolation policy rejected",
			mutate: func(*Input) {},
			planner: func(t *testing.T) *Planner {
				planner := mustPlanner(t)
				planner.policies[paasv1.IsolationSharedCompose] = testIsolationPolicy{
					class:   paasv1.IsolationSharedCompose,
					version: "reject-shared-v1",
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
	for _, isolation := range []paasv1.IsolationClass{
		paasv1.IsolationDedicatedHost,
		paasv1.IsolationKubernetesNS,
		paasv1.IsolationPhysicalHost,
	} {
		t.Run(string(isolation), func(t *testing.T) {
			input := singleTargetInput()
			input.Snapshot.Policy.Spec.RequiredIsolationClass = isolation
			input.Snapshot.Pools[0].Spec.AllowedIsolationClasses = []paasv1.IsolationClass{isolation}
			input.Snapshot.Targets[0].Status.SupportedIsolationClasses = []paasv1.IsolationClass{isolation}
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
			if result.Decision.RuntimeTargetID != "" ||
				result.Decision.RuntimeTargetResourceVersion != 0 ||
				result.Decision.GrantedIsolation != "" {
				t.Fatalf("unsupported isolation selected a target: %#v", result.Decision)
			}
		})
	}
}

func TestPlacementStrategiesUseExactReservedUtilization(t *testing.T) {
	input := baseInput()
	input.Snapshot.Reservations = []Reservation{
		testReservation("reservation-a", "tenant-a", "target-a", Resources{
			CPUMillis: 800, WorkloadSlots: 1,
		}),
		testReservation("reservation-b", "tenant-b", "target-b", Resources{
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
			if result.Decision.RuntimeTargetID != test.want {
				t.Fatalf("target = %q, want %q", result.Decision.RuntimeTargetID, test.want)
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
			if result.Decision.RuntimeTargetID != "target-a" {
				t.Fatalf("tie selected %q, want target-a", result.Decision.RuntimeTargetID)
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
	input.Snapshot.Reservations = []Reservation{
		testReservation("reservation-a", "tenant-b", "target-a", Resources{
			CPUMillis: 100, MemoryBytes: 1024, WorkloadSlots: 1,
		}),
	}
	want := cloneInput(input)
	planner := mustPlanner(t)
	planner.policies[paasv1.IsolationSharedCompose] = testIsolationPolicy{
		class:   paasv1.IsolationSharedCompose,
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
