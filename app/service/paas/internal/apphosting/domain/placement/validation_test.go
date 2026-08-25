package placement

import (
	"math"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func TestRequirementAndCapacityClaimArithmeticRejectsOverflow(t *testing.T) {
	t.Run("component multiplication", func(t *testing.T) {
		input := singleTargetInput()
		input.Snapshot.ApplicationRevision.Spec.Components[0].Resources.CPUMillis = math.MaxInt64
		input.Snapshot.Deployment.Spec.Components[0].Replicas = 2
		if _, err := mustPlanner(t).Plan(input); err == nil ||
			!strings.Contains(err.Error(), "cpu requirement overflows") {
			t.Fatalf("expected multiplication overflow, got %v", err)
		}
	})

	t.Run("component addition", func(t *testing.T) {
		input := singleTargetInput()
		component := input.Snapshot.ApplicationRevision.Spec.Components[0]
		component.Resources.CPUMillis = math.MaxInt64
		second := component
		second.Name = "overflow-two"
		input.Snapshot.ApplicationRevision.Spec.Components = []paasv1.ApplicationRevisionComponent{component, second}
		input.Snapshot.Deployment.Spec.Components = []paasv1.DeploymentComponent{
			{Name: component.Name, Replicas: 1},
			{Name: second.Name, Replicas: 1},
		}
		if _, err := mustPlanner(t).Plan(input); err == nil ||
			!strings.Contains(err.Error(), "aggregate cpu requirement overflows") {
			t.Fatalf("expected addition overflow, got %v", err)
		}
	})

	t.Run("capacity claim addition", func(t *testing.T) {
		input := singleTargetInput()
		input.Snapshot.Targets[0].Status.Capacity.CPUMillis = math.MaxInt64
		input.Snapshot.Targets[0].Status.Allocatable.CPUMillis = math.MaxInt64
		input.Snapshot.CapacityClaims = []CapacityClaim{
			testCapacityClaim("claim-a", "target-a", Resources{
				CPUMillis: math.MaxInt64, WorkloadSlots: 1,
			}),
			testCapacityClaim("claim-b", "target-a", Resources{
				CPUMillis: math.MaxInt64, WorkloadSlots: 1,
			}),
		}
		if _, err := mustPlanner(t).Plan(input); err == nil ||
			!strings.Contains(err.Error(), "reserved cpu capacity overflows") {
			t.Fatalf("expected capacity claim overflow, got %v", err)
		}
	})
}

func TestInvalidSnapshotsFailBeforeSelection(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Input)
		match  string
	}{
		{
			name: "application revision tenant",
			mutate: func(input *Input) {
				input.Snapshot.ApplicationRevision.Metadata.Scope.TenantID = "tenant-b"
			},
			match: "application revision tenant",
		},
		{
			name: "policy tenant",
			mutate: func(input *Input) {
				input.Snapshot.Policy.Metadata.Scope.TenantID = "tenant-b"
			},
			match: "policy tenant",
		},
		{
			name: "missing eligible pool",
			mutate: func(input *Input) {
				input.Snapshot.Pools = nil
				input.Snapshot.Targets = nil
			},
			match: "absent from snapshot",
		},
		{
			name: "duplicate target",
			mutate: func(input *Input) {
				input.Snapshot.Targets = append(input.Snapshot.Targets, input.Snapshot.Targets[0])
			},
			match: "duplicated",
		},
		{
			name: "future target observation",
			mutate: func(input *Input) {
				input.Snapshot.Targets[0].Status.ObservedAt = fixtureTime.Add(time.Microsecond)
			},
			match: "after decidedAt",
		},
		{
			name: "pending capacity claim without lease",
			mutate: func(input *Input) {
				claim := testCapacityClaim(
					"claim-a",
					"target-a",
					Resources{WorkloadSlots: 1},
				)
				claim.State = CapacityClaimPending
				input.Snapshot.CapacityClaims = []CapacityClaim{claim}
			},
			match: "leaseExpiresAt",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := baseInput()
			test.mutate(&input)
			if _, err := mustPlanner(t).Plan(input); err == nil ||
				!strings.Contains(err.Error(), test.match) {
				t.Fatalf("expected %q validation error, got %v", test.match, err)
			}
		})
	}
}

func TestNewV1PlannerRejectsAmbiguousObservationAge(t *testing.T) {
	for _, value := range []time.Duration{0, -time.Second, time.Nanosecond} {
		if _, err := NewV1Planner(value); err == nil {
			t.Fatalf("duration %s must fail", value)
		}
	}
}
