package placement

import (
	"strings"
	"testing"
	"time"

	paasv1 "matrix/api/paas/v1"
)

type testIsolationPolicy struct {
	class   paasv1.IsolationClass
	version string
	admit   bool
	mutate  bool
}

func (policy testIsolationPolicy) IsolationClass() paasv1.IsolationClass {
	return policy.class
}

func (policy testIsolationPolicy) Version() string {
	return policy.version
}

func (policy testIsolationPolicy) Admit(context IsolationContext) bool {
	if policy.mutate {
		context.TargetLabels["runtime"] = "mutated"
		if len(context.Reservations) > 0 {
			context.Reservations[0].ID = "mutated"
		}
	}
	return policy.admit
}

func mustPlanner(t *testing.T) *Planner {
	t.Helper()
	planner, err := NewV1Planner(5 * time.Minute)
	if err != nil {
		t.Fatalf("new planner: %v", err)
	}
	return planner
}

func assertUnschedulable(
	t *testing.T,
	decision paasv1.PlacementDecision,
	code paasv1.ErrorCode,
	retryable bool,
) {
	t.Helper()
	if decision.Outcome != paasv1.PlacementUnschedulable {
		t.Fatalf("outcome = %q, want unschedulable", decision.Outcome)
	}
	if decision.Reason == nil ||
		decision.Reason.Code != code ||
		decision.Reason.Retryable != retryable {
		t.Fatalf("reason = %#v, want code=%q retryable=%t", decision.Reason, code, retryable)
	}
	if err := paasv1.ValidatePlacementDecision(decision); err != nil {
		t.Fatalf("unschedulable decision is invalid: %v", err)
	}
}

func baseInput() Input {
	return Input{
		TenantID:      "tenant-a",
		OperationID:   "operation-placement-a",
		DecisionID:    "decision-placement-a",
		RequestDigest: testDigest('a'),
		TraceID:       "trace-placement-a",
		DecidedAt:     fixtureTime,
		Snapshot: Snapshot{
			Release: testRelease(),
			Policy:  testPolicy(),
			Pools: []paasv1.ResourcePool{
				testPool("pool-b"),
				testPool("pool-a"),
			},
			Targets: []paasv1.RuntimeTarget{
				testTarget("target-b", "pool-b", 4),
				testTarget("target-a", "pool-a", 3),
			},
		},
	}
}

func singleTargetInput() Input {
	input := baseInput()
	input.Snapshot.Pools = []paasv1.ResourcePool{testPool("pool-a")}
	input.Snapshot.Policy.Spec.EligibleResourcePools = []paasv1.ResourceID{"pool-a"}
	input.Snapshot.Targets = []paasv1.RuntimeTarget{testTarget("target-a", "pool-a", 3)}
	return input
}

func testRelease() paasv1.WorkloadRelease {
	return paasv1.WorkloadRelease{
		APIVersion: paasv1.APIVersion,
		Kind:       "WorkloadRelease",
		Metadata:   testMetadata("release-a", "release-a", paasv1.AuthorityTenant, "tenant-a", 2),
		Spec: paasv1.WorkloadReleaseSpec{
			WorkloadID:    "workload-a",
			Revision:      "revision-a",
			ContentDigest: testDigest('c'),
			Components: []paasv1.WorkloadComponent{
				{
					Name: "web",
					Artifact: paasv1.ArtifactRef{
						Kind:    paasv1.ArtifactOCIImage,
						Locator: "registry.example.invalid/workload/web",
						Digest:  testDigest('1'),
					},
					Replicas: 2,
					Resources: paasv1.ResourceRequirements{
						CPUMillis:   100,
						MemoryBytes: 128 * 1024 * 1024,
					},
				},
				{
					Name: "worker",
					Artifact: paasv1.ArtifactRef{
						Kind:    paasv1.ArtifactOCIImage,
						Locator: "registry.example.invalid/workload/worker",
						Digest:  testDigest('2'),
					},
					Replicas: 1,
					Resources: paasv1.ResourceRequirements{
						CPUMillis:   200,
						MemoryBytes: 256 * 1024 * 1024,
					},
				},
			},
		},
		Status: paasv1.WorkloadReleaseStatus{
			Phase:           paasv1.ReleasePending,
			ReadyComponents: 0,
			ObservedAt:      fixtureTime.Add(-2 * time.Minute),
		},
	}
}

func testPolicy() paasv1.PlacementPolicy {
	return paasv1.PlacementPolicy{
		APIVersion: paasv1.APIVersion,
		Kind:       "PlacementPolicy",
		Metadata:   testMetadata("policy-a", "policy-a", paasv1.AuthorityTenant, "tenant-a", 5),
		Spec: paasv1.PlacementPolicySpec{
			RequiredIsolationClass: paasv1.IsolationSharedCompose,
			EligibleResourcePools:  []paasv1.ResourceID{"pool-a", "pool-b"},
			TargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				"runtime": "compose",
			}},
			Strategy: paasv1.PlacementFirstFit,
		},
	}
}

func testPool(id paasv1.ResourceID) paasv1.ResourcePool {
	return paasv1.ResourcePool{
		APIVersion: paasv1.APIVersion,
		Kind:       "ResourcePool",
		Metadata:   testMetadata(id, string(id), paasv1.AuthorityPlatform, "", 2),
		Spec: paasv1.ResourcePoolSpec{
			TargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				"site": "local",
			}},
			AllowedIsolationClasses: []paasv1.IsolationClass{
				paasv1.IsolationSharedCompose,
				paasv1.IsolationDedicatedCompose,
			},
		},
		Status: paasv1.ResourcePoolStatus{
			Phase:            paasv1.ResourcePoolReady,
			TargetCount:      1,
			ReadyTargetCount: 1,
			ObservedAt:       fixtureTime.Add(-2 * time.Minute),
		},
	}
}

func testTarget(
	id paasv1.ResourceID,
	poolID paasv1.ResourceID,
	resourceVersion uint64,
) paasv1.RuntimeTarget {
	capacity := paasv1.Capacity{
		CPUMillis:     4_000,
		MemoryBytes:   8 * 1024 * 1024 * 1024,
		StorageBytes:  1_000_000,
		WorkloadSlots: 20,
	}
	metadata := testMetadata(id, string(id), paasv1.AuthorityPlatform, "", resourceVersion)
	metadata.Labels = map[string]string{
		"fixture": "true",
		"runtime": "compose",
		"site":    "local",
	}
	return paasv1.RuntimeTarget{
		APIVersion: paasv1.APIVersion,
		Kind:       "RuntimeTarget",
		Metadata:   metadata,
		Spec: paasv1.RuntimeTargetSpec{
			ResourcePoolID: poolID,
			InfrastructureAdapter: paasv1.AdapterRef{
				Kind:            paasv1.AdapterInfrastructure,
				Name:            "localmachine",
				ContractVersion: "v1",
			},
			RuntimeAdapter: paasv1.AdapterRef{
				Kind:            paasv1.AdapterRuntime,
				Name:            "compose",
				ContractVersion: "v1",
			},
			DesiredState: paasv1.TargetActive,
		},
		Status: paasv1.RuntimeTargetStatus{
			Health:   paasv1.TargetHealthReady,
			Capacity: capacity,
			Allocatable: paasv1.Capacity{
				CPUMillis:     2_000,
				MemoryBytes:   4 * 1024 * 1024 * 1024,
				StorageBytes:  800_000,
				WorkloadSlots: 10,
			},
			SupportedIsolationClasses: []paasv1.IsolationClass{
				paasv1.IsolationSharedCompose,
				paasv1.IsolationDedicatedCompose,
			},
			ObservedAt: fixtureTime.Add(-2 * time.Minute),
		},
	}
}

func testMetadata(
	id paasv1.ResourceID,
	name string,
	kind paasv1.AuthorityKind,
	tenantID paasv1.TenantID,
	resourceVersion uint64,
) paasv1.ResourceMetadata {
	return paasv1.ResourceMetadata{
		ID:   id,
		Name: name,
		Scope: paasv1.ResourceScope{
			Kind:     kind,
			TenantID: tenantID,
		},
		Labels:          map[string]string{"fixture": "true"},
		ResourceVersion: resourceVersion,
		CreatedAt:       fixtureTime.Add(-10 * time.Minute),
		UpdatedAt:       fixtureTime.Add(-5 * time.Minute),
	}
}

func testReservation(
	id paasv1.ResourceID,
	tenantID paasv1.TenantID,
	targetID paasv1.ResourceID,
	resources Resources,
) Reservation {
	return Reservation{
		ID:                id,
		TenantID:          tenantID,
		WorkloadReleaseID: paasv1.ResourceID("release-" + string(id)),
		DecisionID:        paasv1.ResourceID("decision-" + string(id)),
		RuntimeTargetID:   targetID,
		Isolation:         paasv1.IsolationSharedCompose,
		Resources:         resources,
		State:             ReservationActive,
		ResourceVersion:   1,
	}
}

func testDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}

func reorderedLabels(values map[string]string, reverse bool) map[string]string {
	result := make(map[string]string, len(values))
	keys := []string{"site", "runtime", "fixture"}
	if reverse {
		keys[0], keys[2] = keys[2], keys[0]
	}
	for _, key := range keys {
		if value, found := values[key]; found {
			result[key] = value
		}
	}
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneInput(value Input) Input {
	result := value
	result.Snapshot.Release = cloneRelease(value.Snapshot.Release)
	result.Snapshot.Policy = clonePlacementPolicy(value.Snapshot.Policy)
	result.Snapshot.Pools = append([]paasv1.ResourcePool(nil), value.Snapshot.Pools...)
	for index := range result.Snapshot.Pools {
		result.Snapshot.Pools[index].Metadata = cloneMetadata(result.Snapshot.Pools[index].Metadata)
		result.Snapshot.Pools[index].Spec.TargetSelector.MatchLabels = cloneLabels(
			result.Snapshot.Pools[index].Spec.TargetSelector.MatchLabels,
		)
		result.Snapshot.Pools[index].Spec.AllowedIsolationClasses = append(
			[]paasv1.IsolationClass(nil),
			result.Snapshot.Pools[index].Spec.AllowedIsolationClasses...,
		)
	}
	result.Snapshot.Targets = append([]paasv1.RuntimeTarget(nil), value.Snapshot.Targets...)
	for index := range result.Snapshot.Targets {
		result.Snapshot.Targets[index].Metadata = cloneMetadata(result.Snapshot.Targets[index].Metadata)
		result.Snapshot.Targets[index].Status.SupportedIsolationClasses = append(
			[]paasv1.IsolationClass(nil),
			result.Snapshot.Targets[index].Status.SupportedIsolationClasses...,
		)
		if result.Snapshot.Targets[index].Spec.GatewayAdapter != nil {
			adapter := *result.Snapshot.Targets[index].Spec.GatewayAdapter
			result.Snapshot.Targets[index].Spec.GatewayAdapter = &adapter
		}
	}
	result.Snapshot.Reservations = append([]Reservation(nil), value.Snapshot.Reservations...)
	return result
}

func cloneRelease(value paasv1.WorkloadRelease) paasv1.WorkloadRelease {
	result := value
	result.Metadata = cloneMetadata(value.Metadata)
	result.Spec.Components = append([]paasv1.WorkloadComponent(nil), value.Spec.Components...)
	for index := range result.Spec.Components {
		result.Spec.Components[index].ConfigurationRefs = append(
			[]paasv1.ResourceID(nil),
			result.Spec.Components[index].ConfigurationRefs...,
		)
		result.Spec.Components[index].SecretReferences = append(
			[]paasv1.SecretReference(nil),
			result.Spec.Components[index].SecretReferences...,
		)
		result.Spec.Components[index].Endpoints = append(
			[]paasv1.WorkloadEndpoint(nil),
			result.Spec.Components[index].Endpoints...,
		)
	}
	return result
}

func clonePlacementPolicy(value paasv1.PlacementPolicy) paasv1.PlacementPolicy {
	result := value
	result.Metadata = cloneMetadata(value.Metadata)
	result.Spec.EligibleResourcePools = append(
		[]paasv1.ResourceID(nil),
		value.Spec.EligibleResourcePools...,
	)
	result.Spec.TargetSelector.MatchLabels = cloneLabels(value.Spec.TargetSelector.MatchLabels)
	return result
}

func cloneMetadata(value paasv1.ResourceMetadata) paasv1.ResourceMetadata {
	result := value
	result.Labels = cloneLabels(value.Labels)
	return result
}
