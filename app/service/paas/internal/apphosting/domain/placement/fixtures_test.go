package placement

import (
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type testIsolationPolicy struct {
	class   paasv1.IsolationGuarantee
	version string
	admit   bool
	mutate  bool
}

func (policy testIsolationPolicy) IsolationGuarantee() paasv1.IsolationGuarantee {
	return policy.class
}

func (policy testIsolationPolicy) Version() string {
	return policy.version
}

func (policy testIsolationPolicy) Admit(context IsolationContext) bool {
	if policy.mutate {
		context.TargetLabels["runtime"] = "mutated"
		if len(context.CapacityClaims) > 0 {
			context.CapacityClaims[0].ID = "mutated"
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
			Deployment:          testDeployment(),
			ApplicationRevision: testApplicationRevision(),
			Policy:              testPolicy(),
			Pools: []paasv1.ExecutionPool{
				testPool("pool-b"),
				testPool("pool-a"),
			},
			Targets: []paasv1.ExecutionTarget{
				testTarget("target-b", "pool-b", 4),
				testTarget("target-a", "pool-a", 3),
			},
		},
	}
}

func singleTargetInput() Input {
	input := baseInput()
	input.Snapshot.Pools = []paasv1.ExecutionPool{testPool("pool-a")}
	input.Snapshot.Policy.Spec.EligibleExecutionPoolIDs = []paasv1.ResourceID{"pool-a"}
	input.Snapshot.Targets = []paasv1.ExecutionTarget{testTarget("target-a", "pool-a", 3)}
	return input
}

func testApplicationRevision() paasv1.ApplicationRevision {
	return paasv1.ApplicationRevision{
		APIVersion: paasv1.APIVersion,
		Kind:       "ApplicationRevision",
		Metadata:   testImmutableMetadata("revision-a", "revision-a", "tenant-a"),
		Spec: paasv1.ApplicationRevisionSpec{
			ApplicationID: "application-a",
			Revision:      "revision-a",
			ContentDigest: testDigest('c'),
			Components: []paasv1.ApplicationRevisionComponent{
				{
					Name: "web",
					Artifact: paasv1.ArtifactRef{
						Kind:    paasv1.ArtifactOCIImage,
						Locator: "registry.example.invalid/application/web",
						Digest:  testDigest('1'),
					},
					Resources: paasv1.ResourceRequirements{
						CPUMillis:   100,
						MemoryBytes: 128 * 1024 * 1024,
					},
				},
				{
					Name: "worker",
					Artifact: paasv1.ArtifactRef{
						Kind:    paasv1.ArtifactOCIImage,
						Locator: "registry.example.invalid/application/worker",
						Digest:  testDigest('2'),
					},
					Resources: paasv1.ResourceRequirements{
						CPUMillis:   200,
						MemoryBytes: 256 * 1024 * 1024,
					},
				},
			},
		},
	}
}

func testDeployment() paasv1.Deployment {
	return paasv1.Deployment{
		APIVersion: paasv1.APIVersion,
		Kind:       "Deployment",
		Metadata:   testMetadata("deployment-a", "deployment-a", paasv1.AuthorityTenant, "tenant-a", 2),
		Generation: 1,
		Spec: paasv1.DeploymentSpec{
			ApplicationRevisionID: "revision-a",
			PlacementPolicyID:     "policy-a",
			DesiredState:          paasv1.DeploymentDesiredRunning,
			Components: []paasv1.DeploymentComponent{
				{Name: "web", Replicas: 2},
				{Name: "worker", Replicas: 1},
			},
		},
		Status: paasv1.DeploymentStatus{
			Phase:              paasv1.DeploymentPending,
			ObservedGeneration: 0,
			ObservedAt:         fixtureTime.Add(-2 * time.Minute),
		},
	}
}

func testPolicy() paasv1.PlacementPolicy {
	return paasv1.PlacementPolicy{
		APIVersion: paasv1.APIVersion,
		Kind:       "PlacementPolicy",
		Metadata:   testMetadata("policy-a", "policy-a", paasv1.AuthorityTenant, "tenant-a", 5),
		Spec: paasv1.PlacementPolicySpec{
			RequiredIsolationGuarantee: paasv1.IsolationWorkload,
			EligibleExecutionPoolIDs:   []paasv1.ResourceID{"pool-a", "pool-b"},
			ExecutionTargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				"executor": "compose",
			}},
			Strategy: paasv1.PlacementFirstFit,
		},
	}
}

func testPool(id paasv1.ResourceID) paasv1.ExecutionPool {
	return paasv1.ExecutionPool{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionPool",
		Metadata:   testMetadata(id, string(id), paasv1.AuthorityPlatform, "", 2),
		Spec: paasv1.ExecutionPoolSpec{
			ExecutionTargetSelector: paasv1.LabelSelector{MatchLabels: map[string]string{
				"site": "local",
			}},
			AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{
				paasv1.IsolationWorkload,
			},
		},
		Status: paasv1.ExecutionPoolStatus{
			Phase:                     paasv1.ExecutionPoolReady,
			ExecutionTargetCount:      1,
			ReadyExecutionTargetCount: 1,
			ObservedAt:                fixtureTime.Add(-2 * time.Minute),
		},
	}
}

func testTarget(
	id paasv1.ResourceID,
	poolID paasv1.ResourceID,
	resourceVersion uint64,
) paasv1.ExecutionTarget {
	capacity := paasv1.Capacity{
		CPUMillis:     4_000,
		MemoryBytes:   8 * 1024 * 1024 * 1024,
		StorageBytes:  1_000_000,
		WorkloadSlots: 20,
	}
	metadata := testMetadata(id, string(id), paasv1.AuthorityPlatform, "", resourceVersion)
	metadata.Labels = map[string]string{
		"fixture":  "true",
		"executor": "compose",
		"site":     "local",
	}
	return paasv1.ExecutionTarget{
		APIVersion: paasv1.APIVersion,
		Kind:       "ExecutionTarget",
		Metadata:   metadata,
		Spec: paasv1.ExecutionTargetSpec{
			ExecutionPoolID: poolID,
			InfrastructureAdapter: paasv1.AdapterRef{
				Kind:            paasv1.AdapterInfrastructure,
				Name:            "localmachine",
				ContractVersion: "v1",
			},
			DeploymentExecutor: paasv1.AdapterRef{
				Kind:            paasv1.AdapterDeploymentExecutor,
				Name:            "compose",
				ContractVersion: "v1",
			},
			DesiredState: paasv1.ExecutionTargetActive,
		},
		Status: paasv1.ExecutionTargetStatus{
			Health:   paasv1.ExecutionTargetHealthReady,
			Capacity: capacity,
			Allocatable: paasv1.Capacity{
				CPUMillis:     2_000,
				MemoryBytes:   4 * 1024 * 1024 * 1024,
				StorageBytes:  800_000,
				WorkloadSlots: 10,
			},
			SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{
				paasv1.IsolationWorkload,
			},
			ObservedAt: fixtureTime.Add(-2 * time.Minute),
		},
	}
}

func testImmutableMetadata(
	id paasv1.ResourceID,
	name string,
	tenantID paasv1.TenantID,
) paasv1.ResourceMetadata {
	createdAt := fixtureTime.Add(-10 * time.Minute)
	return paasv1.ResourceMetadata{
		ID:   id,
		Name: name,
		Scope: paasv1.ResourceScope{
			Kind:     paasv1.AuthorityTenant,
			TenantID: tenantID,
		},
		Labels:          map[string]string{"fixture": "true"},
		ResourceVersion: 1,
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
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

func testCapacityClaim(
	id paasv1.ResourceID,
	targetID paasv1.ResourceID,
	resources Resources,
) CapacityClaim {
	return CapacityClaim{
		ID:                id,
		ExecutionTargetID: targetID,
		Isolation:         paasv1.IsolationWorkload,
		Resources:         resources,
		State:             CapacityClaimActive,
		ResourceVersion:   1,
	}
}

func testDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}

func reorderedLabels(values map[string]string, reverse bool) map[string]string {
	result := make(map[string]string, len(values))
	keys := []string{"site", "executor", "fixture"}
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
	result.Snapshot.Deployment = cloneDeployment(value.Snapshot.Deployment)
	result.Snapshot.ApplicationRevision = cloneApplicationRevision(value.Snapshot.ApplicationRevision)
	result.Snapshot.Policy = clonePlacementPolicy(value.Snapshot.Policy)
	result.Snapshot.Pools = append([]paasv1.ExecutionPool(nil), value.Snapshot.Pools...)
	for index := range result.Snapshot.Pools {
		result.Snapshot.Pools[index].Metadata = cloneMetadata(result.Snapshot.Pools[index].Metadata)
		result.Snapshot.Pools[index].Spec.ExecutionTargetSelector.MatchLabels = cloneLabels(
			result.Snapshot.Pools[index].Spec.ExecutionTargetSelector.MatchLabels,
		)
		result.Snapshot.Pools[index].Spec.AllowedIsolationGuarantees = append(
			[]paasv1.IsolationGuarantee(nil),
			result.Snapshot.Pools[index].Spec.AllowedIsolationGuarantees...,
		)
	}
	result.Snapshot.Targets = append([]paasv1.ExecutionTarget(nil), value.Snapshot.Targets...)
	for index := range result.Snapshot.Targets {
		result.Snapshot.Targets[index].Metadata = cloneMetadata(result.Snapshot.Targets[index].Metadata)
		result.Snapshot.Targets[index].Status.SupportedIsolationGuarantees = append(
			[]paasv1.IsolationGuarantee(nil),
			result.Snapshot.Targets[index].Status.SupportedIsolationGuarantees...,
		)
		if result.Snapshot.Targets[index].Spec.GatewayAdapter != nil {
			adapter := *result.Snapshot.Targets[index].Spec.GatewayAdapter
			result.Snapshot.Targets[index].Spec.GatewayAdapter = &adapter
		}
	}
	result.Snapshot.CapacityClaims = append(
		[]CapacityClaim(nil),
		value.Snapshot.CapacityClaims...,
	)
	return result
}

func cloneApplicationRevision(value paasv1.ApplicationRevision) paasv1.ApplicationRevision {
	result := value
	result.Metadata = cloneMetadata(value.Metadata)
	result.Spec.Components = append([]paasv1.ApplicationRevisionComponent(nil), value.Spec.Components...)
	for index := range result.Spec.Components {
		result.Spec.Components[index].Endpoints = append(
			[]paasv1.ApplicationEndpoint(nil),
			result.Spec.Components[index].Endpoints...,
		)
		result.Spec.Components[index].Inputs = append(
			[]paasv1.ComponentInput(nil),
			result.Spec.Components[index].Inputs...,
		)
	}
	return result
}

func cloneDeployment(value paasv1.Deployment) paasv1.Deployment {
	result := value
	result.Metadata = cloneMetadata(value.Metadata)
	result.Spec.Components = append([]paasv1.DeploymentComponent(nil), value.Spec.Components...)
	for index := range result.Spec.Components {
		result.Spec.Components[index].Bindings = append(
			[]paasv1.ComponentBinding(nil),
			result.Spec.Components[index].Bindings...,
		)
		for bindingIndex := range result.Spec.Components[index].Bindings {
			binding := &result.Spec.Components[index].Bindings[bindingIndex]
			if binding.SecretVersion != nil {
				secret := *binding.SecretVersion
				binding.SecretVersion = &secret
			}
		}
	}
	return result
}

func clonePlacementPolicy(value paasv1.PlacementPolicy) paasv1.PlacementPolicy {
	result := value
	result.Metadata = cloneMetadata(value.Metadata)
	result.Spec.EligibleExecutionPoolIDs = append(
		[]paasv1.ResourceID(nil),
		value.Spec.EligibleExecutionPoolIDs...,
	)
	result.Spec.ExecutionTargetSelector.MatchLabels = cloneLabels(value.Spec.ExecutionTargetSelector.MatchLabels)
	return result
}

func cloneMetadata(value paasv1.ResourceMetadata) paasv1.ResourceMetadata {
	result := value
	result.Labels = cloneLabels(value.Labels)
	return result
}
