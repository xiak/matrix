package paasv1

import (
	"testing"
	"time"
)

func TestDeploymentRuntimeSnapshotRetainsExactProofAndProjectsStaleness(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	snapshot := deploymentRuntimeSnapshotFixture(now)
	if err := ValidateDeploymentRuntimeSnapshot(snapshot); err != nil {
		t.Fatalf("valid runtime snapshot: %v", err)
	}

	current := snapshot.Snapshot(now.Add(5 * time.Second))
	if current.State != MeasurementAvailable || current.Value == snapshot.Value ||
		&current.Value.Observation.Instances[0] == &snapshot.Value.Observation.Instances[0] ||
		current.Resources.Value == snapshot.Resources.Value ||
		current.Resources.Value.Observation.Instances[0].CPU.Value == snapshot.Resources.Value.Observation.Instances[0].CPU.Value {
		t.Fatalf("current snapshot was not independently copied: %#v", current)
	}
	stale := snapshot.Snapshot(now.Add(15 * time.Second))
	if stale.State != MeasurementStale || stale.Value.Observation.ObservedAt != now ||
		stale.Value.ValidUntil != now.Add(15*time.Second) || stale.Resources.State != MeasurementStale ||
		stale.Resources.Value.Observation.Instances[0].Storage.State != MeasurementAvailable {
		t.Fatalf("expired snapshot was restamped or not stale: %#v", stale)
	}
	storageStale := snapshot.Snapshot(now.Add(90 * time.Second))
	if storageStale.Resources.Value.Observation.Instances[0].Storage.State != MeasurementStale {
		t.Fatalf("storage did not retain its independent timestamp: %#v", storageStale.Resources)
	}
	stale.Value.Observation.Instances[0].ComponentName = "changed"
	stale.Resources.Value.Observation.Instances[0].CPU.Value.UsedCores = 3
	if snapshot.Value.Observation.Instances[0].ComponentName != "web" {
		t.Fatal("snapshot copy mutated persisted runtime proof")
	}
	if snapshot.Resources.Value.Observation.Instances[0].CPU.Value.UsedCores != 0.25 {
		t.Fatal("snapshot copy mutated persisted resource proof")
	}
}

func TestObserveDeploymentRuntimeRequestIsExactAndTenantScoped(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	request := ObserveDeploymentRuntimeRequest{
		RequestID:             "runtime-observe-a",
		Scope:                 ResourceScope{Kind: AuthorityTenant, TenantID: "tenant-a"},
		DeploymentID:          "deployment-a",
		Generation:            2,
		ApplicationRevisionID: "revision-a",
		ExecutionTargetID:     "target-a",
		ExpectedContentDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline:              now.Add(15 * time.Second),
	}
	if err := ValidateObserveDeploymentRuntimeRequest(request); err != nil {
		t.Fatalf("valid runtime request: %v", err)
	}
	request.Scope = ResourceScope{Kind: AuthorityPlatform}
	if ValidateObserveDeploymentRuntimeRequest(request) == nil {
		t.Fatal("runtime observation accepted platform scope")
	}
}

func TestDeploymentRuntimeContractsRejectAmbiguousOrProviderNativeValues(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	valid := deploymentRuntimeSnapshotFixture(now)

	tests := map[string]func(*DeploymentRuntimeSnapshot){
		"platform scope": func(value *DeploymentRuntimeSnapshot) {
			value.Scope = ResourceScope{Kind: AuthorityPlatform}
		},
		"unsupported state": func(value *DeploymentRuntimeSnapshot) {
			value.State = MeasurementWarmingUp
		},
		"missing value": func(value *DeploymentRuntimeSnapshot) {
			value.Value = nil
		},
		"duplicated opaque instance": func(value *DeploymentRuntimeSnapshot) {
			value.Value.Observation.Instances = append(
				value.Value.Observation.Instances,
				value.Value.Observation.Instances[0],
			)
		},
		"exit code on running instance": func(value *DeploymentRuntimeSnapshot) {
			exitCode := uint32(0)
			value.Value.Observation.Instances[0].ExitCode = &exitCode
		},
		"terminal instance without exit code": func(value *DeploymentRuntimeSnapshot) {
			value.Value.Observation.Instances[0].State = DeploymentInstanceExited
		},
		"provider native instance id": func(value *DeploymentRuntimeSnapshot) {
			value.Value.Observation.Instances[0].ID = "sha256:provider-id"
		},
		"provider native resource id": func(value *DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.Instances[0].ID = "sha256:provider-id"
		},
		"resource identity mismatch": func(value *DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.ExecutionTargetID = "target-b"
		},
		"memory exceeds limit": func(value *DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.Instances[0].Memory.Value.UsedBytes = 65 << 20
		},
		"shared image accounting mismatch": func(value *DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.Instances[0].Storage.Value.ImageSharedBytes++
		},
		"volume state without value": func(value *DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.Instances[0].Storage.Value.Volumes = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := valid.Snapshot(now)
			mutate(&value)
			if ValidateDeploymentRuntimeSnapshot(value) == nil {
				t.Fatalf("invalid runtime snapshot accepted: %#v", value)
			}
		})
	}

	unavailable := DeploymentRuntimeSnapshot{
		APIVersion: APIVersion,
		Kind:       "DeploymentRuntimeSnapshot",
		Scope:      valid.Scope,
		State:      MeasurementUnavailable,
		Resources:  DeploymentResourceSnapshot{State: MeasurementUnavailable},
	}
	if err := ValidateDeploymentRuntimeSnapshot(unavailable); err != nil {
		t.Fatalf("unavailable snapshot without fabricated value: %v", err)
	}
	unavailable.Value = valid.Value
	if ValidateDeploymentRuntimeSnapshot(unavailable) == nil {
		t.Fatal("unavailable snapshot accepted a fabricated last value")
	}
}

func TestDeploymentListIsBoundedAndTenantScoped(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	scope := ResourceScope{Kind: AuthorityTenant, TenantID: "tenant-a"}
	deployment := Deployment{
		APIVersion: APIVersion,
		Kind:       "Deployment",
		Metadata: ResourceMetadata{
			ID: "deployment-a", Name: "deployment-a", Scope: scope,
			ResourceVersion: 1, CreatedAt: now, UpdatedAt: now,
		},
		Generation: 1,
		Spec: DeploymentSpec{
			ApplicationRevisionID: "revision-a",
			PlacementPolicyID:     "policy-a",
			DesiredState:          DeploymentDesiredRunning,
			Components:            []DeploymentComponent{{Name: "web", Replicas: 1}},
		},
		Status: DeploymentStatus{Phase: DeploymentPending, ObservedAt: now},
	}
	list := DeploymentList{
		APIVersion: APIVersion,
		Kind:       "DeploymentList",
		Scope:      scope,
		Items:      []Deployment{deployment},
	}
	if err := ValidateDeploymentList(list); err != nil {
		t.Fatalf("valid Deployment list: %v", err)
	}
	list.Items = append(list.Items, deployment)
	if ValidateDeploymentList(list) == nil {
		t.Fatal("Deployment list accepted duplicate resource identity")
	}
	list.Items[1].Metadata.Scope.TenantID = "tenant-b"
	list.Items[1].Metadata.ID = "deployment-b"
	if ValidateDeploymentList(list) == nil {
		t.Fatal("Deployment list accepted another tenant")
	}
	list.Items[1].Metadata.Scope.TenantID = "tenant-a"
	list.Items = []Deployment{list.Items[1], list.Items[0]}
	if ValidateDeploymentList(list) == nil {
		t.Fatal("Deployment list accepted out-of-order resource identities")
	}
	list.Items = []Deployment{list.Items[1]}
	list.NextAfter = "deployment-b"
	if ValidateDeploymentList(list) == nil {
		t.Fatal("Deployment list accepted a cursor other than its final resource identity")
	}
	list.NextAfter = list.Items[0].Metadata.ID
	if err := ValidateDeploymentList(list); err != nil {
		t.Fatalf("Deployment list rejected exact final-resource cursor: %v", err)
	}
}

func deploymentRuntimeSnapshotFixture(now time.Time) DeploymentRuntimeSnapshot {
	return DeploymentRuntimeSnapshot{
		APIVersion: APIVersion,
		Kind:       "DeploymentRuntimeSnapshot",
		Scope:      ResourceScope{Kind: AuthorityTenant, TenantID: "tenant-a"},
		State:      MeasurementAvailable,
		Value: &DeploymentRuntimeValue{
			Observation: DeploymentRuntimeObservation{
				DeploymentID:          "deployment-a",
				Generation:            2,
				ApplicationRevisionID: "revision-a",
				ExecutionTargetID:     "target-a",
				Instances: []DeploymentRuntimeInstance{{
					ID:            "instance-0123456789abcdef0123456789abcdef",
					ComponentName: "web",
					State:         DeploymentInstanceRunning,
					Health:        DeploymentInstanceHealthHealthy,
				}},
				ObservedAt: now,
			},
			ValidUntil: now.Add(15 * time.Second),
		},
		Resources: DeploymentResourceSnapshot{
			State: MeasurementAvailable,
			Value: &DeploymentResourceValue{
				Observation: DeploymentResourceObservation{
					DeploymentID:          "deployment-a",
					Generation:            2,
					ApplicationRevisionID: "revision-a",
					ExecutionTargetID:     "target-a",
					Instances: []DeploymentResourceInstance{{
						ID: "instance-0123456789abcdef0123456789abcdef",
						CPU: DeploymentInstanceCPUUsage{State: MeasurementAvailable, Value: &DeploymentInstanceCPUUsageValue{
							WindowMillis: 1000, UsedCores: 0.25, LimitCPUMillis: 500,
						}},
						Memory: DeploymentInstanceMemoryUsage{State: MeasurementAvailable, Value: &DeploymentInstanceMemoryUsageValue{
							UsedBytes: 16 << 20, LimitBytes: 64 << 20,
						}},
						Network: DeploymentInstanceNetworkUsage{State: MeasurementAvailable, Value: &DeploymentInstanceNetworkUsageValue{
							ReceivedBytes: 100, TransmittedBytes: 200, ReceiveErrors: 1, TransmitDrops: 2,
						}},
						BlockIO: DeploymentInstanceBlockIOUsage{State: MeasurementAvailable, Value: &DeploymentInstanceBlockIOUsageValue{
							ReadBytes: 300, WriteBytes: 400, ReadOperations: 3, WriteOperations: 4,
						}},
						Storage: DeploymentInstanceStorageUsage{State: MeasurementAvailable, Value: &DeploymentInstanceStorageUsageValue{
							ObservedAt: now, ValidUntil: now.Add(time.Minute), WritableLayerBytes: 500,
							ImageTotalBytes: 1000, ImageSharedBytes: 700, ImageUniqueBytes: 300,
							VolumesState: MeasurementAvailable,
							Volumes:      &DeploymentInstanceVolumeUsage{Count: 2, Bytes: 900, SharedCount: 1, SharedBytes: 600},
						}},
					}},
					ObservedAt: now,
				},
				ValidUntil: now.Add(15 * time.Second),
			},
		},
	}
}
