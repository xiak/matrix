package phase1e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/adapter/infrastructure/localmachine"
)

// The same gate binary probes each independently booted guest before loading
// images or enrolling a node. No HTTP/debug endpoint or caller host selector.
func TestOfflineNativeHostProbe(t *testing.T) {
	phase := os.Getenv("MATRIX_PHASE1_NATIVE_HOST_PROBE")
	if phase != "1" && phase != "runtime" && phase != "after-restart" {
		t.Skip("native offline companion only")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		t.Fatal("native probe requires Linux/amd64 root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if phase != "runtime" && assertNoExternalRoute() != nil || phase == "1" && assertEmptyDocker(ctx) != nil {
		t.Fatal("native companion is not empty and offline")
	}
	if _, err := os.Stat(nativeInstallationRoot); (phase == "1" || phase == "runtime") && !os.IsNotExist(err) || phase == "after-restart" && err != nil {
		t.Fatal("native installation root already exists")
	}
	facts, err := localmachine.NewLocalHostProbe().Inspect(ctx, nativeFixtureRoot)
	if err != nil || !facts.DockerEngineReady || !facts.ComposePluginReady {
		t.Fatal("real native host prerequisites unavailable")
	}
	fingerprint, err := localmachine.DeriveMachineFingerprint(facts)
	if err != nil {
		t.Fatal("native fingerprint unavailable")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal("native boot identity unavailable")
	}
	engine, err := docker(ctx, "info", "--format", "{{.ID}}")
	if err != nil {
		t.Fatal("native engine identity unavailable")
	}
	result := nativeHostFacts{Fingerprint: fingerprint, BootID: strings.TrimSpace(string(boot)), EngineID: strings.TrimSpace(string(engine)), CPUs: int64(facts.LogicalCPUs), MemoryBytes: int64(facts.MemoryTotalBytes), StorageBytes: int64(facts.StorageTotalBytes)}
	if !validNativeFacts(result) {
		t.Fatal("native host facts invalid")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	name := "facts.json"
	if phase == "after-restart" {
		name = "facts-after-restart.json"
	}
	if _, err = privateFixtureFile(nativeFixtureRoot, name, encoded); err != nil {
		t.Fatal(err)
	}
}

func TestNativeBootEvidenceRequiresNewKernelAndSameIdentity(t *testing.T) {
	before := nativeHostFacts{Fingerprint: "sha256:" + strings.Repeat("a", 64), BootID: "00000000-0000-0000-0000-000000000001", EngineID: "engine-1", CPUs: 2, MemoryBytes: 2 << 30, StorageBytes: 20 << 30}
	after := before
	after.BootID = "00000000-0000-0000-0000-000000000002"
	if !sameNativeHostAfterBoot(before, after) || sameNativeHostAfterBoot(before, before) {
		t.Fatal("kernel boot evidence not distinguished")
	}
	for _, change := range []func(*nativeHostFacts){func(v *nativeHostFacts) { v.MemoryBytes -= 4096 }, func(v *nativeHostFacts) { v.StorageBytes += 4096 }, func(v *nativeHostFacts) { v.CPUs++ }} {
		candidate := after
		change(&candidate)
		if !sameNativeHostAfterBoot(before, candidate) {
			t.Fatal("current capacity was mistaken for immutable host identity")
		}
	}
	for _, change := range []func(*nativeHostFacts){func(v *nativeHostFacts) { v.Fingerprint = "sha256:" + strings.Repeat("b", 64) }, func(v *nativeHostFacts) { v.EngineID = "engine-2" }, func(v *nativeHostFacts) { v.BootID = "" }, func(v *nativeHostFacts) { v.MemoryBytes = 0 }, func(v *nativeHostFacts) { v.StorageBytes = 0 }, func(v *nativeHostFacts) { v.CPUs = 0 }} {
		candidate := after
		change(&candidate)
		if sameNativeHostAfterBoot(before, candidate) {
			t.Fatal("replacement host or invalid physical facts accepted as retained boot")
		}
	}
}

func TestNativeFixtureRejectsAmbiguousOrExternalTargets(t *testing.T) {
	directory := t.TempDir()
	valid := nativeFixtureInput{ReleaseA: filepath.Join(directory, "a"), ReleaseB: filepath.Join(directory, "b"), IdentityFile: filepath.Join(directory, "client"), KnownHostsFile: filepath.Join(directory, "known_hosts"), Nodes: []nativeNodeInput{{Port: 2201, Endpoint: "https://172.17.0.1:16443"}, {Port: 2202, Endpoint: "https://172.17.0.1:16444"}}}
	for _, scenario := range []struct {
		name   string
		change func(*nativeFixtureInput)
	}{
		{"one host", func(v *nativeFixtureInput) { v.Nodes = v.Nodes[:1] }},
		{"same SSH forward", func(v *nativeFixtureInput) { v.Nodes[1].Port = v.Nodes[0].Port }},
		{"same node endpoint", func(v *nativeFixtureInput) { v.Nodes[1].Endpoint = v.Nodes[0].Endpoint }},
		{"public endpoint", func(v *nativeFixtureInput) { v.Nodes[0].Endpoint = "https://8.8.8.8:16443" }},
		{"DNS endpoint", func(v *nativeFixtureInput) { v.Nodes[0].Endpoint = "https://node.invalid:16443" }},
		{"HTTP endpoint", func(v *nativeFixtureInput) { v.Nodes[0].Endpoint = "http://172.17.0.1:16443" }},
		{"endpoint credentials", func(v *nativeFixtureInput) { v.Nodes[0].Endpoint = "https://user@172.17.0.1:16443" }},
		{"query", func(v *nativeFixtureInput) { v.Nodes[0].Endpoint += "?" }},
		{"public listen address", func(v *nativeFixtureInput) { v.Nodes[0].ListenAddress = "8.8.8.8:16443" }},
		{"DNS listen address", func(v *nativeFixtureInput) { v.Nodes[0].ListenAddress = "node.invalid:16443" }},
		{"missing listen port", func(v *nativeFixtureInput) { v.Nodes[0].ListenAddress = "172.17.0.1" }},
		{"privileged collector", func(v *nativeFixtureInput) { v.Nodes[0].CollectorPort = 443 }},
		{"shared node and collector port", func(v *nativeFixtureInput) { v.Nodes[0].CollectorPort = 16443 }},
		{"relative signer", func(v *nativeFixtureInput) { v.IdentityFile = "client" }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			input := valid
			input.Nodes = append([]nativeNodeInput(nil), valid.Nodes...)
			scenario.change(&input)
			if validateNativeFixture(input) == nil {
				t.Fatal("unsafe or ambiguous native fixture accepted")
			}
		})
	}
	if validateNativeFixture(valid) != nil {
		t.Fatal("valid isolated native fixture rejected")
	}
}

func TestNativeDeploymentRuntimeRequiresExactAdvancingProviderNeutralProof(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	deployment := paasv1.Deployment{
		Metadata:   paasv1.ResourceMetadata{ID: "deployment-a", Scope: paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-a"}},
		Generation: 1,
		Spec:       paasv1.DeploymentSpec{ApplicationRevisionID: "revision-a"},
	}
	snapshot := paasv1.DeploymentRuntimeSnapshot{
		APIVersion: paasv1.APIVersion,
		Kind:       "DeploymentRuntimeSnapshot",
		Scope:      deployment.Metadata.Scope,
		State:      paasv1.MeasurementAvailable,
		Value: &paasv1.DeploymentRuntimeValue{
			Observation: paasv1.DeploymentRuntimeObservation{
				DeploymentID:          deployment.Metadata.ID,
				Generation:            deployment.Generation,
				ApplicationRevisionID: deployment.Spec.ApplicationRevisionID,
				ExecutionTargetID:     "target-a",
				Instances: []paasv1.DeploymentRuntimeInstance{{
					ID: "instance-0123456789abcdef0123456789abcdef", ComponentName: "web",
					State: paasv1.DeploymentInstanceRunning, Health: paasv1.DeploymentInstanceHealthNone,
				}},
				ObservedAt: now,
			},
			ValidUntil: now.Add(15 * time.Second),
		},
		Resources: paasv1.DeploymentResourceSnapshot{
			State: paasv1.MeasurementAvailable,
			Value: &paasv1.DeploymentResourceValue{
				Observation: paasv1.DeploymentResourceObservation{
					DeploymentID:          deployment.Metadata.ID,
					Generation:            deployment.Generation,
					ApplicationRevisionID: deployment.Spec.ApplicationRevisionID,
					ExecutionTargetID:     "target-a",
					Instances: []paasv1.DeploymentResourceInstance{{
						ID: "instance-0123456789abcdef0123456789abcdef",
						CPU: paasv1.DeploymentInstanceCPUUsage{
							State: paasv1.MeasurementAvailable,
							Value: &paasv1.DeploymentInstanceCPUUsageValue{
								WindowMillis: 1000, UsedCores: 0.1, LimitCPUMillis: 100,
							},
						},
						Memory: paasv1.DeploymentInstanceMemoryUsage{
							State: paasv1.MeasurementAvailable,
							Value: &paasv1.DeploymentInstanceMemoryUsageValue{
								UsedBytes: 8 << 20, LimitBytes: 32 << 20,
							},
						},
						Network: paasv1.DeploymentInstanceNetworkUsage{
							State: paasv1.MeasurementAvailable,
							Value: &paasv1.DeploymentInstanceNetworkUsageValue{},
						},
						BlockIO: paasv1.DeploymentInstanceBlockIOUsage{State: paasv1.MeasurementUnsupported},
						Storage: paasv1.DeploymentInstanceStorageUsage{
							State: paasv1.MeasurementAvailable,
							Value: &paasv1.DeploymentInstanceStorageUsageValue{
								ObservedAt: now.Add(-10 * time.Second), ValidUntil: now.Add(80 * time.Second),
								ImageTotalBytes: 10, ImageSharedBytes: 4, ImageUniqueBytes: 6,
								VolumesState: paasv1.MeasurementAvailable,
								Volumes:      &paasv1.DeploymentInstanceVolumeUsage{},
							},
						},
					}},
					ObservedAt: now,
				},
				ValidUntil: now.Add(15 * time.Second),
			},
		},
	}
	if !validNativeDeploymentRuntime(snapshot, deployment, "target-a", now.Add(-time.Second), now.Add(time.Second)) {
		t.Fatal("exact advancing runtime proof rejected")
	}
	for _, change := range []func(*paasv1.DeploymentRuntimeSnapshot){
		func(value *paasv1.DeploymentRuntimeSnapshot) { value.Value.Observation.ExecutionTargetID = "target-b" },
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Value.Observation.ObservedAt = now.Add(-2 * time.Second)
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Value.Observation.Instances[0].Health = paasv1.DeploymentInstanceHealthUnhealthy
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Value.Observation.Instances[0].Health = paasv1.DeploymentInstanceHealthStarting
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) { value.Value.ValidUntil = now },
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.ExecutionTargetID = "target-b"
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.ObservedAt = now.Add(-2 * time.Second)
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.Instances[0].CPU.State = paasv1.MeasurementUnsupported
			value.Resources.Value.Observation.Instances[0].CPU.Value = nil
		},
		func(value *paasv1.DeploymentRuntimeSnapshot) {
			value.Resources.Value.Observation.Instances[0].ID = "instance-fedcba9876543210fedcba9876543210"
		},
	} {
		candidate := snapshot.Snapshot(now)
		change(&candidate)
		if validNativeDeploymentRuntime(candidate, deployment, "target-a", now.Add(-time.Second), now.Add(time.Second)) {
			t.Fatal("stale, unready or wrong-target runtime proof accepted")
		}
	}
}

func TestNativeRetentionRequiresSameRunningContainerAndStart(t *testing.T) {
	baseline := nativeWorkload{ID: strings.Repeat("a", 64), StartedAt: "2026-08-28T00:00:00Z", Running: true}
	if !sameNativeWorkload(baseline, baseline) {
		t.Fatal("unchanged runtime rejected")
	}
	for _, scenario := range []struct {
		name   string
		change func(*nativeWorkload)
	}{
		{"replacement", func(v *nativeWorkload) { v.ID = strings.Repeat("b", 64) }},
		{"restart", func(v *nativeWorkload) { v.StartedAt = "2026-08-28T00:01:00Z" }},
		{"restart counter", func(v *nativeWorkload) { v.RestartCount++ }},
		{"stopped", func(v *nativeWorkload) { v.Running = false }},
		{"missing start", func(v *nativeWorkload) { v.StartedAt = "" }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			current := baseline
			scenario.change(&current)
			if sameNativeWorkload(baseline, current) {
				t.Fatal("runtime replacement or downtime accepted as retention")
			}
		})
	}
}

func TestNativeRotationAllowsOnlyTheOwnedAPIReplacement(t *testing.T) {
	var before []containerInspection
	for _, name := range []string{"paas-api", "paas-worker", "postgres", "workload"} {
		var container containerInspection
		container.ID = name + "-before"
		container.Config.Image = "sha256:" + strings.Repeat("a", 64)
		container.Config.Labels = map[string]string{"com.xiak.matrix.installation": "installation-test", "com.xiak.matrix.role": name}
		container.State.Running = true
		container.State.StartedAt = "2026-08-28T00:00:00Z"
		before = append(before, container)
	}
	for _, scenario := range []struct {
		name    string
		mutate  func([]containerInspection) []containerInspection
		allowed bool
	}{
		{"API only", func(v []containerInspection) []containerInspection { return v }, true},
		{"worker replacement", func(v []containerInspection) []containerInspection { v[1].ID = "new-worker"; return v }, false},
		{"database restart", func(v []containerInspection) []containerInspection {
			v[2].State.StartedAt = "2026-08-28T00:01:00Z"
			return v
		}, false},
		{"workload restart counter", func(v []containerInspection) []containerInspection { v[3].RestartCount++; return v }, false},
		{"database stopped", func(v []containerInspection) []containerInspection { v[2].State.Running = false; return v }, false},
		{"API foreign installation", func(v []containerInspection) []containerInspection {
			v[0].Config.Labels = map[string]string{"com.xiak.matrix.installation": "foreign", "com.xiak.matrix.role": "paas-api"}
			return v
		}, false},
		{"API wrong image", func(v []containerInspection) []containerInspection { v[0].Config.Image = "other-image"; return v }, false},
		{"additional runtime", func(v []containerInspection) []containerInspection { return append(v, v[2]) }, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			after := append([]containerInspection(nil), before...)
			after[0].ID = "new-api"
			after[0].State.StartedAt = "2026-08-28T00:01:00Z"
			after = scenario.mutate(after)
			if preservesNativeRotationRuntime(before, after, "installation-test") != scenario.allowed {
				t.Fatal("API-only replacement boundary misclassified")
			}
		})
	}
}
