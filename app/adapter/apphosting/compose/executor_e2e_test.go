package compose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/test/composefixture"
)

func TestRealComposeExecutorOfflineVerticalSlice(t *testing.T) {
	if os.Getenv("MATRIX_COMPOSE_E2E") != "1" {
		t.Skip("set MATRIX_COMPOSE_E2E=1 to run the real offline Docker Compose gate")
	}
	requireDocker(t)
	fixtureContext, cancelFixture := context.WithTimeout(context.Background(), 2*time.Minute)
	fixtureImage, err := composefixture.Import(fixtureContext)
	cancelFixture()
	if err != nil {
		t.Fatalf("import offline fixture image: %v", err)
	}
	imageID := fixtureImage.ID
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = fixtureImage.Close(cleanupContext)
	})

	secretSource := t.TempDir()
	if err := os.Chmod(secretSource, 0o700); err != nil {
		t.Fatalf("protect exact-version secret root: %v", err)
	}
	secretResolver, err := NewFileSecretResolver(secretSource)
	if err != nil {
		t.Fatalf("create exact-version file SecretResolver: %v", err)
	}
	secretReference := paasv1.SecretVersionReference{
		SecretID: "secret-offline-credential", Version: "version-0001",
	}
	secretDirectory := filepath.Join(secretSource, string(secretReference.SecretID))
	if err := os.Mkdir(secretDirectory, 0o700); err != nil {
		t.Fatalf("create provisioned secret directory: %v", err)
	}
	secretPlaintext := []byte("offline-secret-value")
	if err := os.WriteFile(
		filepath.Join(secretSource, string(secretReference.SecretID), secretReference.Version),
		secretPlaintext,
		0o600,
	); err != nil {
		t.Fatalf("provision exact secret version: %v", err)
	}
	secretHash := sha256.Sum256(secretPlaintext)
	secretDigest := "sha256:" + hex.EncodeToString(secretHash[:])

	stateRoot := t.TempDir()
	request, artifacts := realComposeRequest(t, imageID, secretReference)
	runtime := &unknownOnceRuntime{delegate: NewLocalRuntime()}
	executor, err := New(Config{
		BindingRef: request.Command.BindingRef, BindingRoot: stateRoot,
		Artifacts: artifacts, Secrets: secretResolver, Runtime: runtime,
	})
	if err != nil {
		t.Fatalf("create real Compose executor: %v", err)
	}
	project := projectName(request.Command.Scope.TenantID, request.Command.DeploymentID)
	projectDirectoryPath := filepath.Join(stateRoot, "projects", project)
	t.Cleanup(func() {
		observationPath := filepath.Join(projectDirectoryPath, "observe.json")
		if _, err := os.Stat(observationPath); err == nil {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = NewLocalRuntime().Stop(cleanupContext, RuntimeProject{
				Name: project, Directory: projectDirectoryPath,
				EffectDocument: observationPath, ObservationDocument: observationPath,
				TimeoutSeconds: 10,
			})
		}
	})

	first, err := executor.ApplyDeployment(context.Background(), request)
	if err != nil || first.State != paasv1.AdapterResultSucceeded {
		t.Fatalf("real generation 1 apply = %#v / %v", first, err)
	}
	firstObservation := requireRealObservation(t, executor, request)
	if firstObservation.Phase != paasv1.DeploymentReady || firstObservation.ReadyComponents != 1 {
		t.Fatalf("real generation 1 observation = %#v", firstObservation)
	}
	containerID, networkID := assertOneUnpublishedProject(t, project)
	requireRealTelemetry(t, executor, request, containerID)
	probeFixture(t, imageID, networkID, "one", secretDigest, "1")
	if output := runDockerTest(t, "port", containerID); strings.TrimSpace(output) != "" {
		t.Fatalf("application container published a host port: %q", output)
	}

	second := nextRealComposeGeneration(
		t, request, 2, paasv1.AdapterApplyDeployment, paasv1.DeploymentDesiredRunning, "two",
	)
	runtime.injectUnknown()
	unknown, err := executor.ApplyDeployment(context.Background(), second)
	if err != nil || unknown.State != paasv1.AdapterResultUnknown {
		t.Fatalf("injected unknown generation 2 apply = %#v / %v", unknown, err)
	}
	assertOneUnpublishedProject(t, project)
	secondObservation := requireRealObservation(t, executor, second)
	if secondObservation.Phase != paasv1.DeploymentReady || secondObservation.Generation != 2 {
		t.Fatalf("reconciled generation 2 observation = %#v", secondObservation)
	}
	_, networkID = assertOneUnpublishedProject(t, project)
	probeFixture(t, imageID, networkID, "two", secretDigest, "2")
	if runtime.applyCount() != 2 {
		t.Fatalf("real apply effects after reconciliation = %d, want 2", runtime.applyCount())
	}

	rollback := nextRealComposeGeneration(
		t, request, 3, paasv1.AdapterRollbackDeployment, paasv1.DeploymentDesiredRunning, "one",
	)
	rolledBack, err := executor.RollbackDeployment(context.Background(), rollback)
	if err != nil || rolledBack.State != paasv1.AdapterResultSucceeded {
		t.Fatalf("real rollback generation 3 = %#v / %v", rolledBack, err)
	}
	rollbackObservation := requireRealObservation(t, executor, rollback)
	if rollbackObservation.Phase != paasv1.DeploymentReady || rollbackObservation.Generation != 3 {
		t.Fatalf("real rollback observation = %#v", rollbackObservation)
	}
	_, networkID = assertOneUnpublishedProject(t, project)
	probeFixture(t, imageID, networkID, "one", secretDigest, "1")

	stop := nextRealComposeGeneration(
		t, rollback, 4, paasv1.AdapterStopDeployment, paasv1.DeploymentDesiredStopped, "one",
	)
	stopped, err := executor.StopDeployment(context.Background(), stop)
	if err != nil || stopped.State != paasv1.AdapterResultSucceeded {
		t.Fatalf("real stop generation 4 = %#v / %v", stopped, err)
	}
	stopObservation := requireRealObservation(t, executor, stop)
	if stopObservation.Phase != paasv1.DeploymentStopped || stopObservation.ReadyComponents != 0 {
		t.Fatalf("real stopped observation = %#v", stopObservation)
	}
	assertProjectAbsent(t, project)
	assertTreeExcludes(t, stateRoot, string(secretPlaintext))
	assertTreeExcludes(t, stateRoot, secretSource)
	assertTreeExcludes(t, stateRoot, "password=native")
}

type unknownOnceRuntime struct {
	delegate Runtime
	mu       sync.Mutex
	unknown  bool
	applies  int
}

func (runtime *unknownOnceRuntime) Apply(ctx context.Context, project RuntimeProject) error {
	if err := runtime.delegate.Apply(ctx, project); err != nil {
		return err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.applies++
	if runtime.unknown {
		runtime.unknown = false
		return ErrEffectOutcomeUnknown
	}
	return nil
}

func (runtime *unknownOnceRuntime) Observe(
	ctx context.Context,
	project RuntimeProject,
) ([]RuntimeContainer, error) {
	return runtime.delegate.Observe(ctx, project)
}

func (runtime *unknownOnceRuntime) ObserveResources(
	ctx context.Context,
	project RuntimeProject,
	containers []RuntimeContainer,
) (map[string]RuntimeContainerResources, error) {
	observer, supported := runtime.delegate.(RuntimeResourceObserver)
	if !supported {
		return nil, ErrRuntimeUnavailable
	}
	return observer.ObserveResources(ctx, project, containers)
}

func (runtime *unknownOnceRuntime) Stop(ctx context.Context, project RuntimeProject) error {
	return runtime.delegate.Stop(ctx, project)
}

func (runtime *unknownOnceRuntime) injectUnknown() {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.unknown = true
}

func (runtime *unknownOnceRuntime) applyCount() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.applies
}

func realComposeRequest(
	t *testing.T,
	imageID string,
	secretReference paasv1.SecretVersionReference,
) (paasv1.DeploymentExecutionRequest, ArtifactResolver) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope := paasv1.ResourceScope{Kind: paasv1.AuthorityTenant, TenantID: "tenant-real-compose"}
	configuration := paasv1.ConfigurationRevision{
		APIVersion: paasv1.APIVersion, Kind: "ConfigurationRevision",
		Metadata: immutableMetadata("configuration-revision-one", "configuration-one", scope, now),
		Spec: paasv1.ConfigurationRevisionSpec{
			ConfigurationID: "configuration-real-compose",
			Values:          map[string]string{"MATRIX_SETTING": "one", "MATRIX_GENERATION": "1"},
		},
	}
	configuration.Spec.ContentDigest = paasv1.ConfigurationValuesDigest(configuration.Spec.Values)
	revision := paasv1.ApplicationRevision{
		APIVersion: paasv1.APIVersion, Kind: "ApplicationRevision",
		Metadata: immutableMetadata("revision-real-compose", "revision-real-compose", scope, now),
		Spec: paasv1.ApplicationRevisionSpec{
			ApplicationID: "application-real-compose", Revision: "revision-0001",
			ContentDigest: testDigest('7'),
			Components: []paasv1.ApplicationRevisionComponent{{
				Name: "web",
				Artifact: paasv1.ArtifactRef{
					Kind: paasv1.ArtifactOCIImage, Locator: "offline.invalid/matrix/fixture",
					Digest: testDigest('8'),
				},
				Resources: paasv1.ResourceRequirements{CPUMillis: 100, MemoryBytes: 32 * 1024 * 1024},
				Endpoints: []paasv1.ApplicationEndpoint{{
					Name: "ready", Port: 8080, Protocol: paasv1.EndpointHTTP,
					Visibility: paasv1.EndpointPrivate,
				}},
				Inputs: []paasv1.ComponentInput{
					{Name: "settings", Kind: paasv1.InputConfiguration, Injection: paasv1.InjectionEnvironment, Required: true},
					{Name: "credential", Kind: paasv1.InputSecret, Injection: paasv1.InjectionFile, Required: true},
				},
			}},
		},
	}
	generation := paasv1.DeploymentGeneration{
		APIVersion: paasv1.APIVersion, Kind: "DeploymentGeneration", Scope: scope,
		DeploymentID: "deployment-real-compose", Generation: 1,
		Spec: paasv1.DeploymentSpec{
			ApplicationRevisionID: revision.Metadata.ID,
			PlacementPolicyID:     "placement-policy-real-compose",
			DesiredState:          paasv1.DeploymentDesiredRunning,
			Components: []paasv1.DeploymentComponent{{
				Name: "web", Replicas: 1,
				Bindings: []paasv1.ComponentBinding{
					{Name: "settings", ConfigurationRevisionID: configuration.Metadata.ID},
					{Name: "credential", SecretVersion: &secretReference},
				},
			}},
		},
		CreatedByOperationID: "operation-real-compose-1", CreatedAt: now,
	}
	generation.ContentDigest = paasv1.DeploymentSpecContentDigest(generation.Spec)
	placement := paasv1.PlacementDecision{
		APIVersion: paasv1.APIVersion, Kind: "PlacementDecision",
		Metadata:     immutableMetadata("decision-real-compose-1", "decision-real-compose-1", scope, now),
		DeploymentID: generation.DeploymentID, DeploymentGeneration: 1,
		DeploymentResourceVersion: 1, ApplicationRevisionID: revision.Metadata.ID,
		PlacementPolicyID: generation.Spec.PlacementPolicyID, PolicyResourceVersion: 1,
		RequestedIsolationGuarantee: paasv1.IsolationWorkload,
		Outcome:                     paasv1.PlacementScheduled, ExecutionTargetID: "target-real-compose",
		ExecutionTargetResourceVersion: 1, GrantedIsolationGuarantee: paasv1.IsolationWorkload,
		CandidateSetDigest: testDigest('9'), DecidedAt: now,
	}
	request := paasv1.DeploymentExecutionRequest{
		Command: paasv1.AdapterCommandEnvelope{
			OperationID: generation.CreatedByOperationID, CommandID: "command-real-compose-1",
			Attempt: 1, Action: paasv1.AdapterApplyDeployment, Scope: scope,
			ApplicationID: revision.Spec.ApplicationID, ApplicationRevisionID: revision.Metadata.ID,
			DeploymentID: generation.DeploymentID, ExecutionTargetID: placement.ExecutionTargetID,
			BindingRef: "compose-real", Deadline: now.Add(2 * time.Minute),
		},
		Generation: generation, ApplicationRevision: revision,
		ConfigurationRevisions: []paasv1.ConfigurationRevision{configuration}, Placement: placement,
	}
	request.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(request)
	if err := paasv1.ValidateDeploymentExecutionRequest(request); err != nil {
		t.Fatalf("real Compose request is invalid: %v", err)
	}
	return request, artifactFixture{images: map[string]VerifiedImage{
		testDigest('8'): {ArtifactDigest: testDigest('8'), LocalReference: imageID},
	}}
}

func nextRealComposeGeneration(
	t *testing.T,
	base paasv1.DeploymentExecutionRequest,
	generation uint64,
	action paasv1.AdapterAction,
	desired paasv1.DeploymentDesiredState,
	setting string,
) paasv1.DeploymentExecutionRequest {
	t.Helper()
	request := cloneCompileRequest(t, base)
	now := time.Now().UTC().Truncate(time.Microsecond)
	operationID := paasv1.OperationID(fmt.Sprintf("operation-real-compose-%d", generation))
	request.Command.OperationID = operationID
	request.Command.CommandID = paasv1.CommandID(fmt.Sprintf("command-real-compose-%d", generation))
	request.Command.Action = action
	request.Command.Deadline = now.Add(2 * time.Minute)
	request.Generation.Generation = generation
	request.Generation.CreatedByOperationID = operationID
	request.Generation.CreatedAt = now
	request.Generation.Spec.DesiredState = desired
	configuration := &request.ConfigurationRevisions[0]
	desiredConfigurationID := paasv1.ResourceID("configuration-revision-" + setting)
	if configuration.Metadata.ID != desiredConfigurationID {
		configuration.Metadata.ID = desiredConfigurationID
		configuration.Metadata.Name = "configuration-" + setting
		configuration.Metadata.CreatedAt = now
		configuration.Metadata.UpdatedAt = now
		configuration.Spec.Values = map[string]string{
			"MATRIX_SETTING": setting, "MATRIX_GENERATION": fmt.Sprintf("%d", generation),
		}
		configuration.Spec.ContentDigest = paasv1.ConfigurationValuesDigest(configuration.Spec.Values)
	}
	request.Generation.Spec.Components[0].Bindings[0].ConfigurationRevisionID = configuration.Metadata.ID
	request.Generation.ContentDigest = paasv1.DeploymentSpecContentDigest(request.Generation.Spec)
	request.Placement.Metadata.ID = paasv1.ResourceID(fmt.Sprintf("decision-real-compose-%d", generation))
	request.Placement.Metadata.Name = fmt.Sprintf("decision-real-compose-%d", generation)
	request.Placement.Metadata.CreatedAt = now
	request.Placement.Metadata.UpdatedAt = now
	request.Placement.DeploymentGeneration = generation
	request.Placement.DecidedAt = now
	request.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(request)
	if err := paasv1.ValidateDeploymentExecutionRequest(request); err != nil {
		t.Fatalf("real Compose generation %d is invalid: %v", generation, err)
	}
	return request
}

func requireRealObservation(
	t *testing.T,
	executor *Executor,
	request paasv1.DeploymentExecutionRequest,
) paasv1.DeploymentObservation {
	t.Helper()
	observation, err := executor.ObserveDeployment(
		context.Background(), observeRequest(request, time.Now().UTC().Add(30*time.Second).Truncate(time.Microsecond)),
	)
	if err != nil {
		t.Fatalf("observe real Compose generation %d: %v", request.Generation.Generation, err)
	}
	return observation
}

func requireRealTelemetry(
	t *testing.T,
	executor *Executor,
	request paasv1.DeploymentExecutionRequest,
	providerContainerID string,
) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastRuntime paasv1.DeploymentRuntimeObservation
	var lastResources paasv1.DeploymentResourceObservation
	var lastErr error
	for time.Now().Before(deadline) {
		observeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		lastRuntime, lastResources, lastErr = executor.ObserveDeploymentTelemetry(
			observeContext,
			runtimeObserveRequest(request, time.Now().Add(5*time.Second).UTC().Truncate(time.Microsecond)),
		)
		cancel()
		if lastErr == nil && validRealTelemetry(lastRuntime, lastResources, request, providerContainerID) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("real Compose telemetry did not become valid: runtime=%#v resources=%#v err=%v", lastRuntime, lastResources, lastErr)
}

func validRealTelemetry(
	runtime paasv1.DeploymentRuntimeObservation,
	resources paasv1.DeploymentResourceObservation,
	request paasv1.DeploymentExecutionRequest,
	providerContainerID string,
) bool {
	if paasv1.ValidateDeploymentRuntimeObservation(runtime) != nil ||
		paasv1.ValidateDeploymentResourceObservation(resources) != nil ||
		runtime.DeploymentID != request.Generation.DeploymentID ||
		runtime.Generation != request.Generation.Generation ||
		runtime.ApplicationRevisionID != request.ApplicationRevision.Metadata.ID ||
		runtime.ExecutionTargetID != request.Command.ExecutionTargetID ||
		resources.DeploymentID != runtime.DeploymentID ||
		resources.Generation != runtime.Generation ||
		resources.ApplicationRevisionID != runtime.ApplicationRevisionID ||
		resources.ExecutionTargetID != runtime.ExecutionTargetID ||
		len(runtime.Instances) != 1 || len(resources.Instances) != 1 ||
		resources.Instances[0].ID != runtime.Instances[0].ID ||
		string(runtime.Instances[0].ID) == providerContainerID {
		return false
	}
	resource := resources.Instances[0]
	if resource.CPU.State != paasv1.MeasurementAvailable || resource.CPU.Value == nil ||
		resource.CPU.Value.WindowMillis < 1 || resource.CPU.Value.LimitCPUMillis != 100 ||
		resource.Memory.State != paasv1.MeasurementAvailable || resource.Memory.Value == nil ||
		resource.Memory.Value.LimitBytes != 32*1024*1024 ||
		resource.Memory.Value.UsedBytes > resource.Memory.Value.LimitBytes ||
		resource.Network.State != paasv1.MeasurementAvailable || resource.Network.Value == nil ||
		(resource.BlockIO.State != paasv1.MeasurementAvailable &&
			resource.BlockIO.State != paasv1.MeasurementUnsupported) ||
		resource.Storage.Value == nil ||
		(resource.Storage.State != paasv1.MeasurementAvailable &&
			resource.Storage.State != paasv1.MeasurementStale) {
		return false
	}
	storage := resource.Storage.Value
	if storage.ObservedAt.After(resources.ObservedAt) ||
		!storage.ValidUntil.After(storage.ObservedAt) ||
		storage.ImageSharedBytes > storage.ImageTotalBytes ||
		storage.ImageUniqueBytes != storage.ImageTotalBytes-storage.ImageSharedBytes ||
		storage.VolumesState != paasv1.MeasurementAvailable || storage.Volumes == nil {
		return false
	}
	document, err := json.Marshal(struct {
		Runtime   paasv1.DeploymentRuntimeObservation  `json:"runtime"`
		Resources paasv1.DeploymentResourceObservation `json:"resources"`
	}{Runtime: runtime, Resources: resources})
	return err == nil && !strings.Contains(string(document), providerContainerID)
}

func requireDocker(t *testing.T) {
	t.Helper()
	context, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(context, "docker", "info", "--format", "{{.Architecture}}")
	if output, err := command.CombinedOutput(); err != nil || strings.TrimSpace(string(output)) == "" {
		t.Fatalf("Docker Engine is unavailable: %v", err)
	}
}

func probeFixture(t *testing.T, imageID, networkID, setting, secretDigest, generation string) {
	t.Helper()
	probeContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := composefixture.Probe(
		probeContext, imageID, networkID, setting, secretDigest, generation,
	); err != nil {
		t.Fatalf("network-scoped fixture probe: %v", err)
	}
}

func assertOneUnpublishedProject(t *testing.T, project string) (string, string) {
	t.Helper()
	containerIDs := nonemptyLines(runDockerTest(
		t, "container", "ls", "--all", "--filter", "label=com.docker.compose.project="+project,
		"--format", "{{.ID}}",
	))
	if len(containerIDs) != 1 {
		t.Fatalf("project %s container count = %d, want 1", project, len(containerIDs))
	}
	networkIDs := nonemptyLines(runDockerTest(
		t, "network", "ls", "--filter", "label=com.docker.compose.project="+project,
		"--format", "{{.ID}}",
	))
	if len(networkIDs) != 1 {
		t.Fatalf("project %s network count = %d, want 1", project, len(networkIDs))
	}
	var projects []struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal([]byte(runDockerTest(t, "compose", "ls", "--format", "json")), &projects); err != nil {
		t.Fatalf("decode Compose project list: %v", err)
	}
	count := 0
	for _, candidate := range projects {
		if candidate.Name == project {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("Compose project identity %s appears %d times", project, count)
	}
	return containerIDs[0], networkIDs[0]
}

func assertProjectAbsent(t *testing.T, project string) {
	t.Helper()
	containers := nonemptyLines(runDockerTest(
		t, "container", "ls", "--all", "--filter", "label=com.docker.compose.project="+project,
		"--format", "{{.ID}}",
	))
	networks := nonemptyLines(runDockerTest(
		t, "network", "ls", "--filter", "label=com.docker.compose.project="+project,
		"--format", "{{.ID}}",
	))
	if len(containers) != 0 || len(networks) != 0 {
		t.Fatalf("stopped project retained containers/networks = %v/%v", containers, networks)
	}
}

func runDockerTest(t *testing.T, arguments ...string) string {
	t.Helper()
	context, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(context, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", arguments[0], err, boundedTestOutput(output))
	}
	return string(output)
}

func boundedTestOutput(output []byte) string {
	const maximum = 2048
	if len(output) > maximum {
		return string(output[:maximum])
	}
	return string(output)
}

func nonemptyLines(output string) []string {
	result := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if value := strings.TrimSpace(line); value != "" {
			result = append(result, value)
		}
	}
	return result
}
