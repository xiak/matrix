package compose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type secretFixture struct {
	content []byte
	err     error
}

func (fixture *secretFixture) ResolveSecret(
	_ context.Context,
	_ paasv1.SecretVersionReference,
) ([]byte, error) {
	if fixture.err != nil {
		return nil, fixture.err
	}
	return append([]byte(nil), fixture.content...), nil
}

type stateRuntime struct {
	mu             sync.Mutex
	applyCalls     int
	stopCalls      int
	applyError     error
	observeError   error
	containers     []RuntimeContainer
	publishedPorts uint32
}

func (runtime *stateRuntime) Apply(_ context.Context, project RuntimeProject) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.applyCalls++
	encoded, err := os.ReadFile(filepath.Join(project.Directory, "current.json"))
	if err != nil {
		return err
	}
	var state projectState
	if err := json.Unmarshal(encoded, &state); err != nil {
		return err
	}
	runtime.containers = containersForState(state, runtime.publishedPorts)
	err = runtime.applyError
	runtime.applyError = nil
	return err
}

func (runtime *stateRuntime) Observe(
	context.Context,
	RuntimeProject,
) ([]RuntimeContainer, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return append([]RuntimeContainer(nil), runtime.containers...), runtime.observeError
}

func (runtime *stateRuntime) Stop(context.Context, RuntimeProject) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.stopCalls++
	runtime.containers = nil
	return nil
}

func containersForState(state projectState, publishedPorts uint32) []RuntimeContainer {
	result := make([]RuntimeContainer, 0)
	for _, service := range state.Services {
		for replica := uint32(0); replica < service.Replicas; replica++ {
			result = append(result, RuntimeContainer{
				ID:      fmt.Sprintf("container-%s-%d-%d", service.Name, state.Generation, replica),
				Name:    fmt.Sprintf("%s-%s-%d", state.ProjectName, service.Name, replica+1),
				Project: state.ProjectName, Service: service.Name, State: "running",
				Labels: map[string]string{
					"com.docker.compose.project":              state.ProjectName,
					"com.docker.compose.service":              service.Name,
					"com.xiak.matrix.application-revision-id": string(state.ApplicationRevisionID),
					"com.xiak.matrix.component":               service.Name,
					"com.xiak.matrix.content-digest":          state.ContentDigest,
					"com.xiak.matrix.deployment-id":           string(state.DeploymentID),
					"com.xiak.matrix.generation":              fmt.Sprintf("%d", state.Generation),
					"com.xiak.matrix.tenant-id":               string(state.TenantID),
				},
				PublishedPorts: publishedPorts,
			})
		}
	}
	return result
}

func TestExecutorRunsRetrySafeApplyRollbackObserveAndStop(t *testing.T) {
	executor, request, runtime, root, now := executorFixture(t)

	first, err := executor.ApplyDeployment(context.Background(), request)
	if err != nil {
		t.Fatalf("apply Deployment: %v", err)
	}
	if first.State != paasv1.AdapterResultSucceeded || first.Replayed {
		t.Fatalf("first apply result = %#v", first)
	}
	replayed, err := executor.ApplyDeployment(context.Background(), request)
	if err != nil {
		t.Fatalf("replay Deployment: %v", err)
	}
	if !replayed.Replayed || replayed.Receipt != first.Receipt || runtime.applyCalls != 1 {
		t.Fatalf("apply replay/result/effects = %#v / %d", replayed, runtime.applyCalls)
	}

	observation, err := executor.ObserveDeployment(
		context.Background(), observeRequest(request, now.Add(3*time.Minute)),
	)
	if err != nil {
		t.Fatalf("observe applied Deployment: %v", err)
	}
	if observation.Phase != paasv1.DeploymentReady || observation.ReadyComponents != 2 ||
		len(observation.Endpoints) != 2 {
		t.Fatalf("ready observation = %#v", observation)
	}

	conflict := cloneCompileRequest(t, request)
	conflict.Generation.Spec.Components[0].Replicas++
	conflict.Generation.ContentDigest = paasv1.DeploymentSpecContentDigest(conflict.Generation.Spec)
	conflict.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(conflict)
	_, err = executor.ApplyDeployment(context.Background(), conflict)
	if fault := requireComposeFault(t, err); fault.Normalized.Code != paasv1.ErrorIdempotencyConflict {
		t.Fatalf("conflicting replay fault = %#v", fault.Normalized)
	}

	rollback := nextExecutionRequest(t, request, 2, paasv1.AdapterRollbackDeployment, paasv1.DeploymentDesiredRunning, now)
	rolledBack, err := executor.RollbackDeployment(context.Background(), rollback)
	if err != nil || rolledBack.State != paasv1.AdapterResultSucceeded || runtime.applyCalls != 2 {
		t.Fatalf("rollback result/error/effects = %#v / %v / %d", rolledBack, err, runtime.applyCalls)
	}
	observation, err = executor.ObserveDeployment(
		context.Background(), observeRequest(rollback, now.Add(3*time.Minute)),
	)
	if err != nil || observation.Phase != paasv1.DeploymentReady || observation.Generation != 2 {
		t.Fatalf("rollback observation/error = %#v / %v", observation, err)
	}

	stop := nextExecutionRequest(t, rollback, 3, paasv1.AdapterStopDeployment, paasv1.DeploymentDesiredStopped, now)
	stopped, err := executor.StopDeployment(context.Background(), stop)
	if err != nil || stopped.State != paasv1.AdapterResultSucceeded || runtime.stopCalls != 1 {
		t.Fatalf("stop result/error/effects = %#v / %v / %d", stopped, err, runtime.stopCalls)
	}
	observation, err = executor.ObserveDeployment(
		context.Background(), observeRequest(stop, now.Add(3*time.Minute)),
	)
	if err != nil || observation.Phase != paasv1.DeploymentStopped || observation.ReadyComponents != 0 {
		t.Fatalf("stop observation/error = %#v / %v", observation, err)
	}
	if _, err := os.Stat(filepath.Join(root, "projects", projectName(
		request.Command.Scope.TenantID, request.Command.DeploymentID,
	), "secrets")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secret directory after stop error = %v, want not found", err)
	}
	assertTreeExcludes(t, root, string((&secretFixture{content: []byte("database-password")}).content))
}

func TestInspectRunningProjectStateProvesExactStoredDocumentsWithoutCreatingState(t *testing.T) {
	executor, request, _, root, _ := executorFixture(t)
	inspection, exists, err := InspectRunningProjectState(
		root, request.Command.Scope.TenantID, request.Command.DeploymentID,
	)
	if err != nil || exists || inspection.ProjectName != projectName(
		request.Command.Scope.TenantID, request.Command.DeploymentID,
	) {
		t.Fatalf("absent running project inspection = %#v / %t / %v", inspection, exists, err)
	}
	if _, err := os.Stat(inspection.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent project inspection created state: %v", err)
	}
	if _, err := executor.ApplyDeployment(context.Background(), request); err != nil {
		t.Fatalf("apply project for inspection: %v", err)
	}
	inspection, exists, err = InspectRunningProjectState(
		root, request.Command.Scope.TenantID, request.Command.DeploymentID,
	)
	if err != nil || !exists || inspection.Generation != request.Generation.Generation ||
		inspection.ApplicationRevisionID != request.ApplicationRevision.Metadata.ID ||
		inspection.ContentDigest != request.Generation.ContentDigest ||
		len(inspection.Services) != len(request.Generation.Spec.Components) ||
		inspection.SecretFileCount != 1 {
		t.Fatalf("running project inspection = %#v / %t / %v", inspection, exists, err)
	}
	if err := os.WriteFile(inspection.ObservationDocument, []byte(`{"services":{}}`), 0o600); err != nil {
		t.Fatalf("tamper observation document: %v", err)
	}
	if _, _, err := InspectRunningProjectState(
		root, request.Command.Scope.TenantID, request.Command.DeploymentID,
	); err == nil {
		t.Fatal("tampered observation document was accepted")
	}
}

func TestExecutorReconcilesUnknownEffectWithoutPersistingNativeError(t *testing.T) {
	executor, request, runtime, root, now := executorFixture(t)
	nativePayload := "password=native-must-not-enter-state"
	runtime.applyError = errors.New(nativePayload)

	result, err := executor.ApplyDeployment(context.Background(), request)
	if err != nil {
		t.Fatalf("unknown apply result: %v", err)
	}
	if result.State != paasv1.AdapterResultUnknown || result.Error == nil ||
		result.Error.Class != paasv1.AdapterErrorUnknownOutcome || runtime.applyCalls != 1 {
		t.Fatalf("unknown apply result = %#v", result)
	}
	assertTreeExcludes(t, root, nativePayload)

	observation, err := executor.ObserveDeployment(
		context.Background(), observeRequest(request, now.Add(3*time.Minute)),
	)
	if err != nil || observation.Phase != paasv1.DeploymentReady {
		t.Fatalf("reconciled observation/error = %#v / %v", observation, err)
	}
	replayed, err := executor.ApplyDeployment(context.Background(), request)
	if err != nil || !replayed.Replayed || replayed.State != paasv1.AdapterResultSucceeded || runtime.applyCalls != 1 {
		t.Fatalf("reconciled replay/error/effects = %#v / %v / %d", replayed, err, runtime.applyCalls)
	}
}

func TestExecutorObservesCrashedUnknownEffectBeforeRetry(t *testing.T) {
	executor, request, runtime, _, now := executorFixture(t)
	runtime.applyError = ErrEffectOutcomeUnknown

	result, err := executor.ApplyDeployment(context.Background(), request)
	if err != nil || result.State != paasv1.AdapterResultUnknown {
		t.Fatalf("unknown apply result/error = %#v / %v", result, err)
	}
	runtime.mu.Lock()
	for index := range runtime.containers {
		runtime.containers[index].State = "exited"
	}
	runtime.mu.Unlock()

	observation, err := executor.ObserveDeployment(
		context.Background(), observeRequest(request, now.Add(3*time.Minute)),
	)
	if err != nil || observation.Phase != paasv1.DeploymentFailed {
		t.Fatalf("crashed observation/error = %#v / %v", observation, err)
	}
	retried, err := executor.ApplyDeployment(context.Background(), request)
	if err != nil || retried.State != paasv1.AdapterResultSucceeded ||
		retried.Replayed || runtime.applyCalls != 2 {
		t.Fatalf("observed retry result/error/effects = %#v / %v / %d", retried, err, runtime.applyCalls)
	}
}

func TestExecutorRejectsInvalidProviderObservation(t *testing.T) {
	executor, request, runtime, _, now := executorFixture(t)
	if _, err := executor.ApplyDeployment(context.Background(), request); err != nil {
		t.Fatalf("apply provider fixture: %v", err)
	}
	runtime.observeError = ErrRuntimeOutputInvalid
	_, err := executor.ObserveDeployment(
		context.Background(), observeRequest(request, now.Add(3*time.Minute)),
	)
	if fault := requireComposeFault(t, err); fault.Normalized.Code != paasv1.ErrorAdapterRejected {
		t.Fatalf("invalid provider output fault = %#v", fault.Normalized)
	}
}

func TestExecutorNormalizesCorruptCommandState(t *testing.T) {
	executor, request, _, root, _ := executorFixture(t)
	if _, err := executor.ApplyDeployment(context.Background(), request); err != nil {
		t.Fatalf("apply Deployment: %v", err)
	}
	project := projectName(request.Command.Scope.TenantID, request.Command.DeploymentID)
	directory := filepath.Join(root, "projects", project)
	path, err := commandFile(root, directory, request.Command.CommandID)
	if err != nil {
		t.Fatalf("resolve command state: %v", err)
	}
	if err := os.WriteFile(path, []byte("invalid"), managedFileMode); err != nil {
		t.Fatalf("corrupt command state: %v", err)
	}
	_, err = executor.ApplyDeployment(context.Background(), request)
	if fault := requireComposeFault(t, err); fault.Normalized.Code != paasv1.ErrorInternal {
		t.Fatalf("corrupt command-state fault = %#v", fault.Normalized)
	}
}

func TestExecutorRejectsProviderHostPorts(t *testing.T) {
	executor, request, runtime, _, now := executorFixture(t)
	runtime.publishedPorts = 1
	if _, err := executor.ApplyDeployment(context.Background(), request); err != nil {
		t.Fatalf("apply provider fixture: %v", err)
	}
	_, err := executor.ObserveDeployment(
		context.Background(), observeRequest(request, now.Add(3*time.Minute)),
	)
	if fault := requireComposeFault(t, err); fault.Normalized.Code != paasv1.ErrorAdapterRejected {
		t.Fatalf("published-port provider fault = %#v", fault.Normalized)
	}
}

func TestFileSecretResolverRejectsOversizeVersions(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("protect secret root: %v", err)
	}
	resolver, err := NewFileSecretResolver(root)
	if err != nil {
		t.Fatalf("new file secret resolver: %v", err)
	}
	reference := paasv1.SecretVersionReference{SecretID: "secret-demo", Version: "version-0001"}
	directory := filepath.Join(root, string(reference.SecretID))
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create secret identity directory: %v", err)
	}
	path := filepath.Join(root, string(reference.SecretID), reference.Version)
	if err := os.WriteFile(path, []byte("exact-version"), 0o600); err != nil {
		t.Fatalf("provision secret version: %v", err)
	}
	resolved, err := resolver.ResolveSecret(context.Background(), reference)
	if err != nil || string(resolved) != "exact-version" {
		t.Fatalf("resolved secret/error = %q / %v", resolved, err)
	}
	wipe(resolved)

	if err := os.WriteFile(path, make([]byte, maxSecretBytes+1), 0o600); err != nil {
		t.Fatalf("provision oversize secret: %v", err)
	}
	if _, err := resolver.ResolveSecret(context.Background(), reference); err == nil ||
		strings.Contains(err.Error(), string(reference.SecretID)) {
		t.Fatalf("oversize secret error = %v", err)
	}
}

func TestFileSecretResolverRejectsLinkedVersions(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("protect secret root: %v", err)
	}
	resolver, err := NewFileSecretResolver(root)
	if err != nil {
		t.Fatalf("new file secret resolver: %v", err)
	}
	reference := paasv1.SecretVersionReference{SecretID: "secret-demo", Version: "version-0001"}
	directory := filepath.Join(root, string(reference.SecretID))
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create secret identity directory: %v", err)
	}
	path := filepath.Join(directory, reference.Version)
	external := t.TempDir()
	if err := createDirectoryLink(external, path); err != nil {
		t.Skipf("filesystem links are unavailable for this account: %v", err)
	}
	if _, err := resolver.ResolveSecret(context.Background(), reference); err == nil {
		t.Fatal("linked secret version must fail closed")
	}
}

func TestFileSecretResolverConsumesProvisionedReadOnlyTreeWithoutMutatingModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows validates protected ACLs rather than POSIX read-only modes")
	}
	root := t.TempDir()
	reference := paasv1.SecretVersionReference{SecretID: "secret-read-only", Version: "version-one"}
	directory := filepath.Join(root, string(reference.SecretID))
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create secret provisioning directory: %v", err)
	}
	file := filepath.Join(directory, reference.Version)
	t.Cleanup(func() {
		_ = os.Chmod(root, 0o700)
		_ = os.Chmod(directory, 0o700)
		_ = os.Chmod(file, 0o600)
	})
	if err := os.WriteFile(file, []byte("read-only-secret"), 0o400); err != nil {
		t.Fatalf("write read-only secret: %v", err)
	}
	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatalf("seal read-only secret directory: %v", err)
	}
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatalf("protect read-only secret root: %v", err)
	}
	resolver, err := NewFileSecretResolver(root)
	if err != nil {
		t.Fatalf("create read-only SecretResolver: %v", err)
	}
	content, err := resolver.ResolveSecret(context.Background(), reference)
	if err != nil || string(content) != "read-only-secret" {
		t.Fatalf("resolve read-only secret content=%q err=%v", content, err)
	}
	for target, want := range map[string]os.FileMode{root: 0o500, directory: 0o500, file: 0o400} {
		info, statErr := os.Stat(target)
		if statErr != nil {
			t.Fatalf("read-only secret mode %s unavailable: %v", target, statErr)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("read-only secret mode %s=%#o want=%#o", target, info.Mode().Perm(), want)
		}
	}
}

func TestManagedRootRejectsVolumeRoot(t *testing.T) {
	root := string(filepath.Separator)
	if volume := filepath.VolumeName(t.TempDir()); volume != "" {
		root = volume + string(filepath.Separator)
	}
	if _, err := prepareManagedRoot(root); err == nil {
		t.Fatalf("volume root %q must not become a managed binding root", root)
	}
}

func createDirectoryLink(target, link string) error {
	if runtime.GOOS != "windows" {
		return os.Symlink(target, link)
	}
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("create directory junction: %w: %s", err, output)
	}
	return nil
}

func executorFixture(
	t *testing.T,
) (*Executor, paasv1.DeploymentExecutionRequest, *stateRuntime, string, time.Time) {
	t.Helper()
	request, artifacts := compileFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	request.Command.Deadline = now.Add(2 * time.Minute)
	request.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(request)
	runtime := &stateRuntime{}
	root := t.TempDir()
	executor, err := New(Config{
		BindingRef: request.Command.BindingRef, BindingRoot: root,
		Artifacts: artifacts, Secrets: &secretFixture{content: []byte("database-password")},
		Runtime: runtime, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new Compose executor: %v", err)
	}
	return executor, request, runtime, root, now
}

func nextExecutionRequest(
	t *testing.T,
	base paasv1.DeploymentExecutionRequest,
	generation uint64,
	action paasv1.AdapterAction,
	desired paasv1.DeploymentDesiredState,
	now time.Time,
) paasv1.DeploymentExecutionRequest {
	t.Helper()
	request := cloneCompileRequest(t, base)
	operationID := paasv1.OperationID(fmt.Sprintf("operation-generation-%d", generation))
	request.Command.OperationID = operationID
	request.Command.CommandID = paasv1.CommandID(fmt.Sprintf("command-generation-%d", generation))
	request.Command.Action = action
	request.Command.Attempt = 1
	request.Command.Deadline = now.Add(2 * time.Minute)
	request.Generation.Generation = generation
	request.Generation.CreatedByOperationID = operationID
	request.Generation.Spec.DesiredState = desired
	request.Generation.ContentDigest = paasv1.DeploymentSpecContentDigest(request.Generation.Spec)
	request.Placement.Metadata.ID = paasv1.ResourceID(fmt.Sprintf("decision-generation-%d", generation))
	request.Placement.Metadata.Name = fmt.Sprintf("decision-generation-%d", generation)
	request.Placement.DeploymentGeneration = generation
	request.Command.RequestDigest = paasv1.DeploymentExecutionRequestDigest(request)
	return request
}

func observeRequest(
	effect paasv1.DeploymentExecutionRequest,
	deadline time.Time,
) paasv1.ObserveDeploymentRequest {
	command := effect.Command
	command.CommandID = paasv1.CommandID(fmt.Sprintf("observe-generation-%d", effect.Generation.Generation))
	command.Action = paasv1.AdapterObserveDeployment
	command.Deadline = deadline
	request := paasv1.ObserveDeploymentRequest{
		Command: command, Generation: effect.Generation.Generation,
		ExpectedContentDigest: effect.Generation.ContentDigest,
	}
	request.Command.RequestDigest = paasv1.ObserveDeploymentRequestDigest(request)
	return request
}

func requireComposeFault(t *testing.T, err error) paasv1.AdapterFault {
	t.Helper()
	if err == nil {
		t.Fatal("expected Compose adapter fault, got nil")
	}
	var fault paasv1.AdapterFault
	if !errors.As(err, &fault) {
		t.Fatalf("error type = %T, want paasv1.AdapterFault", err)
	}
	if validationErr := paasv1.ValidateNormalizedAdapterError(fault.Normalized); validationErr != nil {
		t.Fatalf("normalized fault is invalid: %v", validationErr)
	}
	return fault
}

func assertTreeExcludes(t *testing.T, root, forbidden string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(content), forbidden) {
			return fmt.Errorf("forbidden material found in %s", filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
