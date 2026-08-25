package compose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	adapterName            = "compose"
	adapterContractVersion = "v1"
)

type Clock func() time.Time

type Config struct {
	BindingRef  string
	BindingRoot string
	Artifacts   ArtifactResolver
	Secrets     SecretResolver
	Runtime     Runtime
	Clock       Clock
}

type Executor struct {
	bindingRef string
	root       string
	compiler   *Compiler
	secrets    SecretResolver
	runtime    Runtime
	clock      Clock
}

func New(config Config) (*Executor, error) {
	var problems []error
	problems = append(problems, paasv1.ValidateID("bindingRef", config.BindingRef))
	if config.Artifacts == nil {
		problems = append(problems, errors.New("artifact resolver is required"))
	}
	if config.Secrets == nil {
		problems = append(problems, errors.New("secret resolver is required"))
	}
	if err := errors.Join(problems...); err != nil {
		return nil, err
	}
	root, err := prepareManagedRoot(config.BindingRoot)
	if err != nil {
		return nil, err
	}
	compiler, err := NewCompiler(config.Artifacts)
	if err != nil {
		return nil, err
	}
	if config.Runtime == nil {
		config.Runtime = NewLocalRuntime()
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Executor{
		bindingRef: config.BindingRef, root: root, compiler: compiler,
		secrets: config.Secrets, runtime: config.Runtime, clock: config.Clock,
	}, nil
}

func (executor *Executor) Capabilities(
	ctx context.Context,
) (paasv1.AdapterCapabilitiesContract, error) {
	if executor == nil || executor.compiler == nil {
		return paasv1.AdapterCapabilitiesContract{}, errors.New("Compose executor is nil")
	}
	if ctx == nil {
		return paasv1.AdapterCapabilitiesContract{}, errors.New("capabilities context is required")
	}
	if err := ctx.Err(); err != nil {
		return paasv1.AdapterCapabilitiesContract{}, err
	}
	value := paasv1.AdapterCapabilitiesContract{
		Adapter: paasv1.AdapterRef{
			Kind: paasv1.AdapterDeploymentExecutor, Name: adapterName,
			ContractVersion: adapterContractVersion,
		},
		Actions: []paasv1.AdapterAction{
			paasv1.AdapterCapabilities,
			paasv1.AdapterValidateDeployment,
			paasv1.AdapterApplyDeployment,
			paasv1.AdapterObserveDeployment,
			paasv1.AdapterStopDeployment,
			paasv1.AdapterRollbackDeployment,
		},
		IsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
		ObservedAt:          executor.now(),
	}
	if err := paasv1.ValidateAdapterCapabilities(value); err != nil {
		return paasv1.AdapterCapabilitiesContract{}, errors.New("Compose capabilities are invalid")
	}
	return value, nil
}

func (executor *Executor) ValidateDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	operationContext, cancel, err := executor.validateExecutionRequest(
		ctx,
		request,
		paasv1.AdapterValidateDeployment,
		paasv1.DeploymentDesiredRunning,
	)
	if err != nil {
		return paasv1.AdapterResult{}, err
	}
	defer cancel()
	plan, err := executor.compiler.Compile(operationContext, request)
	if err != nil {
		return paasv1.AdapterResult{}, invalidRequestFault()
	}
	materials, err := executor.resolveSecretMaterials(operationContext, plan)
	if err != nil {
		return paasv1.AdapterResult{}, secretResolutionFault()
	}
	defer wipeSecretMaterials(materials)
	digest := sha256.Sum256([]byte(request.Command.RequestDigest + "\x00" + plan.DocumentDigest))
	result := paasv1.AdapterResult{
		CommandID: request.Command.CommandID, State: paasv1.AdapterResultSucceeded,
		Receipt: "validate-" + hex.EncodeToString(digest[:16]), ObservedAt: executor.now(),
	}
	if err := paasv1.ValidateAdapterResult(result); err != nil {
		return paasv1.AdapterResult{}, internalFault()
	}
	return result, nil
}

func (executor *Executor) ApplyDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return executor.apply(ctx, request, paasv1.AdapterApplyDeployment)
}

func (executor *Executor) RollbackDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	return executor.apply(ctx, request, paasv1.AdapterRollbackDeployment)
}

func (executor *Executor) apply(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
	action paasv1.AdapterAction,
) (paasv1.AdapterResult, error) {
	operationContext, cancel, err := executor.validateExecutionRequest(
		ctx, request, action, paasv1.DeploymentDesiredRunning,
	)
	if err != nil {
		return paasv1.AdapterResult{}, err
	}
	defer cancel()
	plan, err := executor.compiler.Compile(operationContext, request)
	if err != nil {
		return paasv1.AdapterResult{}, invalidRequestFault()
	}
	lock, err := acquireProjectLock(operationContext, executor.root, plan.ProjectName)
	if err != nil {
		return paasv1.AdapterResult{}, boundaryFault(err)
	}
	defer lock.Close()
	directory, composePath, observePath, statePath, err := projectPaths(executor.root, plan.ProjectName)
	if err != nil {
		return paasv1.AdapterResult{}, internalFault()
	}
	commandPath, err := commandFile(executor.root, directory, request.Command.CommandID)
	if err != nil {
		return paasv1.AdapterResult{}, internalFault()
	}
	if replay, err := executor.replayCommand(commandPath, request.Command); replay != nil || err != nil {
		if err != nil {
			return paasv1.AdapterResult{}, err
		}
		return *replay, nil
	}
	if err := rejectStaleApplyState(executor.root, statePath, request); err != nil {
		return paasv1.AdapterResult{}, err
	}
	materials, err := executor.resolveSecretMaterials(operationContext, plan)
	if err != nil {
		return paasv1.AdapterResult{}, secretResolutionFault()
	}
	defer wipeSecretMaterials(materials)
	now := executor.now()
	state, receipt, err := newProjectState(request, plan, now)
	if err != nil {
		return paasv1.AdapterResult{}, internalFault()
	}
	if err := executor.prepareApplyState(
		directory, composePath, observePath, statePath, commandPath,
		plan, materials, state, now,
	); err != nil {
		return paasv1.AdapterResult{}, internalFault()
	}
	runtimeProject, err := executor.runtimeProject(
		request.Command.Deadline, directory, composePath, observePath, plan.ProjectName,
	)
	if err != nil {
		return executor.finishEffectFailure(commandPath, request.Command, state.Receipt, err)
	}
	if err := executor.runtime.Apply(operationContext, runtimeProject); err != nil {
		return executor.finishEffectFailure(commandPath, request.Command, state.Receipt, err)
	}
	if err := executor.finishEffectSuccess(
		directory, commandPath, request.Command, state, receipt,
	); err != nil {
		return paasv1.AdapterResult{}, unknownOutcomeFault()
	}
	return successfulResult(request.Command, state.Receipt, executor.now(), false), nil
}

func (executor *Executor) StopDeployment(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
) (paasv1.AdapterResult, error) {
	operationContext, cancel, err := executor.validateExecutionRequest(
		ctx,
		request,
		paasv1.AdapterStopDeployment,
		paasv1.DeploymentDesiredStopped,
	)
	if err != nil {
		return paasv1.AdapterResult{}, err
	}
	defer cancel()
	project := projectName(request.Command.Scope.TenantID, request.Generation.DeploymentID)
	lock, err := acquireProjectLock(operationContext, executor.root, project)
	if err != nil {
		return paasv1.AdapterResult{}, boundaryFault(err)
	}
	defer lock.Close()
	directory, composePath, observePath, statePath, err := existingProjectPaths(executor.root, project)
	if err != nil {
		return paasv1.AdapterResult{}, notFoundFault()
	}
	commandPath, err := commandFile(executor.root, directory, request.Command.CommandID)
	if err != nil {
		return paasv1.AdapterResult{}, internalFault()
	}
	if replay, err := executor.replayCommand(commandPath, request.Command); replay != nil || err != nil {
		if err != nil {
			return paasv1.AdapterResult{}, err
		}
		return *replay, nil
	}
	current, err := loadProjectState(executor.root, statePath)
	if err != nil {
		return paasv1.AdapterResult{}, notFoundFault()
	}
	stopped, receipt, err := stoppedProjectState(current, request, executor.now())
	if err != nil {
		return paasv1.AdapterResult{}, conflictFault()
	}
	if err := writeObservationDocument(executor.root, observePath, stopped); err != nil {
		return paasv1.AdapterResult{}, internalFault()
	}
	if err := writeManagedJSON(executor.root, statePath, stopped); err != nil {
		return paasv1.AdapterResult{}, internalFault()
	}
	if err := writeCommandState(executor.root, commandPath, commandState{
		SchemaVersion: commandStateSchema, CommandID: request.Command.CommandID,
		RequestDigest: request.Command.RequestDigest, Action: request.Command.Action,
		State: paasv1.AdapterResultInProgress, Receipt: stopped.Receipt,
		ObservedAt: executor.now(),
	}); err != nil {
		return paasv1.AdapterResult{}, internalFault()
	}
	runtimeProject, err := executor.runtimeProject(
		request.Command.Deadline, directory, composePath, observePath, project,
	)
	if err != nil {
		return executor.finishEffectFailure(commandPath, request.Command, stopped.Receipt, err)
	}
	if err := executor.runtime.Stop(operationContext, runtimeProject); err != nil {
		return executor.finishEffectFailure(commandPath, request.Command, stopped.Receipt, err)
	}
	if err := executor.finishEffectSuccess(
		directory, commandPath, request.Command, stopped, receipt,
	); err != nil {
		return paasv1.AdapterResult{}, unknownOutcomeFault()
	}
	return successfulResult(request.Command, stopped.Receipt, executor.now(), false), nil
}

func (executor *Executor) ObserveDeployment(
	ctx context.Context,
	request paasv1.ObserveDeploymentRequest,
) (paasv1.DeploymentObservation, error) {
	if executor == nil || executor.compiler == nil || ctx == nil {
		return paasv1.DeploymentObservation{}, invalidRequestFault()
	}
	if err := paasv1.ValidateObserveDeploymentRequest(request); err != nil ||
		request.Command.BindingRef != executor.bindingRef {
		return paasv1.DeploymentObservation{}, invalidRequestFault()
	}
	operationContext, cancel := context.WithDeadline(ctx, request.Command.Deadline)
	defer cancel()
	project := projectName(request.Command.Scope.TenantID, request.Command.DeploymentID)
	lock, err := acquireProjectLock(operationContext, executor.root, project)
	if err != nil {
		return paasv1.DeploymentObservation{}, boundaryFault(err)
	}
	defer lock.Close()
	directory, composePath, observePath, statePath, err := existingProjectPaths(executor.root, project)
	if err != nil {
		return paasv1.DeploymentObservation{}, notFoundFault()
	}
	state, err := loadProjectState(executor.root, statePath)
	if err != nil {
		return paasv1.DeploymentObservation{}, notFoundFault()
	}
	if state.ProjectName != project || state.TenantID != request.Command.Scope.TenantID ||
		state.DeploymentID != request.Command.DeploymentID || state.Generation != request.Generation ||
		state.ApplicationRevisionID != request.Command.ApplicationRevisionID ||
		state.ContentDigest != request.ExpectedContentDigest {
		return paasv1.DeploymentObservation{}, conflictFault()
	}
	if _, err := readManagedFile(executor.root, observePath, maxManagedStateBytes); err != nil {
		return paasv1.DeploymentObservation{}, internalFault()
	}
	runtimeProject, err := executor.runtimeProject(
		request.Command.Deadline, directory, composePath, observePath, project,
	)
	if err != nil {
		return paasv1.DeploymentObservation{}, boundaryFault(err)
	}
	containers, err := executor.runtime.Observe(operationContext, runtimeProject)
	if err != nil {
		if errors.Is(err, ErrRuntimeOutputInvalid) {
			return paasv1.DeploymentObservation{}, providerRejectedFault()
		}
		return paasv1.DeploymentObservation{}, unavailableFault()
	}
	observation, err := normalizeObservation(state, containers, executor.now())
	if err != nil {
		return paasv1.DeploymentObservation{}, providerRejectedFault()
	}
	if err := executor.recordObservedEffect(directory, state, observation); err != nil {
		return paasv1.DeploymentObservation{}, internalFault()
	}
	return observation, nil
}

type secretMaterial struct {
	relative string
	content  []byte
}

func (executor *Executor) resolveSecretMaterials(
	ctx context.Context,
	plan ExecutionPlan,
) ([]secretMaterial, error) {
	materials := make([]secretMaterial, 0, len(plan.SecretFiles))
	for _, secret := range plan.SecretFiles {
		content, err := executor.secrets.ResolveSecret(ctx, secret.Reference)
		if err != nil {
			wipeSecretMaterials(materials)
			return nil, err
		}
		if len(content) > maxSecretBytes {
			wipe(content)
			wipeSecretMaterials(materials)
			return nil, errors.New("resolved secret exceeds the size limit")
		}
		materials = append(materials, secretMaterial{relative: secret.RelativePath, content: content})
	}
	return materials, nil
}

func wipeSecretMaterials(materials []secretMaterial) {
	for index := range materials {
		wipe(materials[index].content)
	}
}

func (executor *Executor) prepareApplyState(
	directory, composePath, observePath, statePath, commandPath string,
	plan ExecutionPlan,
	materials []secretMaterial,
	state projectState,
	now time.Time,
) error {
	if len(materials) > 0 {
		secretDirectory, err := ensureManagedDirectory(directory, "secrets")
		if err != nil {
			return err
		}
		for _, material := range materials {
			target, err := safeJoin(directory, filepath.FromSlash(material.relative))
			if err != nil || filepath.Dir(target) != secretDirectory {
				return errors.New("compiled secret path is invalid")
			}
			if err := writeManagedFile(executor.root, target, material.content); err != nil {
				return err
			}
		}
	}
	if err := writeManagedFile(executor.root, composePath, plan.Document); err != nil {
		return err
	}
	if err := writeObservationDocument(executor.root, observePath, state); err != nil {
		return err
	}
	if err := writeManagedJSON(executor.root, statePath, state); err != nil {
		return err
	}
	return writeCommandState(executor.root, commandPath, commandState{
		SchemaVersion: commandStateSchema, CommandID: state.EffectCommandID,
		RequestDigest: state.EffectRequestDigest, Action: state.EffectAction,
		State: paasv1.AdapterResultInProgress, Receipt: state.Receipt,
		ObservedAt: now,
	})
}

func (executor *Executor) finishEffectSuccess(
	directory, commandPath string,
	command paasv1.AdapterCommandEnvelope,
	state projectState,
	receipt generationReceipt,
) error {
	receiptPath, err := receiptFile(executor.root, directory, state.Generation)
	if err != nil {
		return err
	}
	if err := writeGenerationReceipt(executor.root, receiptPath, receipt); err != nil {
		return err
	}
	retained := state.SecretFiles
	if state.DesiredState == paasv1.DeploymentDesiredStopped {
		retained = nil
	}
	if err := cleanupProjectSecrets(executor.root, directory, retained); err != nil {
		return err
	}
	return writeCommandState(executor.root, commandPath, commandState{
		SchemaVersion: commandStateSchema, CommandID: command.CommandID,
		RequestDigest: command.RequestDigest, Action: command.Action,
		State: paasv1.AdapterResultSucceeded, Receipt: state.Receipt,
		ObservedAt: executor.now(),
	})
}

func (executor *Executor) finishEffectFailure(
	commandPath string,
	command paasv1.AdapterCommandEnvelope,
	receipt string,
	effectErr error,
) (paasv1.AdapterResult, error) {
	if errors.Is(effectErr, ErrRuntimeUnavailable) {
		normalized := paasv1.NormalizedAdapterError{
			Class: paasv1.AdapterErrorUnavailable, Code: paasv1.ErrorAdapterUnavailable,
			Message:   "Docker Compose is unavailable before the requested effect could start.",
			Retryable: true,
		}
		state := commandState{
			SchemaVersion: commandStateSchema, CommandID: command.CommandID,
			RequestDigest: command.RequestDigest, Action: command.Action,
			State: paasv1.AdapterResultFailed, Receipt: receipt, Error: &normalized,
			ObservedAt: executor.now(),
		}
		if err := writeCommandState(executor.root, commandPath, state); err != nil {
			return paasv1.AdapterResult{}, internalFault()
		}
		return adapterResult(state, false), nil
	}
	normalized := paasv1.NormalizedAdapterError{
		Class: paasv1.AdapterErrorUnknownOutcome, Code: paasv1.ErrorAdapterOutcomeUnknown,
		Message:   "Docker Compose started the requested effect, but its outcome is unknown; observe before retrying.",
		Retryable: true,
	}
	state := commandState{
		SchemaVersion: commandStateSchema, CommandID: command.CommandID,
		RequestDigest: command.RequestDigest, Action: command.Action,
		State: paasv1.AdapterResultUnknown, Receipt: receipt, Error: &normalized,
		ObservedAt: executor.now(),
	}
	if err := writeCommandState(executor.root, commandPath, state); err != nil {
		return paasv1.AdapterResult{}, unknownOutcomeFault()
	}
	return adapterResult(state, false), nil
}

func (executor *Executor) recordObservedEffect(
	directory string,
	state projectState,
	observation paasv1.DeploymentObservation,
) error {
	commandPath, err := commandFile(executor.root, directory, state.EffectCommandID)
	if err != nil {
		return err
	}
	complete := (state.DesiredState == paasv1.DeploymentDesiredRunning && observation.Phase == paasv1.DeploymentReady) ||
		(state.DesiredState == paasv1.DeploymentDesiredStopped && observation.Phase == paasv1.DeploymentStopped)
	if complete {
		receiptPath, err := receiptFile(executor.root, directory, state.Generation)
		if err != nil {
			return err
		}
		if err := writeGenerationReceipt(executor.root, receiptPath, receiptFromProjectState(state)); err != nil {
			return err
		}
		retained := state.SecretFiles
		if state.DesiredState == paasv1.DeploymentDesiredStopped {
			retained = nil
		}
		if err := cleanupProjectSecrets(executor.root, directory, retained); err != nil {
			return err
		}
		return writeCommandState(executor.root, commandPath, commandState{
			SchemaVersion: commandStateSchema, CommandID: state.EffectCommandID,
			RequestDigest: state.EffectRequestDigest, Action: state.EffectAction,
			State: paasv1.AdapterResultSucceeded, Receipt: state.Receipt,
			ObservedAt: executor.now(),
		})
	}
	mayRetry := state.DesiredState == paasv1.DeploymentDesiredStopped ||
		observation.Phase == paasv1.DeploymentFailed || observation.Phase == paasv1.DeploymentStopped
	if !mayRetry {
		return nil
	}
	normalized := paasv1.NormalizedAdapterError{
		Class: paasv1.AdapterErrorUnknownOutcome, Code: paasv1.ErrorAdapterOutcomeUnknown,
		Message:   "The observed Compose project does not match the requested effect; a retry is allowed.",
		Retryable: true,
	}
	return writeCommandState(executor.root, commandPath, commandState{
		SchemaVersion: commandStateSchema, CommandID: state.EffectCommandID,
		RequestDigest: state.EffectRequestDigest, Action: state.EffectAction,
		State: paasv1.AdapterResultUnknown, Receipt: state.Receipt, Error: &normalized,
		MayRetry: true, ObservedAt: executor.now(),
	})
}

func (executor *Executor) replayCommand(
	path string,
	command paasv1.AdapterCommandEnvelope,
) (*paasv1.AdapterResult, error) {
	stored, err := loadCommandState(executor.root, path)
	if err != nil {
		return nil, internalFault()
	}
	if stored == nil {
		return nil, nil
	}
	if stored.CommandID != command.CommandID || stored.RequestDigest != command.RequestDigest ||
		stored.Action != command.Action {
		return nil, idempotencyConflictFault()
	}
	if stored.MayRetry && stored.State == paasv1.AdapterResultUnknown {
		return nil, nil
	}
	result := adapterResult(*stored, true)
	return &result, nil
}

func (executor *Executor) validateExecutionRequest(
	ctx context.Context,
	request paasv1.DeploymentExecutionRequest,
	action paasv1.AdapterAction,
	desired paasv1.DeploymentDesiredState,
) (context.Context, context.CancelFunc, error) {
	if executor == nil || executor.compiler == nil || ctx == nil {
		return nil, nil, invalidRequestFault()
	}
	if err := paasv1.ValidateDeploymentExecutionRequest(request); err != nil ||
		request.Command.Action != action || request.Generation.Spec.DesiredState != desired ||
		request.Command.BindingRef != executor.bindingRef {
		return nil, nil, invalidRequestFault()
	}
	operationContext, cancel := context.WithDeadline(ctx, request.Command.Deadline)
	if err := operationContext.Err(); err != nil {
		cancel()
		return nil, nil, boundaryFault(err)
	}
	return operationContext, cancel, nil
}

func (executor *Executor) runtimeProject(
	deadline time.Time,
	directory, composePath, observePath, project string,
) (RuntimeProject, error) {
	remaining := deadline.Sub(executor.now())
	if remaining <= 0 {
		return RuntimeProject{}, context.DeadlineExceeded
	}
	seconds := uint32(math.Ceil(remaining.Seconds()))
	if seconds == 0 {
		seconds = 1
	}
	if seconds > 300 {
		seconds = 300
	}
	value := RuntimeProject{
		Name: project, Directory: directory, EffectDocument: composePath,
		ObservationDocument: observePath, TimeoutSeconds: seconds,
	}
	if err := validateRuntimeProject(value); err != nil {
		return RuntimeProject{}, err
	}
	return value, nil
}

func (executor *Executor) now() time.Time {
	return executor.clock().UTC().Truncate(time.Microsecond)
}

func rejectStaleApplyState(
	root, path string,
	request paasv1.DeploymentExecutionRequest,
) error {
	current, err := loadProjectState(root, path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return internalFault()
	}
	if current.TenantID != request.Command.Scope.TenantID ||
		current.DeploymentID != request.Generation.DeploymentID ||
		current.Generation > request.Generation.Generation {
		return conflictFault()
	}
	if current.Generation == request.Generation.Generation &&
		(current.ContentDigest != request.Generation.ContentDigest ||
			current.EffectCommandID != request.Command.CommandID ||
			current.EffectRequestDigest != request.Command.RequestDigest) {
		return conflictFault()
	}
	return nil
}

func stoppedProjectState(
	current projectState,
	request paasv1.DeploymentExecutionRequest,
	now time.Time,
) (projectState, generationReceipt, error) {
	project := projectName(request.Command.Scope.TenantID, request.Generation.DeploymentID)
	if current.ProjectName != project || current.TenantID != request.Command.Scope.TenantID ||
		current.DeploymentID != request.Generation.DeploymentID ||
		current.ApplicationRevisionID != request.ApplicationRevision.Metadata.ID {
		return projectState{}, generationReceipt{}, errors.New("stop request does not match current project")
	}
	if current.Generation > request.Generation.Generation {
		return projectState{}, generationReceipt{}, errors.New("stop generation is stale")
	}
	if current.Generation == request.Generation.Generation {
		if current.EffectCommandID != request.Command.CommandID ||
			current.EffectRequestDigest != request.Command.RequestDigest ||
			current.DesiredState != paasv1.DeploymentDesiredStopped {
			return projectState{}, generationReceipt{}, errors.New("stop generation conflicts with current state")
		}
		return current, receiptFromProjectState(current), nil
	}
	current.Generation = request.Generation.Generation
	current.ContentDigest = request.Generation.ContentDigest
	current.DesiredState = paasv1.DeploymentDesiredStopped
	current.EffectAction = request.Command.Action
	current.EffectCommandID = request.Command.CommandID
	current.EffectRequestDigest = request.Command.RequestDigest
	current.UpdatedAt = now
	receipt := receiptFromProjectState(current)
	name, digest, err := receiptIdentity(receipt)
	if err != nil {
		return projectState{}, generationReceipt{}, err
	}
	current.Receipt = name
	current.ReceiptDigest = digest
	if err := validateProjectState(current); err != nil {
		return projectState{}, generationReceipt{}, err
	}
	return current, receipt, nil
}

func normalizeObservation(
	state projectState,
	containers []RuntimeContainer,
	now time.Time,
) (paasv1.DeploymentObservation, error) {
	services := make(map[string]projectService, len(state.Services))
	for _, service := range state.Services {
		services[service.Name] = service
	}
	seenContainers := make(map[string]struct{}, len(containers))
	currentCount := make(map[string]uint32, len(services))
	readyCount := make(map[string]uint32, len(services))
	stale := uint32(0)
	failed := false
	for _, container := range containers {
		service, known := services[container.Service]
		if !known || container.ID == "" || len(container.ID) > 128 ||
			container.Project != state.ProjectName || container.OneOff || container.PublishedPorts != 0 {
			return paasv1.DeploymentObservation{}, errors.New("provider returned an unsafe container declaration")
		}
		if _, duplicate := seenContainers[container.ID]; duplicate {
			return paasv1.DeploymentObservation{}, errors.New("provider returned a duplicated container")
		}
		seenContainers[container.ID] = struct{}{}
		if container.Labels["com.docker.compose.project"] != state.ProjectName ||
			container.Labels["com.docker.compose.service"] != service.Name ||
			container.Labels["com.xiak.matrix.component"] != service.Name ||
			container.Labels["com.xiak.matrix.deployment-id"] != string(state.DeploymentID) ||
			container.Labels["com.xiak.matrix.tenant-id"] != string(state.TenantID) {
			return paasv1.DeploymentObservation{}, errors.New("provider container labels are invalid")
		}
		if !slices.Contains([]string{"created", "running", "restarting", "removing", "paused", "exited", "dead"}, container.State) ||
			!slices.Contains([]string{"", "healthy", "unhealthy", "starting"}, container.Health) {
			return paasv1.DeploymentObservation{}, errors.New("provider container state is unknown")
		}
		if state.DesiredState == paasv1.DeploymentDesiredStopped {
			continue
		}
		current := container.Labels["com.xiak.matrix.generation"] == strconv.FormatUint(state.Generation, 10) &&
			container.Labels["com.xiak.matrix.content-digest"] == state.ContentDigest &&
			container.Labels["com.xiak.matrix.application-revision-id"] == string(state.ApplicationRevisionID)
		if !current {
			stale++
			continue
		}
		currentCount[service.Name]++
		if container.State == "running" && (container.Health == "" || container.Health == "healthy") {
			readyCount[service.Name]++
		}
		if container.State == "exited" || container.State == "dead" ||
			container.State == "removing" || container.Health == "unhealthy" {
			failed = true
		}
	}
	observation := paasv1.DeploymentObservation{
		DeploymentID: state.DeploymentID, Generation: state.Generation,
		ApplicationRevisionID: state.ApplicationRevisionID,
		ReceiptDigest:         state.ReceiptDigest, ObservedAt: now,
	}
	if state.DesiredState == paasv1.DeploymentDesiredStopped {
		if len(containers) == 0 {
			observation.Phase = paasv1.DeploymentStopped
		} else {
			observation.Phase = paasv1.DeploymentStopping
		}
		return observation, paasv1.ValidateDeploymentObservation(observation)
	}
	if len(containers) == 0 {
		observation.Phase = paasv1.DeploymentStopped
		return observation, paasv1.ValidateDeploymentObservation(observation)
	}
	allReady := stale == 0
	for _, service := range state.Services {
		if readyCount[service.Name] == service.Replicas && currentCount[service.Name] == service.Replicas {
			observation.ReadyComponents++
			observation.Endpoints = append(observation.Endpoints, service.Endpoints...)
		} else {
			allReady = false
		}
		if currentCount[service.Name] > service.Replicas {
			failed = true
		}
	}
	slices.SortFunc(observation.Endpoints, func(left, right paasv1.DeploymentEndpointObservation) int {
		if compared := strings.Compare(left.ComponentName, right.ComponentName); compared != 0 {
			return compared
		}
		return strings.Compare(left.EndpointName, right.EndpointName)
	})
	switch {
	case allReady:
		observation.Phase = paasv1.DeploymentReady
	case failed || (stale > 0 && sumCounts(currentCount) == 0):
		observation.Phase = paasv1.DeploymentFailed
	case observation.ReadyComponents > 0:
		observation.Phase = paasv1.DeploymentDegraded
	default:
		observation.Phase = paasv1.DeploymentApplying
	}
	if err := paasv1.ValidateDeploymentObservation(observation); err != nil {
		return paasv1.DeploymentObservation{}, err
	}
	return observation, nil
}

func sumCounts(values map[string]uint32) uint32 {
	var total uint32
	for _, value := range values {
		total += value
	}
	return total
}

func successfulResult(
	command paasv1.AdapterCommandEnvelope,
	receipt string,
	observedAt time.Time,
	replayed bool,
) paasv1.AdapterResult {
	return paasv1.AdapterResult{
		CommandID: command.CommandID, State: paasv1.AdapterResultSucceeded,
		Receipt: receipt, Replayed: replayed, ObservedAt: observedAt,
	}
}

func invalidRequestFault() paasv1.AdapterFault {
	return newComposeFault(
		paasv1.AdapterErrorValidation, paasv1.ErrorInvalidArgument,
		"Compose executor request is invalid.", false,
	)
}

func secretResolutionFault() paasv1.AdapterFault {
	return newComposeFault(
		paasv1.AdapterErrorUnavailable, paasv1.ErrorAdapterUnavailable,
		"An exact secret version could not be resolved safely.", false,
	)
}

func notFoundFault() paasv1.AdapterFault {
	return newComposeFault(
		paasv1.AdapterErrorNotFound, paasv1.ErrorNotFound,
		"The Compose project state was not found.", false,
	)
}

func conflictFault() paasv1.AdapterFault {
	return newComposeFault(
		paasv1.AdapterErrorConflict, paasv1.ErrorConflict,
		"The Compose project state conflicts with the requested generation.", false,
	)
}

func idempotencyConflictFault() paasv1.AdapterFault {
	return newComposeFault(
		paasv1.AdapterErrorConflict, paasv1.ErrorIdempotencyConflict,
		"The Compose command identity was reused with another request digest.", false,
	)
}

func providerRejectedFault() paasv1.AdapterFault {
	return newComposeFault(
		paasv1.AdapterErrorValidation, paasv1.ErrorAdapterRejected,
		"Docker Compose returned an unsafe or unsupported project observation.", false,
	)
}

func unavailableFault() paasv1.AdapterFault {
	return newComposeFault(
		paasv1.AdapterErrorUnavailable, paasv1.ErrorAdapterUnavailable,
		"Docker Compose observation is unavailable.", true,
	)
}

func internalFault() paasv1.AdapterFault {
	return newComposeFault(
		paasv1.AdapterErrorInternal, paasv1.ErrorInternal,
		"Compose executor state could not be processed safely.", false,
	)
}

func unknownOutcomeFault() paasv1.AdapterFault {
	return newComposeFault(
		paasv1.AdapterErrorUnknownOutcome, paasv1.ErrorAdapterOutcomeUnknown,
		"The Compose effect outcome is unknown; observe before retrying.", true,
	)
}

func boundaryFault(err error) paasv1.AdapterFault {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return newComposeFault(
			paasv1.AdapterErrorTimeout, paasv1.ErrorDeadlineExceeded,
			"Compose executor coordination exceeded its deadline.", true,
		)
	}
	return internalFault()
}

func newComposeFault(
	class paasv1.AdapterErrorClass,
	code paasv1.ErrorCode,
	message string,
	retryable bool,
) paasv1.AdapterFault {
	normalized := paasv1.NormalizedAdapterError{
		Class: class, Code: code, Message: message, Retryable: retryable,
	}
	if err := paasv1.ValidateNormalizedAdapterError(normalized); err != nil {
		normalized = paasv1.NormalizedAdapterError{
			Class: paasv1.AdapterErrorInternal, Code: paasv1.ErrorInternal,
			Message: "Compose executor produced an invalid normalized failure.",
		}
	}
	return paasv1.AdapterFault{Normalized: normalized}
}
