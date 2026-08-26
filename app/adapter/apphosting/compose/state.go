package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const (
	projectStateSchema = "compose-project-state-v1"
	commandStateSchema = "compose-command-state-v1"
	receiptStateSchema = "compose-generation-receipt-v1"
)

var serviceNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type projectState struct {
	SchemaVersion         string                        `json:"schemaVersion"`
	ProjectName           string                        `json:"projectName"`
	TenantID              paasv1.TenantID               `json:"tenantId"`
	DeploymentID          paasv1.ResourceID             `json:"deploymentId"`
	Generation            uint64                        `json:"generation"`
	ApplicationRevisionID paasv1.ResourceID             `json:"applicationRevisionId"`
	ContentDigest         string                        `json:"contentDigest"`
	DocumentDigest        string                        `json:"documentDigest"`
	DesiredState          paasv1.DeploymentDesiredState `json:"desiredState"`
	EffectAction          paasv1.AdapterAction          `json:"effectAction"`
	EffectCommandID       paasv1.CommandID              `json:"effectCommandId"`
	EffectRequestDigest   string                        `json:"effectRequestDigest"`
	Receipt               string                        `json:"receipt"`
	ReceiptDigest         string                        `json:"receiptDigest"`
	Services              []projectService              `json:"services"`
	SecretFiles           []string                      `json:"secretFiles,omitempty"`
	UpdatedAt             time.Time                     `json:"updatedAt"`
}

type projectService struct {
	Name      string                                 `json:"name"`
	Image     string                                 `json:"image"`
	Replicas  uint32                                 `json:"replicas"`
	Endpoints []paasv1.DeploymentEndpointObservation `json:"endpoints,omitempty"`
}

// RunningProjectState is the bounded, non-secret proof needed by an
// installation recovery boundary before it may remove one exact Compose
// project. Provider-native configuration and ordinary configuration values
// remain private to the adapter-owned documents.
type RunningProjectState struct {
	ProjectName           string
	Directory             string
	EffectDocument        string
	ObservationDocument   string
	TenantID              paasv1.TenantID
	DeploymentID          paasv1.ResourceID
	Generation            uint64
	ApplicationRevisionID paasv1.ResourceID
	ContentDigest         string
	Services              []RunningProjectService
	SecretFileCount       int
}

type RunningProjectService struct {
	Name     string
	Image    string
	Replicas uint32
}

type commandState struct {
	SchemaVersion string                         `json:"schemaVersion"`
	CommandID     paasv1.CommandID               `json:"commandId"`
	RequestDigest string                         `json:"requestDigest"`
	Action        paasv1.AdapterAction           `json:"action"`
	State         paasv1.AdapterResultState      `json:"state"`
	Receipt       string                         `json:"receipt,omitempty"`
	Error         *paasv1.NormalizedAdapterError `json:"error,omitempty"`
	MayRetry      bool                           `json:"mayRetry"`
	ObservedAt    time.Time                      `json:"observedAt"`
}

type generationReceipt struct {
	SchemaVersion         string               `json:"schemaVersion"`
	ProjectName           string               `json:"projectName"`
	TenantID              paasv1.TenantID      `json:"tenantId"`
	DeploymentID          paasv1.ResourceID    `json:"deploymentId"`
	Generation            uint64               `json:"generation"`
	ApplicationRevisionID paasv1.ResourceID    `json:"applicationRevisionId"`
	ContentDigest         string               `json:"contentDigest"`
	DocumentDigest        string               `json:"documentDigest"`
	Action                paasv1.AdapterAction `json:"action"`
	CommandID             paasv1.CommandID     `json:"commandId"`
	ServiceCount          int                  `json:"serviceCount"`
	SecretFileCount       int                  `json:"secretFileCount"`
}

type observationDocument struct {
	Services map[string]observationService `json:"services"`
}

type observationService struct {
	Image      string `json:"image"`
	PullPolicy string `json:"pull_policy"`
}

func newProjectState(
	request paasv1.DeploymentExecutionRequest,
	plan ExecutionPlan,
	now time.Time,
) (projectState, generationReceipt, error) {
	services := make([]projectService, 0, len(plan.Services))
	for _, planned := range plan.Services {
		services = append(services, projectService{
			Name: planned.Name, Image: planned.Image, Replicas: planned.Replicas,
			Endpoints: append([]paasv1.DeploymentEndpointObservation(nil), planned.Endpoints...),
		})
	}
	secretFiles := make([]string, 0, len(plan.SecretFiles))
	for _, secret := range plan.SecretFiles {
		secretFiles = append(secretFiles, filepath.ToSlash(secret.RelativePath))
	}
	receipt := generationReceipt{
		SchemaVersion: receiptStateSchema, ProjectName: plan.ProjectName,
		TenantID:     request.Command.Scope.TenantID,
		DeploymentID: request.Generation.DeploymentID, Generation: request.Generation.Generation,
		ApplicationRevisionID: request.ApplicationRevision.Metadata.ID,
		ContentDigest:         request.Generation.ContentDigest, DocumentDigest: plan.DocumentDigest,
		Action: request.Command.Action, CommandID: request.Command.CommandID,
		ServiceCount: len(services), SecretFileCount: len(secretFiles),
	}
	receiptName, receiptDigest, err := receiptIdentity(receipt)
	if err != nil {
		return projectState{}, generationReceipt{}, err
	}
	state := projectState{
		SchemaVersion: projectStateSchema, ProjectName: plan.ProjectName,
		TenantID:     request.Command.Scope.TenantID,
		DeploymentID: request.Generation.DeploymentID, Generation: request.Generation.Generation,
		ApplicationRevisionID: request.ApplicationRevision.Metadata.ID,
		ContentDigest:         request.Generation.ContentDigest, DocumentDigest: plan.DocumentDigest,
		DesiredState: request.Generation.Spec.DesiredState, EffectAction: request.Command.Action,
		EffectCommandID: request.Command.CommandID, EffectRequestDigest: request.Command.RequestDigest,
		Receipt: receiptName, ReceiptDigest: receiptDigest,
		Services: services, SecretFiles: secretFiles, UpdatedAt: now,
	}
	if err := validateProjectState(state); err != nil {
		return projectState{}, generationReceipt{}, err
	}
	return state, receipt, nil
}

func receiptIdentity(receipt generationReceipt) (string, string, error) {
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return "", "", errors.New("encode Compose receipt failed")
	}
	digest := sha256.Sum256(encoded)
	return "compose-" + hex.EncodeToString(digest[:16]), "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateProjectState(state projectState) error {
	var problems []error
	if state.SchemaVersion != projectStateSchema {
		problems = append(problems, errors.New("project state schema is unsupported"))
	}
	if !strings.HasPrefix(state.ProjectName, "matrix-") || len(state.ProjectName) != len("matrix-")+24 {
		problems = append(problems, errors.New("project state identity is invalid"))
	}
	problems = append(problems,
		paasv1.ValidateID("tenantId", string(state.TenantID)),
		paasv1.ValidateID("deploymentId", string(state.DeploymentID)),
		paasv1.ValidateID("applicationRevisionId", string(state.ApplicationRevisionID)),
		paasv1.ValidateID("effectCommandId", string(state.EffectCommandID)),
		paasv1.ValidateDigest("contentDigest", state.ContentDigest),
		paasv1.ValidateDigest("documentDigest", state.DocumentDigest),
		paasv1.ValidateDigest("effectRequestDigest", state.EffectRequestDigest),
		paasv1.ValidateDigest("receiptDigest", state.ReceiptDigest),
		paasv1.ValidateSafeExternalText("receipt", state.Receipt, 2048, true),
	)
	if state.Generation == 0 {
		problems = append(problems, errors.New("project state generation must be positive"))
	}
	if state.DesiredState != paasv1.DeploymentDesiredRunning && state.DesiredState != paasv1.DeploymentDesiredStopped {
		problems = append(problems, errors.New("project desired state is invalid"))
	}
	if state.DesiredState == paasv1.DeploymentDesiredStopped && state.EffectAction != paasv1.AdapterStopDeployment {
		problems = append(problems, errors.New("stopped project state has another effect action"))
	}
	if state.DesiredState == paasv1.DeploymentDesiredRunning &&
		state.EffectAction != paasv1.AdapterApplyDeployment && state.EffectAction != paasv1.AdapterRollbackDeployment {
		problems = append(problems, errors.New("running project state has another effect action"))
	}
	if state.UpdatedAt.IsZero() || state.UpdatedAt.Location() != time.UTC ||
		state.UpdatedAt != state.UpdatedAt.Round(0) || state.UpdatedAt.Nanosecond()%1000 != 0 {
		problems = append(problems, errors.New("project state time is invalid"))
	}
	seenServices := make(map[string]struct{}, len(state.Services))
	for _, service := range state.Services {
		if !serviceNamePattern.MatchString(service.Name) || service.Replicas == 0 ||
			!localImageDigestPattern.MatchString(service.Image) {
			problems = append(problems, errors.New("project service declaration is invalid"))
		}
		if _, duplicate := seenServices[service.Name]; duplicate {
			problems = append(problems, errors.New("project service declaration is duplicated"))
		}
		seenServices[service.Name] = struct{}{}
		for _, endpoint := range service.Endpoints {
			if endpoint.ComponentName != service.Name || endpoint.Address != service.Name {
				problems = append(problems, errors.New("project endpoint declaration is invalid"))
			}
		}
		observation := paasv1.DeploymentObservation{
			DeploymentID: state.DeploymentID, Generation: state.Generation,
			ApplicationRevisionID: state.ApplicationRevisionID,
			Phase:                 paasv1.DeploymentReady, ReadyComponents: 1,
			Endpoints: service.Endpoints, ReceiptDigest: state.ReceiptDigest,
			ObservedAt: state.UpdatedAt,
		}
		if err := paasv1.ValidateDeploymentObservation(observation); err != nil {
			problems = append(problems, errors.New("project endpoint declaration is invalid"))
		}
	}
	if len(state.Services) == 0 {
		problems = append(problems, errors.New("project state requires at least one service"))
	}
	seenSecrets := make(map[string]struct{}, len(state.SecretFiles))
	for _, relative := range state.SecretFiles {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative)))
		if clean != relative || !strings.HasPrefix(relative, "secrets/secret-") || strings.Contains(relative, "..") {
			problems = append(problems, errors.New("project secret path is invalid"))
		}
		if _, duplicate := seenSecrets[relative]; duplicate {
			problems = append(problems, errors.New("project secret path is duplicated"))
		}
		seenSecrets[relative] = struct{}{}
	}
	receipt := receiptFromProjectState(state)
	name, digest, err := receiptIdentity(receipt)
	if err != nil || name != state.Receipt || digest != state.ReceiptDigest {
		problems = append(problems, errors.New("project receipt seal is invalid"))
	}
	return errors.Join(problems...)
}

func projectDirectory(root, project string) (string, error) {
	projects, err := ensureManagedDirectory(root, "projects")
	if err != nil {
		return "", err
	}
	return ensureManagedDirectory(projects, project)
}

func projectPaths(root, project string) (directory, composePath, observePath, statePath string, err error) {
	directory, err = projectDirectory(root, project)
	if err != nil {
		return "", "", "", "", err
	}
	composePath = filepath.Join(directory, "compose.json")
	observePath = filepath.Join(directory, "observe.json")
	statePath = filepath.Join(directory, "current.json")
	for _, target := range []string{composePath, observePath, statePath} {
		if err = validateManagedTarget(root, target); err != nil {
			return "", "", "", "", err
		}
	}
	return directory, composePath, observePath, statePath, nil
}

func existingProjectPaths(root, project string) (directory, composePath, observePath, statePath string, err error) {
	directory, err = safeJoin(root, "projects", project)
	if err != nil {
		return "", "", "", "", err
	}
	if _, err = validateExistingPath(directory, true); err != nil {
		return "", "", "", "", err
	}
	composePath = filepath.Join(directory, "compose.json")
	observePath = filepath.Join(directory, "observe.json")
	statePath = filepath.Join(directory, "current.json")
	for _, target := range []string{composePath, observePath, statePath} {
		if err = validateManagedTarget(root, target); err != nil {
			return "", "", "", "", err
		}
	}
	return directory, composePath, observePath, statePath, nil
}

func writeObservationDocument(root, target string, state projectState) error {
	document := observationDocument{Services: make(map[string]observationService, len(state.Services))}
	for _, service := range state.Services {
		document.Services[service.Name] = observationService{Image: service.Image, PullPolicy: "never"}
	}
	return writeManagedJSON(root, target, document)
}

func loadProjectState(root, path string) (projectState, error) {
	var state projectState
	if err := decodeManagedJSON(root, path, &state); err != nil {
		return projectState{}, err
	}
	if err := validateProjectState(state); err != nil {
		return projectState{}, errors.New("stored Compose project state is invalid")
	}
	return state, nil
}

// InspectRunningProjectState validates the private binding root, deterministic
// project identity, current state receipt, and both exact Compose documents.
// An absent project is reported without creating any filesystem object.
func InspectRunningProjectState(
	bindingRoot string,
	tenantID paasv1.TenantID,
	deploymentID paasv1.ResourceID,
) (RunningProjectState, bool, error) {
	if paasv1.ValidateID("tenantId", string(tenantID)) != nil ||
		paasv1.ValidateID("deploymentId", string(deploymentID)) != nil {
		return RunningProjectState{}, false, errors.New("Compose project identity is invalid")
	}
	root, err := inspectManagedRoot(bindingRoot)
	if err != nil {
		return RunningProjectState{}, false, err
	}
	project := projectName(tenantID, deploymentID)
	directory, err := safeJoin(root, "projects", project)
	if err != nil {
		return RunningProjectState{}, false, errors.New("Compose project path is invalid")
	}
	result := RunningProjectState{
		ProjectName: project, Directory: directory,
		EffectDocument:      filepath.Join(directory, "compose.json"),
		ObservationDocument: filepath.Join(directory, "observe.json"),
		TenantID:            tenantID, DeploymentID: deploymentID,
	}
	if _, err := validateExistingPath(directory, true); errors.Is(err, os.ErrNotExist) {
		return result, false, nil
	} else if err != nil || verifySecurePermissions(directory, true) != nil {
		return RunningProjectState{}, false, errors.New("stored Compose project is unsafe")
	}
	_, composePath, observePath, statePath, err := existingProjectPaths(root, project)
	if err != nil {
		return RunningProjectState{}, false, errors.New("stored Compose project is unsafe")
	}
	state, err := loadProjectState(root, statePath)
	if err != nil || state.ProjectName != project || state.TenantID != tenantID ||
		state.DeploymentID != deploymentID ||
		state.DesiredState != paasv1.DeploymentDesiredRunning {
		return RunningProjectState{}, false, errors.New("stored Compose project identity conflicts")
	}
	if err := validateRunningProjectDocuments(root, composePath, observePath, state); err != nil {
		return RunningProjectState{}, false, err
	}
	services := make([]RunningProjectService, 0, len(state.Services))
	for _, service := range state.Services {
		services = append(services, RunningProjectService{
			Name: service.Name, Image: service.Image, Replicas: service.Replicas,
		})
	}
	result.Generation = state.Generation
	result.ApplicationRevisionID = state.ApplicationRevisionID
	result.ContentDigest = state.ContentDigest
	result.Services = services
	result.SecretFileCount = len(state.SecretFiles)
	return result, true, nil
}

func validateRunningProjectDocuments(
	root string,
	composePath string,
	observePath string,
	state projectState,
) error {
	effectContent, err := readManagedFile(root, composePath, maxManagedStateBytes)
	if err != nil {
		return errors.New("stored Compose effect document is unsafe")
	}
	effectDigest := sha256.Sum256(effectContent)
	if state.DocumentDigest != "sha256:"+hex.EncodeToString(effectDigest[:]) {
		return errors.New("stored Compose effect document conflicts")
	}
	var effect composeDocument
	if decodeStrictJSON(effectContent, &effect) != nil ||
		len(effect.Services) != len(state.Services) ||
		len(effect.Secrets) != len(state.SecretFiles) {
		return errors.New("stored Compose effect document conflicts")
	}
	observationContent, err := readManagedFile(root, observePath, maxManagedStateBytes)
	if err != nil {
		return errors.New("stored Compose observation document is unsafe")
	}
	var observation observationDocument
	if decodeStrictJSON(observationContent, &observation) != nil ||
		len(observation.Services) != len(state.Services) {
		return errors.New("stored Compose observation document conflicts")
	}
	for _, service := range state.Services {
		effectService, found := effect.Services[service.Name]
		observedService, observed := observation.Services[service.Name]
		if !found || !observed || effectService.Image != service.Image ||
			effectService.PullPolicy != "never" ||
			effectService.Deploy.Replicas != service.Replicas ||
			observedService.Image != service.Image || observedService.PullPolicy != "never" ||
			!runningProjectLabelsMatch(effectService.Labels, state, service.Name) {
			return errors.New("stored Compose service document conflicts")
		}
	}
	secretPaths := make(map[string]struct{}, len(state.SecretFiles))
	for _, relative := range state.SecretFiles {
		secretPaths[relative] = struct{}{}
	}
	for name, secret := range effect.Secrets {
		if secret.File != "secrets/"+name {
			return errors.New("stored Compose secret document conflicts")
		}
		if _, found := secretPaths[secret.File]; !found {
			return errors.New("stored Compose secret document conflicts")
		}
	}
	return nil
}

func runningProjectLabelsMatch(
	labels map[string]string,
	state projectState,
	serviceName string,
) bool {
	return len(labels) == 6 &&
		labels["com.xiak.matrix.application-revision-id"] == string(state.ApplicationRevisionID) &&
		labels["com.xiak.matrix.component"] == serviceName &&
		labels["com.xiak.matrix.content-digest"] == state.ContentDigest &&
		labels["com.xiak.matrix.deployment-id"] == string(state.DeploymentID) &&
		labels["com.xiak.matrix.generation"] == strconv.FormatUint(state.Generation, 10) &&
		labels["com.xiak.matrix.tenant-id"] == string(state.TenantID)
}

func commandFile(root, projectDirectory string, commandID paasv1.CommandID) (string, error) {
	directory, err := ensureManagedDirectory(projectDirectory, "commands")
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(commandID))
	path := filepath.Join(directory, hex.EncodeToString(digest[:])+".json")
	if err := validateManagedTarget(root, path); err != nil {
		return "", err
	}
	return path, nil
}

func loadCommandState(root, path string) (*commandState, error) {
	var state commandState
	if err := decodeManagedJSON(root, path, &state); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if err := validateCommandState(state); err != nil {
		return nil, errors.New("stored Compose command state is invalid")
	}
	return &state, nil
}

func validateCommandState(state commandState) error {
	if state.SchemaVersion != commandStateSchema {
		return errors.New("command state schema is unsupported")
	}
	result := paasv1.AdapterResult{
		CommandID: state.CommandID, State: state.State, Receipt: state.Receipt,
		Error: state.Error, ObservedAt: state.ObservedAt,
	}
	return errors.Join(
		paasv1.ValidateDigest("requestDigest", state.RequestDigest),
		paasv1.ValidateAdapterResult(result),
	)
}

func writeCommandState(root, path string, state commandState) error {
	if err := validateCommandState(state); err != nil {
		return err
	}
	return writeManagedJSON(root, path, state)
}

func adapterResult(state commandState, replayed bool) paasv1.AdapterResult {
	return paasv1.AdapterResult{
		CommandID: state.CommandID, State: state.State, Receipt: state.Receipt,
		Replayed: replayed, Error: state.Error, ObservedAt: state.ObservedAt,
	}
}

func receiptFile(root, projectDirectory string, generation uint64) (string, error) {
	directory, err := ensureManagedDirectory(projectDirectory, "receipts")
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, "generation-"+strconv.FormatUint(generation, 10)+".json")
	if err := validateManagedTarget(root, path); err != nil {
		return "", err
	}
	return path, nil
}

func writeGenerationReceipt(root, path string, receipt generationReceipt) error {
	if existing, err := readManagedFile(root, path, maxManagedStateBytes); err == nil {
		candidate, encodeErr := json.Marshal(receipt)
		if encodeErr != nil {
			return encodeErr
		}
		if !slices.Equal(existing, candidate) {
			return errors.New("stored generation receipt conflicts with the current effect")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeManagedJSON(root, path, receipt)
}

func receiptFromProjectState(state projectState) generationReceipt {
	return generationReceipt{
		SchemaVersion: receiptStateSchema, ProjectName: state.ProjectName,
		TenantID:     state.TenantID,
		DeploymentID: state.DeploymentID, Generation: state.Generation,
		ApplicationRevisionID: state.ApplicationRevisionID,
		ContentDigest:         state.ContentDigest, DocumentDigest: state.DocumentDigest,
		Action: state.EffectAction, CommandID: state.EffectCommandID,
		ServiceCount: len(state.Services), SecretFileCount: len(state.SecretFiles),
	}
}

func cleanupProjectSecrets(root, directory string, retained []string) error {
	secretDirectory := filepath.Join(directory, "secrets")
	info, err := os.Lstat(secretDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if pathComponentIsLink(secretDirectory, info) || !info.IsDir() {
		return errors.New("managed secret directory is unsafe")
	}
	keep := make(map[string]struct{}, len(retained))
	for _, relative := range retained {
		keep[filepath.Base(filepath.FromSlash(relative))] = struct{}{}
	}
	entries, err := os.ReadDir(secretDirectory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		target := filepath.Join(secretDirectory, entry.Name())
		info, err := os.Lstat(target)
		if err != nil || pathComponentIsLink(target, info) || !info.Mode().IsRegular() {
			return errors.New("managed secret directory contains an unsafe entry")
		}
		if _, retained := keep[entry.Name()]; retained {
			continue
		}
		if err := removeManagedFile(root, target); err != nil {
			return err
		}
	}
	if len(retained) == 0 {
		return os.Remove(secretDirectory)
	}
	return nil
}
