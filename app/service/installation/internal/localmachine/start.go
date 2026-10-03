package localmachine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

const platformStartWaitSeconds = "180"

type platformComposeExpectation struct {
	Name     string                             `json:"name"`
	Services map[string]platformExpectedService `json:"services"`
	Networks map[string]platformExpectedNetwork `json:"networks"`
}

type platformExpectedService struct {
	Image       string                 `json:"image"`
	Restart     string                 `json:"restart"`
	User        string                 `json:"user"`
	ReadOnly    bool                   `json:"read_only"`
	Init        bool                   `json:"init"`
	Networks    []string               `json:"networks"`
	Ports       []string               `json:"ports"`
	Volumes     []platformMount        `json:"volumes"`
	Tmpfs       []string               `json:"tmpfs"`
	SecurityOpt []string               `json:"security_opt"`
	CapAdd      []string               `json:"cap_add"`
	CapDrop     []string               `json:"cap_drop"`
	Deploy      platformExpectedDeploy `json:"deploy"`
	Labels      map[string]string      `json:"labels"`
	ConfigHash  string                 `json:"-"`
}

type platformExpectedDeploy struct {
	Resources struct {
		Limits struct {
			CPUs   string `json:"cpus"`
			Memory string `json:"memory"`
		} `json:"limits"`
	} `json:"resources"`
}

type platformExpectedNetwork struct {
	Internal bool              `json:"internal"`
	Labels   map[string]string `json:"labels"`
}

type platformMount struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

type platformContainerInspection struct {
	ID              string                  `json:"Id"`
	RestartCount    uint64                  `json:"RestartCount"`
	Name            string                  `json:"Name"`
	Image           string                  `json:"Image"`
	Config          platformContainerConfig `json:"Config"`
	State           platformContainerState  `json:"State"`
	HostConfig      platformHostConfig      `json:"HostConfig"`
	Mounts          []platformProviderMount `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID string `json:"NetworkID"`
		} `json:"Networks"`
		Ports map[string][]platformPortBinding `json:"Ports"`
	} `json:"NetworkSettings"`
}

type platformContainerConfig struct {
	Labels     map[string]string `json:"Labels"`
	User       string            `json:"User"`
	Env        []string          `json:"Env"`
	Entrypoint []string          `json:"Entrypoint"`
	Cmd        []string          `json:"Cmd"`
}

type platformContainerState struct {
	Status    string `json:"Status"`
	StartedAt string `json:"StartedAt"`
	Running   bool   `json:"Running"`
	ExitCode  int    `json:"ExitCode"`
	OOMKilled bool   `json:"OOMKilled"`
	Error     string `json:"Error"`
	Health    *struct {
		Status string `json:"Status"`
	} `json:"Health"`
}

type platformHostConfig struct {
	Privileged     bool              `json:"Privileged"`
	ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
	NetworkMode    string            `json:"NetworkMode"`
	Init           *bool             `json:"Init"`
	Memory         int64             `json:"Memory"`
	MemorySwap     int64             `json:"MemorySwap"`
	PidsLimit      *int64            `json:"PidsLimit"`
	PidMode        string            `json:"PidMode"`
	IpcMode        string            `json:"IpcMode"`
	UTSMode        string            `json:"UTSMode"`
	UsernsMode     string            `json:"UsernsMode"`
	CgroupnsMode   string            `json:"CgroupnsMode"`
	Devices        []json.RawMessage `json:"Devices"`
	DeviceRequests []json.RawMessage `json:"DeviceRequests"`
	VolumesFrom    []string          `json:"VolumesFrom"`
	Binds          []string          `json:"Binds"`
	AutoRemove     bool              `json:"AutoRemove"`
	LogConfig      struct {
		Type string `json:"Type"`
	} `json:"LogConfig"`
	NanoCPUs      int64                            `json:"NanoCpus"`
	CapAdd        []string                         `json:"CapAdd"`
	CapDrop       []string                         `json:"CapDrop"`
	SecurityOpt   []string                         `json:"SecurityOpt"`
	Tmpfs         map[string]string                `json:"Tmpfs"`
	PortBindings  map[string][]platformPortBinding `json:"PortBindings"`
	RestartPolicy struct {
		Name string `json:"Name"`
	} `json:"RestartPolicy"`
}

type platformProviderMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

type platformPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type platformNetworkInspection struct {
	ID       string            `json:"Id"`
	Name     string            `json:"Name"`
	Internal bool              `json:"Internal"`
	Labels   map[string]string `json:"Labels"`
}

type platformProjectObservation struct {
	Containers map[string]platformContainerInspection
	Networks   map[string]platformNetworkInspection
}

func startInstallation(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) error {
	installation, expectation, err := preparePlatformObservation(
		ctx, runtimeBoundary, plan,
	)
	if err != nil {
		return err
	}

	complete, err := observePlatformProject(ctx, runtimeBoundary, expectation)
	if err != nil {
		return err
	}
	if complete {
		return nil
	}
	_, started, runErr := runtimeBoundary.Run(
		ctx,
		nil,
		"compose", "--file", installation.composePath,
		"--project-name", installation.topology.ProjectName,
		"up", "--detach", "--wait", "--wait-timeout", platformStartWaitSeconds,
		"--no-build", "--pull", "never",
	)
	if runErr != nil {
		if !started {
			return errors.Join(platformcommand.ErrEffectUnavailable, runErr)
		}
		if ctx.Err() != nil {
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, runErr)
		}
		complete, observeErr := observePlatformProject(ctx, runtimeBoundary, expectation)
		if observeErr != nil {
			if errors.Is(observeErr, platformcommand.ErrEffectConflict) ||
				errors.Is(observeErr, platformcommand.ErrEffectVerification) {
				return observeErr
			}
			return errors.Join(platformcommand.ErrEffectOutcomeUnknown, runErr, observeErr)
		}
		if complete {
			return nil
		}
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("platform failed to reach its fixed healthy topology"),
		)
	}
	complete, err = observePlatformProject(ctx, runtimeBoundary, expectation)
	if err != nil {
		if errors.Is(err, platformcommand.ErrEffectConflict) ||
			errors.Is(err, platformcommand.ErrEffectVerification) {
			return err
		}
		return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
	}
	if !complete {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("platform start did not produce its fixed healthy topology"),
		)
	}
	return nil
}

func observeInstalledPlatform(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) (bool, error) {
	_, expectation, err := preparePlatformObservation(ctx, runtimeBoundary, plan)
	if err != nil {
		return false, err
	}
	return observePlatformProject(ctx, runtimeBoundary, expectation)
}

func preparePlatformObservation(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) (verifiedInstallation, platformComposeExpectation, error) {
	installation, expectation, err := preparePlatformExpectation(
		ctx, runtimeBoundary, plan,
	)
	if err != nil {
		return verifiedInstallation{}, platformComposeExpectation{}, err
	}
	for _, image := range installation.bundle.Manifest.Images {
		present, inspectErr := inspectExactImage(ctx, runtimeBoundary, image.ImageID)
		if inspectErr != nil {
			return verifiedInstallation{}, platformComposeExpectation{}, inspectErr
		}
		if !present {
			return verifiedInstallation{}, platformComposeExpectation{}, errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("platform image identity is absent"),
			)
		}
	}
	return installation, expectation, nil
}

func preparePlatformExpectation(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) (verifiedInstallation, platformComposeExpectation, error) {
	installation, err := verifiedInstallationConfiguration(plan)
	if err != nil {
		return verifiedInstallation{}, platformComposeExpectation{}, errors.Join(
			platformcommand.ErrEffectVerification, err,
		)
	}
	expectation, err := decodePlatformExpectation(installation.topology.ComposeJSON)
	if err != nil || expectation.Name != installation.topology.ProjectName {
		return verifiedInstallation{}, platformComposeExpectation{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("compiled platform topology cannot be observed"),
		)
	}
	if err := loadPlatformServiceHashes(
		ctx,
		runtimeBoundary,
		installation.composePath,
		installation.topology.ProjectName,
		expectation.Services,
	); err != nil {
		return verifiedInstallation{}, platformComposeExpectation{}, err
	}
	return installation, expectation, nil
}

func inspectReadyInstalledPlatform(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) (verifiedInstallation, platformComposeExpectation, platformProjectObservation, error) {
	installation, expectation, err := preparePlatformObservation(ctx, runtimeBoundary, plan)
	if err != nil {
		return verifiedInstallation{}, platformComposeExpectation{}, platformProjectObservation{}, err
	}
	observation, exists, err := inspectOwnedPlatformProject(ctx, runtimeBoundary, expectation)
	if err != nil {
		return verifiedInstallation{}, platformComposeExpectation{}, platformProjectObservation{}, err
	}
	ready, err := validatePlatformObservation(observation, exists, expectation)
	if err != nil {
		return verifiedInstallation{}, platformComposeExpectation{}, platformProjectObservation{}, err
	}
	if !ready {
		return verifiedInstallation{}, platformComposeExpectation{}, platformProjectObservation{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("platform is not in its fixed healthy topology"),
		)
	}
	return installation, expectation, observation, nil
}

func loadPlatformServiceHashes(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	composePath string,
	projectName string,
	services map[string]platformExpectedService,
) error {
	output, _, err := runtimeBoundary.Run(
		ctx,
		nil,
		"compose", "--file", composePath, "--project-name", projectName,
		"config", "--hash", "*",
	)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	observed := make(map[string]string, len(services))
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || services[fields[0]].Image == "" ||
			!validComposeConfigHash(fields[1]) || observed[fields[0]] != "" {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("Compose service hash observation is invalid"),
			)
		}
		observed[fields[0]] = fields[1]
	}
	if len(observed) != len(services) {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("Compose service hash inventory is incomplete"),
		)
	}
	for name, service := range services {
		service.ConfigHash = observed[name]
		services[name] = service
	}
	return nil
}

func validComposeConfigHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func decodePlatformExpectation(content []byte) (platformComposeExpectation, error) {
	var expectation platformComposeExpectation
	if err := json.Unmarshal(content, &expectation); err != nil || expectation.Name == "" ||
		len(expectation.Services) == 0 || len(expectation.Networks) == 0 {
		return platformComposeExpectation{}, errors.New("platform topology expectation is invalid")
	}
	return expectation, nil
}

func observePlatformProject(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	expectation platformComposeExpectation,
) (bool, error) {
	observation, exists, err := inspectOwnedPlatformProject(
		ctx, runtimeBoundary, expectation,
	)
	if err != nil {
		return false, err
	}
	return validatePlatformObservation(observation, exists, expectation)
}

func validatePlatformObservation(
	observation platformProjectObservation,
	exists bool,
	expectation platformComposeExpectation,
) (bool, error) {
	if !exists {
		return false, nil
	}
	networkIDs := make(map[string]string, len(observation.Networks))
	for logicalName, inspection := range observation.Networks {
		expected := expectation.Networks[logicalName]
		if inspection.Internal != expected.Internal {
			return false, errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("platform project network configuration drifted"),
			)
		}
		networkIDs[logicalName] = inspection.ID
	}

	allReady := true
	for serviceName, inspection := range observation.Containers {
		expected := expectation.Services[serviceName]
		if err := validatePlatformContainer(inspection, expected, networkIDs); err != nil {
			return false, errors.Join(platformcommand.ErrEffectVerification, err)
		}
		if inspection.Config.Labels["com.docker.compose.config-hash"] != expected.ConfigHash {
			allReady = false
		}
		if !inspection.State.Running || inspection.State.Status != "running" ||
			inspection.State.Health == nil || inspection.State.Health.Status != "healthy" {
			allReady = false
		}
	}
	return len(observation.Containers) == len(expectation.Services) &&
		len(observation.Networks) == len(expectation.Networks) && allReady, nil
}

func inspectOwnedPlatformProject(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	expectation platformComposeExpectation,
) (platformProjectObservation, bool, error) {
	containers, err := listProjectObjects(ctx, runtimeBoundary, "container", expectation.Name)
	if err != nil {
		return platformProjectObservation{}, false, err
	}
	networks, err := listProjectObjects(ctx, runtimeBoundary, "network", expectation.Name)
	if err != nil {
		return platformProjectObservation{}, false, err
	}
	volumes, err := listProjectObjects(ctx, runtimeBoundary, "volume", expectation.Name)
	if err != nil {
		return platformProjectObservation{}, false, err
	}
	if len(containers) == 0 && len(networks) == 0 && len(volumes) == 0 {
		return platformProjectObservation{}, false, nil
	}
	if len(volumes) != 0 || len(containers) > len(expectation.Services) ||
		len(networks) > len(expectation.Networks) {
		return platformProjectObservation{}, false, errors.Join(
			platformcommand.ErrEffectConflict,
			errors.New("platform project contains an unexpected provider object"),
		)
	}

	observedNetworks := make(map[string]platformNetworkInspection, len(networks))
	for _, identity := range networks {
		inspection, inspectErr := inspectPlatformNetwork(ctx, runtimeBoundary, identity)
		if inspectErr != nil {
			return platformProjectObservation{}, false, inspectErr
		}
		logicalName := inspection.Labels["com.docker.compose.network"]
		expected, found := expectation.Networks[logicalName]
		if !found || observedNetworks[logicalName].ID != "" {
			return platformProjectObservation{}, false, errors.Join(
				platformcommand.ErrEffectConflict,
				errors.New("platform project network inventory conflicts"),
			)
		}
		if !ownershipLabelsMatch(inspection.Labels, expected.Labels) ||
			inspection.Labels["com.docker.compose.project"] != expectation.Name {
			return platformProjectObservation{}, false, errors.Join(
				platformcommand.ErrEffectConflict,
				errors.New("platform project network is not installation-owned"),
			)
		}
		observedNetworks[logicalName] = inspection
	}

	observedContainers := make(map[string]platformContainerInspection, len(containers))
	for _, identity := range containers {
		inspection, inspectErr := inspectPlatformContainer(ctx, runtimeBoundary, identity)
		if inspectErr != nil {
			return platformProjectObservation{}, false, inspectErr
		}
		serviceName := inspection.Config.Labels["com.docker.compose.service"]
		expected, found := expectation.Services[serviceName]
		if !found {
			return platformProjectObservation{}, false, errors.Join(
				platformcommand.ErrEffectConflict,
				errors.New("platform project contains an unexpected service"),
			)
		}
		if observedContainers[serviceName].ID != "" {
			return platformProjectObservation{}, false, errors.Join(
				platformcommand.ErrEffectConflict,
				errors.New("platform project contains duplicate service containers"),
			)
		}
		if inspection.Image != expected.Image ||
			!ownershipLabelsMatch(inspection.Config.Labels, expected.Labels) ||
			inspection.Config.Labels["com.docker.compose.project"] != expectation.Name ||
			!strings.EqualFold(inspection.Config.Labels["com.docker.compose.oneoff"], "false") {
			return platformProjectObservation{}, false, errors.Join(
				platformcommand.ErrEffectConflict,
				errors.New("platform service is not installation-owned"),
			)
		}
		observedContainers[serviceName] = inspection
	}
	return platformProjectObservation{
		Containers: observedContainers,
		Networks:   observedNetworks,
	}, true, nil
}

func listProjectObjects(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	objectType string,
	project string,
) ([]string, error) {
	arguments := []string{objectType, "ls", "--quiet"}
	if objectType != "volume" {
		arguments = append(arguments, "--no-trunc")
	}
	if objectType == "container" {
		arguments = append(arguments, "--all")
	}
	arguments = append(arguments, "--filter", "label=com.docker.compose.project="+project)
	output, _, err := runtimeBoundary.Run(ctx, nil, arguments...)
	if err != nil {
		return nil, errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	identities := strings.Fields(string(output))
	if len(identities) > maximumProviderObjects {
		return nil, errors.Join(
			platformcommand.ErrEffectConflict,
			errors.New("platform project provider inventory exceeds its bound"),
		)
	}
	for _, identity := range identities {
		if !providerIdentity.MatchString(identity) {
			return nil, errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("platform provider identity is invalid"),
			)
		}
	}
	return identities, nil
}

func inspectPlatformNetwork(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	identity string,
) (platformNetworkInspection, error) {
	output, _, err := runtimeBoundary.Run(
		ctx, nil, "network", "inspect", "--format", "{{json .}}", identity,
	)
	if err != nil {
		return platformNetworkInspection{}, errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	var inspection platformNetworkInspection
	if json.Unmarshal(output, &inspection) != nil || inspection.ID != identity || inspection.Labels == nil {
		return platformNetworkInspection{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("platform network observation is invalid"),
		)
	}
	return inspection, nil
}

func inspectPlatformContainer(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	identity string,
) (platformContainerInspection, error) {
	output, _, err := runtimeBoundary.Run(
		ctx, nil, "container", "inspect", "--format", "{{json .}}", identity,
	)
	if err != nil {
		return platformContainerInspection{}, errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	var inspection platformContainerInspection
	if json.Unmarshal(output, &inspection) != nil || inspection.ID != identity ||
		inspection.Config.Labels == nil {
		return platformContainerInspection{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("platform container observation is invalid"),
		)
	}
	return inspection, nil
}

func validatePlatformContainer(
	inspection platformContainerInspection,
	expected platformExpectedService,
	networkIDs map[string]string,
) error {
	expectedNanoCPUs, expectedMemory, err := expectedResourceLimits(expected.Deploy)
	if err != nil {
		return errors.New("platform expected resource limits are invalid")
	}
	expectedTmpfs, err := expectedTmpfsInventory(expected.Tmpfs)
	if err != nil {
		return errors.New("platform expected tmpfs inventory is invalid")
	}
	if inspection.Image != expected.Image || inspection.Config.User != expected.User ||
		inspection.HostConfig.Privileged ||
		inspection.HostConfig.ReadonlyRootfs != expected.ReadOnly ||
		inspection.HostConfig.RestartPolicy.Name != expected.Restart ||
		platformInitEnabled(inspection.HostConfig.Init) != expected.Init ||
		inspection.HostConfig.NanoCPUs != expectedNanoCPUs ||
		inspection.HostConfig.Memory != expectedMemory ||
		!equalStringMaps(inspection.HostConfig.Tmpfs, expectedTmpfs) ||
		!equalStringInventory(inspection.HostConfig.CapAdd, expected.CapAdd, true) ||
		!equalStringInventory(inspection.HostConfig.CapDrop, expected.CapDrop, true) ||
		!equalStringInventory(inspection.HostConfig.SecurityOpt, expected.SecurityOpt, false) {
		return errors.New("platform container isolation or image identity drifted")
	}
	actualNetworks := make([]string, 0, len(inspection.NetworkSettings.Networks))
	for _, network := range inspection.NetworkSettings.Networks {
		if network.NetworkID == "" {
			return errors.New("platform container network identity is invalid")
		}
		actualNetworks = append(actualNetworks, network.NetworkID)
	}
	expectedNetworks := make([]string, 0, len(expected.Networks))
	for _, logicalName := range expected.Networks {
		identity := networkIDs[logicalName]
		if identity == "" {
			return errors.New("platform container references an absent network")
		}
		expectedNetworks = append(expectedNetworks, identity)
	}
	slices.Sort(actualNetworks)
	slices.Sort(expectedNetworks)
	if !slices.Equal(actualNetworks, expectedNetworks) {
		return errors.New("platform container network membership drifted")
	}
	if !slices.Equal(platformMountInventory(inspection.Mounts), expectedMountInventory(expected.Volumes)) {
		return errors.New("platform container mount inventory drifted")
	}
	expectedPorts, err := expectedPortInventory(expected.Ports)
	if err != nil || !slices.Equal(
		platformPortInventory(inspection.HostConfig.PortBindings), expectedPorts,
	) || !slices.Equal(
		platformPortInventory(inspection.NetworkSettings.Ports), expectedPorts,
	) {
		return errors.New("platform container port binding is absent or drifted")
	}
	return nil
}

func expectedResourceLimits(value platformExpectedDeploy) (int64, int64, error) {
	cpus, err := strconv.ParseFloat(value.Resources.Limits.CPUs, 64)
	if err != nil || math.IsNaN(cpus) || math.IsInf(cpus, 0) || cpus <= 0 {
		return 0, 0, errors.New("platform CPU limit is invalid")
	}
	scaledCPUs := cpus * 1_000_000_000
	nanoCPUs := math.Round(scaledCPUs)
	if nanoCPUs > math.MaxInt64 || math.Abs(scaledCPUs-nanoCPUs) > 0.000001 {
		return 0, 0, errors.New("platform CPU limit is invalid")
	}
	memoryText := value.Resources.Limits.Memory
	if len(memoryText) < 2 {
		return 0, 0, errors.New("platform memory limit is invalid")
	}
	multiplier := uint64(0)
	switch memoryText[len(memoryText)-1] {
	case 'M':
		multiplier = 1024 * 1024
	case 'G':
		multiplier = 1024 * 1024 * 1024
	default:
		return 0, 0, errors.New("platform memory limit is invalid")
	}
	memoryUnits, err := strconv.ParseUint(memoryText[:len(memoryText)-1], 10, 63)
	if err != nil || memoryUnits == 0 || memoryUnits > math.MaxInt64/multiplier {
		return 0, 0, errors.New("platform memory limit is invalid")
	}
	return int64(nanoCPUs), int64(memoryUnits * multiplier), nil
}

func expectedTmpfsInventory(values []string) (map[string]string, error) {
	result := make(map[string]string, len(values))
	for _, value := range values {
		separator := strings.IndexByte(value, ':')
		if separator < 1 || separator == len(value)-1 || value[0] != '/' ||
			result[value[:separator]] != "" {
			return nil, errors.New("platform tmpfs entry is invalid")
		}
		result[value[:separator]] = value[separator+1:]
	}
	return result, nil
}

func equalStringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	return labelsContain(left, right)
}

func platformInitEnabled(value *bool) bool {
	return value != nil && *value
}

func equalStringInventory(left, right []string, fold bool) bool {
	if len(left) != len(right) {
		return false
	}
	left = slices.Clone(left)
	right = slices.Clone(right)
	if fold {
		for index := range left {
			left[index] = strings.ToUpper(left[index])
			right[index] = strings.ToUpper(right[index])
		}
	}
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

func labelsContain(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func ownershipLabelsMatch(actual, expected map[string]string) bool {
	if !labelsContain(actual, expected) {
		return false
	}
	for key, value := range actual {
		if strings.HasPrefix(key, "com.xiak.matrix.") && expected[key] != value {
			return false
		}
	}
	return true
}

func platformMountInventory(values []platformProviderMount) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, strings.Join([]string{
			value.Type, value.Source, value.Destination, boolText(!value.RW),
		}, "\x00"))
	}
	slices.Sort(result)
	return result
}

func expectedMountInventory(values []platformMount) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, strings.Join([]string{
			value.Type, value.Source, value.Target, boolText(value.ReadOnly),
		}, "\x00"))
	}
	slices.Sort(result)
	return result
}

func platformPortInventory(values map[string][]platformPortBinding) []string {
	result := make([]string, 0)
	for containerPort, bindings := range values {
		for _, binding := range bindings {
			result = append(result, strings.Join([]string{
				containerPort, binding.HostIP, binding.HostPort,
			}, "\x00"))
		}
	}
	slices.Sort(result)
	return result
}

func expectedPortInventory(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		separator := strings.LastIndexByte(value, ':')
		if separator < 1 || separator == len(value)-1 {
			return nil, errors.New("platform expected port binding is invalid")
		}
		hostIP, hostPort, err := net.SplitHostPort(value[:separator])
		if err != nil || hostIP == "" || hostPort == "" {
			return nil, errors.New("platform expected port binding is invalid")
		}
		result = append(result, strings.Join([]string{
			value[separator+1:], hostIP, hostPort,
		}, "\x00"))
	}
	slices.Sort(result)
	return result, nil
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
