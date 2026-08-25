package localmachine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/execabs"
)

const maximumDockerProbeOutput = 64 * 1024

type dockerHostProbeRuntime interface {
	Run(context.Context, ...string) ([]byte, error)
}

type DockerHostProbe struct {
	runtime dockerHostProbeRuntime
}

// NewDockerHostProbe observes the Docker Engine host rather than the worker
// container. It is the local-machine probe used by the Compose-first release.
func NewDockerHostProbe() *DockerHostProbe {
	return &DockerHostProbe{runtime: dockerCLIHostProbeRuntime{}}
}

func newDockerHostProbe(runtime dockerHostProbeRuntime) *DockerHostProbe {
	return &DockerHostProbe{runtime: runtime}
}

func (probe *DockerHostProbe) Inspect(
	ctx context.Context,
	storagePath string,
) (HostFacts, error) {
	if ctx == nil || ctx.Err() != nil {
		return HostFacts{}, ProbeFailure{Kind: ProbeFailureUnavailable, ID: "docker-host"}
	}
	if probe == nil || probe.runtime == nil {
		return HostFacts{}, ProbeFailure{Kind: ProbeFailureInternal, ID: "docker-host"}
	}
	output, err := probe.runtime.Run(ctx, "info", "--format", "{{json .}}")
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return HostFacts{}, contextProbeFailure(contextErr, "docker-engine")
		}
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return HostFacts{}, contextProbeFailure(err, "docker-engine")
		}
		return HostFacts{}, ProbeFailure{Kind: ProbeFailureUnavailable, ID: "docker-engine"}
	}
	info, err := decodeDockerHostInfo(output)
	if err != nil {
		return HostFacts{}, ProbeFailure{Kind: ProbeFailureValidation, ID: "docker-engine"}
	}
	storageTotal, storageAvailable, err := readDockerHostStorage(storagePath)
	if err != nil {
		return HostFacts{}, ProbeFailure{Kind: ProbeFailureUnavailable, ID: "host-storage"}
	}
	composeOutput, composeErr := probe.runtime.Run(ctx, "compose", "version", "--short")
	if composeErr != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return HostFacts{}, contextProbeFailure(contextErr, "compose-plugin")
		}
		if errors.Is(composeErr, context.Canceled) ||
			errors.Is(composeErr, context.DeadlineExceeded) {
			return HostFacts{}, contextProbeFailure(composeErr, "compose-plugin")
		}
	}
	composeReady := composeErr == nil && strings.TrimSpace(string(composeOutput)) != ""
	return HostFacts{
		MachineID:             info.ID,
		OperatingSystem:       info.OperatingSystem,
		Architecture:          info.Architecture,
		LogicalCPUs:           info.LogicalCPUs,
		MemoryTotalBytes:      info.MemoryTotalBytes,
		MemoryAvailableBytes:  info.MemoryTotalBytes / 2,
		StorageTotalBytes:     storageTotal,
		StorageAvailableBytes: storageAvailable,
		DockerEngineReady:     true,
		ComposePluginReady:    composeReady,
	}, nil
}

type dockerHostInfo struct {
	ID               string `json:"ID"`
	LogicalCPUs      int    `json:"NCPU"`
	MemoryTotalBytes uint64 `json:"MemTotal"`
	OperatingSystem  string `json:"OSType"`
	Architecture     string `json:"Architecture"`
}

func decodeDockerHostInfo(content []byte) (dockerHostInfo, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	var info dockerHostInfo
	if err := decoder.Decode(&info); err != nil {
		return dockerHostInfo{}, errors.New("Docker host information is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return dockerHostInfo{}, errors.New("Docker host information is invalid")
	}
	info.ID = strings.ToLower(strings.TrimSpace(info.ID))
	info.OperatingSystem = strings.ToLower(strings.TrimSpace(info.OperatingSystem))
	info.Architecture = normalizeDockerArchitecture(info.Architecture)
	if info.ID == "" || info.LogicalCPUs <= 0 || info.MemoryTotalBytes < 2*1024*1024*1024 ||
		info.OperatingSystem != "linux" || info.Architecture != "amd64" {
		return dockerHostInfo{}, errors.New("Docker host information is unsupported")
	}
	return info, nil
}

func normalizeDockerArchitecture(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	default:
		return ""
	}
}

type dockerCLIHostProbeRuntime struct{}

func (dockerCLIHostProbeRuntime) Run(
	ctx context.Context,
	arguments ...string,
) ([]byte, error) {
	probeContext, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var output dockerProbeOutput
	command := execabs.CommandContext(probeContext, "docker", arguments...)
	command.Stdin = nil
	command.Stdout = &output
	command.Stderr = io.Discard
	command.Env = append(os.Environ(), "DOCKER_CLI_HINTS=false", "COMPOSE_MENU=0")
	if err := command.Run(); err != nil || output.exceeded {
		if probeContext.Err() != nil {
			return nil, probeContext.Err()
		}
		return nil, errors.New("Docker host probe failed")
	}
	return append([]byte(nil), output.Bytes()...), nil
}

type dockerProbeOutput struct {
	bytes.Buffer
	exceeded bool
}

func (output *dockerProbeOutput) Write(content []byte) (int, error) {
	remaining := maximumDockerProbeOutput - output.Len()
	if len(content) > remaining {
		if remaining > 0 {
			_, _ = output.Buffer.Write(content[:remaining])
		}
		output.exceeded = true
		return 0, errors.New("Docker host probe output exceeds its bound")
	}
	return output.Buffer.Write(content)
}
