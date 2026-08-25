package localmachine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/execabs"
)

type HostFacts struct {
	MachineID             string `json:"-"`
	OperatingSystem       string
	Architecture          string
	LogicalCPUs           int
	MemoryTotalBytes      uint64
	MemoryAvailableBytes  uint64
	StorageTotalBytes     uint64
	StorageAvailableBytes uint64
	DockerEngineReady     bool
	ComposePluginReady    bool
}

func (value HostFacts) String() string {
	return fmt.Sprintf(
		"HostFacts{machineID:<redacted> os:%q arch:%q cpus:%d memoryTotal:%d storageTotal:%d docker:%t compose:%t}",
		value.OperatingSystem,
		value.Architecture,
		value.LogicalCPUs,
		value.MemoryTotalBytes,
		value.StorageTotalBytes,
		value.DockerEngineReady,
		value.ComposePluginReady,
	)
}

func (value HostFacts) GoString() string {
	return value.String()
}

type HostProbe interface {
	Inspect(context.Context, string) (HostFacts, error)
}

type ProbeFailureKind string

const (
	ProbeFailureValidation  ProbeFailureKind = "VALIDATION"
	ProbeFailureTimeout     ProbeFailureKind = "TIMEOUT"
	ProbeFailureUnavailable ProbeFailureKind = "UNAVAILABLE"
	ProbeFailurePermission  ProbeFailureKind = "PERMISSION_DENIED"
	ProbeFailureHostKey     ProbeFailureKind = "HOST_KEY_MISMATCH"
	ProbeFailureInternal    ProbeFailureKind = "INTERNAL"
)

type ProbeFailure struct {
	Kind ProbeFailureKind
	ID   string
}

func (failure ProbeFailure) Error() string {
	return fmt.Sprintf("machine probe %s failed with %s", failure.ID, failure.Kind)
}

type CapabilityProbeID string

const (
	ProbeDockerEngine  CapabilityProbeID = "docker-engine"
	ProbeComposePlugin CapabilityProbeID = "compose-plugin"
)

type CapabilityChecker interface {
	Available(context.Context, CapabilityProbeID) bool
}

type LocalHostProbe struct {
	capabilities CapabilityChecker
}

func NewLocalHostProbe() *LocalHostProbe {
	return &LocalHostProbe{
		capabilities: execCapabilityChecker{timeout: 3 * time.Second},
	}
}

func newLocalHostProbe(checker CapabilityChecker) *LocalHostProbe {
	return &LocalHostProbe{capabilities: checker}
}

func (probe *LocalHostProbe) Inspect(
	ctx context.Context,
	storagePath string,
) (HostFacts, error) {
	if err := ctx.Err(); err != nil {
		return HostFacts{}, contextProbeFailure(err, "host")
	}
	metrics, err := readLocalMetrics(storagePath)
	if err != nil {
		return HostFacts{}, ProbeFailure{
			Kind: ProbeFailureUnavailable,
			ID:   "host",
		}
	}
	facts := HostFacts{
		MachineID:             strings.ToLower(strings.TrimSpace(metrics.machineID)),
		OperatingSystem:       runtime.GOOS,
		Architecture:          runtime.GOARCH,
		LogicalCPUs:           runtime.NumCPU(),
		MemoryTotalBytes:      metrics.memoryTotalBytes,
		MemoryAvailableBytes:  metrics.memoryAvailableBytes,
		StorageTotalBytes:     metrics.storageTotalBytes,
		StorageAvailableBytes: metrics.storageAvailableBytes,
	}
	if err := validateHostFacts(facts); err != nil {
		return HostFacts{}, ProbeFailure{
			Kind: ProbeFailureValidation,
			ID:   "host-facts",
		}
	}
	if probe == nil || probe.capabilities == nil {
		return HostFacts{}, ProbeFailure{
			Kind: ProbeFailureInternal,
			ID:   "capabilities",
		}
	}
	facts.DockerEngineReady = probe.capabilities.Available(ctx, ProbeDockerEngine)
	facts.ComposePluginReady = probe.capabilities.Available(ctx, ProbeComposePlugin)
	return facts, nil
}

type localMetrics struct {
	machineID             string
	memoryTotalBytes      uint64
	memoryAvailableBytes  uint64
	storageTotalBytes     uint64
	storageAvailableBytes uint64
}

type execCapabilityChecker struct {
	timeout time.Duration
}

func (checker execCapabilityChecker) Available(
	ctx context.Context,
	probe CapabilityProbeID,
) bool {
	var executable string
	var arguments []string
	switch probe {
	case ProbeDockerEngine:
		executable = "docker"
		arguments = []string{"info", "--format", "{{.ServerVersion}}"}
	case ProbeComposePlugin:
		executable = "docker"
		arguments = []string{"compose", "version", "--short"}
	default:
		return false
	}
	timeout := checker.timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	probeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := execabs.CommandContext(probeContext, executable, arguments...)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run() == nil
}

func validateHostFacts(value HostFacts) error {
	var problems []error
	problems = append(problems,
		validateSafeExternalText("machine id", value.MachineID, 512, true),
		validateSafeExternalText("operating system", value.OperatingSystem, 64, true),
		validateSafeExternalText("architecture", value.Architecture, 64, true),
	)
	if value.LogicalCPUs <= 0 || uint64(value.LogicalCPUs) > uint64(math.MaxInt64/1000) {
		problems = append(problems, errors.New("logical CPU count is invalid"))
	}
	if value.MemoryTotalBytes == 0 ||
		value.MemoryAvailableBytes > value.MemoryTotalBytes {
		problems = append(problems, errors.New("memory capacity is invalid"))
	}
	if value.StorageTotalBytes == 0 ||
		value.StorageAvailableBytes > value.StorageTotalBytes {
		problems = append(problems, errors.New("storage capacity is invalid"))
	}
	return errors.Join(problems...)
}

func contextProbeFailure(err error, id string) ProbeFailure {
	if errors.Is(err, context.DeadlineExceeded) {
		return ProbeFailure{Kind: ProbeFailureTimeout, ID: id}
	}
	return ProbeFailure{Kind: ProbeFailureUnavailable, ID: id}
}
