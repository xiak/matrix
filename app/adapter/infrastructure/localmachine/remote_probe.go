package localmachine

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	paasv1 "matrix/api/paas/v1"
)

type RemoteHostProbe interface {
	Inspect(context.Context, MachineBinding) (HostFacts, error)
}

type RemoteProbeID string

const (
	RemoteProbeMachineID RemoteProbeID = "machine-id"
	RemoteProbeOS        RemoteProbeID = "operating-system"
	RemoteProbeArch      RemoteProbeID = "architecture"
	RemoteProbeCPU       RemoteProbeID = "logical-cpus"
	RemoteProbeMemory    RemoteProbeID = "memory"
	RemoteProbeStorage   RemoteProbeID = "storage"
	RemoteProbeDocker    RemoteProbeID = "docker-engine"
	RemoteProbeCompose   RemoteProbeID = "compose-plugin"
)

var remoteProbeSequence = []RemoteProbeID{
	RemoteProbeMachineID,
	RemoteProbeOS,
	RemoteProbeArch,
	RemoteProbeCPU,
	RemoteProbeMemory,
	RemoteProbeStorage,
	RemoteProbeDocker,
	RemoteProbeCompose,
}

var remoteMachineIDPattern = regexp.MustCompile(`^[A-Fa-f0-9]{32}$`)

type remoteProbeResult struct {
	output    []byte
	succeeded bool
}

type remoteProbeExecutor interface {
	Execute(
		context.Context,
		MachineBinding,
		SSHCredential,
		[]RemoteProbeID,
	) (map[RemoteProbeID]remoteProbeResult, error)
}

type SSHHostProbe struct {
	credentials SSHCredentialResolver
	executor    remoteProbeExecutor
}

func NewSSHHostProbe(credentials SSHCredentialResolver) (*SSHHostProbe, error) {
	return newSSHHostProbe(
		credentials,
		goSSHProbeExecutor{maxOutputBytes: 64 * 1024},
	)
}

func newSSHHostProbe(
	credentials SSHCredentialResolver,
	executor remoteProbeExecutor,
) (*SSHHostProbe, error) {
	if credentials == nil {
		return nil, errors.New("SSH credential resolver is required")
	}
	if executor == nil {
		return nil, errors.New("SSH probe executor is required")
	}
	return &SSHHostProbe{credentials: credentials, executor: executor}, nil
}

func (probe *SSHHostProbe) Inspect(
	ctx context.Context,
	binding MachineBinding,
) (HostFacts, error) {
	if err := ctx.Err(); err != nil {
		return HostFacts{}, contextProbeFailure(err, "ssh")
	}
	if err := ValidateMachineBinding(binding); err != nil || binding.kind != BindingSSH {
		return HostFacts{}, ProbeFailure{
			Kind: ProbeFailureValidation,
			ID:   "ssh-binding",
		}
	}
	credential, err := probe.credentials.ResolveSSHCredential(
		ctx,
		binding.credentialRef,
	)
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return HostFacts{}, ProbeFailure{Kind: ProbeFailureTimeout, ID: "ssh-credential"}
		case errors.Is(err, context.Canceled):
			return HostFacts{}, ProbeFailure{Kind: ProbeFailureUnavailable, ID: "ssh-credential"}
		default:
			return HostFacts{}, ProbeFailure{Kind: ProbeFailurePermission, ID: "ssh-credential"}
		}
	}
	if err := ValidateSSHCredential(credential); err != nil {
		return HostFacts{}, ProbeFailure{
			Kind: ProbeFailurePermission,
			ID:   "ssh-credential",
		}
	}
	results, err := probe.executor.Execute(
		ctx,
		binding,
		credential,
		remoteProbeSequence,
	)
	if err != nil {
		var failure ProbeFailure
		if errors.As(err, &failure) {
			return HostFacts{}, failure
		}
		return HostFacts{}, ProbeFailure{Kind: ProbeFailureInternal, ID: "ssh"}
	}
	facts, err := parseRemoteHostFacts(results)
	if err != nil {
		return HostFacts{}, ProbeFailure{
			Kind: ProbeFailureValidation,
			ID:   "ssh-output",
		}
	}
	return facts, nil
}

func parseRemoteHostFacts(
	results map[RemoteProbeID]remoteProbeResult,
) (HostFacts, error) {
	machineID, err := requiredRemoteText(results, RemoteProbeMachineID)
	if err != nil {
		return HostFacts{}, err
	}
	if !remoteMachineIDPattern.MatchString(machineID) {
		return HostFacts{}, errors.New("remote machine ID is invalid")
	}
	operatingSystem, err := requiredRemoteText(results, RemoteProbeOS)
	if err != nil {
		return HostFacts{}, err
	}
	if strings.ToLower(operatingSystem) != "linux" {
		return HostFacts{}, errors.New("remote operating system is not Linux")
	}
	architecture, err := requiredRemoteText(results, RemoteProbeArch)
	if err != nil {
		return HostFacts{}, err
	}
	switch strings.ToLower(architecture) {
	case "x86_64", "amd64":
		architecture = "amd64"
	case "aarch64", "arm64":
		architecture = "arm64"
	case "armv7l", "arm":
		architecture = "arm"
	default:
		return HostFacts{}, errors.New("remote architecture is unsupported")
	}
	cpuText, err := requiredRemoteText(results, RemoteProbeCPU)
	if err != nil {
		return HostFacts{}, err
	}
	logicalCPUs, err := strconv.ParseInt(cpuText, 10, 32)
	if err != nil || logicalCPUs <= 0 {
		return HostFacts{}, errors.New("remote logical CPU count is invalid")
	}
	memoryText, err := requiredRemoteText(results, RemoteProbeMemory)
	if err != nil {
		return HostFacts{}, err
	}
	memory, err := parseRemoteKiBPair(memoryText, "memory")
	if err != nil {
		return HostFacts{}, err
	}
	storageText, err := requiredRemoteText(results, RemoteProbeStorage)
	if err != nil {
		return HostFacts{}, err
	}
	storage, err := parseRemoteKiBPair(storageText, "storage")
	if err != nil {
		return HostFacts{}, err
	}
	facts := HostFacts{
		MachineID:             strings.ToLower(machineID),
		OperatingSystem:       "linux",
		Architecture:          architecture,
		LogicalCPUs:           int(logicalCPUs),
		MemoryTotalBytes:      memory[0],
		MemoryAvailableBytes:  memory[1],
		StorageTotalBytes:     storage[0],
		StorageAvailableBytes: storage[1],
		DockerEngineReady:     optionalRemoteSuccess(results, RemoteProbeDocker),
		ComposePluginReady:    optionalRemoteSuccess(results, RemoteProbeCompose),
	}
	if err := validateHostFacts(facts); err != nil {
		return HostFacts{}, err
	}
	return facts, nil
}

func requiredRemoteText(
	results map[RemoteProbeID]remoteProbeResult,
	id RemoteProbeID,
) (string, error) {
	result, found := results[id]
	if !found || !result.succeeded {
		return "", fmt.Errorf("required remote probe %s failed", id)
	}
	value := strings.TrimSpace(string(result.output))
	if err := paasv1.ValidateSafeExternalText(
		"remote probe "+string(id),
		value,
		4096,
		true,
	); err != nil {
		return "", err
	}
	return value, nil
}

func optionalRemoteSuccess(
	results map[RemoteProbeID]remoteProbeResult,
	id RemoteProbeID,
) bool {
	result, found := results[id]
	return found && result.succeeded
}

func parseRemoteKiBPair(value, name string) ([2]uint64, error) {
	fields := strings.Fields(value)
	if len(fields) != 2 {
		return [2]uint64{}, fmt.Errorf("remote %s capacity is invalid", name)
	}
	totalKiB, err := strconv.ParseUint(fields[0], 10, 64)
	maxKiB := uint64(math.MaxInt64) / 1024
	if err != nil || totalKiB == 0 || totalKiB > maxKiB {
		return [2]uint64{}, fmt.Errorf("remote %s total is invalid", name)
	}
	availableKiB, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil ||
		availableKiB > totalKiB ||
		availableKiB > maxKiB {
		return [2]uint64{}, fmt.Errorf("remote %s available capacity is invalid", name)
	}
	return [2]uint64{totalKiB * 1024, availableKiB * 1024}, nil
}

func remoteProbeCommand(id RemoteProbeID, storagePath string) (string, error) {
	switch id {
	case RemoteProbeMachineID:
		return "if test -s /etc/machine-id; then cat /etc/machine-id; " +
			"elif test -s /var/lib/dbus/machine-id; then cat /var/lib/dbus/machine-id; " +
			"else exit 40; fi", nil
	case RemoteProbeOS:
		return "uname -s", nil
	case RemoteProbeArch:
		return "uname -m", nil
	case RemoteProbeCPU:
		return "getconf _NPROCESSORS_ONLN", nil
	case RemoteProbeMemory:
		return "awk '/^MemTotal:/ { total=$2; have_total=1 } " +
			"/^MemAvailable:/ { available=$2; have_available=1 } " +
			"END { if (have_total && have_available && total > 0) " +
			"print total, available; else exit 41 }' " +
			"/proc/meminfo", nil
	case RemoteProbeStorage:
		if storagePath == "" {
			storagePath = "/"
		}
		if len(storagePath) > 4096 ||
			!posixAbsolutePathPattern.MatchString(storagePath) ||
			!strings.HasPrefix(storagePath, "/") {
			return "", errors.New("remote storage path is invalid")
		}
		return "df -Pk -- '" + storagePath +
			"' | awk 'NR == 2 { print $2, $4; found=1 } END { if (!found) exit 42 }'", nil
	case RemoteProbeDocker:
		return "docker info --format '{{.ServerVersion}}' >/dev/null 2>&1", nil
	case RemoteProbeCompose:
		return "docker compose version --short >/dev/null 2>&1", nil
	default:
		return "", fmt.Errorf("unknown remote probe identifier %q", id)
	}
}
