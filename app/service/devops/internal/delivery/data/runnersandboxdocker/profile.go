// Package runnersandboxdocker owns the closed Docker Engine boundary for the
// dedicated Matrix DevOps runner. It never accepts repository-provided image,
// command, environment, mount, network, or resource configuration.
package runnersandboxdocker

import (
	"bytes"
	"encoding/json"
	"errors"
	"path"
	"strconv"
	"strings"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

const (
	EngineAPIVersion         = "1.46"
	RuntimeName              = "runsc"
	ToolchainImage           = devopsv1.Go126OfflineToolchainLocalReference
	ToolchainSourceID        = devopsv1.Go126OfflineToolchainImageDigest
	ToolchainArchiveConfigID = devopsv1.Go126OfflineToolchainArchiveConfigDigest
	ToolchainLocalDigest     = devopsv1.Go126OfflineToolchainLocalDigestReference

	minimumLogicalCPUs  = 4
	minimumMemoryBytes  = 8 * 1024 * 1024 * 1024
	minimumStorageBytes = 20 * 1024 * 1024 * 1024

	workTmpfsBytes  = 512 * 1024 * 1024
	cacheTmpfsBytes = devopsv1.FixedWritableBytes - workTmpfsBytes
	// Docker persists ShmSize even when IpcMode disables the /dev/shm mount.
	// Pin the value so request and inspection do not depend on daemon defaults;
	// the isolation probe separately proves /dev/shm is not mounted or writable.
	fixedSharedMemoryBytes = 64 * 1024 * 1024
	containerUser          = "65532:65532"
	stepWorkingDir         = "/workspace/src"
	probeWorkingDir        = "/tmp"
	stepLogMaxSize         = "64m"
	stepLogMaxFiles        = "2"
)

var (
	ErrInvalid     = errors.New("runner sandbox input is invalid")
	ErrUnavailable = errors.New("runner sandbox engine is unavailable")
	ErrIneligible  = errors.New("runner sandbox host is ineligible")
	ErrUnsupported = errors.New("runner sandbox host operating system is unsupported")
)

type Reason string

const (
	ReasonDockerRelease Reason = "DOCKER_RELEASE"
	ReasonEngineAPI     Reason = "ENGINE_API"
	ReasonHostPlatform  Reason = "HOST_PLATFORM"
	ReasonRuntime       Reason = "RUNSC_RUNTIME"
	ReasonResources     Reason = "HOST_RESOURCES"
	ReasonStorage       Reason = "INSTALLATION_STORAGE"
	ReasonToolchain     Reason = "TOOLCHAIN_IMAGE"
	ReasonIsolation     Reason = "ISOLATION_PROBE"
)

// Report contains only closed readiness evidence. Native daemon configuration,
// paths, registry data, and probe/container identities do not cross this type.
type Report struct {
	Eligible         bool
	Reason           Reason
	DockerVersion    string
	EngineAPIVersion string
	LogicalCPUs      int
	MemoryBytes      int64
	StorageFreeBytes uint64
	ImageID          string
}

type ContainerPlan struct {
	name    string
	request containerCreateRequest
}

func (plan ContainerPlan) Name() string {
	return plan.name
}

func (plan ContainerPlan) MarshalJSON() ([]byte, error) {
	if validateContainerPlan(plan) != nil {
		return nil, ErrInvalid
	}
	content, err := json.Marshal(plan.request)
	if err != nil || len(content) == 0 || len(content) > maximumRequestBytes {
		return nil, ErrInvalid
	}
	return content, nil
}

func validateContainerPlan(plan ContainerPlan) error {
	if !validContainerName(plan.name) || validateContainerRequest(plan.request) != nil {
		return ErrInvalid
	}
	if validProbeName(plan.name) {
		if plan.request.WorkingDir != probeWorkingDir || !equalStringMap(
			plan.request.Labels,
			map[string]string{"com.xiak.matrix.devops.probe": "isolation-v1"},
		) {
			return ErrInvalid
		}
		return nil
	}
	ordinal := "1"
	if strings.HasSuffix(plan.name, "-step-2") {
		ordinal = "2"
	}
	effect := strings.TrimSuffix(plan.name, "-step-"+ordinal)
	if plan.request.Labels["com.xiak.matrix.devops.effect"] != effect ||
		plan.request.Labels["com.xiak.matrix.devops.step"] != ordinal {
		return ErrInvalid
	}
	return nil
}

func NewStepPlan(
	effectID string,
	step devopsv1.VerificationStep,
	sourceRoot string,
) (ContainerPlan, error) {
	if !validEffectID(effectID) || !validSourceRoot(sourceRoot) {
		return ContainerPlan{}, ErrInvalid
	}
	var command []string
	switch {
	case step.Ordinal == 1 && step.Kind == devopsv1.VerificationStepGoTest:
		command = []string{"go", "test", "-mod=vendor", "-count=1", "./..."}
	case step.Ordinal == 2 && step.Kind == devopsv1.VerificationStepGoVet:
		command = []string{"go", "vet", "-mod=vendor", "./..."}
	default:
		return ContainerPlan{}, ErrInvalid
	}
	request := fixedContainerRequest(command, stepWorkingDir)
	request.HostConfig.LogConfig = fixedStepLogConfig()
	request.Labels = map[string]string{
		"com.xiak.matrix.devops.effect": effectID,
		"com.xiak.matrix.devops.step":   strconv.FormatUint(uint64(step.Ordinal), 10),
	}
	request.HostConfig.Mounts = []mount{
		{
			Type:     "bind",
			Source:   sourceRoot,
			Target:   stepWorkingDir,
			ReadOnly: true,
			BindOptions: bindOptions{
				Propagation:  "rprivate",
				NonRecursive: true,
			},
		},
	}
	plan := ContainerPlan{
		name:    effectID + "-step-" + strconv.FormatUint(uint64(step.Ordinal), 10),
		request: request,
	}
	if validateContainerRequest(plan.request) != nil {
		return ContainerPlan{}, ErrInvalid
	}
	return plan, nil
}

func newProbePlan(name string) (ContainerPlan, error) {
	if !validProbeName(name) {
		return ContainerPlan{}, ErrInvalid
	}
	request := fixedContainerRequest(
		[]string{"/bin/sh", "-c", isolationProbeScript},
		probeWorkingDir,
	)
	request.Labels = map[string]string{
		"com.xiak.matrix.devops.probe": "isolation-v1",
	}
	plan := ContainerPlan{name: name, request: request}
	if validateContainerRequest(plan.request) != nil {
		return ContainerPlan{}, ErrInvalid
	}
	return plan, nil
}

const isolationProbeScript = `set -eu
test "$(id -u)" = "65532"
test "$(id -g)" = "65532"
test "$(awk '/^CapEff:/{print $2}' /proc/self/status)" = "0000000000000000"
test "$(awk '/^NoNewPrivs:/{print $2}' /proc/self/status)" = "1"
test -z "$(find /sys/class/net -mindepth 1 -maxdepth 1 ! -name lo -print -quit)"
test -z "$(awk 'NR > 1 && $2 != "00000000" {print; exit}' /proc/net/route)"
if touch /matrix-root-write-probe 2>/dev/null; then exit 1; fi
test ! -S /var/run/docker.sock
test ! -e /dev/kvm
test ! -e /dev/mem
test ! -e /dev/dri
test -z "$(awk '$2 == "/dev/shm" {print; exit}' /proc/mounts)"
if touch /dev/shm/matrix-shm-write-probe 2>/dev/null; then exit 1; fi
test -z "${HTTP_PROXY}${HTTPS_PROXY}${ALL_PROXY}${NO_PROXY}"
test -z "${http_proxy}${https_proxy}${all_proxy}${no_proxy}"
test -z "${AWS_ACCESS_KEY_ID}${AWS_SECRET_ACCESS_KEY}${AWS_SESSION_TOKEN}"
test -z "${GOOGLE_APPLICATION_CREDENTIALS}${AZURE_CLIENT_SECRET}"
test -z "${GITHUB_TOKEN}${CI_JOB_TOKEN}${SSH_AUTH_SOCK}"
`

type containerCreateRequest struct {
	Image           string            `json:"Image"`
	Cmd             []string          `json:"Cmd"`
	Entrypoint      []string          `json:"Entrypoint"`
	Env             []string          `json:"Env"`
	User            string            `json:"User"`
	WorkingDir      string            `json:"WorkingDir"`
	NetworkDisabled bool              `json:"NetworkDisabled"`
	AttachStdin     bool              `json:"AttachStdin"`
	AttachStdout    bool              `json:"AttachStdout"`
	AttachStderr    bool              `json:"AttachStderr"`
	OpenStdin       bool              `json:"OpenStdin"`
	StdinOnce       bool              `json:"StdinOnce"`
	Tty             bool              `json:"Tty"`
	Labels          map[string]string `json:"Labels"`
	HostConfig      hostConfig        `json:"HostConfig"`
}

type hostConfig struct {
	AutoRemove      bool                 `json:"AutoRemove"`
	Binds           []string             `json:"Binds"`
	CapAdd          []string             `json:"CapAdd"`
	CapDrop         []string             `json:"CapDrop"`
	CgroupnsMode    string               `json:"CgroupnsMode"`
	ContainerIDFile string               `json:"ContainerIDFile"`
	Devices         []deviceMapping      `json:"Devices"`
	DeviceRequests  []deviceRequest      `json:"DeviceRequests"`
	DNS             []string             `json:"Dns"`
	DNSOptions      []string             `json:"DnsOptions"`
	DNSSearch       []string             `json:"DnsSearch"`
	ExtraHosts      []string             `json:"ExtraHosts"`
	GroupAdd        []string             `json:"GroupAdd"`
	IpcMode         string               `json:"IpcMode"`
	Links           []string             `json:"Links"`
	LogConfig       logConfig            `json:"LogConfig"`
	Memory          int64                `json:"Memory"`
	MemorySwap      int64                `json:"MemorySwap"`
	Mounts          []mount              `json:"Mounts"`
	NanoCPUs        int64                `json:"NanoCpus"`
	NetworkMode     string               `json:"NetworkMode"`
	PidMode         string               `json:"PidMode"`
	PidsLimit       *int64               `json:"PidsLimit"`
	PortBindings    map[string][]binding `json:"PortBindings"`
	Privileged      bool                 `json:"Privileged"`
	PublishAllPorts bool                 `json:"PublishAllPorts"`
	ReadonlyRootfs  bool                 `json:"ReadonlyRootfs"`
	RestartPolicy   restartPolicy        `json:"RestartPolicy"`
	Runtime         string               `json:"Runtime"`
	SecurityOpt     []string             `json:"SecurityOpt"`
	ShmSize         int64                `json:"ShmSize"`
	StorageOpt      map[string]string    `json:"StorageOpt"`
	Sysctls         map[string]string    `json:"Sysctls"`
	Tmpfs           map[string]string    `json:"Tmpfs"`
	Ulimits         []ulimit             `json:"Ulimits"`
	UTSMode         string               `json:"UTSMode"`
	VolumesFrom     []string             `json:"VolumesFrom"`
}

type logConfig struct {
	Type   string            `json:"Type"`
	Config map[string]string `json:"Config"`
}

type restartPolicy struct {
	Name              string `json:"Name"`
	MaximumRetryCount int    `json:"MaximumRetryCount"`
}

type mount struct {
	Type        string      `json:"Type"`
	Source      string      `json:"Source"`
	Target      string      `json:"Target"`
	ReadOnly    bool        `json:"ReadOnly"`
	Consistency string      `json:"Consistency"`
	BindOptions bindOptions `json:"BindOptions"`
}

type bindOptions struct {
	Propagation  string `json:"Propagation"`
	NonRecursive bool   `json:"NonRecursive"`
}

type deviceMapping struct {
	PathOnHost        string `json:"PathOnHost"`
	PathInContainer   string `json:"PathInContainer"`
	CgroupPermissions string `json:"CgroupPermissions"`
}

type deviceRequest struct {
	Driver       string            `json:"Driver"`
	Count        int               `json:"Count"`
	DeviceIDs    []string          `json:"DeviceIDs"`
	Capabilities [][]string        `json:"Capabilities"`
	Options      map[string]string `json:"Options"`
}

type binding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type ulimit struct {
	Name string `json:"Name"`
	Soft int64  `json:"Soft"`
	Hard int64  `json:"Hard"`
}

func fixedContainerRequest(command []string, workingDirectory string) containerCreateRequest {
	processLimit := int64(devopsv1.FixedProcessLimit)
	return containerCreateRequest{
		Image:           ToolchainImage,
		Cmd:             append([]string(nil), command...),
		Entrypoint:      []string{},
		Env:             fixedEnvironment(),
		User:            containerUser,
		WorkingDir:      workingDirectory,
		NetworkDisabled: true,
		AttachStdin:     false,
		AttachStdout:    true,
		AttachStderr:    true,
		OpenStdin:       false,
		StdinOnce:       false,
		Tty:             false,
		HostConfig: hostConfig{
			AutoRemove:      false,
			Binds:           []string{},
			CapAdd:          []string{},
			CapDrop:         []string{"ALL"},
			CgroupnsMode:    "private",
			ContainerIDFile: "",
			Devices:         []deviceMapping{},
			DeviceRequests:  []deviceRequest{},
			DNS:             []string{},
			DNSOptions:      []string{},
			DNSSearch:       []string{},
			ExtraHosts:      []string{},
			GroupAdd:        []string{},
			IpcMode:         "none",
			Links:           []string{},
			LogConfig:       logConfig{Type: "none", Config: map[string]string{}},
			Memory:          devopsv1.FixedMemoryBytes,
			MemorySwap:      devopsv1.FixedMemoryBytes,
			Mounts:          []mount{},
			NanoCPUs:        devopsv1.FixedCPUMillis * 1_000_000,
			NetworkMode:     "none",
			PidMode:         "",
			PidsLimit:       &processLimit,
			PortBindings:    map[string][]binding{},
			Privileged:      false,
			PublishAllPorts: false,
			ReadonlyRootfs:  true,
			RestartPolicy:   restartPolicy{Name: "no", MaximumRetryCount: 0},
			Runtime:         RuntimeName,
			SecurityOpt:     []string{"no-new-privileges=true"},
			ShmSize:         fixedSharedMemoryBytes,
			StorageOpt:      map[string]string{},
			Sysctls:         map[string]string{},
			Tmpfs: map[string]string{
				"/cache": "rw,noexec,nosuid,nodev,size=" + strconv.FormatInt(cacheTmpfsBytes, 10) + ",mode=0700",
				"/tmp":   "rw,exec,nosuid,nodev,size=" + strconv.FormatInt(workTmpfsBytes, 10) + ",mode=1777",
			},
			Ulimits:     []ulimit{},
			UTSMode:     "",
			VolumesFrom: []string{},
		},
	}
}

func fixedEnvironment() []string {
	return []string{
		"ALL_PROXY=",
		"AWS_ACCESS_KEY_ID=",
		"AWS_SECRET_ACCESS_KEY=",
		"AWS_SESSION_TOKEN=",
		"AZURE_CLIENT_SECRET=",
		"CGO_ENABLED=0",
		"CI_JOB_TOKEN=",
		"GIT_ASKPASS=",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GITHUB_TOKEN=",
		"GOCACHE=/cache/build",
		"GOENV=off",
		"GOLANG_VERSION=1.26.8",
		"GOMODCACHE=/cache/mod",
		"GOOGLE_APPLICATION_CREDENTIALS=",
		"GOPATH=/cache/gopath",
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOTOOLCHAIN=local",
		"GOTMPDIR=/tmp",
		"HOME=/tmp",
		"HTTPS_PROXY=",
		"HTTP_PROXY=",
		"LANG=C",
		"LC_ALL=C",
		"NO_PROXY=",
		"PATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"SSH_AUTH_SOCK=",
		"TERM=dumb",
		"TZ=UTC",
		"all_proxy=",
		"http_proxy=",
		"https_proxy=",
		"no_proxy=",
	}
}

func validateContainerRequest(value containerCreateRequest) error {
	if value.Image != ToolchainImage || len(value.Cmd) == 0 || value.User != containerUser ||
		(value.WorkingDir != stepWorkingDir && value.WorkingDir != probeWorkingDir) ||
		!value.NetworkDisabled || value.AttachStdin || !value.AttachStdout ||
		!value.AttachStderr || value.OpenStdin || value.StdinOnce || value.Tty ||
		len(value.Entrypoint) != 0 || !equalStrings(value.Env, fixedEnvironment()) ||
		len(value.Labels) != 1 && len(value.Labels) != 2 {
		return ErrInvalid
	}
	host := value.HostConfig
	if host.AutoRemove || len(host.Binds) != 0 || len(host.CapAdd) != 0 ||
		!equalStrings(host.CapDrop, []string{"ALL"}) || host.CgroupnsMode != "private" ||
		host.ContainerIDFile != "" || len(host.Devices) != 0 || len(host.DeviceRequests) != 0 ||
		len(host.DNS) != 0 || len(host.DNSOptions) != 0 || len(host.DNSSearch) != 0 ||
		len(host.ExtraHosts) != 0 || len(host.GroupAdd) != 0 || host.IpcMode != "none" ||
		len(host.Links) != 0 ||
		host.Memory != devopsv1.FixedMemoryBytes || host.MemorySwap != devopsv1.FixedMemoryBytes ||
		host.NanoCPUs != devopsv1.FixedCPUMillis*1_000_000 || host.NetworkMode != "none" ||
		host.PidMode != "" || host.PidsLimit == nil || *host.PidsLimit != int64(devopsv1.FixedProcessLimit) ||
		len(host.PortBindings) != 0 || host.Privileged || host.PublishAllPorts ||
		!host.ReadonlyRootfs || host.RestartPolicy != (restartPolicy{Name: "no"}) ||
		host.Runtime != RuntimeName || !equalStrings(host.SecurityOpt, []string{"no-new-privileges=true"}) ||
		host.ShmSize != fixedSharedMemoryBytes || len(host.StorageOpt) != 0 || len(host.Sysctls) != 0 ||
		len(host.Ulimits) != 0 || host.UTSMode != "" || len(host.VolumesFrom) != 0 ||
		!equalTmpfs(host.Tmpfs) || (len(host.Mounts) != 0 && len(host.Mounts) != 1) {
		return ErrInvalid
	}
	if len(host.Mounts) == 1 {
		mounted := host.Mounts[0]
		if value.WorkingDir != stepWorkingDir || mounted.Type != "bind" ||
			!validSourceRoot(mounted.Source) || mounted.Target != stepWorkingDir ||
			!mounted.ReadOnly || mounted.Consistency != "" ||
			mounted.BindOptions != (bindOptions{Propagation: "rprivate", NonRecursive: true}) ||
			!equalLogConfig(host.LogConfig, fixedStepLogConfig()) {
			return ErrInvalid
		}
		ordinal := value.Labels["com.xiak.matrix.devops.step"]
		effect := value.Labels["com.xiak.matrix.devops.effect"]
		if len(value.Labels) != 2 || !validEffectID(effect) ||
			(ordinal == "1" && !equalStrings(value.Cmd, []string{"go", "test", "-mod=vendor", "-count=1", "./..."})) ||
			(ordinal == "2" && !equalStrings(value.Cmd, []string{"go", "vet", "-mod=vendor", "./..."})) ||
			(ordinal != "1" && ordinal != "2") {
			return ErrInvalid
		}
	} else if value.WorkingDir != probeWorkingDir ||
		!equalLogConfig(host.LogConfig, logConfig{Type: "none", Config: map[string]string{}}) ||
		!equalStrings(value.Cmd, []string{"/bin/sh", "-c", isolationProbeScript}) ||
		!equalStringMap(
			value.Labels,
			map[string]string{"com.xiak.matrix.devops.probe": "isolation-v1"},
		) {
		return ErrInvalid
	}
	return nil
}

func fixedStepLogConfig() logConfig {
	return logConfig{
		Type: "local",
		Config: map[string]string{
			"compress": "false",
			"max-file": stepLogMaxFiles,
			"max-size": stepLogMaxSize,
			"mode":     "blocking",
		},
	}
}

func equalLogConfig(left, right logConfig) bool {
	return left.Type == right.Type && equalStringMap(left.Config, right.Config)
}

func equalTmpfs(value map[string]string) bool {
	want := fixedContainerRequest([]string{"true"}, probeWorkingDir).HostConfig.Tmpfs
	if len(value) != len(want) {
		return false
	}
	for key, expected := range want {
		if value[key] != expected {
			return false
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
	return len(left) == len(right) && bytes.Equal(
		[]byte(strings.Join(left, "\x00")),
		[]byte(strings.Join(right, "\x00")),
	)
}

func validSourceRoot(value string) bool {
	return len(value) > 1 && len(value) <= 512 && strings.HasPrefix(value, "/") &&
		path.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n") &&
		!strings.HasPrefix(value+"/", "/proc/") &&
		!strings.HasPrefix(value+"/", "/sys/") &&
		!strings.HasPrefix(value+"/", "/dev/") &&
		!strings.HasPrefix(value+"/", "/run/") &&
		!strings.HasPrefix(value+"/", "/var/run/") &&
		!strings.HasPrefix(value+"/", "/var/lib/docker/")
}

func validEffectID(value string) bool {
	return len(value) == len("matrix-build-")+48 && strings.HasPrefix(value, "matrix-build-") &&
		lowerHex(strings.TrimPrefix(value, "matrix-build-"))
}

func validProbeName(value string) bool {
	return len(value) == len("matrix-runner-isolation-probe-")+16 &&
		strings.HasPrefix(value, "matrix-runner-isolation-probe-") &&
		lowerHex(strings.TrimPrefix(value, "matrix-runner-isolation-probe-"))
}

func validContainerName(value string) bool {
	return validProbeName(value) ||
		(strings.HasSuffix(value, "-step-1") && validEffectID(strings.TrimSuffix(value, "-step-1"))) ||
		(strings.HasSuffix(value, "-step-2") && validEffectID(strings.TrimSuffix(value, "-step-2")))
}

func lowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
