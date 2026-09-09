package runnersandboxdocker

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

func TestStepPlansCloseEveryRepositoryControlledDockerField(t *testing.T) {
	effectID := "matrix-build-" + strings.Repeat("a", 48)
	tests := []struct {
		step        devopsv1.VerificationStep
		wantName    string
		wantCommand []string
	}{
		{
			step:        devopsv1.VerificationStep{Ordinal: 1, Kind: devopsv1.VerificationStepGoTest},
			wantName:    effectID + "-step-1",
			wantCommand: []string{"go", "test", "-mod=vendor", "-count=1", "./..."},
		},
		{
			step:        devopsv1.VerificationStep{Ordinal: 2, Kind: devopsv1.VerificationStepGoVet},
			wantName:    effectID + "-step-2",
			wantCommand: []string{"go", "vet", "-mod=vendor", "./..."},
		},
	}
	for _, test := range tests {
		t.Run(test.wantName, func(t *testing.T) {
			plan, err := NewStepPlan(effectID, test.step, "/var/lib/matrix/runner/work/source")
			if err != nil {
				t.Fatal(err)
			}
			if plan.Name() != test.wantName {
				t.Fatalf("name = %q", plan.Name())
			}
			first, err := plan.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			second, err := plan.MarshalJSON()
			if err != nil || !bytes.Equal(first, second) {
				t.Fatalf("plan is not deterministic: %v", err)
			}
			var request containerCreateRequest
			if err := json.Unmarshal(first, &request); err != nil {
				t.Fatal(err)
			}
			if !equalStrings(request.Cmd, test.wantCommand) ||
				request.Image != ToolchainImage || request.User != containerUser ||
				request.WorkingDir != stepWorkingDir || !request.NetworkDisabled ||
				request.HostConfig.Runtime != RuntimeName ||
				request.HostConfig.NetworkMode != "none" ||
				!request.HostConfig.ReadonlyRootfs || request.HostConfig.Privileged ||
				!equalStrings(request.HostConfig.CapDrop, []string{"ALL"}) ||
				!equalStrings(request.HostConfig.SecurityOpt, []string{"no-new-privileges=true"}) ||
				request.HostConfig.Memory != devopsv1.FixedMemoryBytes ||
				request.HostConfig.MemorySwap != devopsv1.FixedMemoryBytes ||
				request.HostConfig.NanoCPUs != devopsv1.FixedCPUMillis*1_000_000 ||
				request.HostConfig.PidsLimit == nil ||
				*request.HostConfig.PidsLimit != int64(devopsv1.FixedProcessLimit) ||
				request.HostConfig.IpcMode != "none" ||
				request.HostConfig.ShmSize != fixedSharedMemoryBytes ||
				!equalLogConfig(request.HostConfig.LogConfig, fixedStepLogConfig()) {
				t.Fatalf("unsafe fixed request: %#v", request)
			}
			if len(request.HostConfig.Mounts) != 1 {
				t.Fatalf("mounts = %#v", request.HostConfig.Mounts)
			}
			mounted := request.HostConfig.Mounts[0]
			if mounted.Source != "/var/lib/matrix/runner/work/source" ||
				mounted.Target != stepWorkingDir || !mounted.ReadOnly ||
				mounted.BindOptions.Propagation != "rprivate" ||
				!mounted.BindOptions.NonRecursive {
				t.Fatalf("source mount = %#v", mounted)
			}
			if workTmpfsBytes+cacheTmpfsBytes != devopsv1.FixedWritableBytes ||
				!equalTmpfs(request.HostConfig.Tmpfs) {
				t.Fatalf("tmpfs = %#v", request.HostConfig.Tmpfs)
			}
			environment, ok := environmentMap(request.Env)
			if !ok || environment["GOPROXY"] != "off" || environment["GOSUMDB"] != "off" ||
				environment["CGO_ENABLED"] != "0" || environment["GITHUB_TOKEN"] != "" ||
				environment["HTTP_PROXY"] != "" || environment["http_proxy"] != "" {
				t.Fatalf("environment = %#v", environment)
			}
		})
	}
}

func TestStepPlanRejectsOpenOrSensitiveInputs(t *testing.T) {
	effectID := "matrix-build-" + strings.Repeat("b", 48)
	validStep := devopsv1.VerificationStep{Ordinal: 1, Kind: devopsv1.VerificationStepGoTest}
	tests := []struct {
		name       string
		effectID   string
		step       devopsv1.VerificationStep
		sourceRoot string
	}{
		{name: "short effect", effectID: "matrix-build-a", step: validStep, sourceRoot: "/var/lib/matrix/source"},
		{name: "caller step", effectID: effectID, step: devopsv1.VerificationStep{Ordinal: 3, Kind: devopsv1.VerificationStepGoTest}, sourceRoot: "/var/lib/matrix/source"},
		{name: "relative source", effectID: effectID, step: validStep, sourceRoot: "source"},
		{name: "socket tree", effectID: effectID, step: validStep, sourceRoot: "/var/run/docker"},
		{name: "docker data", effectID: effectID, step: validStep, sourceRoot: "/var/lib/docker/overlay2"},
		{name: "non canonical", effectID: effectID, step: validStep, sourceRoot: "/var/lib/matrix/../source"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewStepPlan(test.effectID, test.step, test.sourceRoot); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestContainerPlanRevalidatesBeforeSerialization(t *testing.T) {
	effectID := "matrix-build-" + strings.Repeat("c", 48)
	plan, err := NewStepPlan(
		effectID,
		devopsv1.VerificationStep{Ordinal: 1, Kind: devopsv1.VerificationStepGoTest},
		"/var/lib/matrix/runner/work/source",
	)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*ContainerPlan){
		"command":            func(value *ContainerPlan) { value.request.Cmd = []string{"sh"} },
		"image":              func(value *ContainerPlan) { value.request.Image = "golang:latest" },
		"network":            func(value *ContainerPlan) { value.request.HostConfig.NetworkMode = "host" },
		"privileged":         func(value *ContainerPlan) { value.request.HostConfig.Privileged = true },
		"runtime":            func(value *ContainerPlan) { value.request.HostConfig.Runtime = "runc" },
		"shared memory":      func(value *ContainerPlan) { value.request.HostConfig.ShmSize = 0 },
		"logging":            func(value *ContainerPlan) { value.request.HostConfig.LogConfig.Type = "none" },
		"writeable source":   func(value *ContainerPlan) { value.request.HostConfig.Mounts[0].ReadOnly = false },
		"secret environment": func(value *ContainerPlan) { value.request.Env = append(value.request.Env, "TOKEN=value") },
		"identity": func(value *ContainerPlan) {
			value.request.Labels["com.xiak.matrix.devops.effect"] = "matrix-build-" + strings.Repeat("d", 48)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copy := plan
			copy.request.Cmd = append([]string(nil), plan.request.Cmd...)
			copy.request.Env = append([]string(nil), plan.request.Env...)
			copy.request.HostConfig.Mounts = append([]mount(nil), plan.request.HostConfig.Mounts...)
			copy.request.Labels = map[string]string{}
			for key, value := range plan.request.Labels {
				copy.request.Labels[key] = value
			}
			mutate(&copy)
			if _, err := copy.MarshalJSON(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestEngineAndDockerVersionsAreStrict(t *testing.T) {
	for _, value := range []string{"29.0.0", "29.6.2", "29.1.0-rc.1", "29.1.0+matrix"} {
		if !docker29(value) {
			t.Errorf("expected Docker version %q to pass", value)
		}
	}
	for _, value := range []string{"28.9.9", "30.0.0", "29", "29.1", "29..1", "029.1.1", "29.01.1", "29.1.1/evil"} {
		if docker29(value) {
			t.Errorf("expected Docker version %q to fail", value)
		}
	}
	if !supportsEngineAPI("1.40", "1.55", EngineAPIVersion) ||
		supportsEngineAPI("1.47", "1.55", EngineAPIVersion) ||
		supportsEngineAPI("1.40", "1.45", EngineAPIVersion) ||
		supportsEngineAPI("01.40", "1.55", EngineAPIVersion) {
		t.Fatal("Engine API compatibility check is not closed")
	}
}
