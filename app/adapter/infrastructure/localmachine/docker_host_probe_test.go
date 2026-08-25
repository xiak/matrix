package localmachine

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"
)

const dockerHostProbeIntegrationEnvironment = "MATRIX_LOCALMACHINE_DOCKER_HOST_TEST"

type dockerHostProbeStub struct {
	info       []byte
	infoErr    error
	composeErr error
}

func (stub dockerHostProbeStub) Run(_ context.Context, arguments ...string) ([]byte, error) {
	if len(arguments) > 0 && arguments[0] == "info" {
		if stub.infoErr != nil {
			return nil, stub.infoErr
		}
		return stub.info, nil
	}
	if stub.composeErr != nil {
		return nil, stub.composeErr
	}
	return []byte("2.40.0\n"), nil
}

func TestDockerHostProbePreservesDeadlineClassification(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Docker Engine host observation targets Linux")
	}
	probe := newDockerHostProbe(dockerHostProbeStub{infoErr: context.DeadlineExceeded})
	_, err := probe.Inspect(context.Background(), t.TempDir())
	var failure ProbeFailure
	if !errors.As(err, &failure) || failure.Kind != ProbeFailureTimeout ||
		failure.ID != "docker-engine" {
		t.Fatalf("Docker host deadline failure = %#v / %v", failure, err)
	}
}

func TestDockerHostProbeInspectsRealEngine(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv(dockerHostProbeIntegrationEnvironment) != "1" {
		t.Skip("enable the real Linux Docker Engine host probe explicitly")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	probe := NewDockerHostProbe()
	first, err := probe.Inspect(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("inspect real Docker Engine host: %v", err)
	}
	second, err := probe.Inspect(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("repeat real Docker Engine host inspection: %v", err)
	}
	if validateHostFacts(first) != nil || first.MachineID == "" ||
		first.MachineID != second.MachineID || first.OperatingSystem != "linux" ||
		first.Architecture != "amd64" || !first.DockerEngineReady ||
		!first.ComposePluginReady {
		t.Fatalf("real Docker Engine host facts = %#v / %#v", first, second)
	}
}

func TestDockerHostProbeUsesEngineIdentityAndHostStorage(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Docker Engine host observation targets Linux")
	}
	probe := newDockerHostProbe(dockerHostProbeStub{info: []byte(
		`{"ID":"ENGINE-A","NCPU":8,"MemTotal":17179869184,"OSType":"linux","Architecture":"x86_64"}`,
	)})
	facts, err := probe.Inspect(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("inspect Docker host: %v", err)
	}
	if facts.MachineID != "engine-a" || facts.OperatingSystem != "linux" ||
		facts.Architecture != "amd64" || facts.LogicalCPUs != 8 ||
		facts.MemoryAvailableBytes != facts.MemoryTotalBytes/2 ||
		facts.StorageTotalBytes == 0 || facts.StorageAvailableBytes == 0 ||
		!facts.DockerEngineReady || !facts.ComposePluginReady {
		t.Fatalf("Docker host facts = %#v", facts)
	}
}

func TestDockerHostProbeDegradesWithoutCompose(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Docker Engine host observation targets Linux")
	}
	probe := newDockerHostProbe(dockerHostProbeStub{
		info: []byte(
			`{"ID":"engine-a","NCPU":2,"MemTotal":4294967296,"OSType":"linux","Architecture":"amd64"}`,
		),
		composeErr: errors.New("unavailable"),
	})
	facts, err := probe.Inspect(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("inspect Docker host without Compose: %v", err)
	}
	if !facts.DockerEngineReady || facts.ComposePluginReady {
		t.Fatalf("Docker capability facts = %#v", facts)
	}
}
