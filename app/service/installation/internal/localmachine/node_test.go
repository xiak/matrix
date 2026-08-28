package localmachine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

func TestNodeEffectsSealFilesAndKeepCollectorSeparateFromExecutor(t *testing.T) {
	plan := nodeEffectPlan(t)
	supervisor := &nodeSupervisorFixture{states: map[string]nativeState{}}
	effects := NewNodeEffects(nodeVerifierFixture{})
	effects.supervisor = supervisor
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseStaging, lifecycle.PhaseConfiguring, lifecycle.PhaseStarting, lifecycle.PhaseVerifying} {
		if err := effects.ApplyPhase(context.Background(), plan, phase); err != nil {
			t.Fatalf("node phase %s: %v", phase, err)
		}
	}
	services := nativeNodeServices(plan)
	collector, node := services[0], services[1]
	if !collector.policy.DynamicUser || node.policy.DynamicUser || collector.user == "root" || node.user != "root" || len(collector.writePaths) != 0 {
		t.Fatal("collector shares executor privileges")
	}
	if len(collector.runtimeDirectories) != 1 || len(node.runtimeDirectories) != 0 ||
		collector.policy.RuntimeDirectoryMode != 0o700 || collector.policy.RuntimeDirectoryPreserve != "no" {
		t.Fatal("collector temporary mounts are not bound to supervised cleanup")
	}
	for _, credential := range collector.credentials {
		if credential.Path == plan.Configuration.PrivateKeyFile || credential.Name == "node-key.pem" {
			t.Fatal("collector received executor key")
		}
	}
	for _, binding := range collector.binds {
		if binding.Source != filepath.Join(plan.Root, filepath.FromSlash(layout.CollectorExecutable)) {
			t.Fatal("collector received another host mount")
		}
	}
	emptyConfig, err := readManagedFile(plan.Root, filepath.FromSlash(layout.NodeDockerConfiguration), 16)
	if err != nil || strings.TrimSpace(string(emptyConfig)) != "{}" {
		t.Fatal("node inherited ambient Docker credentials")
	}
	expectedConfig := "DOCKER_CONFIG=" + filepath.Join(plan.Root, filepath.Dir(filepath.FromSlash(layout.NodeDockerConfiguration)))
	found := false
	for _, value := range node.environment {
		if value == expectedConfig {
			found = true
		}
	}
	if !found {
		t.Fatal("node does not use its empty installation-owned Docker configuration")
	}
	if err := effects.ApplyPhase(context.Background(), plan, lifecycle.PhaseStarting); err != nil || supervisor.starts != 2 {
		t.Fatal("repeated startup replaced running services")
	}
	if !supervisor.registered || supervisor.registrations != 1 {
		t.Fatal("replay lost or replaced the boot registration")
	}
	supervisor.registered = false
	if ready, err := effects.Observe(context.Background(), plan); err != nil || ready {
		t.Fatal("running processes without persistent boot registration were ready")
	}
	if err := effects.ApplyPhase(context.Background(), plan, lifecycle.PhaseStarting); err != nil || supervisor.starts != 2 {
		t.Fatal("repairing registration replaced healthy processes")
	}
	config, material, err := effects.ReadInstallation(plan.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	binding, err := nodecommand.Binding(config, material)
	if err != nil || binding != plan.Binding {
		t.Fatal("persisted enrollment differs from its commitment")
	}
	if err := os.WriteFile(config.PrivateKeyFile, []byte("substitution"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := effects.ApplyPhase(context.Background(), plan, lifecycle.PhaseStarting); err == nil || supervisor.starts != 2 {
		t.Fatal("substituted credential reached supervision")
	}
}

func TestNodeRollbackChecksAllServiceOwnershipAndRetainsState(t *testing.T) {
	plan := nodeEffectPlan(t)
	supervisor := &nodeSupervisorFixture{states: map[string]nativeState{}}
	effects := NewNodeEffects(nodeVerifierFixture{})
	effects.supervisor = supervisor
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseStaging, lifecycle.PhaseConfiguring, lifecycle.PhaseStarting} {
		if err := effects.ApplyPhase(context.Background(), plan, phase); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(plan.Configuration.StoragePath, "retained-receipt")
	if err := os.WriteFile(marker, []byte("accepted effect"), 0o600); err != nil {
		t.Fatal(err)
	}
	supervisor.foreign = nativeNodeServices(plan)[0].name
	if err := effects.Rollback(context.Background(), plan); !errors.Is(err, nodecommand.ErrConflict) || supervisor.stops != 0 {
		t.Fatal("rollback partially stopped services before proving ownership")
	}
	supervisor.foreign = ""
	supervisor.foreign = nativeNodeStartup(plan).service.name
	if err := effects.Rollback(context.Background(), plan); !errors.Is(err, nodecommand.ErrConflict) || supervisor.stops != 0 || !supervisor.registered {
		t.Fatal("foreign boot registration allowed partial rollback")
	}
	supervisor.foreign = ""
	if err := effects.Rollback(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if supervisor.stops != 2 || supervisor.registered {
		t.Fatal("rollback did not remove its registration and stop its two services")
	}
	if err := authenticateNodeFiles(plan); err != nil {
		t.Fatal("rollback removed enrollment or release files")
	}
	if content, err := os.ReadFile(marker); err != nil || string(content) != "accepted effect" {
		t.Fatal("rollback changed retained execution state")
	}
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseMigrating, lifecycle.PhaseBackingUp, lifecycle.PhaseLoadingImages, lifecycle.PhaseRecovering} {
		if err := effects.ApplyPhase(context.Background(), plan, phase); err == nil {
			t.Fatal("node accepted a platform phase")
		}
	}
}

func TestNodeStartupOwnershipAndRegistrationFailuresDoNotPartiallyStart(t *testing.T) {
	for _, mode := range []string{"collector", "node", "startup", "registration interrupted"} {
		t.Run(mode, func(t *testing.T) {
			plan := nodeEffectPlan(t)
			supervisor := &nodeSupervisorFixture{states: map[string]nativeState{}}
			effects := NewNodeEffects(nodeVerifierFixture{})
			effects.supervisor = supervisor
			for _, phase := range []lifecycle.Phase{lifecycle.PhaseStaging, lifecycle.PhaseConfiguring} {
				if err := effects.ApplyPhase(context.Background(), plan, phase); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "collector":
				supervisor.foreign = nativeNodeServices(plan)[0].name
			case "node":
				supervisor.foreign = nativeNodeServices(plan)[1].name
			case "startup":
				supervisor.foreign = nativeNodeStartup(plan).service.name
			case "registration interrupted":
				supervisor.registrationFailure = nodecommand.ErrOutcomeUnknown
			}
			if err := effects.ApplyPhase(context.Background(), plan, lifecycle.PhaseStarting); err == nil || supervisor.starts != 0 || supervisor.registrations != 0 {
				t.Fatal("ownership or registration failure partially started a node")
			}
		})
	}
}

func nodeEffectPlan(t *testing.T) nodecommand.Plan {
	t.Helper()
	fixture, err := releasetest.WriteNode(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	trustBytes, trust, err := release.ReadTrustRootFile(fixture.TrustPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := release.VerifyDirectory(fixture.Root, trustBytes)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := protectManagedPath(root, true); err != nil {
		t.Fatal(err)
	}
	config := nodeconfig.Configuration{APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.ConfigurationKind,
		Identity:     nodev1.Identity{InstallationID: "mxi-" + strings.Repeat("a", 32), ExecutionTargetID: "target-a"},
		ControllerID: "controller-a", BindingRef: "binding-a", ExpectedFingerprint: "sha256:" + strings.Repeat("a", 64),
		ListenAddress: "127.0.0.1:16443", CollectorEndpoint: "https://127.0.0.1:19100",
		StoragePath: filepath.Join(root, filepath.FromSlash(layout.ExecutorRoot)), CertificateFile: filepath.Join(root, filepath.FromSlash(layout.NodeCertificate)),
		PrivateKeyFile: filepath.Join(root, filepath.FromSlash(layout.NodePrivateKey)), TrustFile: filepath.Join(root, filepath.FromSlash(layout.NodeTrust))}
	material := nodecommand.Credentials{Certificate: []byte("test-node-certificate"), PrivateKey: []byte("test-node-key"), Trust: []byte("test-trust"),
		CollectorCertificate: []byte("test-collector-certificate"), CollectorPrivateKey: []byte("test-collector-key")}
	binding, err := nodecommand.Binding(config, material)
	if err != nil {
		t.Fatal(err)
	}
	return nodecommand.Plan{Root: root, Bundle: bundle, Trust: trust, TrustBytes: trustBytes, Configuration: config, Credentials: material, Binding: binding}
}

type nodeVerifierFixture struct{}

func (nodeVerifierFixture) Validate(nodeconfig.Configuration, nodecommand.Credentials) error {
	return nil
}
func (nodeVerifierFixture) Verify(context.Context, nodeconfig.Configuration, nodecommand.Credentials) error {
	return nil
}

type nodeSupervisorFixture struct {
	states              map[string]nativeState
	foreign             string
	starts, stops       int
	registered          bool
	registrations       int
	registrationFailure error
}

func (*nodeSupervisorFixture) Preflight(context.Context, uint64) error { return nil }
func (fixture *nodeSupervisorFixture) InspectStartup(_ context.Context, startup nativeStartup) (bool, error) {
	if fixture.foreign == startup.service.name {
		return false, nodecommand.ErrConflict
	}
	return fixture.registered, nil
}
func (fixture *nodeSupervisorFixture) RegisterStartup(ctx context.Context, startup nativeStartup) error {
	registered, err := fixture.InspectStartup(ctx, startup)
	if err != nil {
		return err
	}
	if fixture.registrationFailure != nil {
		return fixture.registrationFailure
	}
	if !registered {
		fixture.registered = true
		fixture.registrations++
	}
	return nil
}
func (fixture *nodeSupervisorFixture) UnregisterStartup(ctx context.Context, startup nativeStartup) error {
	if _, err := fixture.InspectStartup(ctx, startup); err != nil {
		return err
	}
	fixture.registered = false
	return nil
}
func (fixture *nodeSupervisorFixture) Inspect(_ context.Context, service nativeService) (nativeState, error) {
	if fixture.foreign == service.name {
		return "", nodecommand.ErrConflict
	}
	if state, found := fixture.states[service.name]; found {
		return state, nil
	}
	return nativeMissing, nil
}
func (fixture *nodeSupervisorFixture) Start(ctx context.Context, service nativeService) error {
	state, err := fixture.Inspect(ctx, service)
	if err != nil {
		return err
	}
	if state != nativeRunning {
		fixture.states[service.name] = nativeRunning
		fixture.starts++
	}
	return nil
}
func (fixture *nodeSupervisorFixture) Stop(ctx context.Context, service nativeService) error {
	state, err := fixture.Inspect(ctx, service)
	if err != nil {
		return err
	}
	if state != nativeMissing && state != nativeStopped {
		fixture.states[service.name] = nativeStopped
		fixture.stops++
	}
	return nil
}
