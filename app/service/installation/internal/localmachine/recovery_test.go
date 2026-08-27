package localmachine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
)

const recoveryProbeConfigHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestManagedRecoveryInventoryFailsClosedWithoutProviderDetails(t *testing.T) {
	root := t.TempDir()
	providerDetail := "provider-private-path-and-native-error"
	for _, test := range []struct {
		name    string
		inspect func(string) (string, error)
	}{
		{name: "missing inspector"},
		{name: "unavailable", inspect: func(string) (string, error) { return "", errors.New(providerDetail) }},
		{name: "invalid witness", inspect: func(string) (string, error) { return providerDetail, nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := readManagedServiceInventory(root, test.inspect)
			if value != "" || !errors.Is(err, platformcommand.ErrEffectUnavailable) || strings.Contains(err.Error(), providerDetail) {
				t.Fatalf("unproved inventory was admitted or exposed provider details: %v", err)
			}
		})
	}
	for _, matching := range []bool{false, true} {
		witness := "sha256:" + strings.Repeat("a", 64)
		actual := witness
		if !matching {
			actual = "sha256:" + strings.Repeat("b", 64)
		}
		err := requireManagedServiceInventory(root, witness, func(bindingRoot string) (string, error) {
			if bindingRoot != filepath.Join(root, filepath.FromSlash(layout.ExecutorRoot)) {
				t.Fatal("inventory inspection escaped its local worker binding")
			}
			return actual, nil
		})
		if (matching && err != nil) || (!matching && !errors.Is(err, platformcommand.ErrEffectPrecondition)) {
			t.Fatalf("inventory equality was not enforced: %v", err)
		}
	}
}

func TestRecoveryRemovesOnlyTheProvedFixedVerificationProjectAndReplays(t *testing.T) {
	plan := newInstallPlan(t)
	inspector := newRecoveryProbeInspector(t, plan)
	state := inspector.provision(t, 3)
	runtimeBoundary := newRecoveryProbeRuntime(t, plan, state)
	runtimeBoundary.downErr = errors.New("provider response was lost after cleanup")

	if err := removeRecoveredVerificationProject(
		context.Background(), runtimeBoundary, inspector, plan, plan,
	); err != nil {
		t.Fatalf("remove recovered verification project: %v", err)
	}
	if runtimeBoundary.present || runtimeBoundary.downCalls != 1 ||
		runtimeBoundary.unexpectedCalls != 0 {
		t.Fatalf(
			"verification cleanup provider state present=%t down=%d unexpected=%d",
			runtimeBoundary.present, runtimeBoundary.downCalls, runtimeBoundary.unexpectedCalls,
		)
	}
	if _, exists, err := inspector.InspectRecoveryProject(
		inspector.root, state.TenantID, state.DeploymentID,
	); err != nil || exists {
		t.Fatalf("verification project state remains after cleanup: exists=%t err=%v", exists, err)
	}
	if err := removeRecoveredVerificationProject(
		context.Background(), runtimeBoundary, inspector, plan, plan,
	); err != nil || runtimeBoundary.downCalls != 1 || runtimeBoundary.unexpectedCalls != 0 {
		t.Fatalf(
			"verification cleanup replay err=%v down=%d unexpected=%d",
			err, runtimeBoundary.downCalls, runtimeBoundary.unexpectedCalls,
		)
	}
}

func TestRecoveryRefusesUnprovedVerificationProjectBeforeDestructiveEffect(t *testing.T) {
	plan := newInstallPlan(t)
	inspector := newRecoveryProbeInspector(t, plan)
	state := inspector.provision(t, 3)
	runtimeBoundary := newRecoveryProbeRuntime(t, plan, state)
	runtimeBoundary.container.Config.Labels["com.xiak.matrix.deployment-id"] = "foreign-deployment"

	err := removeRecoveredVerificationProject(
		context.Background(), runtimeBoundary, inspector, plan, plan,
	)
	if !errors.Is(err, platformcommand.ErrEffectConflict) ||
		!runtimeBoundary.present || runtimeBoundary.downCalls != 0 ||
		runtimeBoundary.unexpectedCalls != 0 {
		t.Fatalf(
			"unproved verification cleanup err=%v present=%t down=%d unexpected=%d",
			err, runtimeBoundary.present, runtimeBoundary.downCalls, runtimeBoundary.unexpectedCalls,
		)
	}
}

func TestRecoveryRefusesUnboundedVerificationProjectBeforeProviderAccess(t *testing.T) {
	plan := newInstallPlan(t)
	inspector := newRecoveryProbeInspector(t, plan)
	state := inspector.provision(t, 3)
	runtimeBoundary := newRecoveryProbeRuntime(t, plan, state)
	inspector.state.Directory = plan.Root

	err := removeRecoveredVerificationProject(
		context.Background(), runtimeBoundary, inspector, plan, plan,
	)
	if !errors.Is(err, platformcommand.ErrEffectConflict) ||
		runtimeBoundary.downCalls != 0 || runtimeBoundary.unexpectedCalls != 0 {
		t.Fatalf(
			"unbounded verification project err=%v down=%d unexpected=%d",
			err, runtimeBoundary.downCalls, runtimeBoundary.unexpectedCalls,
		)
	}
}

func TestRecoveredVerificationRequiresExactProviderGenerationAndReadiness(t *testing.T) {
	plan := newInstallPlan(t)
	inspector := newRecoveryProbeInspector(t, plan)
	state := inspector.provision(t, 4)
	runtimeBoundary := newRecoveryProbeRuntime(t, plan, state)
	// Application Compose treats a running container with no healthcheck as
	// ready; recovery must use the same provider contract.
	runtimeBoundary.container.State.Health = nil
	verification := paasv1.InstallationVerification{
		DeploymentID: state.DeploymentID, Generation: state.Generation,
	}
	if err := verifyRecoveredVerificationProject(
		context.Background(), runtimeBoundary, inspector, plan, verification,
	); err != nil {
		t.Fatalf("verify recovered provider generation: %v", err)
	}
	verification.Generation--
	if err := verifyRecoveredVerificationProject(
		context.Background(), runtimeBoundary, inspector, plan, verification,
	); !errors.Is(err, platformcommand.ErrEffectVerification) {
		t.Fatalf("stale recovered provider generation error=%v", err)
	}
	verification.Generation = state.Generation
	runtimeBoundary.container.State.Health = &struct {
		Status string `json:"Status"`
	}{Status: "unhealthy"}
	if err := verifyRecoveredVerificationProject(
		context.Background(), runtimeBoundary, inspector, plan, verification,
	); !errors.Is(err, platformcommand.ErrEffectVerification) {
		t.Fatalf("unhealthy recovered provider generation error=%v", err)
	}
}

type recoveryProbeInspector struct {
	installationRoot string
	root             string
	state            RecoveryProjectState
}

func newRecoveryProbeInspector(
	t *testing.T,
	plan platformcommand.InstallPlan,
) *recoveryProbeInspector {
	t.Helper()
	executorRoot, err := ensureManagedDirectory(
		plan.Root, filepath.FromSlash(layout.ExecutorRoot),
	)
	if err != nil {
		t.Fatalf("prepare recovery probe executor root: %v", err)
	}
	boundary := recoveryProbeComposeBoundary{}
	if _, err := composeadapter.New(composeadapter.Config{
		BindingRef: "compose-recovery-test", BindingRoot: executorRoot,
		Artifacts: boundary, Secrets: boundary, Runtime: boundary,
	}); err != nil {
		t.Fatalf("protect recovery probe executor root: %v", err)
	}
	deploymentID, err := paasv1.InstallationVerificationDeploymentID(plan.InstallationID)
	if err != nil {
		t.Fatalf("derive recovery probe Deployment identity: %v", err)
	}
	adapterState, exists, err := composeadapter.InspectRunningProjectState(
		executorRoot, recoveryVerificationTenantID, deploymentID,
	)
	if err != nil || exists {
		t.Fatalf("prepare absent recovery probe state: exists=%t err=%v", exists, err)
	}
	state := RecoveryProjectState{
		ProjectName:         adapterState.ProjectName,
		Directory:           adapterState.Directory,
		EffectDocument:      adapterState.EffectDocument,
		ObservationDocument: adapterState.ObservationDocument,
		TenantID:            adapterState.TenantID,
		DeploymentID:        adapterState.DeploymentID,
	}
	state.ApplicationRevisionID = "installation-verification-app-rev-fixture"
	state.ContentDigest = "sha256:" + strings.Repeat("d", 64)
	state.Services = []RecoveryProjectService{{
		Name:     recoveryVerificationComponent,
		Image:    recoveryVerificationImage(t, plan.Bundle.Manifest).ImageID,
		Replicas: 1,
	}}
	return &recoveryProbeInspector{
		installationRoot: plan.Root, root: executorRoot, state: state,
	}
}

func (inspector *recoveryProbeInspector) provision(
	t *testing.T,
	generation uint64,
) RecoveryProjectState {
	t.Helper()
	inspector.state.Generation = generation
	relative := filepath.Join(
		filepath.FromSlash(layout.ExecutorRoot), "projects", inspector.state.ProjectName,
	)
	if _, err := ensureManagedDirectory(inspector.installationRoot, relative); err != nil {
		t.Fatalf("create recovery probe state directory: %v", err)
	}
	for _, target := range []string{inspector.state.EffectDocument, inspector.state.ObservationDocument} {
		path, err := filepath.Rel(inspector.installationRoot, target)
		if err != nil {
			t.Fatalf("resolve recovery probe state document: %v", err)
		}
		if err := writeManagedOnce(
			inspector.installationRoot, path, []byte(`{"services":{"probe":{}}}`),
		); err != nil {
			t.Fatalf("create recovery probe state document: %v", err)
		}
	}
	return inspector.state
}

type recoveryProbeComposeBoundary struct{}

func (recoveryProbeComposeBoundary) ResolveVerifiedImage(
	context.Context,
	paasv1.ArtifactRef,
) (composeadapter.VerifiedImage, error) {
	return composeadapter.VerifiedImage{}, errors.New("recovery test does not resolve an image")
}

func (recoveryProbeComposeBoundary) ResolveSecret(
	context.Context,
	paasv1.SecretVersionReference,
) ([]byte, error) {
	return nil, errors.New("recovery test does not resolve a Secret")
}

func (recoveryProbeComposeBoundary) Apply(context.Context, composeadapter.RuntimeProject) error {
	return errors.New("recovery test does not apply through the adapter")
}

func (recoveryProbeComposeBoundary) Observe(
	context.Context,
	composeadapter.RuntimeProject,
) ([]composeadapter.RuntimeContainer, error) {
	return nil, errors.New("recovery test does not observe through the adapter")
}

func (recoveryProbeComposeBoundary) Stop(context.Context, composeadapter.RuntimeProject) error {
	return errors.New("recovery test does not stop through the adapter")
}

func (inspector *recoveryProbeInspector) InspectRecoveryProject(
	root string,
	tenantID paasv1.TenantID,
	deploymentID paasv1.ResourceID,
) (RecoveryProjectState, bool, error) {
	if inspector == nil || root != inspector.root ||
		tenantID != inspector.state.TenantID || deploymentID != inspector.state.DeploymentID {
		return RecoveryProjectState{}, false, errors.New("unexpected recovery project inspection")
	}
	if _, err := os.Lstat(inspector.state.Directory); errors.Is(err, os.ErrNotExist) {
		return inspector.state, false, nil
	} else if err != nil {
		return RecoveryProjectState{}, false, err
	}
	return inspector.state, true, nil
}

func recoveryVerificationImage(t *testing.T, manifest release.Manifest) release.Image {
	t.Helper()
	for _, image := range manifest.Images {
		if image.Component == "verification" {
			return image
		}
	}
	t.Fatal("verification image is absent from release fixture")
	return release.Image{}
}

type recoveryProbeRuntime struct {
	state           RecoveryProjectState
	container       platformContainerInspection
	network         platformNetworkInspection
	present         bool
	downCalls       int
	downErr         error
	unexpectedCalls int
}

func newRecoveryProbeRuntime(
	t *testing.T,
	plan platformcommand.InstallPlan,
	state RecoveryProjectState,
) *recoveryProbeRuntime {
	t.Helper()
	image := recoveryVerificationImage(t, plan.Bundle.Manifest)
	labels := map[string]string{
		"com.docker.compose.project":              state.ProjectName,
		"com.docker.compose.service":              recoveryVerificationComponent,
		"com.docker.compose.oneoff":               "False",
		"com.docker.compose.container-number":     "1",
		"com.docker.compose.project.config_files": state.EffectDocument,
		"com.docker.compose.project.working_dir":  state.Directory,
		"com.docker.compose.config-hash":          recoveryProbeConfigHash,
		"com.xiak.matrix.application-revision-id": string(state.ApplicationRevisionID),
		"com.xiak.matrix.component":               recoveryVerificationComponent,
		"com.xiak.matrix.content-digest":          state.ContentDigest,
		"com.xiak.matrix.deployment-id":           string(state.DeploymentID),
		"com.xiak.matrix.generation":              fmt.Sprintf("%d", state.Generation),
		"com.xiak.matrix.tenant-id":               string(state.TenantID),
	}
	for key, value := range release.BuiltImageLabels(plan.Bundle.Manifest.Release, "verification") {
		if key != release.BuiltImageLabelComponent {
			labels[key] = value
		}
	}
	networkName := state.ProjectName + "_default"
	container := platformContainerInspection{
		ID: "container-recovery-probe", Name: "/" + state.ProjectName + "-probe-1",
		Image: image.ImageID,
		Config: platformContainerConfig{
			Labels: labels,
			Env: []string{
				"PATH=/usr/local/bin:/usr/bin:/bin",
				"MATRIX_INSTALLATION_ID=" + plan.InstallationID,
				"MATRIX_RELEASE_ID=" + plan.Bundle.Manifest.Release.ID,
			},
		},
		HostConfig: platformHostConfig{
			NetworkMode: networkName, NanoCPUs: 50 * 1_000_000,
			Memory: 64 * 1024 * 1024,
		},
		State: platformContainerState{Status: "running", Running: true},
	}
	container.State.Health = &struct {
		Status string `json:"Status"`
	}{Status: "healthy"}
	container.NetworkSettings.Networks = map[string]struct {
		NetworkID string `json:"NetworkID"`
	}{networkName: {NetworkID: "network-recovery-probe"}}
	return &recoveryProbeRuntime{
		state: state, container: container,
		network: platformNetworkInspection{
			ID: "network-recovery-probe", Name: networkName,
			Labels: map[string]string{
				"com.docker.compose.project": state.ProjectName,
				"com.docker.compose.network": "default",
			},
		},
		present: true,
	}
}

func (runtimeBoundary *recoveryProbeRuntime) handles(arguments []string) bool {
	if runtimeBoundary == nil {
		return false
	}
	for index, argument := range arguments {
		if argument == runtimeBoundary.container.ID || argument == runtimeBoundary.network.ID ||
			argument == "label=com.docker.compose.project="+runtimeBoundary.state.ProjectName {
			return true
		}
		if (argument == "--project-name" || argument == "--file" ||
			argument == "--project-directory") && index+1 < len(arguments) {
			next := arguments[index+1]
			if next == runtimeBoundary.state.ProjectName || next == runtimeBoundary.state.EffectDocument ||
				next == runtimeBoundary.state.ObservationDocument || next == runtimeBoundary.state.Directory {
				return true
			}
		}
	}
	return false
}

func (runtimeBoundary *recoveryProbeRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	if input != nil {
		runtimeBoundary.unexpectedCalls++
		return nil, false, errors.New("recovery probe Docker input is unexpected")
	}
	if len(arguments) >= 2 && arguments[1] == "ls" {
		if !hasArgumentPair(
			arguments, "--filter",
			"label=com.docker.compose.project="+runtimeBoundary.state.ProjectName,
		) {
			runtimeBoundary.unexpectedCalls++
			return nil, false, errors.New("recovery cleanup enumerated another project")
		}
		if !runtimeBoundary.present {
			return nil, true, nil
		}
		switch arguments[0] {
		case "container":
			return []byte(runtimeBoundary.container.ID + "\n"), true, nil
		case "network":
			return []byte(runtimeBoundary.network.ID + "\n"), true, nil
		case "volume":
			return nil, true, nil
		}
	}
	if len(arguments) >= 2 && arguments[1] == "inspect" {
		identity := arguments[len(arguments)-1]
		switch {
		case arguments[0] == "container" && identity == runtimeBoundary.container.ID:
			content, err := json.Marshal(runtimeBoundary.container)
			return content, true, err
		case arguments[0] == "network" && identity == runtimeBoundary.network.ID:
			content, err := json.Marshal(runtimeBoundary.network)
			return content, true, err
		}
	}
	if len(arguments) > 0 && arguments[0] == "compose" &&
		slices.Contains(arguments, "config") {
		if !hasArgumentPair(arguments, "--file", runtimeBoundary.state.EffectDocument) ||
			!hasArgumentPair(arguments, "--project-name", runtimeBoundary.state.ProjectName) {
			runtimeBoundary.unexpectedCalls++
			return nil, false, errors.New("recovery probe config hash used another project")
		}
		return []byte(recoveryVerificationComponent + " " + recoveryProbeConfigHash + "\n"), true, nil
	}
	if len(arguments) > 0 && arguments[0] == "compose" &&
		slices.Contains(arguments, "down") {
		if !hasArgumentPair(arguments, "--project-name", runtimeBoundary.state.ProjectName) ||
			!hasArgumentPair(arguments, "--project-directory", runtimeBoundary.state.Directory) ||
			!hasArgumentPair(arguments, "--file", runtimeBoundary.state.ObservationDocument) ||
			slices.Contains(arguments, "--volumes") {
			runtimeBoundary.unexpectedCalls++
			return nil, false, errors.New("recovery probe cleanup command is not bounded")
		}
		runtimeBoundary.downCalls++
		runtimeBoundary.present = false
		return nil, true, runtimeBoundary.downErr
	}
	runtimeBoundary.unexpectedCalls++
	return nil, false, fmt.Errorf("unexpected recovery probe Docker command: %q", strings.Join(arguments, " "))
}
