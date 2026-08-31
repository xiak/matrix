package localmachine

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	apphostingv1 "github.com/xiak/matrix/api/adapter/apphosting/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

func TestNodeControllerReplacementIsAtomicResumableAndAPIScoped(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("protected platform topology targets Linux")
	}
	installation, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformStartRuntime(installation, expectation)
	runtimeBoundary.started = true
	effects := &Effects{runtime: runtimeBoundary, validateController: func(nodeconfig.ControllerConfiguration) error { return nil }}
	installed := installedPlanFrom(installation)
	expected, err := effects.NodeConnectionsDigest(context.Background(), installed)
	if err != nil {
		t.Fatal(err)
	}
	configuration := nodeconfig.EmptyController(installation.InstallationID)
	configuration.Nodes = []nodeconfig.Connection{{BindingRef: "binding-a", TargetID: "target-a", Endpoint: "https://192.168.50.10:16443", IdentityFingerprint: "sha256:" + strings.Repeat("a", 64)}}
	configuration.Certificate, configuration.PrivateKey, configuration.Trust = []byte("cert"), []byte("private-controller-key"), []byte("trust")
	input, err := nodeconfig.EncodeController(configuration)
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	if os.Chmod(private, 0o700) != nil {
		t.Fatal("protect fixture input")
	}
	path := filepath.Join(private, "connections.json")
	if os.WriteFile(path, input, 0o600) != nil {
		t.Fatal("write fixture input")
	}
	credentials := snapshotManagedCredentials(t, installation.Root)
	before := readTestFile(t, installation.Root, layout.NodeControllerConfiguration)
	plan, err := effects.PrepareNodeConnections(context.Background(), installed, path, expected, nil)
	if err != nil {
		t.Fatal("prepare controller", err)
	}
	defer plan.Clear()
	plan.CommandID = "cmd-" + strings.Repeat("a", 32)
	if _, err := effects.PrepareNodeConnections(context.Background(), installed, path, "sha256:"+strings.Repeat("f", 64), nil); !errors.Is(err, platformcommand.ErrEffectConflict) {
		t.Fatal("wrong expected configuration admitted")
	}
	if runtimeBoundary.composeCalls != 0 || !bytes.Equal(before, readTestFile(t, installation.Root, layout.NodeControllerConfiguration)) {
		t.Fatal("preparation changed runtime or configuration")
	}
	if err := effects.ApplyNodeConnectionsPhase(context.Background(), plan, lifecycle.PhaseStaging); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readTestFile(t, installation.Root, layout.NodeControllerConfiguration)) {
		t.Fatal("staging published live credentials")
	}
	pending := &lifecycle.Execution{Command: lifecycle.Command{ID: plan.CommandID, Action: lifecycle.ActionConfigureNodes, InputDigest: plan.InputDigest, ExpectedConfigurationDigest: expected}, Phase: lifecycle.PhaseConfiguring}
	if os.Remove(path) != nil {
		t.Fatal("remove original input")
	}
	resumed, err := effects.PrepareNodeConnections(context.Background(), installed, "", "", pending)
	if err != nil || !bytes.Equal(resumed.After, plan.After) {
		t.Fatal("no-input resume changed the private intent")
	}
	defer resumed.Clear()
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseConfiguring, lifecycle.PhaseConfiguring, lifecycle.PhaseStarting, lifecycle.PhaseVerifying, lifecycle.PhaseCommitting, lifecycle.PhaseCommitting} {
		if err := effects.ApplyNodeConnectionsPhase(context.Background(), resumed, phase); err != nil {
			t.Fatalf("controller phase %s failed: %v", phase, err)
		}
	}
	args := runtimeBoundary.composeArguments
	if runtimeBoundary.composeCalls != 1 || args[len(args)-1] != "paas-api" || !slices.Contains(args, "--no-deps") || !slices.Contains(args, "--force-recreate") || !hasArgumentPair(args, "--pull", "never") || len(runtimeBoundary.migrationRuns) != 0 {
		t.Fatal("connection replacement changed more than the API")
	}
	if !bytes.Equal(input, readTestFile(t, installation.Root, layout.NodeControllerConfiguration)) || !equalSnapshots(credentials, snapshotManagedCredentials(t, installation.Root)) {
		t.Fatal("connection replacement changed other credentials or lost input")
	}
	if exists, err := managedFileExists(installation.Root, filepath.FromSlash(layout.NodeControllerPending)); err != nil || exists {
		t.Fatal("committed replacement retained previous private keys")
	}
	pending.Phase = lifecycle.PhaseCommitting
	resumedAfterCleanup, err := effects.PrepareNodeConnections(context.Background(), installed, "", "", pending)
	defer resumedAfterCleanup.Clear()
	if err != nil || resumedAfterCleanup.InputDigest != plan.InputDigest || effects.ApplyNodeConnectionsPhase(context.Background(), resumedAfterCleanup, lifecycle.PhaseCommitting) != nil {
		t.Fatal("cleanup-before-journal crash cannot resume")
	}
	if runtimeBoundary.composeCalls != 1 {
		t.Fatal("cleanup replay restarted the API")
	}
}

func TestNodeControllerRejectsRebindingUntrustedCredentialsAndForeignRuntime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("protected platform topology targets Linux")
	}
	for _, mode := range []string{"wrong installation", "bad credential", "runtime drift", "remove binding", "rebind endpoint", "wrong pending intent", "foreign file"} {
		t.Run(mode, func(t *testing.T) {
			installation, expectation := configuredPlatformStartFixture(t)
			runtimeBoundary := newPlatformStartRuntime(installation, expectation)
			runtimeBoundary.started = true
			effects := &Effects{runtime: runtimeBoundary, validateController: func(nodeconfig.ControllerConfiguration) error { return nil }}
			installed := installedPlanFrom(installation)
			configuration := nodeconfig.EmptyController(installation.InstallationID)
			configuration.Nodes = []nodeconfig.Connection{{BindingRef: "binding-a", TargetID: "target-a", Endpoint: "https://192.168.50.10:16443", IdentityFingerprint: "sha256:" + strings.Repeat("a", 64)}}
			configuration.Certificate, configuration.PrivateKey, configuration.Trust = []byte("cert"), []byte("private-key"), []byte("trust")
			encoded, _ := nodeconfig.EncodeController(configuration)
			if err := replaceManagedExpected(installation.Root, filepath.FromSlash(layout.NodeControllerConfiguration), readTestFile(t, installation.Root, layout.NodeControllerConfiguration), encoded); err != nil {
				t.Fatal(err)
			}
			expected, _ := effects.NodeConnectionsDigest(context.Background(), installed)
			configuration.PrivateKey = []byte("new-private-key")
			switch mode {
			case "wrong installation":
				configuration.InstallationID = "other"
			case "bad credential":
				effects.validateController = func(nodeconfig.ControllerConfiguration) error { return errors.New("secret not for output") }
			case "runtime drift":
				runtimeBoundary.resourceDriftService = "paas-worker"
			case "remove binding":
				configuration.Nodes = []nodeconfig.Connection{}
				configuration.Certificate = nil
				configuration.PrivateKey = nil
				configuration.Trust = nil
			case "rebind endpoint":
				configuration.Nodes[0].Endpoint = "https://192.168.50.11:16443"
			}
			input, _ := nodeconfig.EncodeController(configuration)
			private := t.TempDir()
			_ = os.Chmod(private, 0o700)
			path := filepath.Join(private, "input.json")
			if os.WriteFile(path, input, 0o600) != nil {
				t.Fatal("write private input")
			}
			before := readTestFile(t, installation.Root, layout.NodeControllerConfiguration)
			plan, err := effects.PrepareNodeConnections(context.Background(), installed, path, expected, nil)
			defer plan.Clear()
			if mode == "wrong pending intent" || mode == "foreign file" {
				if err != nil {
					t.Fatal(err)
				}
				plan.CommandID = "cmd-" + strings.Repeat("b", 32)
				if err := effects.ApplyNodeConnectionsPhase(context.Background(), plan, lifecycle.PhaseStaging); err != nil {
					t.Fatal(err)
				}
				if mode == "wrong pending intent" {
					plan.CommandID = "cmd-" + strings.Repeat("c", 32)
				} else {
					if os.WriteFile(filepath.Join(installation.Root, filepath.FromSlash(layout.NodeControllerConfiguration)), []byte("foreign"), 0o600) != nil {
						t.Fatal("write foreign configuration")
					}
					before = []byte("foreign")
				}
				err = effects.ApplyNodeConnectionsPhase(context.Background(), plan, lifecycle.PhaseConfiguring)
			}
			if err == nil || strings.Contains(err.Error(), "secret") || runtimeBoundary.composeCalls != 0 || !bytes.Equal(before, readTestFile(t, installation.Root, layout.NodeControllerConfiguration)) {
				t.Fatal("rejected controller input changed state, started a provider or exposed details")
			}
		})
	}
}

func TestCredentialRecoveryReadsOnlyBoundedPrivateRegularInput(t *testing.T) {
	const source = `{"apiVersion":"installation.matrix.xiak.com/v1","kind":"PlatformCredentialRecoveryInput","commandId":"cmd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password":"temporary-Recovery1!"}`
	for _, mode := range []string{"valid", "relative", "missing", "directory", "too large", "empty", "unknown field", "file link", "parent link", "public file", "public parent", "foreign owner"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			private := filepath.Join(root, "private")
			if os.Mkdir(private, 0o700) != nil {
				t.Fatal("create private input fixture")
			}
			original := filepath.Join(private, "recovery.json")
			if os.WriteFile(original, []byte(source), 0o600) != nil {
				t.Fatal("create private recovery fixture")
			}
			path := original
			switch mode {
			case "relative":
				path = "recovery.json"
			case "missing":
				path = filepath.Join(private, "absent.json")
			case "directory":
				path = private
			case "too large":
				if os.WriteFile(path, []byte(source+strings.Repeat(" ", platformcommand.MaximumCredentialRecoveryInputBytes)), 0o600) != nil {
					t.Fatal("write bounded-input fixture")
				}
			case "empty":
				if os.WriteFile(path, nil, 0o600) != nil {
					t.Fatal("write empty-input fixture")
				}
			case "unknown field":
				if os.WriteFile(path, []byte(strings.Replace(source, `"password":`, `"principalId":"foreign","password":`, 1)), 0o600) != nil {
					t.Fatal("write closed-input fixture")
				}
			case "file link":
				path = filepath.Join(private, "link.json")
				if err := os.Symlink(original, path); err != nil {
					t.Skip("host cannot create a symlink fixture")
				}
			case "parent link":
				linked := filepath.Join(root, "linked")
				if err := os.Symlink(private, linked); err != nil {
					t.Skip("host cannot create a symlink fixture")
				}
				path = filepath.Join(linked, "recovery.json")
			case "public file", "public parent":
				if runtime.GOOS == "windows" {
					t.Skip("POSIX ownership is enforced by the Linux installation boundary")
				}
				target, permissions := path, os.FileMode(0o644)
				if mode == "public parent" {
					target, permissions = private, 0o755
				}
				if os.Chmod(target, permissions) != nil {
					t.Fatal("change input fixture permissions")
				}
			case "foreign owner":
				if runtime.GOOS == "windows" || os.Geteuid() != 0 {
					t.Skip("foreign-owner fixture needs a disposable Linux root process")
				}
				if err := os.Chown(path, 65534, 65534); err != nil {
					t.Skip("fixture process cannot change its temporary file owner")
				}
			}
			input, err := readCredentialRecoveryInput(path)
			if mode == "valid" {
				retained, readErr := os.ReadFile(original)
				if err != nil || readErr != nil || !bytes.Equal(retained, []byte(source)) ||
					input.CommandID != "cmd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || !input.Password.Present() {
					t.Fatal("valid private input was rejected or modified")
				}
				return
			}
			if !errors.Is(err, platformcommand.ErrEffectVerification) || input.Password.Present() ||
				strings.Contains(err.Error(), "temporary-Recovery") || strings.Contains(err.Error(), root) {
				t.Fatal("unsafe recovery input was accepted or leaked")
			}
		})
	}
}

func TestLocalRecoveryInvocationUsesOwnedProcessOutcomeAndNeverKillsPendingWork(t *testing.T) {
	for _, scenario := range []struct {
		name, mode, existingState  string
		exitCode, existingExitCode int
		attachErr                  bool
		want                       error
		wantStarts, wantRemoves    int
	}{
		{name: "apply success", mode: "apply", wantStarts: 1},
		{name: "inspect success is temporary", mode: "inspect", wantStarts: 1, wantRemoves: 1},
		{name: "invalid", mode: "apply", exitCode: 2, want: platformcommand.ErrCredentialRecoveryInvalid, wantStarts: 1},
		{name: "forbidden", mode: "apply", exitCode: 3, want: platformcommand.ErrCredentialRecoveryForbidden, wantStarts: 1},
		{name: "conflict", mode: "apply", exitCode: 4, want: platformcommand.ErrCredentialRecoveryConflict, wantStarts: 1},
		{name: "unavailable is unknown", mode: "apply", exitCode: 6, want: platformcommand.ErrEffectOutcomeUnknown, wantStarts: 1},
		{name: "unknown exit", mode: "apply", exitCode: 42, want: platformcommand.ErrEffectOutcomeUnknown, wantStarts: 1},
		{name: "committed but attach lost", mode: "apply", attachErr: true, want: platformcommand.ErrEffectOutcomeUnknown, wantStarts: 1},
		{name: "resume created invocation", mode: "apply", existingState: "created", wantStarts: 1},
		{name: "prior invocation still running", mode: "apply", existingState: "running", want: platformcommand.ErrEffectOutcomeUnknown},
		{name: "never rerun known completion", mode: "apply", existingState: "exited", want: platformcommand.ErrEffectOutcomeUnknown},
		{name: "retain prior rejection", mode: "apply", existingState: "exited", existingExitCode: 3, want: platformcommand.ErrCredentialRecoveryForbidden},
		{name: "retry same unavailable invocation", mode: "apply", existingState: "exited", existingExitCode: 6, wantStarts: 1, wantRemoves: 1},
		{name: "no cached inspect answer", mode: "inspect", existingState: "exited", wantStarts: 1, wantRemoves: 2},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			expected, actual := localRecoveryInvocationFixture(scenario.mode)
			runtimeBoundary := &localRecoveryInvocationRuntime{container: actual, exitCode: scenario.exitCode, attachErr: scenario.attachErr}
			if scenario.existingState != "" {
				runtimeBoundary.present = true
				runtimeBoundary.container.State.Status = scenario.existingState
				runtimeBoundary.container.State.ExitCode = scenario.existingExitCode
				runtimeBoundary.container.State.Running = scenario.existingState == "running"
				if runtimeBoundary.container.State.Running {
					endpoint := runtimeBoundary.container.NetworkSettings.Networks[expected.networkName]
					endpoint.NetworkID = expected.networkID
					runtimeBoundary.container.NetworkSettings.Networks[expected.networkName] = endpoint
				}
			}
			output, err := invokeCredentialRecoveryEntry(context.Background(), runtimeBoundary, []string{"container", "create"}, expected)
			if !errors.Is(err, scenario.want) || runtimeBoundary.starts != scenario.wantStarts || runtimeBoundary.removes != scenario.wantRemoves {
				t.Fatalf("one-shot outcome=%v, starts=%d, removals=%d", err, runtimeBoundary.starts, runtimeBoundary.removes)
			}
			if err != nil && (len(output) != 0 || strings.Contains(err.Error(), "private-native-error")) {
				t.Fatal("unverified output or provider error escaped")
			}
		})
	}
}

func TestLocalRecoveryInvocationRejectsSubstitutedRuntimeAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*platformContainerInspection){
		"image":      func(v *platformContainerInspection) { v.Image = "sha256:" + strings.Repeat("f", 64) },
		"name":       func(v *platformContainerInspection) { v.Name = "/foreign" },
		"command":    func(v *platformContainerInspection) { v.Config.Labels["com.xiak.matrix.command"] = "cmd-foreign" },
		"entrypoint": func(v *platformContainerInspection) { v.Config.Entrypoint = []string{"/bin/sh"} },
		"mode":       func(v *platformContainerInspection) { v.Config.Cmd = []string{"other"} },
		"environment": func(v *platformContainerInspection) {
			v.Config.Env = append(v.Config.Env, "MATRIX_DATABASE_DSN=private")
		},
		"writable secret":  func(v *platformContainerInspection) { v.Mounts[0].RW = true },
		"different secret": func(v *platformContainerInspection) { v.Mounts[0].Source = "/other/credential" },
		"extra mount": func(v *platformContainerInspection) {
			v.Mounts = append(v.Mounts, platformProviderMount{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock", RW: true})
		},
		"privileged":          func(v *platformContainerInspection) { v.HostConfig.Privileged = true },
		"host PID":            func(v *platformContainerInspection) { v.HostConfig.PidMode = "host" },
		"host IPC":            func(v *platformContainerInspection) { v.HostConfig.IpcMode = "host" },
		"unbounded processes": func(v *platformContainerInspection) { v.HostConfig.PidsLimit = nil },
		"unbounded memory":    func(v *platformContainerInspection) { v.HostConfig.Memory = 0 },
		"other network":       func(v *platformContainerInspection) { v.HostConfig.NetworkMode = "host" },
		"unassigned foreign network": func(v *platformContainerInspection) {
			v.NetworkSettings.Networks["other"] = v.NetworkSettings.Networks["private"]
			delete(v.NetworkSettings.Networks, "private")
		},
		"additional network": func(v *platformContainerInspection) {
			v.NetworkSettings.Networks["other"] = v.NetworkSettings.Networks["private"]
		},
		"foreign endpoint": func(v *platformContainerInspection) {
			endpoint := v.NetworkSettings.Networks["private"]
			endpoint.NetworkID = "foreign-network"
			v.NetworkSettings.Networks["private"] = endpoint
		},
		"running without authenticated endpoint": func(v *platformContainerInspection) {
			v.State.Status, v.State.Running = "running", true
		},
		"extra capabilities": func(v *platformContainerInspection) { v.HostConfig.CapAdd = []string{"SYS_ADMIN"} },
		"persistent logging": func(v *platformContainerInspection) { v.HostConfig.LogConfig.Type = "json-file" },
	} {
		t.Run(name, func(t *testing.T) {
			expected, actual := localRecoveryInvocationFixture("apply")
			mutate(&actual)
			runtimeBoundary := &localRecoveryInvocationRuntime{container: actual, present: true}
			_, err := invokeCredentialRecoveryEntry(context.Background(), runtimeBoundary, []string{"container", "create"}, expected)
			if !errors.Is(err, platformcommand.ErrEffectConflict) || runtimeBoundary.starts != 0 || runtimeBoundary.removes != 0 {
				t.Fatal("substituted container was used or removed")
			}
		})
	}
}

func localRecoveryInvocationFixture(mode string) (credentialRecoveryContainerExpectation, platformContainerInspection) {
	expected := credentialRecoveryContainerExpectation{name: "mxi-local-iam-local-recovery-" + mode, mode: mode, networkID: "network-private", networkName: "private", environment: []string{"PATH=/usr/bin", "MATRIX_IAM_LOCAL_RECOVERY_AUTHORITY_FILE=/run/private/authority"}}
	expected.service = platformExpectedService{Image: "sha256:" + strings.Repeat("a", 64), User: "0:0", ReadOnly: true, Restart: "no", Networks: []string{"control"},
		CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, Tmpfs: []string{"/tmp:rw,noexec,nosuid,size=64m"},
		Volumes: []platformMount{{Type: "bind", Source: "/root/private/authority", Target: "/run/private/authority", ReadOnly: true}},
		Labels:  map[string]string{"com.xiak.matrix.command": "cmd-" + strings.Repeat("a", 32)}}
	expected.service.Deploy.Resources.Limits.CPUs, expected.service.Deploy.Resources.Limits.Memory = "1", "256M"
	limit := int64(64)
	actual := platformContainerInspection{ID: strings.Repeat("b", 64), Name: "/" + expected.name, Image: expected.service.Image,
		Config: platformContainerConfig{User: "0:0", Labels: cloneTestLabels(expected.service.Labels), Env: slices.Clone(expected.environment), Entrypoint: []string{localRecoveryEntrypoint}, Cmd: []string{mode}},
		State:  platformContainerState{Status: "created"},
		HostConfig: platformHostConfig{ReadonlyRootfs: true, NetworkMode: expected.networkID, Memory: 256 * 1024 * 1024, MemorySwap: 256 * 1024 * 1024, NanoCPUs: 1_000_000_000,
			PidsLimit: &limit, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, Tmpfs: map[string]string{"/tmp": "rw,noexec,nosuid,size=64m"}, IpcMode: "private", CgroupnsMode: "private"},
		Mounts: []platformProviderMount{{Type: "bind", Source: "/root/private/authority", Destination: "/run/private/authority"}}}
	actual.HostConfig.RestartPolicy.Name = "no"
	actual.HostConfig.LogConfig.Type = "none"
	actual.NetworkSettings.Networks = map[string]struct {
		NetworkID string `json:"NetworkID"`
	}{"private": {}}
	return expected, actual
}

type localRecoveryInvocationRuntime struct {
	container       platformContainerInspection
	present         bool
	exitCode        int
	attachErr       bool
	starts, removes int
}

func (boundary *localRecoveryInvocationRuntime) Run(_ context.Context, input io.Reader, arguments ...string) ([]byte, bool, error) {
	if input != nil || len(arguments) < 2 || arguments[0] != "container" {
		return nil, false, errors.New("unexpected one-shot boundary")
	}
	switch arguments[1] {
	case "ls":
		if !boundary.present {
			return nil, true, nil
		}
		return []byte(boundary.container.ID), true, nil
	case "inspect":
		output, err := json.Marshal(boundary.container)
		return output, true, err
	case "create":
		boundary.present = true
		boundary.container.State = platformContainerState{Status: "created"}
		return []byte(boundary.container.ID), true, nil
	case "start":
		boundary.starts++
		boundary.container.State = platformContainerState{Status: "exited", ExitCode: boundary.exitCode}
		if boundary.attachErr {
			return nil, true, errors.New("private-native-error")
		}
		return []byte(`{"sanitized":true}`), true, nil
	case "rm":
		if len(arguments) != 3 || arguments[2] != boundary.container.ID || boundary.container.State.Running {
			return nil, false, errors.New("unsafe one-shot removal")
		}
		boundary.removes++
		boundary.present = false
		return nil, true, nil
	default:
		return nil, false, errors.New("unexpected one-shot action")
	}
}

func TestCredentialRecoveryCleanupAuthenticatesOnlyItsExactTemporaryFiles(t *testing.T) {
	for _, mode := range []string{"exact", "wrong query", "wrong request", "already cleaned"} {
		t.Run(mode, func(t *testing.T) {
			installed := newInstallPlan(t)
			if err := stageInstallation(installed, rand.Reader); err != nil {
				t.Fatal(err)
			}
			authority, err := readLocalCredentialRecoveryAuthority(installed.Root, installed.InstallationID)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := iamv1.NewSecret("Temporary-Recovery1!")
			if err != nil {
				t.Fatal(err)
			}
			request, err := iamv1.SignLocalCredentialRecoveryRequest(authority, iamv1.LocalCredentialRecoveryRequest{
				APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryRequest", Purpose: iamv1.LocalCredentialRecoveryPurpose,
				CommandID: "cmd-" + strings.Repeat("a", 32), Scope: authority.Scope, NewPassword: secret,
				Expected: iamv1.LocalCredentialRecoveryExpected{OrganizationResourceVersion: 1, PrincipalResourceVersion: 2, CredentialGeneration: 2, PlatformBindingID: "binding-original", PlatformBindingResourceVersion: 1}})
			if err != nil {
				t.Fatal(err)
			}
			commitment, err := iamv1.VerifyLocalCredentialRecoveryRequest(authority, request)
			if err != nil {
				t.Fatal(err)
			}
			plan := platformcommand.CredentialRecoveryPlan{InstalledPlan: installedPlanFrom(installed), CommandID: request.CommandID, InputCommitment: commitment, Request: &request}
			query := iamv1.LocalCredentialRecoveryReceiptQuery{APIVersion: iamv1.APIVersion, Kind: "LocalCredentialRecoveryReceiptQuery", CommandID: request.CommandID, InputCommitment: commitment}
			if mode == "wrong query" {
				query.CommandID = "cmd-" + strings.Repeat("c", 32)
			}
			encoded, err := iamv1.EncodeLocalCredentialRecoveryRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "wrong request" {
				encoded = bytes.Replace(encoded, []byte("Temporary-Recovery1!"), []byte("Forged-Password1!"), 1)
			}
			queryBytes, _ := json.Marshal(query)
			if mode != "already cleaned" {
				if writeManagedOnce(installed.Root, filepath.FromSlash(layout.IAMLocalRecoveryRequest), encoded) != nil || writeManagedOnce(installed.Root, filepath.FromSlash(layout.IAMLocalRecoveryQuery), queryBytes) != nil {
					t.Fatal("stage private cleanup fixture")
				}
			}
			before := snapshotManagedCredentials(t, installed.Root)
			cleanupErr := finalizeCredentialRecoveryFiles(plan, authority)
			if strings.HasPrefix(mode, "wrong") {
				if !errors.Is(cleanupErr, platformcommand.ErrEffectConflict) {
					t.Fatal("cleanup accepted a different intent")
				}
				if _, err := os.Stat(filepath.Join(installed.Root, filepath.FromSlash(layout.IAMLocalRecoveryRequest))); err != nil {
					t.Fatal("cleanup removed an unauthenticated request")
				}
			} else {
				if cleanupErr != nil || finalizeCredentialRecoveryFiles(plan, authority) != nil {
					t.Fatal("exact cleanup did not replay")
				}
				for _, relative := range []string{layout.IAMLocalRecoveryRequest, layout.IAMLocalRecoveryQuery} {
					if _, err := os.Lstat(filepath.Join(installed.Root, filepath.FromSlash(relative))); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("cleanup retained temporary material")
					}
				}
			}
			if !equalSnapshots(before, snapshotManagedCredentials(t, installed.Root)) {
				t.Fatal("cleanup changed persistent credentials or bootstrap")
			}
		})
	}
}

func TestProviderVersionComparisonAcceptsBoundedDistributionMetadata(t *testing.T) {
	for _, test := range []struct {
		actual, minimum string
		want            int
	}{
		{"2.33.0+ds1-0ubuntu1~22.04.1", "2.33.0", 0},
		{"27.5.1", "27.5.1", 0},
		{"2.32.9+ds1-0ubuntu1~22.04.1", "2.33.0", -1},
		{"2.33.1-vendor", "2.33.0", 1},
		{"2.33.0;ignored", "2.33.0", -1},
		{"2.33.0+" + strings.Repeat("a", 256), "2.33.0", -1},
	} {
		if got := compareProviderVersion(test.actual, test.minimum); got != test.want {
			t.Errorf("provider version %q comparison = %d, want %d", test.actual, got, test.want)
		}
	}
}

func TestStageAndConfigurePreserveCredentialsAndExposeOnlyWorkload(t *testing.T) {
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage installation: %v", err)
	}
	if runtime.GOOS != "windows" {
		postgresRoot, err := managedPath(plan.Root, layout.PostgresData)
		info, statErr := os.Lstat(postgresRoot)
		if err != nil || statErr != nil || info.Mode().Perm() != 0o711 {
			t.Fatalf("PostgreSQL bind root is not private and traversable: %v / %v", err, statErr)
		}
	}

	bootstrapBytes := readTestFile(t, plan.Root, layout.IAMBootstrap)
	bootstrap, err := iamv1.DecodeBootstrapDocument(bytes.NewReader(bootstrapBytes))
	if err != nil {
		t.Fatalf("decode staged IAM bootstrap: %v", err)
	}
	if bootstrap.InstallationID != plan.InstallationID ||
		len(bootstrap.Services) != len(iamv1.AllServicePurposes()) {
		t.Fatalf("staged IAM bootstrap identity = %#v", bootstrap)
	}
	localAuthority, err := readLocalCredentialRecoveryAuthority(plan.Root, plan.InstallationID)
	bootstrapDigest, digestErr := iamv1.BootstrapDigest(bootstrap)
	if err != nil || digestErr != nil || localAuthority.Scope != (iamv1.LocalCredentialRecoveryScope{
		InstallationID: bootstrap.InstallationID, BootstrapDigest: bootstrapDigest,
		OrganizationID: bootstrap.Organization.ID, PrincipalID: bootstrap.Administrator.ID,
	}) {
		t.Fatal("local recovery authority is not bound to the sealed original primary")
	}

	serviceCredentials := make(map[iamv1.ServicePurpose][]byte, len(bootstrap.Services))
	for _, service := range bootstrap.Services {
		serviceCredentials[service.Purpose] = service.Credential.CopyBytes()
	}
	defer func() {
		for purpose, credential := range serviceCredentials {
			clear(credential)
			delete(serviceCredentials, purpose)
		}
	}()
	serviceFiles := map[iamv1.ServicePurpose][]string{
		iamv1.ServiceIAM:                  {layout.IAMAuditCredential},
		iamv1.ServicePaaS:                 {layout.PaaSIAMCredential, layout.PaaSAuditCredential},
		iamv1.ServiceAudit:                {layout.AuditIAMCredential},
		iamv1.ServiceInstallationVerifier: {layout.InstallationVerifierCredential},
	}
	for purpose, paths := range serviceFiles {
		for _, path := range paths {
			if actual := readTestFile(t, plan.Root, path); !bytes.Equal(actual, serviceCredentials[purpose]) {
				t.Fatalf("service credential file %s differs from IAM bootstrap", path)
			}
		}
	}
	administrator := bootstrap.Administrator.Password.CopyBytes()
	defer clear(administrator)
	if actual := readTestFile(t, plan.Root, layout.InitialAdministratorPassword); !bytes.Equal(actual, administrator) {
		t.Fatal("initial administrator password file differs from IAM bootstrap")
	}

	for _, database := range []struct {
		path string
		role string
	}{
		{layout.PostgresMigration, "matrix"},
		{layout.IAMAPI, "matrix_iam_api_login"},
		{layout.IAMWorker, "matrix_iam_worker_login"},
		{layout.IAMCredentialRecovery, "matrix_iam_credential_recovery_login"},
		{layout.AuditRuntime, "matrix_audit_runtime_login"},
		{layout.PaaSAPI, "matrix_paas_api_login"},
		{layout.PaaSWorker, "matrix_paas_worker_login"},
	} {
		content := readTestFile(t, plan.Root, database.path)
		if err := validateDatabaseDSN(string(content), database.role); err != nil {
			t.Fatalf("validate staged database credential %s: %v", database.path, err)
		}
		clear(content)
	}

	before := snapshotManagedCredentials(t, plan.Root)
	if err := stageInstallation(plan, failingEntropy{}); err != nil {
		t.Fatalf("replay staged installation without new entropy: %v", err)
	}
	after := snapshotManagedCredentials(t, plan.Root)
	if !equalSnapshots(before, after) {
		t.Fatal("staging replay changed installation credentials")
	}

	compiled, err := topology.Compile(plan.Bundle.Manifest, topology.Options{
		InstallationID: plan.InstallationID,
		Root:           "/matrix-installation-root",
		Listener:       plan.Listener,
		Port:           plan.Port,
	})
	if err != nil {
		t.Fatalf("compile fixture topology: %v", err)
	}
	if err := publishInstallationConfiguration(plan.Root, plan.Bundle.Manifest, compiled); err != nil {
		t.Fatalf("publish installation configuration: %v", err)
	}
	catalogBytes := readTestFile(t, plan.Root, layout.ArtifactCatalog)
	catalog, err := apphostingv1.DecodeArtifactCatalog(catalogBytes)
	if err != nil {
		t.Fatalf("decode artifact catalog: %v", err)
	}
	var expected []apphostingv1.ArtifactCatalogEntry
	for _, image := range plan.Bundle.Manifest.Images {
		if image.Purpose == release.ImageWorkload {
			expected = append(expected, apphostingv1.ArtifactCatalogEntry{
				ArtifactDigest: image.SourceDigest,
				ImageID:        image.ImageID,
			})
		}
	}
	slices.SortFunc(expected, func(left, right apphostingv1.ArtifactCatalogEntry) int {
		return strings.Compare(left.ArtifactDigest, right.ArtifactDigest)
	})
	if !slices.Equal(catalog.Entries, expected) {
		t.Fatalf("workload catalog = %#v, want %#v", catalog.Entries, expected)
	}
	apisix := readTestFile(t, plan.Root, layout.APISIXRoutes)
	for _, required := range []string{
		"uri: /api/audit/v1/installation:verify",
		"uri: /api/paas/v1/installation:verify",
		"id: matrix-paas-terminal",
		"enable_websocket: true",
		"terminal-session-[0-9a-f]{32}/connect$",
		"read: 130",
		"uri: /api/managed-services/*",
		`- "/managed-services/$1"`,
		"priority: 100",
		"uri: /v1/installation:verify",
	} {
		if !bytes.Contains(apisix, []byte(required)) {
			t.Fatalf("APISIX configuration lacks fixed verifier route %q", required)
		}
	}
	terminalStart := bytes.Index(apisix, []byte("id: matrix-paas-terminal"))
	terminalEnd := bytes.Index(apisix, []byte("id: matrix-paas-installation-verification"))
	if terminalStart < 0 || terminalEnd <= terminalStart {
		t.Fatal("APISIX terminal WebSocket route is absent or unordered")
	}
	terminalRoute := apisix[terminalStart:terminalEnd]
	if bytes.Contains(terminalRoute, []byte("Authorization")) ||
		bytes.Contains(terminalRoute, []byte("Matrix-Subject-Credential")) {
		t.Fatal("terminal route must let the PaaS endpoint reject ambient authority")
	}
	if bytes.Contains(apisix, []byte("matrix-service-auth")) ||
		bytes.Contains(apisix, []byte("apisix-iam-credential")) {
		t.Fatal("APISIX must preserve user Bearer credentials for IAM and Audit")
	}
	readyStart := bytes.Index(apisix, []byte("id: matrix-ready"))
	readyEnd := bytes.Index(apisix, []byte("id: matrix-iam"))
	if readyStart < 0 || readyEnd <= readyStart {
		t.Fatal("APISIX readiness route is absent")
	}
	readyRoute := apisix[readyStart:readyEnd]
	if !bytes.Contains(readyRoute, []byte("serverless-pre-function")) ||
		!bytes.Contains(readyRoute, []byte("priority: 1000")) ||
		bytes.Contains(readyRoute, []byte("upstream:")) {
		t.Fatal("APISIX readiness route depends on a platform upstream")
	}
	mainConfig := readTestFile(t, plan.Root, layout.APISIXConfig)
	for _, required := range []string{
		"config_provider: yaml", "stream_plugins: []", "user: root",
		"client_body_temp_path /tmp/",
	} {
		if !bytes.Contains(mainConfig, []byte(required)) {
			t.Fatalf("APISIX main configuration lacks runtime boundary %q", required)
		}
	}
	if actual := string(readTestFile(t, plan.Root, layout.APISIXUID)); actual != compiled.ProjectName {
		t.Fatalf("APISIX instance identity = %q, want %q", actual, compiled.ProjectName)
	}
	nginxPath, err := managedPath(plan.Root, filepath.FromSlash(layout.APISIXNginx))
	if err != nil {
		t.Fatalf("resolve APISIX runtime file: %v", err)
	}
	providerContent := []byte("# generated by APISIX\n")
	if err := os.WriteFile(nginxPath, providerContent, 0o600); err != nil {
		t.Fatalf("simulate APISIX runtime write: %v", err)
	}
	if err := publishInstallationConfiguration(plan.Root, plan.Bundle.Manifest, compiled); err != nil {
		t.Fatalf("replay configuration with provider-owned runtime file: %v", err)
	}
	if actual := readTestFile(t, plan.Root, layout.APISIXNginx); !bytes.Equal(actual, providerContent) {
		t.Fatal("configuration replay replaced provider-owned APISIX runtime content")
	}

	publicConfiguration := bytes.Join([][]byte{
		readTestFile(t, plan.Root, layout.Compose),
		catalogBytes,
		apisix,
		mainConfig,
	}, nil)
	expectation, err := decodePlatformExpectation(compiled.ComposeJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range expectation.Services {
		for _, mount := range service.Volumes {
			if mount.Type != "bind" {
				continue
			}
			for _, private := range []string{layout.IAMCredentialRecovery, layout.IAMLocalRecoveryAuthority, layout.IAMLocalRecoveryRequest, layout.IAMLocalRecoveryQuery} {
				privatePath := "/matrix-installation-root/" + private
				if mount.Source == privatePath || strings.HasPrefix(privatePath, strings.TrimRight(mount.Source, "/")+"/") {
					t.Fatal("ordinary platform service mounted a local recovery capability or its parent")
				}
			}
		}
	}
	secrets := [][]byte{
		administrator,
		readTestFile(t, plan.Root, layout.PostgresPassword),
		readTestFile(t, plan.Root, layout.BackupSealKey),
		readTestFile(t, plan.Root, layout.IAMCredentialRecovery),
		localAuthority.CapabilityKey.CopyBytes(),
	}
	for _, credential := range serviceCredentials {
		secrets = append(secrets, credential)
	}
	for _, secret := range secrets {
		if len(secret) == 0 || bytes.Contains(publicConfiguration, secret) {
			t.Fatal("generated configuration contains credential material")
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(nginxPath, 0o644); err != nil {
			t.Fatalf("drift APISIX runtime permissions: %v", err)
		}
		if err := publishInstallationConfiguration(
			plan.Root, plan.Bundle.Manifest, compiled,
		); !errors.Is(err, platformcommand.ErrEffectConflict) {
			t.Fatalf("unsafe APISIX runtime replay error=%v", err)
		}
	}
}

func TestLocalRecoveryAuthorityCannotAdoptAnotherBootstrapOrTarget(t *testing.T) {
	for _, mode := range []string{"installation", "home organization", "original primary", "bootstrap bytes", "invalid key", "absent authority"} {
		t.Run(mode, func(t *testing.T) {
			plan := newInstallPlan(t)
			if err := stageInstallation(plan, rand.Reader); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(plan.Root, filepath.FromSlash(layout.IAMLocalRecoveryAuthority))
			content := readTestFile(t, plan.Root, layout.IAMLocalRecoveryAuthority)
			switch mode {
			case "installation":
				content = bytes.Replace(content, []byte(plan.InstallationID), []byte("mxi-ffffffffffffffffffffffffffffffff"), 1)
			case "home organization":
				content = bytes.Replace(content, []byte("organization-default"), []byte("organization-foreign"), 1)
			case "original primary":
				content = bytes.Replace(content, []byte("principal-admin"), []byte("principal-child"), 1)
			case "bootstrap bytes":
				bootstrapPath := filepath.Join(plan.Root, filepath.FromSlash(layout.IAMBootstrap))
				bootstrap := readTestFile(t, plan.Root, layout.IAMBootstrap)
				bootstrap = bytes.Replace(bootstrap, []byte("Matrix Administrator"), []byte("Changed Administrator"), 1)
				if os.WriteFile(bootstrapPath, bootstrap, 0o600) != nil {
					t.Fatal("write changed bootstrap fixture")
				}
			case "invalid key":
				content = bytes.Replace(content, []byte(`"capabilityKey":"`), []byte(`"capabilityKey":"invalid`), 1)
			case "absent authority":
				if os.Remove(path) != nil {
					t.Fatal("remove temporary authority fixture")
				}
				if _, err := readLocalCredentialRecoveryAuthority(plan.Root, plan.InstallationID); !errors.Is(err, platformcommand.ErrEffectVerification) {
					t.Fatal("recovery silently created a missing local capability")
				}
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("read-only recovery inspection changed authority state")
				}
				return
			}
			if os.WriteFile(path, content, 0o600) != nil {
				t.Fatal("write substituted authority fixture")
			}
			before := snapshotManagedCredentials(t, plan.Root)
			if _, err := readLocalCredentialRecoveryAuthority(plan.Root, plan.InstallationID); !errors.Is(err, platformcommand.ErrEffectVerification) {
				t.Fatal("recovery accepted substituted authority provenance")
			}
			if err := stageInstallation(plan, failingEntropy{}); !errors.Is(err, platformcommand.ErrEffectVerification) {
				t.Fatal("staging replay adopted a substituted local recovery authority")
			}
			if !equalSnapshots(before, snapshotManagedCredentials(t, plan.Root)) {
				t.Fatal("rejected authority changed existing installation credentials")
			}
		})
	}
}

func TestArtifactCatalogRejectsConflictingAuthenticatedMappings(t *testing.T) {
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	first := release.Manifest{Images: []release.Image{{
		Purpose: release.ImageWorkload, SourceDigest: digest,
		ImageID: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}}}
	second := release.Manifest{Images: []release.Image{{
		Purpose: release.ImageWorkload, SourceDigest: digest,
		ImageID: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}}}
	if _, err := artifactCatalogConfig(first, second); err == nil {
		t.Fatal("catalog accepted one artifact digest mapped to different images")
	}
}

func TestUpgradeConfigurationReplacesOnlyReleaseDerivedFilesAndReplaysBothWays(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine upgrade configuration targets Linux")
	}
	plan := newUpgradePlan(t)
	source, err := authenticateInstalledPlan(plan.Source)
	if err != nil {
		t.Fatalf("authenticate upgrade source: %v", err)
	}
	defer clear(source.TrustBytes)
	uncorrelated := plan.Target
	uncorrelated.CorrelationID = ""
	if validateUpgradeIdentity(source, uncorrelated) == nil {
		t.Fatal("active upgrade accepted a missing command correlation")
	}
	credentials := snapshotManagedCredentials(t, source.Root)
	runtimeBoundary := newImageRuntime(plan.Target.Bundle.Manifest, true)

	if err := configureUpgrade(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("configure upgrade: %v", err)
	}
	assertReleaseConfiguration(
		t, plan.Target, source.Bundle.Manifest, plan.Target.Bundle.Manifest,
	)
	if _, err := verifiedInstallationConfiguration(plan.Target); err != nil {
		t.Fatalf("verify successor configuration with predecessor catalog: %v", err)
	}
	operational := plan.Target
	operational.CorrelationID = ""
	if _, err := verifiedInstallationConfiguration(operational); err != nil {
		t.Fatalf("read-only status rejected authenticated predecessor catalog: %v", err)
	}
	wrongPredecessor := plan.Target
	wrongPredecessor.PreviousDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := verifiedInstallationConfiguration(wrongPredecessor); err == nil {
		t.Fatal("successor configuration accepted a different predecessor digest")
	}
	predecessorRoot := filepath.Join(
		plan.Target.Root,
		filepath.FromSlash(layout.ReleaseDirectory(source.Bundle.Manifest.Release.ID)),
	)
	missingPredecessor := predecessorRoot + ".missing"
	if err := os.Rename(predecessorRoot, missingPredecessor); err != nil {
		t.Fatalf("hide authenticated predecessor: %v", err)
	}
	if _, err := verifiedInstallationConfiguration(plan.Target); err == nil {
		t.Fatal("successor configuration verified without its authenticated predecessor")
	}
	if err := os.Rename(missingPredecessor, predecessorRoot); err != nil {
		t.Fatalf("restore authenticated predecessor: %v", err)
	}
	if after := snapshotManagedCredentials(t, source.Root); !equalSnapshots(credentials, after) {
		t.Fatal("upgrade configuration changed installation credentials")
	}
	if err := configureUpgrade(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("replay upgrade configuration: %v", err)
	}

	if err := restoreUpgradeConfiguration(plan); err != nil {
		t.Fatalf("restore source configuration: %v", err)
	}
	assertReleaseConfiguration(t, source)
	if err := restoreUpgradeConfiguration(plan); err != nil {
		t.Fatalf("replay source configuration restore: %v", err)
	}

	composePath := filepath.Join(source.Root, filepath.FromSlash(layout.Compose))
	if err := os.WriteFile(composePath, []byte(`{"unowned":true}`), 0o600); err != nil {
		t.Fatalf("drift upgrade configuration: %v", err)
	}
	if err := configureUpgrade(
		context.Background(), runtimeBoundary, plan,
	); !errors.Is(err, platformcommand.ErrEffectConflict) {
		t.Fatalf("unrelated configuration drift error = %v", err)
	}
}

func TestPrepareReleaseRollbackRemovesOnlyCurrentAndRestoresPreviousConfiguration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine release rollback targets Linux")
	}
	upgrade := newUpgradePlan(t)
	previous, err := authenticateInstalledPlan(upgrade.Source)
	if err != nil {
		t.Fatalf("authenticate rollback predecessor: %v", err)
	}
	defer clear(previous.TrustBytes)
	if err := configureUpgrade(
		context.Background(), newImageRuntime(upgrade.Target.Bundle.Manifest, true), upgrade,
	); err != nil {
		t.Fatalf("configure rollback current release: %v", err)
	}
	expectation, err := compileUpgradeExpectation(upgrade.Target)
	if err != nil {
		t.Fatalf("compile rollback current expectation: %v", err)
	}
	runtimeBoundary := newPlatformCleanupRuntime(t, upgrade.Target, expectation)
	rollback := platformcommand.RollbackPlan{
		Current: upgrade.Target, Previous: upgrade.Source,
	}

	if err := prepareReleaseRollback(
		context.Background(), runtimeBoundary, rollback,
	); err != nil {
		t.Fatalf("prepare explicit release rollback: %v", err)
	}
	assertReleaseConfiguration(t, previous)
	wantContainers := len(expectation.Services) + 1
	wantNetworks := len(expectation.Networks)
	if len(runtimeBoundary.containers) != 0 || len(runtimeBoundary.networks) != 0 ||
		runtimeBoundary.containerRemovals != wantContainers ||
		runtimeBoundary.networkRemovals != wantNetworks ||
		runtimeBoundary.unexpectedRemovals != 0 {
		t.Fatalf(
			"release rollback inventory=%d/%d removals=%d/%d unexpected=%d",
			len(runtimeBoundary.containers), len(runtimeBoundary.networks),
			runtimeBoundary.containerRemovals, runtimeBoundary.networkRemovals,
			runtimeBoundary.unexpectedRemovals,
		)
	}
	if err := prepareReleaseRollback(
		context.Background(), runtimeBoundary, rollback,
	); err != nil {
		t.Fatalf("replay explicit release rollback: %v", err)
	}
	if runtimeBoundary.containerRemovals != wantContainers ||
		runtimeBoundary.networkRemovals != wantNetworks {
		t.Fatal("release rollback replay removed additional provider objects")
	}
}

func TestLoadInstallImagesUsesAuthenticatedStdinAndExactIdentities(t *testing.T) {
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage installation: %v", err)
	}
	runtimeBoundary := newImageRuntime(plan.Bundle.Manifest, false)
	if err := loadInstallImages(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("load installation images: %v", err)
	}
	if len(runtimeBoundary.loads) != len(plan.Bundle.Manifest.Images) {
		t.Fatalf("image load count = %d, want %d", len(runtimeBoundary.loads), len(plan.Bundle.Manifest.Images))
	}
	for _, image := range plan.Bundle.Manifest.Images {
		if !runtimeBoundary.present[image.ImageID] {
			t.Fatalf("image %s was not verified after load", image.Component)
		}
	}
	for _, arguments := range runtimeBoundary.commands {
		joined := strings.Join(arguments, " ")
		if strings.Contains(joined, " pull") || strings.Contains(joined, " build") ||
			strings.Contains(joined, " tag") || strings.Contains(joined, " push") ||
			strings.Contains(joined, " registry") {
			t.Fatalf("offline image loader used forbidden provider command %q", joined)
		}
	}
	loads := len(runtimeBoundary.loads)
	if err := loadInstallImages(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("replay image loading: %v", err)
	}
	if len(runtimeBoundary.loads) != loads {
		t.Fatal("image-loading replay imported already verified images")
	}
}

func TestLoadInstallImagesKeepsStartedFailureOutcomeUnknown(t *testing.T) {
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage installation: %v", err)
	}
	runtimeBoundary := newImageRuntime(plan.Bundle.Manifest, false)
	runtimeBoundary.failLoad = true
	err := loadInstallImages(context.Background(), runtimeBoundary, plan)
	if !errors.Is(err, platformcommand.ErrEffectOutcomeUnknown) {
		t.Fatalf("started image load failure = %v", err)
	}
}

func TestControlNetworkResolutionPreservesFullIdentityAndRejectsAmbiguity(t *testing.T) {
	const installationID = "mxi-11111111111111111111111111111111"
	const project = "matrix-" + installationID
	const releaseID = "matrix-v0.3.0-test"
	identity := strings.Repeat("a", 64)
	for _, scenario := range []struct {
		name      string
		foreign   bool
		ambiguous bool
		want      error
	}{
		{name: "full identity"},
		{name: "foreign ownership", foreign: true, want: platformcommand.ErrEffectConflict},
		{name: "ambiguous prefix", ambiguous: true, want: platformcommand.ErrEffectVerification},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			labels := map[string]string{
				"com.xiak.matrix.managed": "true", "com.xiak.matrix.installation": installationID,
				"com.xiak.matrix.release": releaseID, "com.xiak.matrix.role": "network-control",
				"com.docker.compose.project": project, "com.docker.compose.network": "control",
			}
			if scenario.foreign {
				labels["com.xiak.matrix.installation"] = "another-installation"
			}
			boundary := &scriptedRuntime{run: func(arguments []string) ([]byte, bool, error) {
				if len(arguments) < 2 || arguments[0] != "network" {
					return nil, false, errors.New("unexpected network resolution effect")
				}
				switch arguments[1] {
				case "ls":
					listed := []string{identity}
					if scenario.ambiguous {
						listed = append(listed, identity[:12]+strings.Repeat("b", 52))
					}
					if !slices.Contains(arguments, "--no-trunc") {
						for index := range listed {
							listed[index] = listed[index][:12]
						}
					}
					return []byte(strings.Join(listed, "\n") + "\n"), true, nil
				case "inspect":
					if !strings.HasPrefix(identity, arguments[len(arguments)-1]) {
						return nil, true, errors.New("network is absent")
					}
					var value any = platformNetworkInspection{ID: identity, Name: project + "_control", Internal: true, Labels: labels}
					if hasArgumentPair(arguments, "--format", "{{json .Labels}}") {
						value = labels
					}
					output, err := json.Marshal(value)
					return output, true, err
				default:
					return nil, false, errors.New("network resolution attempted mutation")
				}
			}}
			resolved, err := controlNetworkID(context.Background(), boundary, project, installationID, releaseID)
			if !errors.Is(err, scenario.want) {
				t.Fatalf("control network resolution: %v", err)
			}
			if scenario.want != nil {
				if resolved != "" {
					t.Fatal("rejected network retained a usable identity")
				}
				return
			}
			observed, err := inspectPlatformNetwork(context.Background(), boundary, resolved)
			if resolved != identity || err != nil || observed.ID != resolved {
				t.Fatal("network listing identity cannot authenticate the actual provider observation")
			}
		})
	}
}

func TestMigrateInstallationUsesFixedGoBinariesWithoutCredentialArguments(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine migration effects target Linux")
	}
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage installation: %v", err)
	}
	images := newImageRuntime(plan.Bundle.Manifest, true)
	if err := configureInstallation(context.Background(), images, plan); err != nil {
		t.Fatalf("configure installation: %v", err)
	}
	compiled, err := topology.Compile(plan.Bundle.Manifest, topology.Options{
		InstallationID: plan.InstallationID, Root: plan.Root,
		Listener: plan.Listener, Port: plan.Port,
	})
	if err != nil {
		t.Fatalf("compile migration topology: %v", err)
	}
	runtimeBoundary := newMigrationRuntime(plan, compiled.ProjectName)
	if err := migrateInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("migrate installation: %v", err)
	}
	if runtimeBoundary.composeCalls != 1 || len(runtimeBoundary.runs) != 6 {
		t.Fatalf("migration provider calls compose=%d run=%d", runtimeBoundary.composeCalls, len(runtimeBoundary.runs))
	}
	wantModes := []string{"apply", "apply", "apply", "verify", "verify", "verify"}
	wantEntrypoints := []string{
		"/matrix/bin/matrix-iam-migrate",
		"/matrix/bin/matrix-audit-migrate",
		"/matrix/bin/matrix-paas-migrate",
		"/matrix/bin/matrix-iam-migrate",
		"/matrix/bin/matrix-audit-migrate",
		"/matrix/bin/matrix-paas-migrate",
	}
	secretValues := [][]byte{
		readTestFile(t, plan.Root, layout.PostgresMigration),
		readTestFile(t, plan.Root, layout.IAMAPI),
		readTestFile(t, plan.Root, layout.IAMWorker),
		readTestFile(t, plan.Root, layout.IAMCredentialRecovery),
		readTestFile(t, plan.Root, layout.AuditRuntime),
		readTestFile(t, plan.Root, layout.PaaSAPI),
		readTestFile(t, plan.Root, layout.PaaSWorker),
	}
	for index, arguments := range runtimeBoundary.runs {
		joined := strings.Join(arguments, " ")
		if arguments[len(arguments)-1] != wantModes[index] ||
			!hasArgumentPair(arguments, "--entrypoint", wantEntrypoints[index]) ||
			!hasArgumentPair(arguments, "--pull", "never") ||
			!slices.Contains(arguments, "--read-only") ||
			strings.Contains(joined, "docker.sock") ||
			strings.Contains(joined, "--privileged") ||
			strings.Contains(joined, "--network host") {
			t.Fatalf("migration command %d violates fixed isolation: %q", index, joined)
		}
		for _, secret := range secretValues {
			if bytes.Contains([]byte(joined), secret) {
				t.Fatalf("migration command %d contains database credential material", index)
			}
		}
		recoveryMount := "type=bind,src=" + filepath.Join(plan.Root, filepath.FromSlash(layout.IAMCredentialRecovery)) + ",dst=/run/matrix/iam-recovery-dsn,readonly"
		iamMigration := wantEntrypoints[index] == "/matrix/bin/matrix-iam-migrate"
		if hasArgumentPair(arguments, "--mount", recoveryMount) != iamMigration ||
			hasArgumentPair(arguments, "--env", "MATRIX_MIGRATION_IAM_RECOVERY_DSN_FILE=/run/matrix/iam-recovery-dsn") != iamMigration {
			t.Fatal("local recovery database capability escaped the IAM role-provisioning boundary")
		}
	}
	installation, err := verifiedInstallationConfiguration(plan)
	if err != nil {
		t.Fatalf("authenticate migration verification fixture: %v", err)
	}
	runtimeBoundary.composeCalls = 0
	runtimeBoundary.runs = nil
	if err := verifyInstallationMigrations(
		context.Background(), runtimeBoundary, plan, installation,
	); err != nil {
		t.Fatalf("verify installation migrations: %v", err)
	}
	if runtimeBoundary.composeCalls != 0 || len(runtimeBoundary.runs) != len(platformMigrations) {
		t.Fatalf(
			"verify-only migration provider calls compose=%d run=%d",
			runtimeBoundary.composeCalls, len(runtimeBoundary.runs),
		)
	}
	for _, arguments := range runtimeBoundary.runs {
		if arguments[len(arguments)-1] != "verify" {
			t.Fatalf("migration verification applied state: %q", strings.Join(arguments, " "))
		}
	}
}

func TestMigrateUpgradeUsesTargetBinariesOnTheOwnedSourceNetwork(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine migration effects target Linux")
	}
	plan := newUpgradePlan(t)
	source, err := authenticateInstalledPlan(plan.Source)
	if err != nil {
		t.Fatalf("authenticate migration upgrade source: %v", err)
	}
	defer clear(source.TrustBytes)
	compiled, err := topology.Compile(plan.Target.Bundle.Manifest, topology.Options{
		InstallationID: plan.Target.InstallationID, Root: plan.Target.Root,
		Listener: plan.Target.Listener, Port: plan.Target.Port,
	})
	if err != nil {
		t.Fatalf("compile migration upgrade target: %v", err)
	}
	runtimeBoundary := newMigrationRuntime(plan.Target, compiled.ProjectName)
	runtimeBoundary.release = source.Bundle.Manifest.Release.ID
	if err := configureUpgrade(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("configure migration upgrade: %v", err)
	}
	if err := migrateUpgrade(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("migrate upgrade: %v", err)
	}
	if runtimeBoundary.composeCalls != 0 {
		t.Fatal("upgrade migration recreated PostgreSQL from target Compose configuration")
	}
	want := make(map[string]struct{}, len(platformMigrations)*2)
	for _, migration := range platformMigrations {
		for _, mode := range []string{"apply", "verify"} {
			want[migration.name+"/"+mode] = struct{}{}
		}
	}
	for _, arguments := range runtimeBoundary.runs {
		mode := arguments[len(arguments)-1]
		name := ""
		for _, migration := range platformMigrations {
			if hasArgumentPair(arguments, "--entrypoint", migration.entrypoint) {
				name = migration.name
				break
			}
		}
		if _, found := want[name+"/"+mode]; !found ||
			!hasArgumentPair(arguments, "--network", runtimeBoundary.controlNetwork) ||
			!hasArgumentPair(
				arguments, "--label",
				"com.xiak.matrix.release="+plan.Target.Bundle.Manifest.Release.ID,
			) {
			t.Fatalf("upgrade migration escaped its target/source binding: %q", strings.Join(arguments, " "))
		}
		delete(want, name+"/"+mode)
	}
	if len(want) != 0 {
		t.Fatalf("upgrade migration modes are incomplete: %#v", want)
	}
}

func TestStartInstallationObservesThenConvergesFixedOfflineTopology(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform start effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	if err := startInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("start installation: %v", err)
	}
	if runtimeBoundary.composeCalls != 1 || runtimeBoundary.observationsBeforeStart == 0 {
		t.Fatalf(
			"platform convergence compose=%d observations-before-start=%d",
			runtimeBoundary.composeCalls,
			runtimeBoundary.observationsBeforeStart,
		)
	}
	joined := strings.Join(runtimeBoundary.composeArguments, " ")
	if !hasArgumentPair(runtimeBoundary.composeArguments, "--pull", "never") ||
		!slices.Contains(runtimeBoundary.composeArguments, "--no-build") ||
		strings.Contains(joined, "registry") || strings.Contains(joined, "--privileged") {
		t.Fatalf("platform start command is not fixed offline input: %q", joined)
	}
	if err := startInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("replay platform start: %v", err)
	}
	if runtimeBoundary.composeCalls != 1 {
		t.Fatal("healthy platform start replay invoked Compose again")
	}
}

func TestStartInstallationRejectsObservedRuntimeDriftWithoutRecreating(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform start effects target Linux")
	}
	tests := []struct {
		name   string
		mutate func(*platformStartRuntime)
	}{
		{"resource limit", func(value *platformStartRuntime) { value.resourceDriftService = "paas-worker" }},
		{"runtime user", func(value *platformStartRuntime) { value.userDriftService = "apisix" }},
		{"inactive published port", func(value *platformStartRuntime) { value.portDriftService = "apisix" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, expectation := configuredPlatformStartFixture(t)
			runtimeBoundary := newPlatformStartRuntime(plan, expectation)
			runtimeBoundary.started = true
			test.mutate(runtimeBoundary)
			err := startInstallation(context.Background(), runtimeBoundary, plan)
			if !errors.Is(err, platformcommand.ErrEffectVerification) ||
				runtimeBoundary.composeCalls != 0 {
				t.Fatalf("observed platform drift err=%v compose=%d", err, runtimeBoundary.composeCalls)
			}
		})
	}
}

func TestStartInstallationConvergesRecoverableComposeConfigurationDrift(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform start effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	runtimeBoundary.started = true
	runtimeBoundary.configHashDriftService = "paas-api"
	if err := startInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("converge recoverable platform configuration drift: %v", err)
	}
	if runtimeBoundary.composeCalls != 1 {
		t.Fatalf("recoverable platform drift Compose calls = %d", runtimeBoundary.composeCalls)
	}
}

func TestStartInstallationMarksUnobservedSuccessfulEffectUnknown(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform start effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	runtimeBoundary.failObservationAfterStart = true
	err := startInstallation(context.Background(), runtimeBoundary, plan)
	if !errors.Is(err, platformcommand.ErrEffectOutcomeUnknown) ||
		errors.Is(err, platformcommand.ErrEffectVerification) ||
		runtimeBoundary.composeCalls != 1 {
		t.Fatalf("unobserved successful start err=%v compose=%d", err, runtimeBoundary.composeCalls)
	}
}

func TestOperationalEffectsObserveAndVerifyWithoutComposeConvergence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine operational effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	runtimeBoundary.started = true
	verifier := &recordingInstallationVerifier{}
	effects := &Effects{
		runtime: runtimeBoundary, entropy: rand.Reader, verifier: verifier,
	}
	installed := installedPlanFrom(plan)

	ready, err := effects.ObserveInstallation(context.Background(), installed)
	if err != nil || !ready || runtimeBoundary.composeCalls != 0 ||
		len(runtimeBoundary.migrationRuns) != 0 || verifier.calls != 0 {
		t.Fatalf(
			"read-only observation ready=%t err=%v compose=%d migrations=%d verifier=%d",
			ready, err, runtimeBoundary.composeCalls,
			len(runtimeBoundary.migrationRuns), verifier.calls,
		)
	}
	if err := effects.VerifyInstallation(context.Background(), installed); err != nil {
		t.Fatalf("verify installed platform: %v", err)
	}
	if runtimeBoundary.composeCalls != 0 ||
		len(runtimeBoundary.migrationRuns) != len(platformMigrations) || verifier.calls != 1 {
		t.Fatalf(
			"verification provider calls compose=%d migrations=%d verifier=%d",
			runtimeBoundary.composeCalls, len(runtimeBoundary.migrationRuns), verifier.calls,
		)
	}
	for _, arguments := range runtimeBoundary.migrationRuns {
		if arguments[len(arguments)-1] != "verify" {
			t.Fatalf("operational verification applied migration state: %q", strings.Join(arguments, " "))
		}
	}
}

func TestAuthenticateInstalledPlanPinsSealedTrustAndRelease(t *testing.T) {
	plan := newInstallPlan(t)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage authentication fixture: %v", err)
	}
	installed := installedPlanFrom(plan)
	authenticated, err := authenticateInstalledPlan(installed)
	if err != nil {
		t.Fatalf("authenticate sealed current release: %v", err)
	}
	clear(authenticated.TrustBytes)

	for _, test := range []struct {
		name   string
		mutate func(*platformcommand.InstalledPlan)
	}{
		{
			name: "trust fingerprint",
			mutate: func(value *platformcommand.InstalledPlan) {
				value.TrustFingerprint = "sha256:" + strings.Repeat("e", 64)
			},
		},
		{
			name: "release digest",
			mutate: func(value *platformcommand.InstalledPlan) {
				value.ReleaseDigest = "sha256:" + strings.Repeat("d", 64)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			drifted := installed
			test.mutate(&drifted)
			if authenticated, err := authenticateInstalledPlan(drifted); err == nil {
				clear(authenticated.TrustBytes)
				t.Fatal("sealed installation drift was accepted")
			}
		})
	}
}

func TestCreateBackupSealsDatabaseAndWorkloadSecretsAndReplays(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine backup effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	credentials := snapshotManagedCredentials(t, plan.Root)
	authority, err := readLocalCredentialRecoveryAuthority(plan.Root, plan.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	capabilityKey := authority.CapabilityKey.CopyBytes()
	defer clear(capabilityKey)
	secret := []byte("backup-secret-value-that-must-not-enter-metadata")
	secretRelative := filepath.Join(
		filepath.FromSlash(layout.WorkloadSecretRoot),
		"secret-backup", "version-one",
	)
	if err := writeManagedOnce(plan.Root, secretRelative, secret); err != nil {
		t.Fatalf("provision workload secret fixture: %v", err)
	}
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	runtimeBoundary.started = true
	effects := &Effects{
		runtime: runtimeBoundary, entropy: rand.Reader,
		verifier: &recordingInstallationVerifier{},
	}
	request := platformcommand.BackupPlan{
		InstalledPlan: installedPlanFrom(plan),
		BackupID:      "backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CreatedAt:     time.Date(2026, 8, 26, 5, 0, 0, 0, time.UTC),
	}
	if err := effects.CreateBackup(context.Background(), request); err != nil {
		t.Fatalf("create protected backup: %v", err)
	}
	backupRoot := filepath.Join(
		plan.Root, filepath.FromSlash(layout.BackupDirectory), request.BackupID,
	)
	manifestContent, err := os.ReadFile(filepath.Join(backupRoot, backupManifestFilename))
	if err != nil {
		t.Fatalf("read backup manifest: %v", err)
	}
	sealKey := readTestFile(t, plan.Root, layout.BackupSealKey)
	for _, forbidden := range [][]byte{secret, sealKey, capabilityKey, readTestFile(t, plan.Root, layout.IAMCredentialRecovery), []byte(plan.Root)} {
		if bytes.Contains(manifestContent, forbidden) {
			t.Fatal("backup manifest contains secret or absolute-path material")
		}
	}
	var manifest backupManifest
	if json.Unmarshal(manifestContent, &manifest) != nil ||
		manifest.BackupID != request.BackupID ||
		manifest.InstallationID != plan.InstallationID ||
		manifest.ReleaseDigest != plan.Bundle.ManifestSHA256 ||
		len(manifest.Artifacts) != 2 || manifest.Seal == nil || manifest.Seal.Value == "" {
		t.Fatalf("sealed backup manifest = %#v", manifest)
	}
	source, err := effects.InspectBackup(
		context.Background(), request.InstalledPlan, request.BackupID,
	)
	if err != nil || source.InstallationID != plan.InstallationID ||
		source.BackupID != request.BackupID || !validSHA256(source.BackupDigest) ||
		source.ReleaseID != plan.Bundle.Manifest.Release.ID ||
		source.ReleaseDigest != plan.Bundle.ManifestSHA256 ||
		source.Database != plan.Bundle.Manifest.Database {
		t.Fatalf("authenticated recovery source = %#v / %v", source, err)
	}
	foreign := request.InstalledPlan
	foreign.InstallationID = "mxi-22222222222222222222222222222222"
	if _, err := effects.InspectBackup(
		context.Background(), foreign, request.BackupID,
	); !errors.Is(err, platformcommand.ErrEffectVerification) {
		t.Fatalf("cross-installation backup inspection error = %v", err)
	}
	archiveFile, err := os.Open(filepath.Join(backupRoot, workloadSecretsFilename))
	if err != nil {
		t.Fatalf("open workload secret archive: %v", err)
	}
	archive := tar.NewReader(archiveFile)
	header, err := archive.Next()
	if err != nil || header.Name != "secret-backup/version-one" {
		_ = archiveFile.Close()
		t.Fatalf("workload secret archive header=%#v err=%v", header, err)
	}
	archivedSecret, err := io.ReadAll(archive)
	if _, nextErr := archive.Next(); !errors.Is(nextErr, io.EOF) {
		_ = archiveFile.Close()
		t.Fatal("workload backup included material outside the workload secret inventory")
	}
	if closeErr := archiveFile.Close(); err != nil || closeErr != nil ||
		!bytes.Equal(archivedSecret, secret) {
		t.Fatalf("workload secret snapshot differs: read=%v close=%v", err, closeErr)
	}
	streams := runtimeBoundary.backupStreams
	if streams == 0 || runtimeBoundary.restoreChecks == 0 ||
		len(runtimeBoundary.migrationRuns) != len(platformMigrations) {
		t.Fatal("backup did not verify the schema and PostgreSQL custom dump")
	}
	if err := effects.CreateBackup(context.Background(), request); err != nil {
		t.Fatalf("replay protected backup: %v", err)
	}
	if runtimeBoundary.backupStreams != streams {
		t.Fatal("backup replay streamed a second database snapshot")
	}
	if !equalSnapshots(credentials, snapshotManagedCredentials(t, plan.Root)) {
		t.Fatal("backup changed persistent installation or recovery credentials")
	}
	for _, scalar := range []string{"0", "null"} {
		ambiguous := append([]byte(`{"schemaVersion":`+scalar+`,`), manifestContent[1:]...)
		if err := os.WriteFile(filepath.Join(backupRoot, backupManifestFilename), ambiguous, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := effects.InspectBackup(context.Background(), request.InstalledPlan, request.BackupID); !errors.Is(err, platformcommand.ErrEffectVerification) {
			t.Fatal("v2 backup accepted an empty legacy schema selector without changing its seal")
		}
	}
	if err := os.WriteFile(filepath.Join(backupRoot, backupManifestFilename), manifestContent, 0o600); err != nil {
		t.Fatal(err)
	}

	dumpPath := filepath.Join(backupRoot, databaseDumpFilename)
	if err := os.WriteFile(dumpPath, []byte("tampered-dump"), 0o600); err != nil {
		t.Fatalf("tamper backup dump: %v", err)
	}
	if err := effects.CreateBackup(
		context.Background(), request,
	); !errors.Is(err, platformcommand.ErrEffectVerification) {
		t.Fatalf("tampered backup replay error = %v", err)
	}
}

func TestRecoverBackupRestoresSelectedSnapshotAndConvergesTarget(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine recovery effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	secret := []byte("selected-backup-secret")
	secretRelative := filepath.Join(
		filepath.FromSlash(layout.WorkloadSecretRoot),
		"secret-recovery", "version-one",
	)
	if err := writeManagedOnce(plan.Root, secretRelative, secret); err != nil {
		t.Fatalf("provision recovery secret fixture: %v", err)
	}
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	runtimeBoundary.started = true
	projectInspector := newRecoveryProbeInspector(t, plan)
	verifier := &recordingInstallationVerifier{}
	verifier.after = func(verifiedPlan platformcommand.InstallPlan) (paasv1.InstallationVerification, error) {
		state := projectInspector.provision(t, 2)
		runtimeBoundary.probe = newRecoveryProbeRuntime(t, verifiedPlan, state)
		return paasv1.InstallationVerification{
			DeploymentID: state.DeploymentID, Generation: state.Generation,
		}, nil
	}
	effects := &Effects{
		runtime: runtimeBoundary, entropy: rand.Reader, verifier: verifier,
		projectInspector: projectInspector,
	}
	backup := platformcommand.BackupPlan{
		InstalledPlan: installedPlanFrom(plan),
		BackupID:      "backup-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt:     time.Date(2026, 8, 26, 5, 5, 0, 0, time.UTC),
	}
	if err := effects.CreateBackup(context.Background(), backup); err != nil {
		t.Fatalf("create recovery backup: %v", err)
	}
	source, err := effects.InspectBackup(
		context.Background(), backup.InstalledPlan, backup.BackupID,
	)
	if err != nil {
		t.Fatalf("inspect recovery backup: %v", err)
	}
	secretPath, err := managedPath(plan.Root, secretRelative)
	if err != nil {
		t.Fatalf("resolve recovery secret: %v", err)
	}
	if err := os.WriteFile(secretPath, []byte("conflicting-live-secret"), 0o600); err != nil {
		t.Fatalf("write conflicting live secret: %v", err)
	}
	removals := runtimeBoundary.providerRemovals
	if _, err := effects.InspectBackup(
		context.Background(), backup.InstalledPlan, backup.BackupID,
	); !errors.Is(err, platformcommand.ErrEffectConflict) ||
		runtimeBoundary.providerRemovals != removals {
		t.Fatalf("conflicting secret recovery preflight = %v / removals=%d", err, runtimeBoundary.providerRemovals)
	}
	if err := os.Remove(secretPath); err != nil {
		t.Fatalf("remove live secret before recovery: %v", err)
	}

	recovery := platformcommand.RecoveryPlan{
		Current:      plan,
		Target:       plan,
		BackupID:     source.BackupID,
		BackupDigest: source.BackupDigest,
	}
	for _, phase := range []lifecycle.Phase{
		lifecycle.PhaseRecovering, lifecycle.PhaseStarting, lifecycle.PhaseVerifying,
	} {
		if err := effects.ApplyRecoveryPhase(
			context.Background(), recovery, phase,
		); err != nil {
			t.Fatalf("apply recovery phase %s: %v", phase, err)
		}
	}
	restored, err := readManagedFile(plan.Root, secretRelative, 1024*1024)
	if err != nil || !bytes.Equal(restored, secret) {
		clear(restored)
		t.Fatalf("restored secret differs: %v", err)
	}
	clear(restored)
	if runtimeBoundary.recoveryRestores != 1 || runtimeBoundary.postgresOnly ||
		!runtimeBoundary.started || runtimeBoundary.providerRemovals == removals ||
		verifier.calls != 1 ||
		verifier.plan.Bundle.Manifest.Release.ID != plan.Bundle.Manifest.Release.ID {
		t.Fatalf(
			"recovery effects = restores:%d postgresOnly:%t started:%t removals:%d verifier:%d",
			runtimeBoundary.recoveryRestores, runtimeBoundary.postgresOnly,
			runtimeBoundary.started, runtimeBoundary.providerRemovals, verifier.calls,
		)
	}
}

func TestPublishedBackupSealRemainsReadableAndProfileCannotBeSubstituted(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine backup effects target Linux")
	}
	legacy := release.DatabaseProfile{SchemaVersion: 1, Compatibility: "expand-contract-n-minus-one"}
	plan, expectation := configuredPlatformStartFixture(t, legacy)
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	runtimeBoundary.started = true
	effects := &Effects{runtime: runtimeBoundary, entropy: rand.Reader, verifier: &recordingInstallationVerifier{}}
	request := platformcommand.BackupPlan{
		InstalledPlan: installedPlanFrom(plan), BackupID: "backup-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt: time.Date(2026, 8, 26, 5, 0, 0, 0, time.UTC),
	}
	if err := effects.CreateBackup(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(plan.Root, filepath.FromSlash(layout.BackupDirectory), request.BackupID, backupManifestFilename)
	content, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest backupManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.APIVersion, manifest.SchemaVersion, manifest.Database = legacyBackupAPIVersion, 1, release.DatabaseProfile{}
	key, err := loadBackupSealKey(plan.Root, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	artifacts, err := json.Marshal(manifest.Artifacts)
	if err != nil {
		t.Fatal(err)
	}
	// Freeze the published v1 HMAC input independently of the new Go struct.
	canonical := []byte(fmt.Sprintf(`{"apiVersion":"installation.matrix.xiak.com/v1","kind":"PlatformBackup","backupId":%q,"installationId":%q,"releaseId":%q,"releaseDigest":%q,"schemaVersion":1,"createdAt":"2026-08-26T05:00:00Z","artifacts":%s}`,
		manifest.BackupID, manifest.InstallationID, manifest.ReleaseID, manifest.ReleaseDigest, artifacts))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("matrix-platform-backup-v1\x00"))
	_, _ = mac.Write(canonical)
	sealed := append(append([]byte(nil), canonical[:len(canonical)-1]...),
		[]byte(fmt.Sprintf(`,"seal":{"algorithm":"HMAC-SHA256","keyId":"installation-backup-v1","value":"sha256:%s"}}`+"\n", hex.EncodeToString(mac.Sum(nil))))...)
	roundTrip, err := sealBackupManifest(manifest, key)
	if err != nil || !bytes.Equal(roundTrip, sealed) {
		t.Fatalf("published backup seal changed: %v", err)
	}
	if err := os.WriteFile(backupPath, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := effects.InspectBackup(context.Background(), request.InstalledPlan, request.BackupID)
	if err != nil || source.Database != legacy {
		t.Fatalf("read published backup: %#v / %v", source.Database, err)
	}
	if err := effects.CreateBackup(context.Background(), request); err != nil {
		t.Fatalf("replay published backup: %v", err)
	}
	retained, err := os.ReadFile(backupPath)
	if err != nil || !bytes.Equal(retained, sealed) {
		t.Fatal("legacy backup replay rewrote its sealed bytes")
	}

	manifest.APIVersion, manifest.SchemaVersion, manifest.Database = backupAPIVersion, 0, release.CurrentDatabaseProfile()
	substituted, err := sealBackupManifest(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, substituted, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := effects.InspectBackup(context.Background(), request.InstalledPlan, request.BackupID); !errors.Is(err, platformcommand.ErrEffectVerification) {
		t.Fatalf("validly sealed different profile masked the backup release: %v", err)
	}
}

func TestRecoveryRejectsDifferentCurrentProfileAtEveryEffectBoundary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine recovery effects target Linux")
	}
	current := release.CurrentDatabaseProfile()
	revised, changedSchema := current, current
	revised.ContractRevision++
	changedSchema.Authorities.Audit++
	for _, test := range []struct {
		name    string
		profile release.DatabaseProfile
	}{{"authority schema", changedSchema}, {"same schemas changed contract", revised}} {
		t.Run(test.name, func(t *testing.T) {
			pair := newUpgradePlan(t, current, test.profile)
			target, err := authenticateInstalledPlan(pair.Source)
			if err != nil {
				t.Fatal(err)
			}
			installation, err := verifiedInstallationConfiguration(target)
			if err != nil {
				t.Fatal(err)
			}
			expectation, err := decodePlatformExpectation(installation.topology.ComposeJSON)
			if err != nil {
				t.Fatal(err)
			}
			runtimeBoundary := newPlatformStartRuntime(target, expectation)
			runtimeBoundary.started = true
			verifier := &recordingInstallationVerifier{}
			effects := &Effects{runtime: runtimeBoundary, entropy: rand.Reader, verifier: verifier,
				projectInspector: newRecoveryProbeInspector(t, target)}
			secretPath := filepath.Join(filepath.FromSlash(layout.WorkloadSecretRoot), "retained-secret", "version-one")
			if err := writeManagedOnce(target.Root, secretPath, []byte("retained-workload-secret")); err != nil {
				t.Fatal(err)
			}
			backup := platformcommand.BackupPlan{InstalledPlan: pair.Source,
				BackupID: "backup-cccccccccccccccccccccccccccccccc", CreatedAt: pair.CreatedAt}
			if err := effects.CreateBackup(context.Background(), backup); err != nil {
				t.Fatal(err)
			}
			source, err := effects.InspectBackup(context.Background(), pair.Source, backup.BackupID)
			if err != nil || source.Database != target.Bundle.Manifest.Database {
				t.Fatal("backup and recovery target must authenticate before the cross-profile check")
			}
			retained := map[string][]byte{}
			for _, relative := range []string{layout.Compose, layout.PostgresPassword, layout.IAMBootstrap, secretPath,
				filepath.Join(layout.BackupDirectory, backup.BackupID, backupManifestFilename),
				filepath.Join(layout.BackupDirectory, backup.BackupID, databaseDumpFilename)} {
				retained[relative] = readTestFile(t, target.Root, relative)
			}
			defer func() {
				for _, content := range retained {
					clear(content)
				}
			}()
			recovery := platformcommand.RecoveryPlan{Current: pair.Target, Target: target,
				BackupID: source.BackupID, BackupDigest: source.BackupDigest}
			composeBefore, removalsBefore, restoresBefore := runtimeBoundary.composeCalls, runtimeBoundary.providerRemovals, runtimeBoundary.recoveryRestores
			migrationsBefore, verificationsBefore := len(runtimeBoundary.migrationRuns), verifier.calls
			for _, phase := range []lifecycle.Phase{lifecycle.PhaseRecovering, lifecycle.PhaseStarting, lifecycle.PhaseVerifying} {
				if err := effects.ApplyRecoveryPhase(context.Background(), recovery, phase); !errors.Is(err, platformcommand.ErrEffectPrecondition) {
					t.Fatalf("cross-profile %s did not fail closed: %v", phase, err)
				}
				if !runtimeBoundary.started || runtimeBoundary.composeCalls != composeBefore || runtimeBoundary.providerRemovals != removalsBefore ||
					runtimeBoundary.recoveryRestores != restoresBefore || len(runtimeBoundary.migrationRuns) != migrationsBefore || verifier.calls != verificationsBefore {
					t.Fatal("cross-profile recovery reached service, provider, database or verification effects")
				}
				for relative, expected := range retained {
					actual := readTestFile(t, target.Root, relative)
					equal := bytes.Equal(actual, expected)
					clear(actual)
					if !equal {
						t.Fatal("rejected recovery changed configuration, credentials or the selected backup")
					}
				}
			}
		})
	}
}

func TestBackupProfileRejectsMissingAndAmbiguousVersions(t *testing.T) {
	for _, manifest := range []backupManifest{
		{APIVersion: backupAPIVersion},
		{APIVersion: legacyBackupAPIVersion},
		{APIVersion: legacyBackupAPIVersion, SchemaVersion: 1, Database: release.CurrentDatabaseProfile()},
		{APIVersion: backupAPIVersion, SchemaVersion: 1, Database: release.CurrentDatabaseProfile()},
		{APIVersion: "installation.matrix.xiak.com/v3", Database: release.CurrentDatabaseProfile()},
	} {
		if _, err := manifest.databaseProfile(); err == nil {
			t.Fatal("ambiguous backup profile accepted")
		}
		if _, err := sealBackupManifest(manifest, bytes.Repeat([]byte{1}, sha256.Size)); err == nil {
			t.Fatal("ambiguous backup profile was sealed")
		}
	}
}

func TestSupportEvidenceIsBoundedSanitizedAndUsefulWhenDegraded(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine support effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	authority, err := readLocalCredentialRecoveryAuthority(plan.Root, plan.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	capabilityKey := authority.CapabilityKey.CopyBytes()
	defer clear(capabilityKey)
	secret := []byte("support-secret-value-that-must-never-be-emitted")
	if err := writeManagedOnce(
		plan.Root,
		filepath.Join(
			filepath.FromSlash(layout.WorkloadSecretRoot),
			"secret-support", "version-one",
		),
		secret,
	); err != nil {
		t.Fatalf("provision support secret fixture: %v", err)
	}
	runtimeBoundary := newPlatformStartRuntime(plan, expectation)
	runtimeBoundary.started = true
	effects := &Effects{
		runtime: runtimeBoundary, entropy: rand.Reader,
		verifier: &recordingInstallationVerifier{},
	}
	request := platformcommand.SupportPlan{
		InstalledPlan: installedPlanFrom(plan),
		Output: filepath.Join(
			plan.Root, filepath.FromSlash(layout.SupportDirectory), "healthy.json",
		),
		CorrelationID: "cmd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		GeneratedAt:   time.Date(2026, 8, 26, 5, 10, 0, 0, time.UTC),
	}
	if err := effects.WriteSupportEvidence(context.Background(), request); err != nil {
		t.Fatalf("write healthy support evidence: %v", err)
	}
	content, err := os.ReadFile(request.Output)
	if err != nil {
		t.Fatalf("read support evidence: %v", err)
	}
	for _, forbidden := range [][]byte{
		secret,
		capabilityKey,
		readTestFile(t, plan.Root, layout.IAMCredentialRecovery),
		readTestFile(t, plan.Root, layout.BackupSealKey),
		readTestFile(t, plan.Root, layout.PaaSAPI),
		[]byte(plan.Root),
		[]byte(request.Output),
	} {
		if bytes.Contains(content, forbidden) {
			t.Fatal("support evidence contains secret, native configuration, or absolute path")
		}
	}
	var healthy supportEvidence
	if json.Unmarshal(content, &healthy) != nil || healthy.State != supportStateReady ||
		healthy.ReleaseDigest != plan.Bundle.ManifestSHA256 ||
		healthy.Database != plan.Bundle.Manifest.Database ||
		len(healthy.Components) != len(expectation.Services) ||
		len(healthy.Images) != len(plan.Bundle.Manifest.Images) {
		t.Fatalf("healthy support evidence = %#v", healthy)
	}
	contradictory := healthy
	contradictory.State = supportStateNotReady
	contradictoryContent, err := json.Marshal(contradictory)
	if err != nil || verifySupportEvidence(
		contradictoryContent, request, plan, expectation,
	) == nil {
		t.Fatal("support evidence accepted a state that contradicted its components")
	}
	if runtimeBoundary.composeCalls != 0 || len(runtimeBoundary.migrationRuns) != 0 ||
		runtimeBoundary.backupStreams != 0 {
		t.Fatal("support evidence invoked a mutating platform effect")
	}
	if err := effects.WriteSupportEvidence(context.Background(), request); err != nil {
		t.Fatalf("replay healthy support evidence: %v", err)
	}

	runtimeBoundary.unhealthyService = "paas-worker"
	degraded := request
	degraded.Output = filepath.Join(
		plan.Root, filepath.FromSlash(layout.SupportDirectory), "degraded.json",
	)
	degraded.CorrelationID = "cmd-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	degraded.GeneratedAt = degraded.GeneratedAt.Add(time.Minute)
	if err := effects.WriteSupportEvidence(context.Background(), degraded); err != nil {
		t.Fatalf("write degraded support evidence: %v", err)
	}
	content, err = os.ReadFile(degraded.Output)
	if err != nil {
		t.Fatalf("read degraded support evidence: %v", err)
	}
	var observed supportEvidence
	if json.Unmarshal(content, &observed) != nil || observed.State != supportStateNotReady {
		t.Fatalf("degraded support evidence = %#v", observed)
	}
	workerFound := false
	for _, component := range observed.Components {
		if component.Name == "paas-worker" {
			workerFound = true
			if component.State != supportStateNotReady {
				t.Fatalf("degraded worker evidence = %#v", component)
			}
		}
	}
	if !workerFound {
		t.Fatal("degraded support evidence omitted the affected component")
	}
}

func TestRollbackInstallationRemovesUnhealthyOnlyProvedOwnedObjectsAndReplays(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform cleanup effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformCleanupRuntime(t, plan, expectation)
	apisix := runtimeBoundary.containers["container-apisix"]
	apisix.State.Status = "restarting"
	apisix.State.Running = false
	runtimeBoundary.containers["container-apisix"] = apisix
	wantContainers := len(expectation.Services) + 1
	wantNetworks := len(expectation.Networks)

	if err := rollbackInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("rollback installation: %v", err)
	}
	if len(runtimeBoundary.containers) != 0 || len(runtimeBoundary.networks) != 0 ||
		runtimeBoundary.containerRemovals != wantContainers ||
		runtimeBoundary.networkRemovals != wantNetworks ||
		runtimeBoundary.unexpectedRemovals != 0 {
		t.Fatalf(
			"cleanup inventory containers=%d networks=%d removals=%d/%d unexpected=%d",
			len(runtimeBoundary.containers), len(runtimeBoundary.networks),
			runtimeBoundary.containerRemovals, runtimeBoundary.networkRemovals,
			runtimeBoundary.unexpectedRemovals,
		)
	}

	if err := rollbackInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("replay rollback installation: %v", err)
	}
	if runtimeBoundary.containerRemovals != wantContainers ||
		runtimeBoundary.networkRemovals != wantNetworks {
		t.Fatal("cleanup replay removed additional provider objects")
	}
}

func TestRollbackInstallationRejectsUnprovedOwnershipBeforeRemoval(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform cleanup effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformCleanupRuntime(t, plan, expectation)
	migration := runtimeBoundary.containers[runtimeBoundary.migrationID]
	migration.Config.Labels["com.xiak.matrix.release"] = "sha256:" + strings.Repeat("f", 64)
	runtimeBoundary.containers[runtimeBoundary.migrationID] = migration

	err := rollbackInstallation(context.Background(), runtimeBoundary, plan)
	if !errors.Is(err, platformcommand.ErrEffectConflict) ||
		runtimeBoundary.containerRemovals != 0 || runtimeBoundary.networkRemovals != 0 {
		t.Fatalf(
			"unproved cleanup err=%v removals=%d/%d",
			err, runtimeBoundary.containerRemovals, runtimeBoundary.networkRemovals,
		)
	}
}

func TestRollbackInstallationReplaysAStartedRemovalWithUnknownOutcome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform cleanup effects target Linux")
	}
	plan, expectation := configuredPlatformStartFixture(t)
	runtimeBoundary := newPlatformCleanupRuntime(t, plan, expectation)
	runtimeBoundary.failStartedRemovalOnce = true

	err := rollbackInstallation(context.Background(), runtimeBoundary, plan)
	if !errors.Is(err, platformcommand.ErrEffectOutcomeUnknown) ||
		runtimeBoundary.containerRemovals != 1 {
		t.Fatalf("started cleanup err=%v removals=%d", err, runtimeBoundary.containerRemovals)
	}
	if err := rollbackInstallation(context.Background(), runtimeBoundary, plan); err != nil {
		t.Fatalf("replay uncertain rollback: %v", err)
	}
	if len(runtimeBoundary.containers) != 0 || len(runtimeBoundary.networks) != 0 ||
		runtimeBoundary.containerRemovals != len(expectation.Services)+1 ||
		runtimeBoundary.networkRemovals != len(expectation.Networks) {
		t.Fatalf(
			"replayed cleanup inventory=%d/%d removals=%d/%d",
			len(runtimeBoundary.containers), len(runtimeBoundary.networks),
			runtimeBoundary.containerRemovals, runtimeBoundary.networkRemovals,
		)
	}
}

func TestUpgradeProjectClassificationRejectsMixedReleaseOwnership(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local-machine platform ownership effects target Linux")
	}
	plan := newUpgradePlan(t)
	source, err := authenticateInstalledPlan(plan.Source)
	if err != nil {
		t.Fatalf("authenticate classification source: %v", err)
	}
	defer clear(source.TrustBytes)
	expectation, err := compileUpgradeExpectation(source)
	if err != nil {
		t.Fatalf("compile classification source: %v", err)
	}
	runtimeBoundary := newPlatformCleanupRuntime(t, source, expectation)
	state, err := inspectUpgradeProject(
		context.Background(), runtimeBoundary, source, plan.Target,
	)
	if err != nil || state.releaseID != source.Bundle.Manifest.Release.ID {
		t.Fatalf("source project classification = %#v / %v", state, err)
	}

	services := make([]string, 0, len(expectation.Services))
	for service := range expectation.Services {
		services = append(services, service)
	}
	slices.Sort(services)
	identity := "container-" + services[0]
	inspection := runtimeBoundary.containers[identity]
	inspection.Config.Labels["com.xiak.matrix.release"] = plan.Target.Bundle.Manifest.Release.ID
	runtimeBoundary.containers[identity] = inspection
	_, err = inspectUpgradeProject(
		context.Background(), runtimeBoundary, source, plan.Target,
	)
	if !errors.Is(err, platformcommand.ErrEffectConflict) ||
		runtimeBoundary.containerRemovals != 0 || runtimeBoundary.networkRemovals != 0 {
		t.Fatalf(
			"mixed release classification err=%v removals=%d/%d",
			err, runtimeBoundary.containerRemovals, runtimeBoundary.networkRemovals,
		)
	}
}

func configuredPlatformStartFixture(
	t *testing.T,
	profiles ...release.DatabaseProfile,
) (platformcommand.InstallPlan, platformComposeExpectation) {
	t.Helper()
	plan := newInstallPlan(t, profiles...)
	if err := stageInstallation(plan, rand.Reader); err != nil {
		t.Fatalf("stage installation: %v", err)
	}
	images := newImageRuntime(plan.Bundle.Manifest, true)
	if err := configureInstallation(context.Background(), images, plan); err != nil {
		t.Fatalf("configure installation: %v", err)
	}
	installation, err := verifiedInstallationConfiguration(plan)
	if err != nil {
		t.Fatalf("verify installation configuration: %v", err)
	}
	expectation, err := decodePlatformExpectation(installation.topology.ComposeJSON)
	if err != nil {
		t.Fatalf("decode platform expectation: %v", err)
	}
	return plan, expectation
}

func TestRejectProjectCollisionRequiresExactInstallationOwnership(t *testing.T) {
	foreign := &scriptedRuntime{run: func(arguments []string) ([]byte, bool, error) {
		switch {
		case len(arguments) >= 2 && arguments[1] == "ls" && arguments[0] == "container":
			return []byte("foreign-container\n"), true, nil
		case len(arguments) >= 2 && arguments[1] == "inspect":
			return []byte(`{"com.docker.compose.project":"matrix-mxi"}`), true, nil
		default:
			return nil, true, nil
		}
	}}
	err := rejectProjectCollision(
		context.Background(), foreign, "matrix-mxi", "mxi-11111111111111111111111111111111",
	)
	if !errors.Is(err, platformcommand.ErrEffectConflict) {
		t.Fatalf("foreign project collision = %v", err)
	}

	owned := &scriptedRuntime{run: func(arguments []string) ([]byte, bool, error) {
		switch {
		case len(arguments) >= 2 && arguments[1] == "ls" && arguments[0] == "network":
			return []byte("owned-network\n"), true, nil
		case len(arguments) >= 2 && arguments[1] == "inspect":
			return []byte(`{"com.xiak.matrix.managed":"true","com.xiak.matrix.installation":"mxi-11111111111111111111111111111111"}`), true, nil
		default:
			return nil, true, nil
		}
	}}
	if err := rejectProjectCollision(
		context.Background(), owned, "matrix-mxi", "mxi-11111111111111111111111111111111",
	); err != nil {
		t.Fatalf("installation-owned project collision: %v", err)
	}
}

func TestCompareProviderVersionUsesSemanticComponents(t *testing.T) {
	tests := []struct {
		actual  string
		minimum string
		want    int
	}{
		{actual: "29.0.1", minimum: "29.0.0", want: 1},
		{actual: "v29.0.0", minimum: "29.0.0", want: 0},
		{actual: "28.10.0", minimum: "29.0.0", want: -1},
		{actual: "2.40.0-desktop.1", minimum: "2.40.0", want: 0},
		{actual: "latest", minimum: "2.40.0", want: -1},
	}
	for _, test := range tests {
		if got := compareProviderVersion(test.actual, test.minimum); got != test.want {
			t.Errorf("compareProviderVersion(%q, %q) = %d, want %d", test.actual, test.minimum, got, test.want)
		}
	}
}

func TestLocalDockerEnvironmentPinsThePhaseOneEngineAndComposeInput(t *testing.T) {
	environment := localDockerEnvironment([]string{
		"PATH=/usr/bin",
		"DOCKER_HOST=tcp://remote.example:2376",
		"docker_context=remote",
		"DOCKER_API_VERSION=1.20",
		"COMPOSE_FILE=/tmp/untrusted.yaml",
		"COMPOSE_PROJECT_NAME=untrusted",
		"COMPOSE_ENV_FILES=/tmp/untrusted.env",
		"COMPOSE_DISABLE_ENV_FILE=0",
		"COMPOSE_REMOVE_ORPHANS=1",
	})
	values := make(map[string][]string)
	for _, entry := range environment {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			t.Fatalf("Docker environment entry is malformed: %q", entry)
		}
		values[strings.ToUpper(key)] = append(values[strings.ToUpper(key)], value)
	}
	if !slices.Equal(values["PATH"], []string{"/usr/bin"}) ||
		!slices.Equal(values["DOCKER_HOST"], []string{"unix:///var/run/docker.sock"}) ||
		len(values["DOCKER_CONTEXT"]) != 0 || len(values["DOCKER_API_VERSION"]) != 0 ||
		len(values["COMPOSE_FILE"]) != 0 || len(values["COMPOSE_PROJECT_NAME"]) != 0 ||
		len(values["COMPOSE_ENV_FILES"]) != 0 ||
		!slices.Equal(values["COMPOSE_DISABLE_ENV_FILE"], []string{"1"}) ||
		!slices.Equal(values["COMPOSE_REMOVE_ORPHANS"], []string{"false"}) {
		t.Fatalf("fixed Docker command environment = %#v", values)
	}
}

func TestGeneratedCredentialKindsCannotBeSubstituted(t *testing.T) {
	random := strings.Repeat("A", 43)
	service := []byte("mx1." + random)
	database := []byte("mxp1." + random)
	administrator := []byte("mxp1." + random + "-Aa1!")
	if !validGeneratedCredential(service, "mx1.", false) ||
		!validGeneratedCredential(database, "mxp1.", false) ||
		!validGeneratedCredential(administrator, "mxp1.", true) {
		t.Fatal("canonical generated credential was rejected")
	}
	if validGeneratedCredential(service, "mxp1.", false) ||
		validGeneratedCredential(database, "mx1.", false) ||
		validGeneratedCredential(administrator, "mxp1.", false) ||
		validGeneratedCredential(database, "mxp1.", true) {
		t.Fatal("generated credential was accepted for a different authority kind")
	}
}

func newInstallPlan(t *testing.T, profiles ...release.DatabaseProfile) platformcommand.InstallPlan {
	t.Helper()
	fixtures, err := releasetest.WriteSequence(t.TempDir(), 1, profiles...)
	if err != nil {
		t.Fatalf("write release fixture: %v", err)
	}
	fixture := fixtures[0]
	trustBytes, err := os.ReadFile(fixture.TrustPath)
	if err != nil {
		t.Fatalf("read release trust: %v", err)
	}
	bundle, err := release.VerifyDirectory(fixture.Root, trustBytes)
	if err != nil {
		t.Fatalf("verify release fixture: %v", err)
	}
	root := filepath.Clean(t.TempDir())
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("protect installation fixture root: %v", err)
	}
	return platformcommand.InstallPlan{
		Root: root, InstallationID: "mxi-11111111111111111111111111111111",
		CorrelationID: "cmd-11111111111111111111111111111111",
		Listener:      "0.0.0.0", Port: 8080, Bundle: bundle,
		Trust: fixture.Trust, TrustBytes: trustBytes,
	}
}

func newUpgradePlan(t *testing.T, profiles ...release.DatabaseProfile) platformcommand.UpgradePlan {
	t.Helper()
	fixtures, err := releasetest.WriteSequence(t.TempDir(), 2, profiles...)
	if err != nil {
		t.Fatalf("write upgrade release fixtures: %v", err)
	}
	trustBytes, err := os.ReadFile(fixtures[0].TrustPath)
	if err != nil {
		t.Fatalf("read upgrade release trust: %v", err)
	}
	bundles := make([]release.VerifiedBundle, len(fixtures))
	for index, fixture := range fixtures {
		bundles[index], err = release.VerifyDirectory(fixture.Root, trustBytes)
		if err != nil {
			t.Fatalf("verify upgrade release %d: %v", index, err)
		}
	}
	root := filepath.Clean(t.TempDir())
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("protect upgrade fixture root: %v", err)
	}
	source := platformcommand.InstallPlan{
		Root: root, InstallationID: "mxi-11111111111111111111111111111111",
		CorrelationID: "cmd-11111111111111111111111111111111",
		Listener:      "0.0.0.0", Port: 8080, Bundle: bundles[0],
		Trust: fixtures[0].Trust, TrustBytes: trustBytes,
	}
	if err := stageInstallation(source, rand.Reader); err != nil {
		t.Fatalf("stage upgrade source: %v", err)
	}
	if err := configureInstallation(
		context.Background(), newImageRuntime(source.Bundle.Manifest, true), source,
	); err != nil {
		t.Fatalf("configure upgrade source: %v", err)
	}
	target := source
	target.Bundle = bundles[1]
	target.PreviousID = source.Bundle.Manifest.Release.ID
	target.PreviousDigest = source.Bundle.ManifestSHA256
	if err := stageInstallation(target, rand.Reader); err != nil {
		t.Fatalf("stage upgrade target: %v", err)
	}
	return platformcommand.UpgradePlan{
		Source: installedPlanFrom(source), Target: target,
		BackupID:  "backup-11111111111111111111111111111111",
		CreatedAt: time.Date(2026, 8, 26, 6, 0, 0, 0, time.UTC),
	}
}

func assertReleaseConfiguration(
	t *testing.T,
	plan platformcommand.InstallPlan,
	catalogManifests ...release.Manifest,
) {
	t.Helper()
	compiled, err := topology.Compile(plan.Bundle.Manifest, topology.Options{
		InstallationID: plan.InstallationID, Root: plan.Root,
		Listener: plan.Listener, Port: plan.Port,
	})
	if err != nil {
		t.Fatalf("compile expected release configuration: %v", err)
	}
	if actual := readTestFile(t, plan.Root, layout.Compose); !bytes.Equal(actual, compiled.ComposeJSON) {
		t.Fatal("installed Compose configuration differs from authenticated release")
	}
	if len(catalogManifests) == 0 {
		catalogManifests = []release.Manifest{plan.Bundle.Manifest}
	}
	catalog, err := artifactCatalogConfig(catalogManifests...)
	if err != nil {
		t.Fatalf("compile expected artifact catalog: %v", err)
	}
	if actual := readTestFile(t, plan.Root, layout.ArtifactCatalog); !bytes.Equal(actual, catalog) {
		t.Fatal("installed artifact catalog differs from authenticated release")
	}
}

func installedPlanFrom(plan platformcommand.InstallPlan) platformcommand.InstalledPlan {
	return platformcommand.InstalledPlan{
		Root: plan.Root, InstallationID: plan.InstallationID,
		CorrelationID: plan.CorrelationID,
		Listener:      plan.Listener, Port: plan.Port,
		ReleaseID:        plan.Bundle.Manifest.Release.ID,
		ReleaseDigest:    plan.Bundle.ManifestSHA256,
		PreviousID:       plan.PreviousID,
		PreviousDigest:   plan.PreviousDigest,
		TrustKeyID:       plan.Trust.KeyID,
		TrustFingerprint: plan.Trust.PublicKeyFingerprint,
	}
}

func readTestFile(t *testing.T, root, relative string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	return content
}

func snapshotManagedCredentials(t *testing.T, root string) map[string]string {
	t.Helper()
	paths := []string{
		layout.ReleaseTrust, layout.IAMBootstrap, layout.AuditIAMCredential,
		layout.IAMAuditCredential, layout.PaaSIAMCredential, layout.PaaSAuditCredential,
		layout.InstallationVerifierCredential, layout.AuditCursorKey,
		layout.BackupSealKey,
		layout.InitialAdministratorPassword,
		layout.PostgresPassword, layout.PostgresMigration, layout.IAMAPI,
		layout.IAMWorker, layout.AuditRuntime, layout.PaaSAPI, layout.PaaSWorker,
		layout.IAMCredentialRecovery,
		layout.IAMLocalRecoveryAuthority,
	}
	result := make(map[string]string, len(paths))
	for _, path := range paths {
		result[path] = string(readTestFile(t, root, path))
	}
	return result
}

func equalSnapshots(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for path, content := range left {
		if right[path] != content {
			return false
		}
	}
	return true
}

type failingEntropy struct{}

func (failingEntropy) Read([]byte) (int, error) {
	return 0, errors.New("unexpected entropy read")
}

type imageRuntime struct {
	present          map[string]bool
	payloadToImageID map[string]string
	commands         [][]string
	loads            []string
	failLoad         bool
}

func newImageRuntime(manifest release.Manifest, present bool) *imageRuntime {
	result := &imageRuntime{
		present:          make(map[string]bool, len(manifest.Images)),
		payloadToImageID: make(map[string]string, len(manifest.Images)),
	}
	for _, image := range manifest.Images {
		result.present[image.ImageID] = present
		result.payloadToImageID["matrix-release-payload:"+image.ArchivePath] = image.ImageID
	}
	return result
}

func (runtimeBoundary *imageRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	runtimeBoundary.commands = append(runtimeBoundary.commands, slices.Clone(arguments))
	switch {
	case slices.Equal(arguments[:min(len(arguments), 2)], []string{"image", "inspect"}):
		if len(arguments) != 5 || input != nil {
			return nil, false, errors.New("invalid image inspect command")
		}
		imageID := arguments[4]
		if !runtimeBoundary.present[imageID] {
			return nil, true, errors.New("image absent")
		}
		return []byte(imageID + "|linux|amd64\n"), true, nil
	case slices.Equal(arguments, []string{"image", "load", "--quiet"}):
		if input == nil {
			return nil, false, errors.New("image archive stdin is absent")
		}
		content, err := io.ReadAll(input)
		if err != nil {
			return nil, true, err
		}
		imageID, found := runtimeBoundary.payloadToImageID[string(content)]
		if !found {
			return nil, true, errors.New("image archive stdin is unauthenticated")
		}
		runtimeBoundary.loads = append(runtimeBoundary.loads, imageID)
		if runtimeBoundary.failLoad {
			return nil, true, errors.New("image load interrupted")
		}
		runtimeBoundary.present[imageID] = true
		return nil, true, nil
	default:
		return nil, false, fmt.Errorf("unexpected Docker command: %q", strings.Join(arguments, " "))
	}
}

type scriptedRuntime struct {
	run func([]string) ([]byte, bool, error)
}

type migrationRuntime struct {
	images         map[string]bool
	project        string
	installation   string
	release        string
	composeCalls   int
	runs           [][]string
	controlNetwork string
}

type platformStartRuntime struct {
	expectation               platformComposeExpectation
	images                    map[string]bool
	started                   bool
	resourceDriftService      string
	userDriftService          string
	portDriftService          string
	configHashDriftService    string
	unhealthyService          string
	failObservationAfterStart bool
	composeCalls              int
	observationsBeforeStart   int
	composeArguments          []string
	migrationRuns             [][]string
	databaseDump              []byte
	backupStreams             int
	restoreChecks             int
	recoveryRestores          int
	postgresOnly              bool
	networkCreated            bool
	removedContainers         map[string]bool
	removedNetworks           map[string]bool
	providerRemovals          int
	probe                     *recoveryProbeRuntime
}

type platformCleanupRuntime struct {
	expectation            platformComposeExpectation
	installation           string
	containers             map[string]platformContainerInspection
	networks               map[string]platformNetworkInspection
	migrationID            string
	containerRemovals      int
	networkRemovals        int
	unexpectedRemovals     int
	failStartedRemovalOnce bool
	failedStartedRemoval   bool
}

const platformTestConfigHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func newPlatformStartRuntime(
	plan platformcommand.InstallPlan,
	expectation platformComposeExpectation,
) *platformStartRuntime {
	images := make(map[string]bool, len(plan.Bundle.Manifest.Images))
	for _, image := range plan.Bundle.Manifest.Images {
		images[image.ImageID] = true
	}
	return &platformStartRuntime{
		expectation: expectation, images: images,
		databaseDump: []byte("matrix-postgresql-custom-backup-fixture"),
	}
}

func newPlatformCleanupRuntime(
	t *testing.T,
	plan platformcommand.InstallPlan,
	expectation platformComposeExpectation,
) *platformCleanupRuntime {
	t.Helper()
	runtimeBoundary := &platformCleanupRuntime{
		expectation:  expectation,
		installation: plan.InstallationID,
		containers:   make(map[string]platformContainerInspection, len(expectation.Services)+1),
		networks:     make(map[string]platformNetworkInspection, len(expectation.Networks)),
		migrationID:  "migration-test-container",
	}
	for serviceName, expected := range expectation.Services {
		identity := "container-" + serviceName
		labels := cloneTestLabels(expected.Labels)
		labels["com.docker.compose.project"] = expectation.Name
		labels["com.docker.compose.service"] = serviceName
		labels["com.docker.compose.oneoff"] = "False"
		runtimeBoundary.containers[identity] = platformContainerInspection{
			ID: identity, Name: "/" + expectation.Name + "-" + serviceName + "-1",
			Image: expected.Image, Config: platformContainerConfig{Labels: labels},
		}
	}
	for logicalName, expected := range expectation.Networks {
		identity := "network-" + logicalName
		labels := cloneTestLabels(expected.Labels)
		labels["com.docker.compose.project"] = expectation.Name
		labels["com.docker.compose.network"] = logicalName
		runtimeBoundary.networks[identity] = platformNetworkInspection{
			ID: identity, Internal: expected.Internal, Labels: labels,
		}
	}
	migrations, err := expectedMigrationCleanupIdentities(plan, expectation.Name)
	if err != nil {
		t.Fatalf("derive cleanup migration identities: %v", err)
	}
	names := make([]string, 0, len(migrations))
	for name := range migrations {
		names = append(names, name)
	}
	slices.Sort(names)
	selected := migrations[names[0]]
	runtimeBoundary.containers[runtimeBoundary.migrationID] = platformContainerInspection{
		ID: runtimeBoundary.migrationID, Name: "/" + names[0], Image: selected.imageID,
		Config: platformContainerConfig{Labels: cloneTestLabels(selected.labels)},
	}
	return runtimeBoundary
}

func (runtimeBoundary *platformCleanupRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	if input != nil || len(arguments) < 2 {
		return nil, false, errors.New("platform cleanup Docker invocation is invalid")
	}
	if arguments[1] == "ls" {
		switch arguments[0] {
		case "container":
			if hasArgumentPair(
				arguments, "--filter",
				"label=com.xiak.matrix.installation="+runtimeBoundary.installation,
			) {
				return cleanupContainerInventory(runtimeBoundary.containers, "", ""), true, nil
			}
			return cleanupContainerInventory(
				runtimeBoundary.containers,
				"com.docker.compose.project", runtimeBoundary.expectation.Name,
			), true, nil
		case "network":
			return cleanupNetworkInventory(
				runtimeBoundary.networks,
				"com.docker.compose.project", runtimeBoundary.expectation.Name,
			), true, nil
		case "volume":
			return nil, true, nil
		}
	}
	identity := arguments[len(arguments)-1]
	if arguments[1] == "inspect" {
		switch arguments[0] {
		case "container":
			inspection, found := runtimeBoundary.containers[identity]
			if !found {
				return nil, true, errors.New("cleanup test container is absent")
			}
			content, err := json.Marshal(inspection)
			return content, true, err
		case "network":
			inspection, found := runtimeBoundary.networks[identity]
			if !found {
				return nil, true, errors.New("cleanup test network is absent")
			}
			content, err := json.Marshal(inspection)
			return content, true, err
		}
	}
	if arguments[1] == "rm" {
		removed := false
		switch arguments[0] {
		case "container":
			if !slices.Contains(arguments, "--force") ||
				!slices.Contains(arguments, "--volumes") {
				runtimeBoundary.unexpectedRemovals++
				return nil, false, errors.New("cleanup test container removal is incomplete")
			}
			if _, found := runtimeBoundary.containers[identity]; found {
				delete(runtimeBoundary.containers, identity)
				runtimeBoundary.containerRemovals++
				removed = true
			}
		case "network":
			if _, found := runtimeBoundary.networks[identity]; found {
				delete(runtimeBoundary.networks, identity)
				runtimeBoundary.networkRemovals++
				removed = true
			}
		default:
			runtimeBoundary.unexpectedRemovals++
		}
		if !removed {
			return nil, true, errors.New("cleanup test object is absent or unsupported")
		}
		if runtimeBoundary.failStartedRemovalOnce && !runtimeBoundary.failedStartedRemoval {
			runtimeBoundary.failedStartedRemoval = true
			return nil, true, errors.New("cleanup test removal outcome is unknown")
		}
		return nil, true, nil
	}
	runtimeBoundary.unexpectedRemovals++
	return nil, false, fmt.Errorf("unexpected cleanup Docker command: %q", strings.Join(arguments, " "))
}

func cleanupContainerInventory(
	containers map[string]platformContainerInspection,
	label, value string,
) []byte {
	identities := make([]string, 0, len(containers))
	for identity, inspection := range containers {
		if label == "" || inspection.Config.Labels[label] == value {
			identities = append(identities, identity)
		}
	}
	slices.Sort(identities)
	if len(identities) == 0 {
		return nil
	}
	return []byte(strings.Join(identities, "\n") + "\n")
}

func cleanupNetworkInventory(
	networks map[string]platformNetworkInspection,
	label, value string,
) []byte {
	identities := make([]string, 0, len(networks))
	for identity, inspection := range networks {
		if inspection.Labels[label] == value {
			identities = append(identities, identity)
		}
	}
	slices.Sort(identities)
	if len(identities) == 0 {
		return nil
	}
	return []byte(strings.Join(identities, "\n") + "\n")
}

func (runtimeBoundary *platformStartRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	if runtimeBoundary.probe != nil && runtimeBoundary.probe.handles(arguments) {
		return runtimeBoundary.probe.Run(context.Background(), input, arguments...)
	}
	if len(arguments) >= 2 && arguments[1] == "ls" {
		for _, argument := range arguments {
			const prefix = "label=com.docker.compose.project="
			if strings.HasPrefix(argument, prefix) &&
				strings.TrimPrefix(argument, prefix) != runtimeBoundary.expectation.Name {
				return nil, true, nil
			}
		}
	}
	if len(arguments) == 0 {
		return nil, false, errors.New("platform start Docker invocation is invalid")
	}
	if input != nil {
		return nil, false, errors.New("platform start Docker invocation has unexpected stdin")
	}
	if arguments[0] == "exec" && slices.Contains(arguments, "psql") {
		if !slices.Contains(arguments, "--no-password") {
			return nil, false, errors.New("platform database observation may prompt for a password")
		}
		return []byte("1048576\n"), true, nil
	}
	if len(arguments) == 5 && arguments[0] == "image" && arguments[1] == "inspect" {
		imageID := arguments[4]
		if !runtimeBoundary.images[imageID] {
			return nil, true, errors.New("platform image is absent")
		}
		return []byte(imageID + "|linux|amd64\n"), true, nil
	}
	if arguments[0] == "compose" && slices.Contains(arguments, "config") {
		services := make([]string, 0, len(runtimeBoundary.expectation.Services))
		for service := range runtimeBoundary.expectation.Services {
			services = append(services, service+" "+platformTestConfigHash)
		}
		slices.Sort(services)
		return []byte(strings.Join(services, "\n") + "\n"), true, nil
	}
	if arguments[0] == "compose" {
		if !hasArgumentPair(arguments, "--pull", "never") ||
			!slices.Contains(arguments, "--no-build") ||
			!slices.Contains(arguments, "up") {
			return nil, true, errors.New("platform Compose invocation is not fixed offline input")
		}
		runtimeBoundary.composeCalls++
		runtimeBoundary.composeArguments = slices.Clone(arguments)
		runtimeBoundary.started = true
		runtimeBoundary.postgresOnly = arguments[len(arguments)-1] == "postgres"
		runtimeBoundary.networkCreated = true
		runtimeBoundary.removedContainers = make(map[string]bool)
		runtimeBoundary.removedNetworks = make(map[string]bool)
		return nil, true, nil
	}
	if arguments[0] == "run" {
		runtimeBoundary.migrationRuns = append(
			runtimeBoundary.migrationRuns, slices.Clone(arguments),
		)
		return nil, true, nil
	}
	if len(arguments) >= 2 && arguments[1] == "ls" {
		if !runtimeBoundary.started && !runtimeBoundary.networkCreated {
			runtimeBoundary.observationsBeforeStart++
			return nil, true, nil
		}
		if runtimeBoundary.failObservationAfterStart {
			return nil, true, errors.New("platform observation is temporarily unavailable")
		}
		switch arguments[0] {
		case "container":
			if !runtimeBoundary.started {
				return nil, true, nil
			}
			services := make([]string, 0, len(runtimeBoundary.expectation.Services))
			for service := range runtimeBoundary.expectation.Services {
				if (runtimeBoundary.postgresOnly && service != "postgres") ||
					runtimeBoundary.removedContainers[service] {
					continue
				}
				services = append(services, "container-"+service)
			}
			slices.Sort(services)
			return []byte(strings.Join(services, "\n") + "\n"), true, nil
		case "network":
			if hasArgumentPair(
				arguments, "--filter", "label=com.docker.compose.network=control",
			) {
				if runtimeBoundary.removedNetworks["control"] {
					return nil, true, nil
				}
				return []byte("network-control\n"), true, nil
			}
			networks := make([]string, 0, len(runtimeBoundary.expectation.Networks))
			for network := range runtimeBoundary.expectation.Networks {
				if runtimeBoundary.removedNetworks[network] {
					continue
				}
				networks = append(networks, "network-"+network)
			}
			slices.Sort(networks)
			return []byte(strings.Join(networks, "\n") + "\n"), true, nil
		case "volume":
			return nil, true, nil
		}
	}
	if len(arguments) >= 2 && arguments[1] == "rm" {
		identity := arguments[len(arguments)-1]
		switch arguments[0] {
		case "container":
			service := strings.TrimPrefix(identity, "container-")
			_, expected := runtimeBoundary.expectation.Services[service]
			active := expected && runtimeBoundary.started &&
				(!runtimeBoundary.postgresOnly || service == "postgres") &&
				!runtimeBoundary.removedContainers[service]
			if !active || !slices.Contains(arguments, "--force") ||
				!slices.Contains(arguments, "--volumes") {
				return nil, true, errors.New("platform test container removal is invalid")
			}
			if !runtimeBoundary.networkCreated {
				runtimeBoundary.networkCreated = true
			}
			if runtimeBoundary.removedContainers == nil {
				runtimeBoundary.removedContainers = make(map[string]bool)
			}
			runtimeBoundary.removedContainers[service] = true
			activeCount := len(runtimeBoundary.expectation.Services)
			if runtimeBoundary.postgresOnly {
				activeCount = 1
			}
			if len(runtimeBoundary.removedContainers) == activeCount {
				runtimeBoundary.started = false
				runtimeBoundary.postgresOnly = false
			}
		case "network":
			network := strings.TrimPrefix(identity, "network-")
			_, expected := runtimeBoundary.expectation.Networks[network]
			if !expected || (!runtimeBoundary.networkCreated && !runtimeBoundary.started) ||
				runtimeBoundary.removedNetworks[network] {
				return nil, true, errors.New("platform test network removal is invalid")
			}
			if runtimeBoundary.removedNetworks == nil {
				runtimeBoundary.removedNetworks = make(map[string]bool)
			}
			runtimeBoundary.removedNetworks[network] = true
			if len(runtimeBoundary.removedNetworks) == len(runtimeBoundary.expectation.Networks) {
				runtimeBoundary.networkCreated = false
			}
		default:
			return nil, false, errors.New("platform test provider removal is unsupported")
		}
		runtimeBoundary.providerRemovals++
		return nil, true, nil
	}
	if len(arguments) >= 2 && arguments[1] == "inspect" {
		switch arguments[0] {
		case "network":
			if hasArgumentPair(arguments, "--format", "{{json .Labels}}") {
				return runtimeBoundary.inspectNetworkLabels(arguments[len(arguments)-1])
			}
			return runtimeBoundary.inspectNetwork(arguments[len(arguments)-1])
		case "container":
			return runtimeBoundary.inspectContainer(arguments[len(arguments)-1])
		}
	}
	return nil, false, fmt.Errorf("unexpected platform Docker command: %q", strings.Join(arguments, " "))
}

func (runtimeBoundary *platformStartRuntime) RunTo(
	_ context.Context,
	input io.Reader,
	output io.Writer,
	arguments ...string,
) (bool, error) {
	if output == nil {
		return false, errors.New("platform backup streaming invocation is invalid")
	}
	if slices.Contains(arguments, "pg_restore") {
		if input == nil {
			return false, errors.New("backup verification stdin is absent")
		}
		content, err := io.ReadAll(input)
		if err != nil || !bytes.Equal(content, runtimeBoundary.databaseDump) {
			return true, errors.New("backup verification content is invalid")
		}
		if slices.Contains(arguments, "--list") {
			if slices.Contains(arguments, "--clean") {
				return true, errors.New("backup verification unexpectedly mutates the database")
			}
			runtimeBoundary.restoreChecks++
			_, err = output.Write([]byte("; Archive created for test\n"))
			return true, err
		}
		return true, errors.New("recovery used direct pg_restore outside its schema-reset transaction")
	}
	if slices.Contains(arguments, databaseRestoreScript) {
		if input == nil {
			return false, errors.New("recovery restore stdin is absent")
		}
		content, err := io.ReadAll(input)
		if err != nil || !bytes.Equal(content, runtimeBoundary.databaseDump) {
			return true, errors.New("recovery restore content is invalid")
		}
		wantTail := []string{
			"/bin/bash", "-o", "pipefail", "-ceu", databaseRestoreScript,
		}
		if len(arguments) < len(wantTail) ||
			!slices.Equal(arguments[len(arguments)-len(wantTail):], wantTail) ||
			!hasArgumentPair(arguments, "--user", "postgres") {
			return true, errors.New("recovery restore process boundary is invalid")
		}
		for _, required := range []string{
			"BEGIN;", "DROP SCHEMA IF EXISTS audit, iam, managedservice, paas CASCADE;",
			"pg_restore --file=- --exit-on-error --no-privileges --no-password",
			"COMMIT;", "ROLLBACK;", "psql -X --set=ON_ERROR_STOP=1",
			"--username=matrix --dbname=matrix",
		} {
			if !strings.Contains(databaseRestoreScript, required) {
				return true, fmt.Errorf("recovery restore transaction lacks %s", required)
			}
		}
		for _, forbidden := range []string{"--clean", "--no-owner"} {
			if strings.Contains(databaseRestoreScript, forbidden) {
				return true, fmt.Errorf("recovery restore transaction contains %s", forbidden)
			}
		}
		runtimeBoundary.recoveryRestores++
		return true, nil
	}
	if input != nil || !slices.Contains(arguments, "pg_dump") ||
		slices.Contains(arguments, "--no-owner") ||
		!slices.Contains(arguments, "--no-privileges") ||
		!slices.Contains(arguments, "--no-password") {
		return false, errors.New("platform backup streaming invocation is invalid")
	}
	runtimeBoundary.backupStreams++
	_, err := output.Write(runtimeBoundary.databaseDump)
	return true, err
}

func (runtimeBoundary *platformStartRuntime) inspectNetworkLabels(
	identity string,
) ([]byte, bool, error) {
	logicalName := strings.TrimPrefix(identity, "network-")
	expected, found := runtimeBoundary.expectation.Networks[logicalName]
	if !found {
		return nil, true, errors.New("platform test network is unknown")
	}
	labels := cloneTestLabels(expected.Labels)
	labels["com.docker.compose.project"] = runtimeBoundary.expectation.Name
	labels["com.docker.compose.network"] = logicalName
	content, err := json.Marshal(labels)
	return content, true, err
}

func (runtimeBoundary *platformStartRuntime) inspectNetwork(
	identity string,
) ([]byte, bool, error) {
	logicalName := strings.TrimPrefix(identity, "network-")
	expected, found := runtimeBoundary.expectation.Networks[logicalName]
	if !found {
		return nil, true, errors.New("platform test network is unknown")
	}
	labels := cloneTestLabels(expected.Labels)
	labels["com.docker.compose.project"] = runtimeBoundary.expectation.Name
	labels["com.docker.compose.network"] = logicalName
	content, err := json.Marshal(map[string]any{
		"Id": identity, "Internal": expected.Internal, "Labels": labels,
	})
	return content, true, err
}

func (runtimeBoundary *platformStartRuntime) inspectContainer(
	identity string,
) ([]byte, bool, error) {
	serviceName := strings.TrimPrefix(identity, "container-")
	expected, found := runtimeBoundary.expectation.Services[serviceName]
	if !found {
		return nil, true, errors.New("platform test service is unknown")
	}
	labels := cloneTestLabels(expected.Labels)
	labels["com.docker.compose.project"] = runtimeBoundary.expectation.Name
	labels["com.docker.compose.service"] = serviceName
	labels["com.docker.compose.oneoff"] = "False"
	labels["com.docker.compose.config-hash"] = platformTestConfigHash
	if runtimeBoundary.configHashDriftService == serviceName &&
		runtimeBoundary.composeCalls == 0 {
		labels["com.docker.compose.config-hash"] = strings.Repeat("b", 64)
	}
	imageID := expected.Image
	mounts := make([]map[string]any, 0, len(expected.Volumes))
	for _, mount := range expected.Volumes {
		mounts = append(mounts, map[string]any{
			"Type": mount.Type, "Source": mount.Source,
			"Destination": mount.Target, "RW": !mount.ReadOnly,
		})
	}
	networks := make(map[string]any, len(expected.Networks))
	for _, network := range expected.Networks {
		networks[runtimeBoundary.expectation.Name+"_"+network] = map[string]any{
			"NetworkID": "network-" + network,
		}
	}
	ports, err := testPortBindings(expected.Ports)
	if err != nil {
		return nil, true, err
	}
	publishedPorts := ports
	if runtimeBoundary.portDriftService == serviceName {
		publishedPorts = map[string][]map[string]string{}
	}
	initEnabled := expected.Init
	nanoCPUs, memory, err := expectedResourceLimits(expected.Deploy)
	if err != nil {
		return nil, true, err
	}
	if runtimeBoundary.resourceDriftService == serviceName {
		memory++
	}
	tmpfs, err := expectedTmpfsInventory(expected.Tmpfs)
	if err != nil {
		return nil, true, err
	}
	user := expected.User
	if runtimeBoundary.userDriftService == serviceName {
		user = "636:636"
	}
	health := "healthy"
	if runtimeBoundary.unhealthyService == serviceName {
		health = "unhealthy"
	}
	content, err := json.Marshal(map[string]any{
		"Id": identity, "Image": imageID,
		"Config": map[string]any{"Labels": labels, "User": user},
		"State": map[string]any{
			"Status": "running", "Running": true,
			"Health": map[string]any{"Status": health},
		},
		"HostConfig": map[string]any{
			"Privileged": false, "ReadonlyRootfs": expected.ReadOnly,
			"Init": &initEnabled, "Memory": memory, "NanoCpus": nanoCPUs,
			"CapAdd": expected.CapAdd, "CapDrop": []string{"ALL"}, "Tmpfs": tmpfs,
			"SecurityOpt":   []string{"no-new-privileges:true"},
			"PortBindings":  ports,
			"RestartPolicy": map[string]any{"Name": expected.Restart},
		},
		"Mounts":          mounts,
		"NetworkSettings": map[string]any{"Networks": networks, "Ports": publishedPorts},
	})
	return content, true, err
}

func testPortBindings(values []string) (map[string][]map[string]string, error) {
	result := make(map[string][]map[string]string, len(values))
	for _, value := range values {
		separator := strings.LastIndexByte(value, ':')
		if separator < 1 || separator == len(value)-1 {
			return nil, errors.New("platform test port binding is invalid")
		}
		hostIP, hostPort, err := net.SplitHostPort(value[:separator])
		if err != nil {
			return nil, err
		}
		containerPort := value[separator+1:]
		result[containerPort] = append(result[containerPort], map[string]string{
			"HostIp": hostIP, "HostPort": hostPort,
		})
	}
	return result, nil
}

func cloneTestLabels(source map[string]string) map[string]string {
	result := make(map[string]string, len(source)+3)
	for key, value := range source {
		result[key] = value
	}
	return result
}

func newMigrationRuntime(plan platformcommand.InstallPlan, project string) *migrationRuntime {
	images := make(map[string]bool, len(plan.Bundle.Manifest.Images))
	for _, image := range plan.Bundle.Manifest.Images {
		images[image.ImageID] = true
	}
	return &migrationRuntime{
		images: images, project: project, installation: plan.InstallationID,
		release:        plan.Bundle.Manifest.Release.ID,
		controlNetwork: strings.Repeat("a", 64),
	}
}

func (runtimeBoundary *migrationRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	if input != nil || len(arguments) == 0 {
		return nil, false, errors.New("migration Docker invocation is invalid")
	}
	switch arguments[0] {
	case "compose":
		if !hasArgumentPair(arguments, "--pull", "never") ||
			!slices.Contains(arguments, "--no-build") ||
			arguments[len(arguments)-1] != "postgres" {
			return nil, true, errors.New("PostgreSQL Compose start is not offline")
		}
		runtimeBoundary.composeCalls++
		return nil, true, nil
	case "network":
		if len(arguments) >= 2 && arguments[1] == "ls" {
			return []byte(runtimeBoundary.controlNetwork + "\n"), true, nil
		}
		if len(arguments) >= 2 && arguments[1] == "inspect" {
			return []byte(fmt.Sprintf(
				`{"com.xiak.matrix.managed":"true","com.xiak.matrix.installation":%q,"com.xiak.matrix.release":%q,"com.xiak.matrix.role":"network-control","com.docker.compose.project":%q,"com.docker.compose.network":"control"}`,
				runtimeBoundary.installation, runtimeBoundary.release, runtimeBoundary.project,
			)), true, nil
		}
	case "image":
		if len(arguments) == 5 && arguments[1] == "inspect" && runtimeBoundary.images[arguments[4]] {
			return []byte(arguments[4] + "|linux|amd64\n"), true, nil
		}
	case "run":
		runtimeBoundary.runs = append(runtimeBoundary.runs, slices.Clone(arguments))
		return nil, true, nil
	}
	return nil, false, fmt.Errorf("unexpected migration Docker command: %q", strings.Join(arguments, " "))
}

func hasArgumentPair(arguments []string, name, value string) bool {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name && arguments[index+1] == value {
			return true
		}
	}
	return false
}

func (runtimeBoundary *scriptedRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
	if input != nil {
		return nil, false, errors.New("unexpected Docker stdin")
	}
	return runtimeBoundary.run(arguments)
}
