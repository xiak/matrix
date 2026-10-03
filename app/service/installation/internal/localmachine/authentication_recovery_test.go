package localmachine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

func TestAuthenticationRecoveryInvocationRemovesKnownWorkAndRetainsUnknownWork(t *testing.T) {
	for _, scenario := range []struct {
		name, existingState        string
		exitCode, existingExitCode int
		attachErr                  bool
		want                       error
		wantStarts, wantRemoves    int
	}{
		{name: "success", wantStarts: 1, wantRemoves: 1},
		{name: "invalid", exitCode: 2, want: platformcommand.ErrEffectVerification, wantStarts: 1, wantRemoves: 1},
		{name: "forbidden", exitCode: 3, want: platformcommand.ErrEffectPrecondition, wantStarts: 1, wantRemoves: 1},
		{name: "conflict", exitCode: 4, want: platformcommand.ErrEffectConflict, wantStarts: 1, wantRemoves: 1},
		{name: "unavailable", exitCode: 6, want: platformcommand.ErrEffectOutcomeUnknown, wantStarts: 1, wantRemoves: 1},
		{name: "committed but attach lost", attachErr: true, want: platformcommand.ErrEffectOutcomeUnknown, wantStarts: 1, wantRemoves: 1},
		{name: "resume created invocation", existingState: "created", wantStarts: 1, wantRemoves: 1},
		{name: "prior invocation still running", existingState: "running", want: platformcommand.ErrEffectOutcomeUnknown},
		{name: "replay prior successful invocation", existingState: "exited", wantStarts: 1, wantRemoves: 2},
		{name: "retain prior rejection", existingState: "exited", existingExitCode: 3, want: platformcommand.ErrEffectPrecondition, wantRemoves: 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			expected, actual := authenticationRecoveryInvocationFixture(installationv1.AuthenticationRecoveryCloseCommand)
			runtimeBoundary := &authenticationRecoveryInvocationRuntime{
				container: actual, exitCode: scenario.exitCode, attachErr: scenario.attachErr,
			}
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
			output, err := invokeAuthenticationRecoveryEntry(
				context.Background(), runtimeBoundary, []string{"container", "create"}, expected,
			)
			if !errors.Is(err, scenario.want) || runtimeBoundary.starts != scenario.wantStarts ||
				runtimeBoundary.removes != scenario.wantRemoves {
				t.Fatalf("one-shot outcome=%v starts=%d removals=%d", err, runtimeBoundary.starts, runtimeBoundary.removes)
			}
			if err != nil && (len(output) != 0 || strings.Contains(err.Error(), "private-native-error")) {
				t.Fatal("unverified output or provider error escaped")
			}
		})
	}
}

func TestAuthenticationRecoveryCompletionAnchorAdvancesOnlyAcrossExactEpochs(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	intentOne, closureOne, completionOne := authenticationRecoveryEvidenceFixture(t, 1, 'a')
	writeAuthenticationRecoveryClosure(t, root, intentOne, closureOne)
	if err := persistAuthenticationRecoveryCompletion(root, intentOne, closureOne, completionOne); err != nil {
		t.Fatal(err)
	}
	before := readTestFile(t, root, layout.IAMAuthenticationRecoveryCompletion)
	if err := persistAuthenticationRecoveryCompletion(root, intentOne, closureOne, completionOne); err != nil ||
		!bytes.Equal(before, readTestFile(t, root, layout.IAMAuthenticationRecoveryCompletion)) {
		t.Fatal("equal completion did not replay")
	}

	skippedIntent, skippedClosure, skippedCompletion := authenticationRecoveryEvidenceFixture(t, 3, 'c')
	writeAuthenticationRecoveryClosure(t, root, skippedIntent, skippedClosure)
	if err := persistAuthenticationRecoveryCompletion(root, skippedIntent, skippedClosure, skippedCompletion); !errors.Is(err, platformcommand.ErrEffectConflict) ||
		!bytes.Equal(before, readTestFile(t, root, layout.IAMAuthenticationRecoveryCompletion)) {
		t.Fatal("skipped recovery epoch changed the completion anchor")
	}

	intentTwo, closureTwo, completionTwo := authenticationRecoveryEvidenceFixture(t, 2, 'b')
	writeAuthenticationRecoveryClosure(t, root, intentTwo, closureTwo)
	if err := persistAuthenticationRecoveryCompletion(root, intentTwo, closureTwo, completionTwo); err != nil {
		t.Fatal(err)
	}
	actual, encoded, exists, err := readAuthenticationRecoveryCompletion(root)
	defer clear(encoded)
	if err != nil || !exists || actual != completionTwo || bytes.Equal(before, encoded) {
		t.Fatal("authentication recovery completion did not advance exactly once")
	}
}

func authenticationRecoveryEvidenceFixture(
	t *testing.T,
	epoch uint64,
	identity byte,
) (installationv1.AuthenticationRecoveryIntent, installationv1.AuthenticationRecoveryClosure, installationv1.AuthenticationRecoveryCompletion) {
	t.Helper()
	value := string(identity)
	intent := installationv1.AuthenticationRecoveryIntent{
		APIVersion: installationv1.AuthenticationRecoveryAPIVersion, Kind: installationv1.AuthenticationRecoveryIntentKind,
		Purpose: installationv1.AuthenticationRecoveryPurpose, InstallationID: "mxi-" + strings.Repeat("1", 32),
		Epoch: epoch, CommandID: "cmd-" + strings.Repeat(value, 32), BackupID: "backup-" + strings.Repeat(value, 32),
		BackupDigest:    "sha256:" + strings.Repeat(value, 64),
		SourceReleaseID: "matrix-v1.2.3-source-0123456789ab", SourceReleaseDigest: "sha256:" + strings.Repeat("2", 64),
		TargetReleaseID: "matrix-v1.2.3-target-abcdef012345", TargetReleaseDigest: "sha256:" + strings.Repeat("3", 64),
		TOTPCustodyDigest: "sha256:" + strings.Repeat("4", 64),
	}
	intentDigest, err := installationv1.AuthenticationRecoveryIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	closure := installationv1.AuthenticationRecoveryClosure{
		APIVersion: installationv1.AuthenticationRecoveryAPIVersion, Kind: installationv1.AuthenticationRecoveryClosureKind,
		Purpose: installationv1.AuthenticationRecoveryPurpose, InstallationID: intent.InstallationID,
		Epoch: epoch, State: installationv1.AuthenticationRecoveryStateClosed, CommandID: intent.CommandID,
		BackupID: intent.BackupID, BackupDigest: intent.BackupDigest, RecoveryIntentDigest: intentDigest,
		TOTPCustodyDigest: intent.TOTPCustodyDigest,
		ClosedAt:          time.Date(2026, 9, 21, 2, int(epoch), 0, 0, time.UTC),
	}
	closureDigest, err := installationv1.AuthenticationRecoveryClosureDigest(closure)
	if err != nil {
		t.Fatal(err)
	}
	completion := installationv1.AuthenticationRecoveryCompletion{
		APIVersion: installationv1.AuthenticationRecoveryAPIVersion, Kind: installationv1.AuthenticationRecoveryCompletionKind,
		Purpose: installationv1.AuthenticationRecoveryPurpose, InstallationID: intent.InstallationID,
		Epoch: epoch, State: installationv1.AuthenticationRecoveryStateReopened, CommandID: intent.CommandID,
		ClosureDigest: closureDigest, CompletedAt: closure.ClosedAt.Add(time.Microsecond),
	}
	return intent, closure, completion
}

func writeAuthenticationRecoveryClosure(
	t *testing.T,
	root string,
	intent installationv1.AuthenticationRecoveryIntent,
	closure installationv1.AuthenticationRecoveryClosure,
) {
	t.Helper()
	encoded, err := installationv1.EncodeAuthenticationRecoveryClosure(closure)
	if err != nil || writeManagedOnce(
		root, filepath.FromSlash(layout.IAMAuthenticationRecoveryClosure(intent.CommandID)), encoded,
	) != nil {
		t.Fatal("stage authentication recovery closure")
	}
	clear(encoded)
}

func authenticationRecoveryInvocationFixture(mode string) (purposeOnlyIAMContainerExpectation, platformContainerInspection) {
	expected := purposeOnlyIAMContainerExpectation{
		name: "mxi-local-iam-authentication-recovery-" + mode, mode: mode,
		entrypoint: authenticationRecoveryEntrypoint, networkID: strings.Repeat("b", 64), networkName: "private",
		environment: []string{
			"PATH=/usr/bin",
			installationv1.AuthenticationRecoveryDatabaseDSNFileEnvironment + "=/run/matrix/authentication-recovery-dsn",
			installationv1.AuthenticationRecoveryIntentFileEnvironment + "=/run/matrix/authentication-recovery-input.json",
		},
	}
	expected.service = platformExpectedService{
		Image: "sha256:" + strings.Repeat("a", 64), User: "0:0", ReadOnly: true, Restart: "no",
		Networks: []string{"control"}, CapDrop: []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"}, Tmpfs: []string{"/tmp:rw,noexec,nosuid,size=64m"},
		Volumes: []platformMount{
			{Type: "bind", Source: "/root/private/authentication-recovery-dsn", Target: "/run/matrix/authentication-recovery-dsn", ReadOnly: true},
			{Type: "bind", Source: "/root/private/intent", Target: "/run/matrix/authentication-recovery-input.json", ReadOnly: true},
		},
		Labels: map[string]string{"com.xiak.matrix.command": "cmd-" + strings.Repeat("a", 32)},
	}
	expected.service.Deploy.Resources.Limits.CPUs, expected.service.Deploy.Resources.Limits.Memory = "1", "256M"
	limit := int64(64)
	actual := platformContainerInspection{
		ID: strings.Repeat("c", 64), Name: "/" + expected.name, Image: expected.service.Image,
		Config: platformContainerConfig{
			User: "0:0", Labels: cloneTestLabels(expected.service.Labels), Env: slices.Clone(expected.environment),
			Entrypoint: []string{authenticationRecoveryEntrypoint}, Cmd: []string{mode},
		},
		State: platformContainerState{Status: "created"},
		HostConfig: platformHostConfig{
			ReadonlyRootfs: true, NetworkMode: expected.networkID, Memory: 256 * 1024 * 1024,
			MemorySwap: 256 * 1024 * 1024, NanoCPUs: 1_000_000_000, PidsLimit: &limit,
			CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			Tmpfs: map[string]string{"/tmp": "rw,noexec,nosuid,size=64m"}, IpcMode: "private", CgroupnsMode: "private",
		},
		Mounts: []platformProviderMount{
			{Type: "bind", Source: "/root/private/authentication-recovery-dsn", Destination: "/run/matrix/authentication-recovery-dsn"},
			{Type: "bind", Source: "/root/private/intent", Destination: "/run/matrix/authentication-recovery-input.json"},
		},
	}
	actual.HostConfig.RestartPolicy.Name = "no"
	actual.HostConfig.LogConfig.Type = "none"
	actual.NetworkSettings.Networks = map[string]struct {
		NetworkID string `json:"NetworkID"`
	}{"private": {}}
	return expected, actual
}

type authenticationRecoveryInvocationRuntime struct {
	container       platformContainerInspection
	present         bool
	exitCode        int
	attachErr       bool
	starts, removes int
}

func (boundary *authenticationRecoveryInvocationRuntime) Run(
	_ context.Context,
	input io.Reader,
	arguments ...string,
) ([]byte, bool, error) {
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
