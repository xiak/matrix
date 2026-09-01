package localmachine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
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

func TestNodeVerificationBackoffBoundsLiveRuntimeProbes(t *testing.T) {
	delay := nodeVerificationInitialDelay
	for index, expected := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		if delay != expected {
			t.Fatalf("node verification delay %d = %s, want %s", index, delay, expected)
		}
		delay = nextNodeVerificationDelay(delay)
	}
	if nodeVerificationTimeout < 2*nodeVerificationMaximumDelay ||
		nodeVerificationMaximumDelay > nodev1.MaximumObservationAge/2 {
		t.Fatal("node verification cannot leave two background observation opportunities inside its bounded window")
	}
}

func TestNodeEffectsReauthenticateExactInstalledRuntimePredecessor(t *testing.T) {
	fixtures, err := releasetest.WriteNodeRuntimeSequence(t.TempDir(), nodeconfig.DeploymentRuntimePredecessorRevision)
	if err != nil {
		t.Fatal(err)
	}
	plan := nodeEffectPlan(t, fixtures[0])
	effects := NewNodeEffects(nodeVerifierFixture{})
	effects.supervisor = &nodeSupervisorFixture{states: map[string]nativeState{}}
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseStaging, lifecycle.PhaseConfiguring} {
		if err := effects.ApplyPhase(context.Background(), plan, phase); err != nil {
			t.Fatalf("prepare installed predecessor at %s: %v", phase, err)
		}
	}
	if _, err := authenticateNodeRelease(plan); err != nil {
		t.Fatal("exact frozen predecessor could not be reauthenticated as installed state")
	}
}

func TestNodeCredentialReplacementResumesMixedFilesAndRetiresOnlyItsSnapshots(t *testing.T) {
	previous := nodeEffectPlan(t)
	supervisor := &nodeSupervisorFixture{states: map[string]nativeState{}}
	effects := NewNodeEffects(nodeVerifierFixture{})
	effects.supervisor = supervisor
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseStaging, lifecycle.PhaseConfiguring, lifecycle.PhaseStarting} {
		if err := effects.ApplyPhase(context.Background(), previous, phase); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(previous.Configuration.StoragePath, "accepted-receipt")
	if err := os.WriteFile(marker, []byte("retained effect"), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := previous
	candidate.Credentials = nodecommand.Credentials{Certificate: []byte("next certificate"), PrivateKey: []byte("next key"),
		Trust: []byte("next trust"), CollectorCertificate: []byte("next collector certificate"), CollectorPrivateKey: []byte("next collector key")}
	var err error
	candidate.Binding, err = nodecommand.Binding(candidate.Configuration, candidate.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Previous, candidate.RevokePreviousCredentials = &previous, true
	if !bytes.Equal(nativeStartupUnit(nativeNodeStartup(previous)), nativeStartupUnit(nativeNodeStartup(candidate))) {
		t.Fatal("credential replacement would change immutable boot ownership")
	}
	for index, service := range nativeNodeServices(previous) {
		if service.description != nativeNodeServices(candidate)[index].description {
			t.Fatal("credential replacement would reject its own existing service owner")
		}
	}
	if err := effects.ApplyPhase(context.Background(), candidate, lifecycle.PhaseStaging); err != nil {
		t.Fatal(err)
	}
	for _, plan := range []nodecommand.Plan{previous, candidate} {
		config, material, err := effects.ReadRotation(plan.Root, plan.Binding.ConfigurationDigest)
		binding, bindingErr := nodecommand.Binding(config, material)
		material.Clear()
		if err != nil || bindingErr != nil || binding != plan.Binding {
			t.Fatal("staged credentials did not authenticate their commitment")
		}
	}
	files, _ := nodeFiles(previous)
	for _, foreign := range []string{nativeNodeServices(previous)[0].name, nativeNodeServices(previous)[1].name, nativeNodeStartup(previous).service.name} {
		supervisor.foreign = foreign
		if err := effects.ApplyPhase(context.Background(), candidate, lifecycle.PhaseConfiguring); err == nil || supervisor.stops != 0 {
			t.Fatal("foreign service ownership allowed partial credential effects")
		}
	}
	supervisor.foreign = ""
	for _, file := range files {
		actual, err := readManagedFile(previous.Root, filepath.FromSlash(file.name), int64(len(file.content)))
		if err != nil || !bytes.Equal(actual, file.content) {
			t.Fatal("rejected replacement changed a sealed file")
		}
	}
	foreignKey := []byte("not part of either sealed credential set")
	keyPath := filepath.FromSlash(layout.NodePrivateKey)
	if err := replaceManagedExpected(previous.Root, keyPath, previous.Credentials.PrivateKey, foreignKey); err != nil {
		t.Fatal(err)
	}
	if err := effects.ApplyPhase(context.Background(), candidate, lifecycle.PhaseConfiguring); err == nil || supervisor.stops != 0 {
		t.Fatal("an unknown active key caused partial replacement or process effects")
	}
	if err := replaceManagedExpected(previous.Root, keyPath, foreignKey, previous.Credentials.PrivateKey); err != nil {
		t.Fatal(err)
	}
	// An interrupted activation has stopped only its own processes and replaced
	// one file. The next attempt accepts only this exact old/candidate mixture.
	for _, service := range nativeNodeServices(previous) {
		if err := supervisor.Stop(context.Background(), service); err != nil {
			t.Fatal(err)
		}
	}
	if err := replaceManagedExpected(previous.Root, filepath.FromSlash(layout.NodeCertificate), previous.Credentials.Certificate, candidate.Credentials.Certificate); err != nil {
		t.Fatal(err)
	}
	if err := effects.ApplyPhase(context.Background(), candidate, lifecycle.PhaseConfiguring); err != nil {
		t.Fatal(err)
	}
	if err := effects.ApplyPhase(context.Background(), candidate, lifecycle.PhaseStarting); err != nil {
		t.Fatal(err)
	}
	if err := effects.ApplyPhase(context.Background(), candidate, lifecycle.PhaseVerifying); err != nil {
		t.Fatal(err)
	}
	if supervisor.starts != 4 || supervisor.stops != 2 || supervisor.registrations != 1 || !supervisor.registered {
		t.Fatal("rotation replaced boot ownership or failed to restart its two authenticated services")
	}
	if err := effects.Rollback(context.Background(), candidate); err == nil {
		t.Fatal("credential retirement admitted automatic rollback")
	}
	command := lifecycle.Command{Action: lifecycle.ActionRotateCredentials, InputDigest: candidate.Binding.ConfigurationDigest,
		ExpectedConfigurationDigest: previous.Binding.ConfigurationDigest, RevokePreviousCredentials: true}
	oldSnapshot := filepath.Join(previous.Root, filepath.FromSlash(layout.NodeCredentialSnapshot(previous.Binding.ConfigurationDigest)))
	if err := os.Remove(oldSnapshot); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := effects.FinalizeRotation(context.Background(), candidate, command); err != nil {
			t.Fatal("post-commit snapshot cleanup could not resume after an unlink", err)
		}
	}
	for _, digest := range []string{previous.Binding.ConfigurationDigest, candidate.Binding.ConfigurationDigest} {
		if _, err := os.Lstat(filepath.Join(previous.Root, filepath.FromSlash(layout.NodeCredentialSnapshot(digest)))); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("completed retirement retained a staged private-key snapshot")
		}
	}
	if err := authenticateNodeFiles(candidate); err != nil {
		t.Fatal("cleanup removed the active credential set")
	}
	if content, err := os.ReadFile(marker); err != nil || string(content) != "retained effect" {
		t.Fatal("rotation changed executor state")
	}
}

func TestNodeCredentialSnapshotsRejectSubstitutionBeforeReplacement(t *testing.T) {
	plan := nodeEffectPlan(t)
	effects := NewNodeEffects(nodeVerifierFixture{})
	effects.supervisor = &nodeSupervisorFixture{states: map[string]nativeState{}}
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseStaging, lifecycle.PhaseConfiguring} {
		if err := effects.ApplyPhase(context.Background(), plan, phase); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := encodeNodeCredentials(plan.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	path := filepath.FromSlash(layout.NodeCredentialSnapshot(plan.Binding.ConfigurationDigest))
	if err := writeManagedOnce(plan.Root, path, encoded); err != nil {
		t.Fatal(err)
	}
	altered := plan.Credentials
	altered.PrivateKey = []byte("foreign key")
	wrong, _ := encodeNodeCredentials(altered)
	defer clear(wrong)
	if err := replaceManagedExpected(plan.Root, path, encoded, wrong); err != nil {
		t.Fatal(err)
	}
	if _, material, err := effects.ReadRotation(plan.Root, plan.Binding.ConfigurationDigest); err == nil {
		material.Clear()
		t.Fatal("a snapshot filename authorized substituted credentials")
	}
	if err := authenticateNodeFiles(plan); err != nil {
		t.Fatal("snapshot rejection changed active enrollment")
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

func TestNodeCollectorFilesystemScopeMatchesOnlyStorageAncestors(t *testing.T) {
	plan := nodeEffectPlan(t)
	plan.Configuration.StoragePath = filepath.Join(plan.Root, "storage.with[meta]", "executor")
	collector := nativeNodeServices(plan)[0]
	var include, exclude *regexp.Regexp
	for _, argument := range collector.arguments {
		if expression, ok := strings.CutPrefix(argument, "--collector.filesystem.mount-points-include="); ok {
			include = regexp.MustCompile(expression)
		}
		if expression, ok := strings.CutPrefix(argument, "--collector.filesystem.fs-types-exclude="); ok {
			exclude = regexp.MustCompile(expression)
		}
	}
	if include == nil || exclude == nil || exclude.MatchString("ext4") || exclude.MatchString("zfs") {
		t.Fatal("filesystem selection excluded actual storage types")
	}
	for path := plan.Configuration.StoragePath; ; path = filepath.Dir(path) {
		if !include.MatchString(filepath.ToSlash(path)) {
			t.Fatal("filesystem selection missed a storage ancestor")
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	for _, path := range []string{plan.Configuration.StoragePath + "-other", plan.Configuration.StoragePath + "\n",
		filepath.Join(plan.Configuration.StoragePath, "child"), filepath.Join(plan.Root, "storageXwithm", "executor")} {
		if include.MatchString(filepath.ToSlash(path)) {
			t.Fatal("filesystem selection admitted an unrelated mount")
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

func TestNodeReleaseActivationResumesBootReloadAndRetainsCurrentCredentials(t *testing.T) {
	fixtures, err := releasetest.WriteNodeSequence(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	source := nodeEffectPlan(t, fixtures[0])
	supervisor := &nodeSupervisorFixture{states: map[string]nativeState{}}
	effects := NewNodeEffects(nodeVerifierFixture{})
	effects.supervisor = supervisor
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseStaging, lifecycle.PhaseConfiguring, lifecycle.PhaseStarting} {
		if err := effects.ApplyPhase(context.Background(), source, phase); err != nil {
			t.Fatal(err)
		}
	}
	receiptPath := filepath.Join(filepath.FromSlash(layout.ExecutorRoot), "retained-receipt")
	if err := writeManagedOnce(source.Root, receiptPath, []byte("accepted-workload-generation")); err != nil {
		t.Fatal(err)
	}
	candidate := source
	candidate.Bundle, err = release.VerifyDirectory(fixtures[1].Root, source.TrustBytes)
	if err != nil {
		t.Fatal(err)
	}
	candidate.ReleaseSource = &source
	if err := effects.ApplyPhase(context.Background(), candidate, lifecycle.PhaseStaging); err != nil {
		t.Fatal(err)
	}
	supervisor.foreign = nativeNodeServices(candidate)[1].name
	if err := effects.ApplyPhase(context.Background(), candidate, lifecycle.PhaseConfiguring); !errors.Is(err, nodecommand.ErrConflict) || supervisor.stops != 0 {
		t.Fatal("release activation changed a service before rejecting foreign ownership")
	}
	supervisor.foreign = ""
	supervisor.startupReloadFailure = nodecommand.ErrOutcomeUnknown
	if err := effects.ApplyPhase(context.Background(), candidate, lifecycle.PhaseConfiguring); !errors.Is(err, nodecommand.ErrOutcomeUnknown) || supervisor.stops != 0 {
		t.Fatalf("lost boot reload did not retain known old/new state without stopping services: %v", err)
	}
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseConfiguring, lifecycle.PhaseStarting, lifecycle.PhaseVerifying} {
		if err := effects.ApplyPhase(context.Background(), candidate, phase); err != nil {
			t.Fatalf("resume node release %s: %v", phase, err)
		}
	}
	if supervisor.stops != 2 || supervisor.starts != 4 || supervisor.registrations != 1 || !supervisor.registered {
		t.Fatal("release activation recreated registrations or did not replace exactly the two owned services")
	}
	// Rotate credentials after the upgrade. The previous release must consume
	// these current bytes, never an enrollment or credential snapshot from A.
	candidate.ReleaseSource = nil
	rotated := candidate
	rotated.Credentials = nodecommand.Credentials{Certificate: []byte("new-node-certificate"), PrivateKey: []byte("new-node-key"),
		Trust: []byte("new-trust"), CollectorCertificate: []byte("new-collector-certificate"), CollectorPrivateKey: []byte("new-collector-key")}
	rotated.Binding, err = nodecommand.Binding(rotated.Configuration, rotated.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	rotated.Previous, rotated.RevokePreviousCredentials = &candidate, true
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseStaging, lifecycle.PhaseConfiguring, lifecycle.PhaseStarting} {
		if err := effects.ApplyPhase(context.Background(), rotated, phase); err != nil {
			t.Fatal(err)
		}
	}
	rotated.Previous, rotated.RevokePreviousCredentials = nil, false
	restored := source
	restored.Credentials, restored.Binding, restored.ReleaseSource = rotated.Credentials, rotated.Binding, &rotated
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseRollingBack, lifecycle.PhaseStarting, lifecycle.PhaseVerifying} {
		if err := effects.ApplyPhase(context.Background(), restored, phase); err != nil {
			t.Fatalf("rollback with current keys %s: %v", phase, err)
		}
	}
	if err := authenticateNodeFiles(restored); err != nil {
		t.Fatal(err)
	}
	retained, err := readManagedFile(source.Root, receiptPath, 128)
	if err != nil || string(retained) != "accepted-workload-generation" || supervisor.registrations != 1 {
		t.Fatal("node release change rewrote workload state or boot registration")
	}
}

func TestNodeSupportIsSanitizedWriteOnceAndReportsOutageWithoutEffects(t *testing.T) {
	plan := nodeEffectPlan(t)
	request := nodeSupportRequest(t, plan)
	usage := nodeSupportFixtureUsage(request.GeneratedAt)
	usageCalls := 0
	supervisor := &nodeSupervisorFixture{states: map[string]nativeState{}}
	effects := NewNodeEffects(nodeVerifierFixture{usage: &usage, usageCalls: &usageCalls})
	effects.supervisor = supervisor
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseStaging, lifecycle.PhaseConfiguring, lifecycle.PhaseStarting} {
		if err := effects.ApplyPhase(context.Background(), plan, phase); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := nodeFiles(plan)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := effects.WriteSupportEvidence(canceled, request); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled diagnostic collection ignored its caller")
	}
	if _, err := os.Lstat(request.Output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled diagnostic collection wrote an artifact")
	}
	created, err := effects.WriteSupportEvidence(context.Background(), request)
	if err != nil || !created {
		t.Fatalf("write bounded node evidence: %v", err)
	}
	content, err := os.ReadFile(request.Output)
	if err != nil || verifyManagedPermissions(request.Output, false) != nil {
		t.Fatal("support output is missing or not private")
	}
	var evidence nodeSupportEvidence
	if json.Unmarshal(content, &evidence) != nil || evidence.Kind != nodeSupportKind || evidence.State != supportStateReady ||
		evidence.Binding.Identity != plan.Configuration.Identity || evidence.Binding.ConfigurationDigest != plan.Binding.ConfigurationDigest ||
		evidence.Binding.RuntimeRevision != nodeconfig.RuntimeRevision || evidence.Usage == nil ||
		evidence.Usage.Memory.Value.TotalBytes != 1024 || evidence.Usage.Filesystems[0].Value.TotalBytes != 8192 ||
		evidence.Usage.ObservedAt != usage.ObservedAt || evidence.Usage.ValidUntil != usage.ValidUntil {
		t.Fatalf("node support lost authenticated identity, quantities or source times: %s", content)
	}
	for _, forbidden := range []string{plan.Root, plan.Configuration.ListenAddress, plan.Configuration.CollectorEndpoint,
		string(plan.Credentials.Certificate), string(plan.Credentials.PrivateKey), string(plan.Credentials.CollectorPrivateKey),
		base64.StdEncoding.EncodeToString(plan.Credentials.PrivateKey),
		usage.Filesystems[0].Device, usage.Filesystems[0].MountPoint, `"mountPoint"`, `"device"`, `"environment"`, `"privateKey"`} {
		encoded, _ := json.Marshal(forbidden)
		if bytes.Contains(content, []byte(forbidden)) || bytes.Contains(content, encoded[1:len(encoded)-1]) {
			t.Fatalf("node support exposed excluded material: %q", forbidden)
		}
	}
	// A repeated file is the historical snapshot, not a new readiness claim.
	supervisor.states[nativeNodeServices(plan)[1].name] = nativeStopped
	request.GeneratedAt = request.GeneratedAt.Add(time.Second)
	created, err = effects.WriteSupportEvidence(context.Background(), request)
	replayed, readErr := os.ReadFile(request.Output)
	if err != nil || created || readErr != nil || !bytes.Equal(content, replayed) || usageCalls != 1 {
		t.Fatal("support replay resampled/restamped or rewrote its completed snapshot")
	}
	request.Output = filepath.Join(plan.Root, layout.SupportDirectory, "outage.json")
	created, err = effects.WriteSupportEvidence(context.Background(), request)
	outage, _ := os.ReadFile(request.Output)
	if err != nil || !created || json.Unmarshal(outage, &evidence) != nil || evidence.State != supportStateNotReady ||
		evidence.Readiness != nodeSupportUnavailable || evidence.Components[1].State != nativeStopped {
		t.Fatal("node outage was hidden or diagnosed through process replacement")
	}
	effects.verifier = nodeVerifierFixture{verifyErr: errors.New("private node diagnostic detail"), usageErr: errors.New("/private/collector/key.pem")}
	request.Output = filepath.Join(plan.Root, layout.SupportDirectory, "unavailable.json")
	created, err = effects.WriteSupportEvidence(context.Background(), request)
	unavailable, _ := os.ReadFile(request.Output)
	evidence = nodeSupportEvidence{}
	if err != nil || !created || json.Unmarshal(unavailable, &evidence) != nil || evidence.Usage != nil ||
		evidence.UsageState != paasv1.MeasurementUnavailable || bytes.Contains(unavailable, []byte("private")) {
		t.Fatal("missing collector data became zero values or raw failure details")
	}
	if supervisor.starts != 2 || supervisor.stops != 0 || supervisor.registrations != 1 {
		t.Fatal("diagnosis reconciled native services or boot registration")
	}
	for _, file := range files {
		retained, err := readManagedFile(plan.Root, filepath.FromSlash(file.name), int64(len(file.content)))
		if err != nil || !bytes.Equal(retained, file.content) {
			t.Fatal("diagnosis changed protected configuration, boot source or credentials")
		}
	}
}

func TestNodeSupportRejectsConflictingSnapshotsAndForeignOwners(t *testing.T) {
	plan := nodeEffectPlan(t)
	request := nodeSupportRequest(t, plan)
	usage := nodeSupportFixtureUsage(request.GeneratedAt)
	supervisor := &nodeSupervisorFixture{states: map[string]nativeState{}}
	effects := NewNodeEffects(nodeVerifierFixture{usage: &usage})
	effects.supervisor = supervisor
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseStaging, lifecycle.PhaseConfiguring, lifecycle.PhaseStarting} {
		if err := effects.ApplyPhase(context.Background(), plan, phase); err != nil {
			t.Fatal(err)
		}
	}
	for _, output := range []string{filepath.Join(filepath.Dir(plan.Root), "outside.json"),
		filepath.Join(plan.Root, layout.SupportDirectory, ".hidden.json"), filepath.Join(plan.Root, layout.SupportDirectory, "raw.log")} {
		invalid := request
		invalid.Output = output
		if _, err := effects.WriteSupportEvidence(context.Background(), invalid); err == nil {
			t.Fatal("unsupported support output was written")
		}
		if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("rejected support output left a file")
		}
	}
	for _, owner := range []string{nativeNodeStartup(plan).service.name, nativeNodeServices(plan)[0].name, nativeNodeServices(plan)[1].name} {
		supervisor.foreign = owner
		if _, err := effects.WriteSupportEvidence(context.Background(), request); err == nil {
			t.Fatal("foreign native ownership was accepted as diagnostic evidence")
		}
		if _, err := os.Lstat(request.Output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("foreign ownership produced a diagnostic file")
		}
	}
	supervisor.foreign = ""
	if _, err := effects.WriteSupportEvidence(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(request.Output)
	mutations := []struct {
		name   string
		change func(*nodeSupportEvidence)
	}{
		{"different identity", func(value *nodeSupportEvidence) { value.Binding.Identity.ExecutionTargetID = "another-target" }},
		{"different credential commitment", func(value *nodeSupportEvidence) {
			value.Binding.ConfigurationDigest = "sha256:" + strings.Repeat("f", 64)
		}},
		{"different journal", func(value *nodeSupportEvidence) { value.Binding.JournalVersion++ }},
		{"different runtime", func(value *nodeSupportEvidence) { value.Binding.RuntimeRevision++ }},
		{"future snapshot", func(value *nodeSupportEvidence) { value.GeneratedAt = request.GeneratedAt.Add(time.Hour) }},
		{"false readiness", func(value *nodeSupportEvidence) { value.Components[1].State = nativeStopped }},
		{"unknown process state", func(value *nodeSupportEvidence) { value.Components[0].State = "ARBITRARY_PROVIDER_OUTPUT" }},
		{"invalid quantity", func(value *nodeSupportEvidence) { value.Usage.Filesystems[0].Value.TotalBytes = -1 }},
		{"unavailable with values", func(value *nodeSupportEvidence) { value.UsageState = paasv1.MeasurementUnavailable }},
		{"expired but current", func(value *nodeSupportEvidence) {
			value.Usage.ObservedAt = request.GeneratedAt.Add(-time.Hour)
			value.Usage.ValidUntil = value.Usage.ObservedAt.Add(nodev1.MaximumObservationAge)
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			var value nodeSupportEvidence
			if err := json.Unmarshal(original, &value); err != nil {
				t.Fatal(err)
			}
			test.change(&value)
			changed, err := json.Marshal(value)
			if err != nil || os.WriteFile(request.Output, changed, 0o600) != nil {
				t.Fatal("prepare conflicting evidence")
			}
			if _, err := effects.WriteSupportEvidence(context.Background(), request); err == nil {
				t.Fatal("changed evidence was reused")
			}
			retained, _ := os.ReadFile(request.Output)
			if !bytes.Equal(retained, changed) {
				t.Fatal("conflicting evidence was overwritten")
			}
		})
	}
	for _, malformed := range [][]byte{
		bytes.Replace(original, []byte(`"kind":`), []byte(`"extra":"raw-detail","kind":`), 1),
		bytes.Replace(original, []byte(`"kind":`), []byte(`"kind":"duplicate","kind":`), 1),
		append(bytes.Repeat([]byte(" "), int(maximumNodeSupportBytes)), original...),
	} {
		if err := os.WriteFile(request.Output, malformed, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := effects.WriteSupportEvidence(context.Background(), request); err == nil {
			t.Fatal("unbounded, duplicate or unknown support content was reused")
		}
	}
	if supervisor.starts != 2 || supervisor.stops != 0 || supervisor.registrations != 1 {
		t.Fatal("failed support collection changed native ownership")
	}
}

func nodeSupportRequest(t *testing.T, plan nodecommand.Plan) nodecommand.SupportPlan {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	state, err := lifecycle.NewNode(plan.Configuration.Identity.InstallationID,
		lifecycle.ReleaseTrust{KeyID: plan.Trust.KeyID, Fingerprint: plan.Trust.PublicKeyFingerprint}, plan.Binding)
	if err != nil {
		t.Fatal(err)
	}
	command := lifecycle.Command{ID: "cmd-" + strings.Repeat("a", 32), Action: lifecycle.ActionInstall,
		InputDigest: plan.Bundle.ManifestSHA256, TargetReleaseID: plan.Bundle.Manifest.Release.ID, RequestedAt: now.Add(-time.Second)}
	started, err := lifecycle.Start(state, command)
	if err != nil {
		t.Fatal(err)
	}
	state = started.Journal
	for index, phase := range []lifecycle.Phase{lifecycle.PhaseStaging, lifecycle.PhaseConfiguring, lifecycle.PhaseStarting,
		lifecycle.PhaseVerifying, lifecycle.PhaseCommitting, lifecycle.PhaseReady} {
		state, err = lifecycle.Advance(state, command.ID, phase, command.RequestedAt.Add(time.Duration(index+1)*time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
	}
	return nodecommand.SupportPlan{Installation: plan, Journal: state,
		Output: filepath.Join(plan.Root, layout.SupportDirectory, "snapshot.json"), GeneratedAt: now}
}

func nodeSupportFixtureUsage(now time.Time) paasv1.ExecutionTargetUsage {
	totalInodes, freeInodes := int64(128), int64(96)
	return paasv1.ExecutionTargetUsage{ObservedAt: now, ValidUntil: now.Add(nodev1.MaximumObservationAge),
		CPU:              paasv1.CPUUsage{State: paasv1.MeasurementAvailable, Value: &paasv1.CPUUsageValue{LogicalCPUs: 2, WindowMillis: 1000, UtilizationRatio: 0.1}},
		Memory:           paasv1.MemoryUsage{State: paasv1.MeasurementAvailable, Value: &paasv1.MemoryUsageValue{TotalBytes: 1024, AvailableBytes: 512, UsedBytes: 512}},
		FilesystemsState: paasv1.MeasurementAvailable, Filesystems: []paasv1.FilesystemUsage{{
			Device: "/dev/never-output-disk", MountPoint: "/private/never-output-storage", FilesystemType: "ext4", State: paasv1.MeasurementAvailable,
			Value: &paasv1.FilesystemUsageValue{TotalBytes: 8192, UsedBytes: 4096, AvailableBytes: 2048,
				InodesState: paasv1.MeasurementAvailable, TotalInodes: &totalInodes, FreeInodes: &freeInodes},
		}}}
}

func nodeEffectPlan(t *testing.T, supplied ...releasetest.Fixture) nodecommand.Plan {
	t.Helper()
	var fixture releasetest.Fixture
	if len(supplied) == 0 {
		var err error
		fixture, err = releasetest.WriteNode(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
	} else if len(supplied) == 1 {
		fixture = supplied[0]
	} else {
		t.Fatal("one signed node release fixture is required")
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

type nodeVerifierFixture struct {
	verifyErr  error
	usage      *paasv1.ExecutionTargetUsage
	usageErr   error
	usageCalls *int
}

func (nodeVerifierFixture) Validate(nodeconfig.Configuration, nodecommand.Credentials) error {
	return nil
}
func (nodeVerifierFixture) ValidateRotation(nodeconfig.Configuration, nodecommand.Credentials, nodecommand.Credentials, bool) error {
	return nil
}
func (fixture nodeVerifierFixture) Verify(context.Context, nodeconfig.Configuration, nodecommand.Credentials) error {
	return fixture.verifyErr
}
func (fixture nodeVerifierFixture) ObserveUsage(context.Context, nodeconfig.Configuration, nodecommand.Credentials) (paasv1.ExecutionTargetUsage, error) {
	if fixture.usageCalls != nil {
		(*fixture.usageCalls)++
	}
	if fixture.usageErr != nil {
		return paasv1.ExecutionTargetUsage{}, fixture.usageErr
	}
	if fixture.usage == nil {
		return paasv1.ExecutionTargetUsage{}, nodecommand.ErrUnavailable
	}
	return *fixture.usage, nil
}

type nodeSupervisorFixture struct {
	states               map[string]nativeState
	owners               map[string]string
	startupOwner         string
	startupReloadFailure error
	foreign              string
	starts, stops        int
	registered           bool
	registrations        int
	registrationFailure  error
}

func (*nodeSupervisorFixture) Preflight(context.Context, uint64) error { return nil }
func (fixture *nodeSupervisorFixture) InspectStartup(_ context.Context, startup nativeStartup) (bool, error) {
	if fixture.foreign == startup.service.name {
		return false, nodecommand.ErrConflict
	}
	if fixture.startupOwner != "" && fixture.startupOwner != startup.service.description {
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
		fixture.startupOwner = startup.service.description
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
func (fixture *nodeSupervisorFixture) ReplaceStartup(_ context.Context, before, after nativeStartup) error {
	if fixture.foreign == after.service.name || !fixture.registered ||
		before.root != after.root || before.unitFile != after.unitFile || before.service.name != after.service.name ||
		(fixture.startupOwner != before.service.description && fixture.startupOwner != after.service.description) {
		return nodecommand.ErrConflict
	}
	relative, err := filepath.Rel(after.root, after.unitFile)
	if err != nil {
		return nodecommand.ErrConflict
	}
	if err := replaceManagedExpected(after.root, relative, nativeStartupUnit(before), nativeStartupUnit(after)); err != nil {
		return nodecommand.ErrConflict
	}
	if fixture.startupReloadFailure != nil {
		err := fixture.startupReloadFailure
		fixture.startupReloadFailure = nil
		return err
	}
	fixture.startupOwner = after.service.description
	return nil
}
func (fixture *nodeSupervisorFixture) Inspect(_ context.Context, service nativeService) (nativeState, error) {
	if fixture.foreign == service.name {
		return "", nodecommand.ErrConflict
	}
	if state, found := fixture.states[service.name]; found {
		if owner := fixture.owners[service.name]; owner != "" && owner != service.description {
			return "", nodecommand.ErrConflict
		}
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
		if fixture.owners == nil {
			fixture.owners = map[string]string{}
		}
		fixture.states[service.name] = nativeRunning
		fixture.owners[service.name] = service.description
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
		delete(fixture.states, service.name)
		delete(fixture.owners, service.name)
		fixture.stops++
	}
	return nil
}
