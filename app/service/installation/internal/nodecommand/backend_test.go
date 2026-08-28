package nodecommand

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

func TestNodeInstallResumesUnknownStartupAndPinsEnrollment(t *testing.T) {
	request, input := nodeRequest(t)
	effects := &nodeEffects{failPhase: lifecycle.PhaseStarting, failure: ErrOutcomeUnknown}
	backend, _ := NewBackend(effects)
	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
	state := nodeState(t, request.Root)
	if state.Node == nil || state.Active == nil || state.Active.Phase != lifecycle.PhaseStarting || state.CurrentReleaseID != "" {
		t.Fatal("unknown startup was not retained as an uncommitted intent")
	}
	commandID := state.Active.Command.ID
	before := journalBytes(t, request.Root)
	input.Node.ExpectedFingerprint = "sha256:" + strings.Repeat("b", 64)
	writeInput(t, request.Configuration, input)
	_, err = backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_CONFLICT")
	if !bytes.Equal(before, journalBytes(t, request.Root)) {
		t.Fatal("conflicting enrollment changed the sealed journal")
	}
	input.Node.ExpectedFingerprint = "sha256:" + strings.Repeat("a", 64)
	writeInput(t, request.Configuration, input)
	result, err := backend.Run(context.Background(), request)
	if err != nil || result.State != "READY" || !result.Changed || result.CorrelationID != commandID {
		t.Fatalf("resume node: %#v / %v", result, err)
	}
	state = nodeState(t, request.Root)
	if state.CurrentReleaseID != result.ReleaseID || state.Active != nil || state.Last.Outcome != lifecycle.OutcomeSucceeded {
		t.Fatal("node release was not committed")
	}
	for _, phase := range effects.phases {
		if phase == lifecycle.PhaseMigrating || phase == lifecycle.PhaseLoadingImages || phase == lifecycle.PhaseBackingUp {
			t.Fatal("node ran platform effects")
		}
	}
	before = journalBytes(t, request.Root)
	effects.ready = false
	result, err = backend.Run(context.Background(), request)
	if err != nil || result.Changed || result.State != "NOT_READY" || !bytes.Equal(before, journalBytes(t, request.Root)) {
		t.Fatal("install replay fabricated readiness or changed state")
	}
	result, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionStart, Root: request.Root})
	if err != nil || result.State != "READY" || nodeState(t, request.Root).PreviousRelease != "" {
		t.Fatalf("restart sealed node: %v", err)
	}
}

func TestNodeUpgradeResumesProtectedCandidateAndRollbackKeepsLatestCredentials(t *testing.T) {
	fixtures, err := releasetest.WriteNodeSequence(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	request, input := nodeRequest(t, fixtures[0])
	effects := &nodeEffects{}
	backend, _ := NewBackend(effects)
	if _, err := backend.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	before := nodeState(t, request.Root)
	effects.failPhase, effects.failure = lifecycle.PhaseStarting, ErrOutcomeUnknown
	upgrade := cli.Request{Subject: cli.SubjectNode, Action: lifecycle.ActionUpgrade, Root: request.Root, Bundle: fixtures[1].Root}
	_, err = backend.Run(context.Background(), upgrade)
	assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
	pending := nodeState(t, request.Root)
	if pending.Active == nil || pending.Active.Command.Action != lifecycle.ActionUpgrade || pending.CurrentReleaseID != before.CurrentReleaseID ||
		pending.Active.DestinationDigest != fixtures[1].ManifestDigest || pending.Active.Command.BackupID != "" {
		t.Fatal("node upgrade did not retain its exact source/candidate intent")
	}
	// The operator's original media is no longer available. Resume must use the
	// authenticated, installation-owned staged bundle, not these input paths.
	if err := os.Rename(fixtures[1].Root, fixtures[1].Root+"-unmounted"); err != nil {
		t.Fatal(err)
	}
	result, err := backend.Run(context.Background(), cli.Request{Subject: cli.SubjectNode, Action: lifecycle.ActionStart, Root: request.Root})
	if err != nil || result.State != "READY" || result.ReleaseID != fixtures[1].Manifest.Release.ID || result.CorrelationID != pending.Active.Command.ID {
		t.Fatalf("node upgrade resume: %#v / %v", result, err)
	}
	if state := nodeState(t, request.Root); state.PreviousRelease != before.CurrentReleaseID || *state.Node != *before.Node {
		t.Fatal("node upgrade lost predecessor or credential commitment")
	}
	// A read/verify command must not destroy the completed upgrade receipt.
	if _, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionVerify, Root: request.Root}); err != nil {
		t.Fatal(err)
	}
	result, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionUpgrade, Root: request.Root, Resume: true})
	if err != nil || result.Changed || result.CorrelationID != pending.Active.Command.ID {
		t.Fatalf("completed upgrade replay: %#v / %v", result, err)
	}
	if err := os.WriteFile(input.Node.PrivateKeyFile, []byte("new-key-after-upgrade"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionRotateCredentials, Root: request.Root,
		Configuration: request.Configuration, ExpectedConfigurationDigest: before.Node.ConfigurationDigest, RevokePreviousCredentials: true}); err != nil {
		t.Fatal(err)
	}
	latest := nodeState(t, request.Root)
	rollback := cli.Request{Subject: cli.SubjectNode, Action: lifecycle.ActionRollback, Root: request.Root}
	result, err = backend.Run(context.Background(), rollback)
	if err != nil || !result.Changed || result.ReleaseID != before.CurrentReleaseID {
		t.Fatalf("node rollback: %#v / %v", result, err)
	}
	rolledBack := nodeState(t, request.Root)
	if rolledBack.PreviousRelease != "" || *rolledBack.Node != *latest.Node ||
		*rolledBack.NodeCredentialRotation != *latest.NodeCredentialRotation {
		t.Fatal("node rollback rewrote enrollment or retained an invalid predecessor")
	}
	if _, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionVerify, Root: request.Root}); err != nil {
		t.Fatal(err)
	}
	replayed, err := backend.Run(context.Background(), rollback)
	if err != nil || replayed.Changed || replayed.CorrelationID != result.CorrelationID {
		t.Fatalf("completed rollback replay: %#v / %v", replayed, err)
	}
	for _, phase := range effects.phases {
		if phase == lifecycle.PhaseBackingUp || phase == lifecycle.PhaseMigrating || phase == lifecycle.PhaseLoadingImages || phase == lifecycle.PhaseRecovering {
			t.Fatal("node release change ran platform effects")
		}
	}
}

func TestNodeReleaseChangesResumeEveryAcceptedPhase(t *testing.T) {
	fixtures, err := releasetest.WriteNodeSequence(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []lifecycle.Action{lifecycle.ActionUpgrade, lifecycle.ActionRollback} {
		phases := []lifecycle.Phase{lifecycle.PhasePreflight, lifecycle.PhaseStaging, lifecycle.PhaseConfiguring,
			lifecycle.PhaseStarting, lifecycle.PhaseVerifying, lifecycle.PhaseCommitting}
		if action == lifecycle.ActionRollback {
			phases = []lifecycle.Phase{lifecycle.PhaseRollingBack, lifecycle.PhaseStarting, lifecycle.PhaseVerifying, lifecycle.PhaseCommitting}
		}
		for _, phase := range phases {
			t.Run(string(action)+"/"+string(phase), func(t *testing.T) {
				request, _ := nodeRequest(t, fixtures[0])
				effects := &nodeEffects{}
				backend, _ := NewBackend(effects)
				if _, err := backend.Run(context.Background(), request); err != nil {
					t.Fatal(err)
				}
				change := cli.Request{Action: lifecycle.ActionUpgrade, Root: request.Root, Bundle: fixtures[1].Root}
				if action == lifecycle.ActionRollback {
					if _, err := backend.Run(context.Background(), change); err != nil {
						t.Fatal(err)
					}
					change.Action, change.Bundle = action, ""
				}
				before := nodeState(t, request.Root)
				effects.failPhase, effects.failure = phase, ErrOutcomeUnknown
				_, err := backend.Run(context.Background(), change)
				assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
				pending := nodeState(t, request.Root)
				if pending.Active == nil || pending.Active.Phase != phase || pending.CurrentReleaseID != before.CurrentReleaseID {
					t.Fatal("interrupted activation advanced its release pointer")
				}
				// Lost resident processes do not require another command or source
				// media, even when the journal was already verifying/committing.
				effects.ready = false
				result, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionStart, Root: request.Root})
				if err != nil || result.State != "READY" || result.ReleaseID != pending.Active.Destination ||
					result.CorrelationID != pending.Active.Command.ID || *nodeState(t, request.Root).Node != *before.Node {
					t.Fatalf("resume sealed activation: %#v / %v", result, err)
				}
			})
		}
	}
}

func TestNodeFailedUpgradeRetainsRecoveryIntentAndCannotFabricateReadiness(t *testing.T) {
	fixtures, err := releasetest.WriteNodeSequence(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := nodeRequest(t, fixtures[0])
	effects := &nodeEffects{}
	backend, _ := NewBackend(effects)
	if _, err := backend.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	before := nodeState(t, request.Root)
	effects.failPhase, effects.failure, effects.rollbackFailure = lifecycle.PhaseVerifying, ErrVerification, ErrOutcomeUnknown
	_, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionUpgrade, Root: request.Root, Bundle: fixtures[1].Root})
	assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
	pending := nodeState(t, request.Root)
	if pending.Active == nil || pending.Active.Phase != lifecycle.PhaseRollingBack || pending.CurrentReleaseID != before.CurrentReleaseID || pending.NodeReleaseChange != nil {
		t.Fatal("unverified recovery fabricated a completed release")
	}
	_, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionRollback, Root: request.Root})
	assertNodeFault(t, err, "INSTALLATION_COMMAND_CONFLICT")
	effects.rollbackFailure = nil
	_, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionUpgrade, Root: request.Root, Resume: true})
	assertNodeFault(t, err, "NODE_VERIFICATION_FAILED")
	restored := nodeState(t, request.Root)
	if restored.Active != nil || restored.Last.Outcome != lifecycle.OutcomeRolledBack ||
		restored.Last.Command.ID != pending.Active.Command.ID || restored.CurrentReleaseID != before.CurrentReleaseID ||
		*restored.Node != *before.Node || !effects.ready {
		t.Fatal("source recovery lost its original identity, credentials or failure")
	}
	_, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionUpgrade, Root: request.Root, Resume: true})
	assertNodeFault(t, err, "NODE_RELEASE_CHANGE_NOT_FOUND")
}

func TestNodeReleaseChangeRejectsWrongLineageAndTamperedStagedIntent(t *testing.T) {
	fixtures, err := releasetest.WriteNodeSequence(t.TempDir(), 3)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := nodeRequest(t, fixtures[0])
	effects := &nodeEffects{}
	backend, _ := NewBackend(effects)
	if _, err := backend.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	before, calls := journalBytes(t, request.Root), len(effects.phases)
	_, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionUpgrade, Root: request.Root, Bundle: fixtures[2].Root})
	assertNodeFault(t, err, "NODE_RELEASE_TRANSITION_UNSUPPORTED")
	if !bytes.Equal(before, journalBytes(t, request.Root)) || calls != len(effects.phases) {
		t.Fatal("non-adjacent release created an activation intent")
	}
	effects.failPhase, effects.failure = lifecycle.PhaseConfiguring, ErrOutcomeUnknown
	_, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionUpgrade, Root: request.Root, Bundle: fixtures[1].Root})
	assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
	before, calls = journalBytes(t, request.Root), len(effects.phases)
	if err := os.WriteFile(filepath.Join(request.Root, "releases", fixtures[1].Manifest.Release.ID, "bin", "mx"), []byte("not-the-signed-executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionStart, Root: request.Root})
	assertNodeFault(t, err, "INSTALLATION_RELEASE_INVALID")
	if !bytes.Equal(before, journalBytes(t, request.Root)) || calls != len(effects.phases) {
		t.Fatal("tampered pending release caused effects or selected another release")
	}
}

func TestNodeReleasePlanRejectsDifferentRuntimeAndCredentialAuthority(t *testing.T) {
	fixtures, err := releasetest.WriteNodeSequence(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := nodeRequest(t, fixtures[0])
	configuration, material, err := enrollment(request.Root, request.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	trustBytes, trust, _ := release.ReadTrustRootFile(request.TrustKey)
	sourceBundle, _ := release.VerifyDirectory(fixtures[0].Root, trustBytes)
	targetBundle, _ := release.VerifyDirectory(fixtures[1].Root, trustBytes)
	binding, _ := Binding(configuration, material)
	source := Plan{Root: request.Root, Bundle: sourceBundle, Configuration: configuration, Credentials: material,
		Trust: trust, TrustBytes: trustBytes, Binding: binding}
	plan := source
	plan.Bundle, plan.ReleaseSource = targetBundle, &source
	if err := ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"runtime", "topology", "credential", "trust", "enrollment", "nested source"} {
		t.Run(mode, func(t *testing.T) {
			value := plan
			switch mode {
			case "runtime":
				profile := *value.Bundle.Manifest.Node
				profile.RuntimeRevision--
				value.Bundle.Manifest.Node = &profile
			case "topology":
				value.Bundle.Manifest.TopologyDigest = "sha256:" + strings.Repeat("d", 64)
			case "credential":
				value.Credentials.PrivateKey = []byte("a-different-current-credential")
				value.Binding, _ = Binding(value.Configuration, value.Credentials)
			case "trust":
				value.Trust.KeyID = "another-signer"
			case "enrollment":
				value.Configuration.ControllerID = "another-controller"
				value.Binding, _ = Binding(value.Configuration, value.Credentials)
			case "nested source":
				value.ReleaseSource = &value
			}
			if ValidatePlan(value) == nil {
				t.Fatal("release change admitted another runtime or authority")
			}
		})
	}
}

func TestNodeStartResumesOnlyConfiguredInstallWithoutNewEnrollment(t *testing.T) {
	for _, phase := range []lifecycle.Phase{lifecycle.PhasePreflight, lifecycle.PhaseStaging,
		lifecycle.PhaseConfiguring, lifecycle.PhaseStarting, lifecycle.PhaseVerifying, lifecycle.PhaseCommitting} {
		t.Run(string(phase), func(t *testing.T) {
			request, _ := nodeRequest(t)
			effects := &nodeEffects{failPhase: phase, failure: ErrOutcomeUnknown}
			backend, _ := NewBackend(effects)
			_, err := backend.Run(context.Background(), request)
			assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
			state := nodeState(t, request.Root)
			command := state.Active.Command
			before, calls := journalBytes(t, request.Root), len(effects.phases)
			effects.ready = false // A guest boot loses its transient services.
			if err := os.Remove(request.Configuration); err != nil {
				t.Fatal(err)
			}
			result, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionStart, Root: request.Root})
			if phase == lifecycle.PhasePreflight || phase == lifecycle.PhaseStaging || phase == lifecycle.PhaseConfiguring {
				assertNodeFault(t, err, "NODE_NOT_INSTALLED")
				if !bytes.Equal(before, journalBytes(t, request.Root)) || calls != len(effects.phases) {
					t.Fatal("boot created effects from an unconfigured installation")
				}
				return
			}
			if err != nil || result.State != "READY" || result.CorrelationID != command.ID {
				t.Fatalf("boot did not resume its sealed install: %#v / %v", result, err)
			}
			state = nodeState(t, request.Root)
			if state.Active != nil || state.Last.Command != command || state.CurrentReleaseID != command.TargetReleaseID || state.CurrentReleaseDigest != command.InputDigest {
				t.Fatal("boot changed the original command or committed a different release")
			}
		})
	}
}

func TestNodeBootRejectsTamperedPendingInstallationBeforeEffects(t *testing.T) {
	for _, mode := range []string{"credential", "signed payload"} {
		t.Run(mode, func(t *testing.T) {
			request, _ := nodeRequest(t)
			effects := &nodeEffects{failPhase: lifecycle.PhaseStarting, failure: ErrOutcomeUnknown}
			backend, _ := NewBackend(effects)
			_, err := backend.Run(context.Background(), request)
			assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
			artifact := layout.NodePrivateKey
			if mode == "signed payload" {
				artifact = layout.ReleaseDirectory(nodeState(t, request.Root).Active.Command.TargetReleaseID) + "/bin/mx"
			}
			path := filepath.Join(request.Root, filepath.FromSlash(artifact))
			if err := os.WriteFile(path, []byte("substitution"), 0o600); err != nil {
				t.Fatal(err)
			}
			before, calls := journalBytes(t, request.Root), len(effects.phases)
			if _, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionStart, Root: request.Root}); err == nil {
				t.Fatal("boot accepted tampered staged material")
			}
			if !bytes.Equal(before, journalBytes(t, request.Root)) || calls != len(effects.phases) || effects.rollbacks != 0 {
				t.Fatal("tampered boot changed journal or provider")
			}
		})
	}
}

func TestNodeRejectsInvalidInputAndPlatformRootsBeforeEffects(t *testing.T) {
	for _, mode := range []string{"platform release", "invalid credential", "platform root"} {
		t.Run(mode, func(t *testing.T) {
			request, _ := nodeRequest(t)
			effects := &nodeEffects{}
			if mode == "platform release" {
				fixture, err := releasetest.Write(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				request.Bundle, request.TrustKey = fixture.Root, fixture.TrustPath
			}
			if mode == "invalid credential" {
				effects.invalid = true
			}
			var before []byte
			if mode == "platform root" {
				_, trust, err := release.ReadTrustRootFile(request.TrustKey)
				if err != nil {
					t.Fatal(err)
				}
				session, err := journal.Acquire(context.Background(), request.Root)
				if err != nil {
					t.Fatal(err)
				}
				state, err := lifecycle.New("mxi-"+strings.Repeat("a", 32), lifecycle.ReleaseTrust{KeyID: trust.KeyID, Fingerprint: trust.PublicKeyFingerprint})
				if err != nil || session.Initialize(state) != nil || session.Close() != nil {
					t.Fatal("initialize platform fixture")
				}
				before = journalBytes(t, request.Root)
			}
			backend, _ := NewBackend(effects)
			if _, err := backend.Run(context.Background(), request); err == nil || len(effects.phases) != 0 || effects.rollbacks != 0 {
				t.Fatal("invalid node install reached effects")
			}
			if mode == "platform root" {
				if !bytes.Equal(before, journalBytes(t, request.Root)) {
					t.Fatal("node command changed a platform root")
				}
			} else if _, err := os.Lstat(request.Root); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid enrollment created a root")
			}
		})
	}
}

func TestNodeStoredCredentialSubstitutionAndUnsupportedActionsFailClosed(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{}
	backend, _ := NewBackend(effects)
	if _, err := backend.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	before := journalBytes(t, request.Root)
	keyPath := filepath.Join(request.Root, filepath.FromSlash(layout.NodePrivateKey))
	if err := os.WriteFile(keyPath, []byte("substituted-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []lifecycle.Action{lifecycle.ActionStart, lifecycle.ActionStatus, lifecycle.ActionVerify,
		lifecycle.ActionUpgrade, lifecycle.ActionRecover, lifecycle.ActionBackup, lifecycle.ActionRollback} {
		calls := len(effects.phases)
		if _, err := backend.Run(context.Background(), cli.Request{Action: action, Root: request.Root}); err == nil {
			t.Fatalf("action %s accepted substituted material", action)
		}
		if calls != len(effects.phases) || !bytes.Equal(before, journalBytes(t, request.Root)) {
			t.Fatal("rejected node action changed state or provider")
		}
	}
}

func TestNodeFailedVerificationRollsBackOnlySupervisionAndCanRetry(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{failPhase: lifecycle.PhaseVerifying, failure: ErrVerification}
	backend, _ := NewBackend(effects)
	if _, err := backend.Run(context.Background(), request); err == nil {
		t.Fatal("failed node verification was committed")
	}
	state := nodeState(t, request.Root)
	if state.CurrentReleaseID != "" || state.Active != nil || state.Last.Outcome != lifecycle.OutcomeRolledBack || effects.rollbacks != 1 {
		t.Fatal("node failure lost its rollback intent or committed the release")
	}
	keyPath := filepath.Join(request.Root, filepath.FromSlash(layout.NodePrivateKey))
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal("node rollback removed enrollment credentials")
	}
	result, err := backend.Run(context.Background(), request)
	if err != nil || result.State != "READY" {
		t.Fatalf("node retry: %v", err)
	}
	retained, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(retained, key) {
		t.Fatal("node retry rotated credentials")
	}
}

func TestNodeCredentialRotationResumesSealedInputWithoutRestoringRetiredKeys(t *testing.T) {
	for _, phase := range []lifecycle.Phase{lifecycle.PhaseConfiguring, lifecycle.PhaseStarting,
		lifecycle.PhaseVerifying, lifecycle.PhaseCommitting} {
		t.Run(string(phase), func(t *testing.T) {
			request, input := nodeRequest(t)
			effects := &nodeEffects{}
			backend, _ := NewBackend(effects)
			if _, err := backend.Run(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			original := nodeState(t, request.Root)
			for _, path := range []string{input.Node.CertificateFile, input.Node.PrivateKeyFile, input.Node.TrustFile,
				input.CollectorCertificateFile, input.CollectorPrivateKeyFile} {
				if os.WriteFile(path, []byte("replacement:"+filepath.Base(path)), 0o600) != nil {
					t.Fatal("replace external enrollment fixture")
				}
			}
			rotation := cli.Request{Subject: cli.SubjectNode, Action: lifecycle.ActionRotateCredentials,
				Root: request.Root, Configuration: request.Configuration,
				ExpectedConfigurationDigest: original.Node.ConfigurationDigest, RevokePreviousCredentials: true}
			effects.failPhase, effects.failure = phase, ErrOutcomeUnknown
			_, err := backend.Run(context.Background(), rotation)
			assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
			pending := nodeState(t, request.Root)
			if pending.Active == nil || pending.Active.Phase != phase || *pending.Node != *original.Node || effects.rollbacks != 0 {
				t.Fatal("interrupted rotation changed authority or rolled back")
			}
			command := pending.Active.Command
			before, calls := journalBytes(t, request.Root), len(effects.phases)
			changed := rotation
			changed.RevokePreviousCredentials = false
			if _, err := backend.Run(context.Background(), changed); err == nil || !bytes.Equal(before, journalBytes(t, request.Root)) || calls != len(effects.phases) {
				t.Fatal("active rotation accepted a different retirement policy")
			}
			if err := os.Remove(request.Configuration); err != nil {
				t.Fatal(err)
			}
			result, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionStart, Root: request.Root})
			if err != nil || result.State != "READY" || result.CorrelationID != command.ID || result.ConfigurationDigest != command.InputDigest {
				t.Fatalf("resume staged rotation: %#v / %v", result, err)
			}
			completed := nodeState(t, request.Root)
			if completed.Active != nil || completed.CurrentReleaseID != original.CurrentReleaseID ||
				completed.CurrentReleaseDigest != original.CurrentReleaseDigest || completed.Node.ExecutionTargetID != original.Node.ExecutionTargetID ||
				completed.Node.ConfigurationDigest != command.InputDigest || effects.rollbacks != 0 {
				t.Fatal("credential commit changed its release/target or restored the source")
			}
			if _, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionStart, Root: request.Root}); err != nil {
				t.Fatal(err)
			}
			writeInput(t, request.Configuration, input)
			before = journalBytes(t, request.Root)
			result, err = backend.Run(context.Background(), rotation)
			if err != nil || result.Changed || result.CorrelationID != command.ID || !bytes.Equal(before, journalBytes(t, request.Root)) {
				t.Fatalf("rotation replay after startup changed input/state: %#v / %v", result, err)
			}
		})
	}
}

func TestNodeCredentialCleanupFailureRetainsCommitAndBlocksAnotherRotation(t *testing.T) {
	request, input := nodeRequest(t)
	effects := &nodeEffects{}
	backend, _ := NewBackend(effects)
	if _, err := backend.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	original := nodeState(t, request.Root)
	if err := os.WriteFile(input.Node.PrivateKeyFile, []byte("replacement-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	rotation := cli.Request{Action: lifecycle.ActionRotateCredentials, Root: request.Root, Configuration: request.Configuration,
		ExpectedConfigurationDigest: original.Node.ConfigurationDigest, RevokePreviousCredentials: true}
	effects.cleanupFailure = ErrUnavailable
	_, err := backend.Run(context.Background(), rotation)
	assertNodeFault(t, err, "NODE_CREDENTIAL_CLEANUP_PENDING")
	committed := nodeState(t, request.Root)
	if committed.Active != nil || committed.NodeCredentialRotation == nil || committed.Node.ConfigurationDigest == original.Node.ConfigurationDigest ||
		committed.Node.ConfigurationDigest != committed.NodeCredentialRotation.InputDigest || effects.rollbacks != 0 {
		t.Fatal("cleanup failure lost or rolled back the committed credential set")
	}
	if err := os.WriteFile(input.Node.PrivateKeyFile, []byte("another-replacement-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	rotation.ExpectedConfigurationDigest = committed.Node.ConfigurationDigest
	before, calls := journalBytes(t, request.Root), len(effects.phases)
	_, err = backend.Run(context.Background(), rotation)
	assertNodeFault(t, err, "NODE_CREDENTIAL_CLEANUP_PENDING")
	if !bytes.Equal(before, journalBytes(t, request.Root)) || calls != len(effects.phases) {
		t.Fatal("a second rotation staged more private keys before cleanup completed")
	}
	effects.cleanupFailure = nil
	if result, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionStart, Root: request.Root}); err != nil || result.ConfigurationDigest != committed.Node.ConfigurationDigest {
		t.Fatalf("cleanup replay did not retain the current credentials: %v", err)
	}
	if result, err := backend.Run(context.Background(), rotation); err != nil || result.ConfigurationDigest == committed.Node.ConfigurationDigest || effects.rollbacks != 0 {
		t.Fatalf("cleaned installation could not accept its next rotation: %v", err)
	}
}

func TestNodeCredentialRotationRejectsChangedIdentityAndStaleInputBeforeIntent(t *testing.T) {
	for _, mode := range []string{"target", "installation", "controller", "binding", "fingerprint", "listener", "collector", "reserve", "stale digest"} {
		t.Run(mode, func(t *testing.T) {
			request, input := nodeRequest(t)
			effects := &nodeEffects{}
			backend, _ := NewBackend(effects)
			if _, err := backend.Run(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			rotation := cli.Request{Action: lifecycle.ActionRotateCredentials, Root: request.Root,
				Configuration: request.Configuration, ExpectedConfigurationDigest: nodeState(t, request.Root).Node.ConfigurationDigest,
				RevokePreviousCredentials: true}
			if os.WriteFile(input.Node.PrivateKeyFile, []byte("new-test-key"), 0o600) != nil {
				t.Fatal("write replacement fixture")
			}
			switch mode {
			case "target":
				input.Node.Identity.ExecutionTargetID = "target-other"
			case "installation":
				input.Node.Identity.InstallationID = "mxi-" + strings.Repeat("b", 32)
			case "controller":
				input.Node.ControllerID = "controller-other"
			case "binding":
				input.Node.BindingRef = "binding-other"
			case "fingerprint":
				input.Node.ExpectedFingerprint = "sha256:" + strings.Repeat("b", 64)
			case "listener":
				input.Node.ListenAddress = "127.0.0.1:16444"
			case "collector":
				input.Node.CollectorEndpoint = "https://127.0.0.1:19101"
			case "reserve":
				input.Node.SystemReserve.CPUMillis = 10
			case "stale digest":
				rotation.ExpectedConfigurationDigest = "sha256:" + strings.Repeat("b", 64)
			}
			writeInput(t, request.Configuration, input)
			before, calls := journalBytes(t, request.Root), len(effects.phases)
			if _, err := backend.Run(context.Background(), rotation); err == nil || !bytes.Equal(before, journalBytes(t, request.Root)) || calls != len(effects.phases) {
				t.Fatal("invalid rotation changed intent or native effects")
			}
		})
	}
}

type nodeEffects struct {
	invalid         bool
	ready           bool
	failPhase       lifecycle.Phase
	failure         error
	cleanupFailure  error
	rollbackFailure error
	phases          []lifecycle.Phase
	rollbacks       int
}

func (effects *nodeEffects) ValidateEnrollment(Plan) error {
	if effects.invalid {
		return ErrVerification
	}
	return nil
}
func (effects *nodeEffects) ApplyPhase(_ context.Context, plan Plan, phase lifecycle.Phase) error {
	effects.phases = append(effects.phases, phase)
	if phase == effects.failPhase && effects.failure != nil {
		err := effects.failure
		effects.failure = nil
		return err
	}
	switch phase {
	case lifecycle.PhaseStaging:
		if plan.Previous != nil {
			for _, candidate := range []Plan{*plan.Previous, plan} {
				prefix := "fixture-rotation/" + candidate.Binding.ConfigurationDigest[len("sha256:"):]
				for relative, source := range map[string][]byte{
					layout.NodeCertificate: candidate.Credentials.Certificate, layout.NodePrivateKey: candidate.Credentials.PrivateKey,
					layout.NodeTrust: candidate.Credentials.Trust, layout.CollectorCertificate: candidate.Credentials.CollectorCertificate,
					layout.CollectorPrivateKey: candidate.Credentials.CollectorPrivateKey} {
					path := filepath.Join(plan.Root, filepath.FromSlash(prefix), filepath.FromSlash(relative))
					if os.MkdirAll(filepath.Dir(path), 0o700) != nil || os.WriteFile(path, source, 0o600) != nil {
						return ErrUnavailable
					}
				}
			}
			return nil
		}
		if err := os.MkdirAll(filepath.Join(plan.Root, "releases"), 0o700); err != nil {
			return err
		}
		_, err := release.StageDirectory(plan.Bundle, plan.TrustBytes, filepath.Join(plan.Root, "releases", plan.Bundle.Manifest.Release.ID))
		return err
	case lifecycle.PhaseConfiguring:
		encoded, _ := json.Marshal(plan.Configuration)
		for relative, source := range map[string][]byte{layout.ReleaseTrust: plan.TrustBytes, layout.NodeConfiguration: encoded,
			layout.NodeCertificate: plan.Credentials.Certificate, layout.NodePrivateKey: plan.Credentials.PrivateKey, layout.NodeTrust: plan.Credentials.Trust,
			layout.CollectorCertificate: plan.Credentials.CollectorCertificate, layout.CollectorPrivateKey: plan.Credentials.CollectorPrivateKey} {
			path := filepath.Join(plan.Root, filepath.FromSlash(relative))
			if os.MkdirAll(filepath.Dir(path), 0o700) != nil || os.WriteFile(path, source, 0o600) != nil {
				return ErrUnavailable
			}
		}
	case lifecycle.PhaseStarting:
		effects.ready = true
	case lifecycle.PhaseVerifying, lifecycle.PhaseCommitting:
		if !effects.ready {
			return ErrVerification
		}
	}
	return nil
}
func (effects *nodeEffects) StageRelease(_ context.Context, plan Plan) error {
	if err := os.MkdirAll(filepath.Join(plan.Root, "releases"), 0o700); err != nil {
		return err
	}
	_, err := release.StageDirectory(plan.Bundle, plan.TrustBytes, filepath.Join(plan.Root, "releases", plan.Bundle.Manifest.Release.ID))
	return err
}
func (effects *nodeEffects) Rollback(_ context.Context, plan Plan) error {
	effects.rollbacks++
	if effects.rollbackFailure != nil {
		return effects.rollbackFailure
	}
	effects.ready = plan.ReleaseSource != nil
	return nil
}
func (effects *nodeEffects) Observe(context.Context, Plan) (bool, error) { return effects.ready, nil }
func (effects *nodeEffects) ReadInstallation(root string) (nodeconfig.Configuration, Credentials, error) {
	return readFixtureNodeCredentials(root, "")
}
func (effects *nodeEffects) ReadRotation(root, digest string) (nodeconfig.Configuration, Credentials, error) {
	return readFixtureNodeCredentials(root, "fixture-rotation/"+digest[len("sha256:"):])
}
func (effects *nodeEffects) FinalizeRotation(context.Context, Plan, lifecycle.Command) error {
	return effects.cleanupFailure
}
func readFixtureNodeCredentials(root, prefix string) (nodeconfig.Configuration, Credentials, error) {
	source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(layout.NodeConfiguration)))
	if err != nil {
		return nodeconfig.Configuration{}, Credentials{}, err
	}
	config, err := nodeconfig.DecodeConfiguration(source)
	if err != nil {
		return nodeconfig.Configuration{}, Credentials{}, err
	}
	var material Credentials
	for relative, target := range map[string]*[]byte{layout.NodeCertificate: &material.Certificate, layout.NodePrivateKey: &material.PrivateKey,
		layout.NodeTrust: &material.Trust, layout.CollectorCertificate: &material.CollectorCertificate, layout.CollectorPrivateKey: &material.CollectorPrivateKey} {
		*target, err = os.ReadFile(filepath.Join(root, filepath.FromSlash(prefix), filepath.FromSlash(relative)))
		if err != nil {
			material.Clear()
			return nodeconfig.Configuration{}, Credentials{}, err
		}
	}
	return config, material, nil
}

func nodeRequest(t *testing.T, supplied ...releasetest.Fixture) (cli.Request, nodeconfig.Enrollment) {
	t.Helper()
	var fixture releasetest.Fixture
	if len(supplied) == 1 {
		fixture = supplied[0]
	} else if len(supplied) == 0 {
		var err error
		fixture, err = releasetest.WriteNode(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal("node request accepts one release fixture")
	}
	base := t.TempDir()
	root := filepath.Join(base, "node")
	files := []string{"node.pem", "node-key.pem", "trust.pem", "collector.pem", "collector-key.pem"}
	for _, file := range files {
		if os.WriteFile(filepath.Join(base, file), []byte("test-only:"+file), 0o600) != nil {
			t.Fatal("write enrollment fixture")
		}
	}
	input := nodeconfig.Enrollment{APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.EnrollmentKind,
		Node: nodeconfig.Configuration{APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.ConfigurationKind,
			Identity:     nodev1.Identity{InstallationID: "mxi-" + strings.Repeat("a", 32), ExecutionTargetID: "target-a"},
			ControllerID: "controller-a", BindingRef: "binding-a", ExpectedFingerprint: "sha256:" + strings.Repeat("a", 64),
			ListenAddress: "127.0.0.1:16443", CollectorEndpoint: "https://127.0.0.1:19100", StoragePath: filepath.Join(root, "runtime", "executor"),
			CertificateFile: filepath.Join(base, files[0]), PrivateKeyFile: filepath.Join(base, files[1]), TrustFile: filepath.Join(base, files[2])},
		CollectorCertificateFile: filepath.Join(base, files[3]), CollectorPrivateKeyFile: filepath.Join(base, files[4])}
	path := filepath.Join(base, "enrollment.json")
	writeInput(t, path, input)
	return cli.Request{Action: lifecycle.ActionInstall, Subject: cli.SubjectNode, Root: root, Bundle: fixture.Root, TrustKey: fixture.TrustPath, Configuration: path}, input
}

func writeInput(t *testing.T, path string, value nodeconfig.Enrollment) {
	t.Helper()
	source, err := json.Marshal(value)
	if err != nil || os.WriteFile(path, source, 0o600) != nil {
		t.Fatal("write node input")
	}
}
func nodeState(t *testing.T, root string) lifecycle.Journal {
	t.Helper()
	session, err := journal.AcquireExisting(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	state, err := session.Read()
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func journalBytes(t *testing.T, root string) []byte {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(root, "state", "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	return source
}
func assertNodeFault(t *testing.T, err error, code string) {
	t.Helper()
	var value *cli.Fault
	if !errors.As(err, &value) || value.Code != code {
		t.Fatalf("node fault = %v, want %s", err, code)
	}
}
