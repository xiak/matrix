package platformcommand

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

func TestCredentialRecoveryInputIsClosedBoundedAndSecretSafe(t *testing.T) {
	const source = `{"apiVersion":"installation.matrix.xiak.com/v1","kind":"PlatformCredentialRecoveryInput","commandId":"cmd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password":"temporary-Recovery1!"}`
	input, err := DecodeCredentialRecoveryInput([]byte(source))
	if err != nil || input.CommandID != "cmd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || !input.Password.Present() {
		t.Fatal("valid private credential recovery input was rejected")
	}
	if _, err := json.Marshal(input); !errors.Is(err, iamv1.ErrSecretSerialization) {
		t.Fatal("ordinary serialization exposed credential recovery material")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", input, input, input), "temporary-Recovery") {
		t.Fatal("formatting exposed credential recovery material")
	}
	for _, invalid := range []string{
		"null", "[]", "{}", source + "{}", source + strings.Repeat(" ", MaximumCredentialRecoveryInputBytes),
		strings.Replace(source, "installation.matrix.xiak.com/v1", "installation.matrix.xiak.com/v2", 1),
		strings.Replace(source, "PlatformCredentialRecoveryInput", "PlatformAuthorization", 1),
		strings.Replace(source, `"password":"temporary-Recovery1!"`, `"password":null`, 1),
		strings.Replace(source, `"password":"temporary-Recovery1!"`, `"password":""`, 1),
		strings.Replace(source, `"password":"temporary-Recovery1!"`, `"password":"temporary-Recovery1!","password":"other"`, 1),
		strings.Replace(source, `"commandId":"cmd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"commandId":"../another"`, 1),
		strings.Replace(source, `"password":`, `"principalId":"principal-other","password":`, 1),
		strings.Replace(source, `"password":`, `"organizationId":"organization-other","password":`, 1),
		strings.Replace(source, `"password":`, `"purpose":"grant-platform","password":`, 1),
		strings.Replace(source, `"password":`, `"databaseDsn":"postgresql://secret@foreign/other","password":`, 1),
	} {
		if _, err := DecodeCredentialRecoveryInput([]byte(invalid)); err == nil ||
			strings.Contains(err.Error(), "temporary-Recovery") || strings.Contains(err.Error(), "foreign") {
			t.Fatal("invalid credential recovery input was accepted or disclosed")
		}
	}
}

func TestNodeConfigurationRetainsOneIntentAcrossEveryInterruptedPhase(t *testing.T) {
	for _, phase := range []lifecycle.Phase{"", lifecycle.PhaseStaging, lifecycle.PhaseConfiguring, lifecycle.PhaseStarting, lifecycle.PhaseVerifying, lifecycle.PhaseCommitting} {
		t.Run(string(phase), func(t *testing.T) {
			fixture := writeReleaseFixture(t)
			effects := &installEffects{nodeFailPhase: phase, nodeFailErr: ErrEffectOutcomeUnknown}
			backend := newTestBackend(t, effects)
			root := filepath.Join(t.TempDir(), "matrix")
			if _, err := backend.Run(context.Background(), installRequest(root, fixture)); err != nil {
				t.Fatal(err)
			}
			before := readJournal(t, root)
			expected, input := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
			effects.nodePlan = NodeConnectionsPlan{ExpectedDigest: expected, InputDigest: input}
			request := cli.Request{Action: lifecycle.ActionConfigureNodes, Root: root, Configuration: filepath.Join(root, "private.json"), ExpectedConfigurationDigest: expected}
			result, err := backend.Run(context.Background(), request)
			state := readJournal(t, root)
			if phase != "" {
				if err == nil || state.Active == nil || state.Active.Phase != phase || state.Active.Command.InputDigest != input || state.Active.Command.ExpectedConfigurationDigest != expected {
					t.Fatal("interruption lost the exact connection intent")
				}
				command := state.Active.Command
				starts := effects.nodeCalls[lifecycle.PhaseStarting]
				backend = newTestBackend(t, effects)
				result, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionConfigureNodes, Root: root, Resume: true})
				state = readJournal(t, root)
				if state.Last == nil || state.Last.Command != command {
					t.Fatal("resume allocated a different intent")
				}
				if (phase == lifecycle.PhaseVerifying || phase == lifecycle.PhaseCommitting) && effects.nodeCalls[lifecycle.PhaseStarting] != starts {
					t.Fatal("late resume restarted the API again")
				}
			}
			if err != nil || !result.Changed || result.ConfigurationDigest != input || state.Active != nil || state.Last.Outcome != lifecycle.OutcomeSucceeded ||
				state.CurrentReleaseID != before.CurrentReleaseID || state.CurrentReleaseDigest != before.CurrentReleaseDigest {
				t.Fatalf("connection workflow did not complete in place: %v", err)
			}
			calls := fmt.Sprint(effects.nodeCalls)
			result, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionConfigureNodes, Root: root, Resume: true})
			if err != nil || result.Changed || fmt.Sprint(effects.nodeCalls) != calls || !reflect.DeepEqual(state, readJournal(t, root)) {
				t.Fatal("completed replay reran connection effects")
			}
			if effects.rollbackCalls != 0 || effects.backupCalls != 0 || len(effects.upgradeCalls) != 0 || len(effects.recoveryCalls) != 0 {
				t.Fatal("node connection used a release or recovery effect")
			}
		})
	}
}

func TestNodeConfigurationPreparationFailureDoesNotAdvanceJournal(t *testing.T) {
	fixture := writeReleaseFixture(t)
	effects := &installEffects{nodePrepareErr: ErrEffectConflict}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(context.Background(), installRequest(root, fixture)); err != nil {
		t.Fatal(err)
	}
	before := readJournal(t, root)
	_, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionConfigureNodes, Root: root, Configuration: filepath.Join(root, "private.json"), ExpectedConfigurationDigest: "sha256:" + strings.Repeat("a", 64)})
	if err == nil || len(effects.nodeCalls) != 0 || !reflect.DeepEqual(before, readJournal(t, root)) {
		t.Fatal("invalid node input advanced the journal or provider")
	}
}

func TestCredentialRecoveryRetainsOneIntentAndNeverRollsBackCredentials(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		phase       lifecycle.Phase
		err         error
		wantPending lifecycle.Phase
		wantFailure string
	}{
		{name: "success"},
		{name: "stage interruption", phase: lifecycle.PhaseStaging, err: ErrEffectUnavailable, wantPending: lifecycle.PhaseStaging},
		{name: "lost apply response", phase: lifecycle.PhaseRecoveringCredentials, err: ErrEffectOutcomeUnknown, wantPending: lifecycle.PhaseRecoveringCredentials},
		{name: "unverifiable provider", phase: lifecycle.PhaseRecoveringCredentials, err: ErrEffectVerification, wantPending: lifecycle.PhaseRecoveringCredentials},
		{name: "known rejection", phase: lifecycle.PhaseRecoveringCredentials, err: ErrCredentialRecoveryForbidden, wantFailure: "CREDENTIAL_RECOVERY_FORBIDDEN"},
		{name: "cleanup unavailable", phase: lifecycle.PhaseCommitting, err: ErrEffectUnavailable, wantPending: lifecycle.PhaseCommitting},
		{name: "cleanup cannot reclassify success", phase: lifecycle.PhaseCommitting, err: ErrCredentialRecoveryForbidden, wantPending: lifecycle.PhaseCommitting},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			fixture := writeReleaseFixture(t)
			effects := &installEffects{credentialFailPhase: scenario.phase, credentialFailErr: scenario.err, credentialFailOnce: true}
			backend := newTestBackend(t, effects)
			root := filepath.Join(t.TempDir(), "matrix")
			if _, err := backend.Run(context.Background(), installRequest(root, fixture)); err != nil {
				t.Fatal(err)
			}
			materializeInstalledRelease(t, root, fixture)
			before := readJournal(t, root)
			const commandID = "cmd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			commitment := "sha256:" + strings.Repeat("b", 64)
			effects.credentialPlan = CredentialRecoveryPlan{CommandID: commandID, InputCommitment: commitment}
			request := cli.Request{Action: lifecycle.ActionRecoverCredentials, Root: root, RecoveryInput: filepath.Join(root, "private-input.json")}
			result, runErr := backend.Run(context.Background(), request)
			state := readJournal(t, root)
			if scenario.wantPending != "" {
				if runErr == nil || state.Active == nil || state.Active.Phase != scenario.wantPending || state.Active.FailureCode != "" ||
					state.Active.Command.ID != commandID || state.Active.Command.InputDigest != commitment ||
					state.Active.Command.Action != lifecycle.ActionRecoverCredentials {
					t.Fatal("unknown/cleanup failure lost or recategorized the sealed intent")
				}
				originalCommand := state.Active.Command
				applyCalls := effects.credentialCalls[lifecycle.PhaseRecoveringCredentials]
				backend = newTestBackend(t, effects)
				result, runErr = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionRecoverCredentials, Root: root, Resume: true})
				if scenario.wantPending == lifecycle.PhaseCommitting && effects.credentialCalls[lifecycle.PhaseRecoveringCredentials] != applyCalls {
					t.Fatal("cleanup replay invoked credential recovery again")
				}
				state = readJournal(t, root)
				if state.Last == nil || state.Last.Command != originalCommand {
					t.Fatal("public resume replaced the original journal intent")
				}
			}
			if state.Active != nil || state.Last == nil || state.Last.Command.ID != commandID || state.Last.Command.InputDigest != commitment ||
				state.CurrentReleaseID != before.CurrentReleaseID || state.CurrentReleaseDigest != before.CurrentReleaseDigest ||
				state.PreviousRelease != before.PreviousRelease || state.PreviousReleaseDigest != before.PreviousReleaseDigest {
				t.Fatal("credential recovery changed release ownership or lost completion")
			}
			if scenario.wantFailure == "" {
				if runErr != nil || state.Last.Outcome != lifecycle.OutcomeSucceeded || result.CorrelationID != commandID || !result.Changed {
					t.Fatalf("recovery did not finish its sealed intent: %v", runErr)
				}
				applyCalls := effects.credentialCalls[lifecycle.PhaseRecoveringCredentials]
				replayed, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionRecoverCredentials, Root: root, Resume: true})
				if err != nil || replayed.Changed || replayed.CorrelationID != commandID ||
					!reflect.DeepEqual(state, readJournal(t, root)) || effects.credentialCalls[lifecycle.PhaseRecoveringCredentials] != applyCalls {
					t.Fatal("completed public resume changed credentials or journal state")
				}
			} else {
				assertFault(t, runErr, cli.FaultPrecondition, scenario.wantFailure)
				if state.Last.Outcome != lifecycle.OutcomeFailed || state.Last.Phase != lifecycle.PhaseReady || effects.credentialCalls[lifecycle.PhaseCommitting] != 1 {
					t.Fatal("known rejection did not commit sanitized failure and clean private material")
				}
			}
			for phase := range effects.credentialCalls {
				if phase != lifecycle.PhaseStaging && phase != lifecycle.PhaseRecoveringCredentials && phase != lifecycle.PhaseCommitting {
					t.Fatal("credential recovery reached an unrelated lifecycle phase")
				}
			}
			if effects.rollbackCalls != 0 || effects.backupCalls != 0 || len(effects.recoveryCalls) != 0 || len(effects.upgradeCalls) != 0 || len(effects.explicitRollbackCalls) != 0 {
				t.Fatal("credential recovery used release/backup/restart effects")
			}
		})
	}
}

func TestCredentialRecoveryRejectsUnsupportedProfilesBeforePreparingAnIntent(t *testing.T) {
	profiles := []struct {
		name    string
		profile release.DatabaseProfile
	}{
		{name: "published scalar is not first-authorization admission", profile: release.DatabaseProfile{SchemaVersion: 1, Compatibility: "expand-contract-n-minus-one"}},
		{name: "prior credential contract", profile: release.DatabaseProfile{Compatibility: "identical-authority-profile", Authorities: release.AuthoritySchemas{IAM: 3, Audit: 2, PaaS: 2}, ContractRevision: 3}},
		{name: "different PaaS schema", profile: release.DatabaseProfile{Compatibility: "identical-authority-profile", Authorities: release.AuthoritySchemas{IAM: 4, Audit: 3, PaaS: 1}, ContractRevision: 4}},
		{name: "different contract revision", profile: release.DatabaseProfile{Compatibility: "identical-authority-profile", Authorities: release.AuthoritySchemas{IAM: 4, Audit: 3, PaaS: 2}, ContractRevision: 8}},
	}
	for _, test := range profiles {
		t.Run(test.name, func(t *testing.T) {
			fixtures, err := releasetest.WriteSequence(t.TempDir(), 2, test.profile, test.profile)
			if err != nil {
				t.Fatal(err)
			}
			effects := &installEffects{}
			backend := newTestBackend(t, effects)
			root := filepath.Join(t.TempDir(), "matrix")
			if _, err := backend.Run(context.Background(), installRequest(root, fixtures[0])); err != nil {
				t.Fatal(err)
			}
			materializeInstalledRelease(t, root, fixtures[0])
			before := readJournal(t, root)
			_, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionRecoverCredentials, Root: root, RecoveryInput: filepath.Join(root, "private-input.json")})
			assertFault(t, err, cli.FaultPrecondition, "CREDENTIAL_RECOVERY_PROFILE_UNSUPPORTED")
			if !reflect.DeepEqual(before, readJournal(t, root)) || effects.credentialPrepareCalls != 0 || len(effects.credentialCalls) != 0 {
				t.Fatal("unsupported profile reached recovery preparation or changed its journal")
			}
		})
	}
}

func TestCredentialRecoveryRetainsExactPhase3Predecessor(t *testing.T) {
	profile := release.SupportedDatabasePredecessorProfile()
	if err := ValidateCredentialRecoveryProfile(profile); err != nil {
		t.Fatalf("phase3 predecessor credential recovery profile: %v", err)
	}
}

func TestInstallCommitsPinnedReleaseOnlyAfterEffectsAndReplays(t *testing.T) {
	fixture := writeReleaseFixture(t)
	effects := &installEffects{}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	request := installRequest(root, fixture)

	result, err := backend.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("install release: %v", err)
	}
	if result.State != "READY" || result.ReleaseID != fixture.Manifest.Release.ID ||
		!result.Changed || result.CorrelationID == "" {
		t.Fatalf("install result = %#v", result)
	}
	for _, phase := range effectingInstallPhases() {
		if effects.calls[phase] != 1 {
			t.Fatalf("phase %s calls = %d, want one", phase, effects.calls[phase])
		}
	}
	state := readJournal(t, root)
	if state.CurrentReleaseID != fixture.Manifest.Release.ID ||
		state.CurrentReleaseDigest != fixture.ManifestDigest ||
		state.ReleaseTrust.KeyID != fixture.Trust.KeyID ||
		state.ReleaseTrust.Fingerprint != fixture.Trust.PublicKeyFingerprint ||
		state.Active != nil || state.Last == nil ||
		state.Last.Outcome != lifecycle.OutcomeSucceeded {
		t.Fatalf("committed journal = %#v", state)
	}

	replayed, err := backend.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("replay installed release: %v", err)
	}
	if replayed.Changed || replayed.ReleaseID != result.ReleaseID ||
		replayed.CorrelationID != result.CorrelationID {
		t.Fatalf("replayed result = %#v", replayed)
	}
	for _, phase := range effectingInstallPhases() {
		if effects.calls[phase] != 1 {
			t.Fatalf("replay repeated phase %s", phase)
		}
	}
}

func TestInstallResumesUnknownEffectWithTheSameDurableCommand(t *testing.T) {
	fixture := writeReleaseFixture(t)
	effects := &installEffects{
		failPhase: lifecycle.PhaseLoadingImages,
		failErr:   ErrEffectOutcomeUnknown,
		failOnce:  true,
	}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	request := installRequest(root, fixture)

	_, err := backend.Run(context.Background(), request)
	assertFault(t, err, cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
	interrupted := readJournal(t, root)
	if interrupted.Active == nil || interrupted.Active.Phase != lifecycle.PhaseLoadingImages {
		t.Fatalf("interrupted journal = %#v", interrupted)
	}
	commandID := interrupted.Active.Command.ID
	installationID := interrupted.InstallationID

	result, err := backend.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("resume install: %v", err)
	}
	if result.CorrelationID != commandID || !result.Changed {
		t.Fatalf("resumed result = %#v", result)
	}
	completed := readJournal(t, root)
	if completed.InstallationID != installationID || completed.CurrentReleaseID != result.ReleaseID {
		t.Fatalf("resumed journal = %#v", completed)
	}
	if effects.calls[lifecycle.PhasePreflight] != 1 ||
		effects.calls[lifecycle.PhaseStaging] != 1 ||
		effects.calls[lifecycle.PhaseLoadingImages] != 2 || effects.rollbackCalls != 0 {
		t.Fatalf("resume effect counts = %#v / rollback=%d", effects.calls, effects.rollbackCalls)
	}
}

func TestInstallRollsBackDefinitiveFailureAndPermitsANewAttempt(t *testing.T) {
	fixture := writeReleaseFixture(t)
	effects := &installEffects{
		failPhase: lifecycle.PhaseStarting,
		failErr:   ErrEffectVerification,
	}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	request := installRequest(root, fixture)

	_, err := backend.Run(context.Background(), request)
	assertFault(t, err, cli.FaultVerification, "START_VERIFICATION_FAILED")
	failed := readJournal(t, root)
	if failed.CurrentReleaseID != "" || failed.Active != nil || failed.Last == nil ||
		failed.Last.Outcome != lifecycle.OutcomeRolledBack || effects.rollbackCalls != 1 {
		t.Fatalf("rolled-back install = %#v / rollback=%d", failed, effects.rollbackCalls)
	}
	failedCommandID := failed.Last.Command.ID

	effects.failErr = nil
	result, err := backend.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("retry failed install: %v", err)
	}
	if !result.Changed || result.CorrelationID == failedCommandID {
		t.Fatalf("retry result = %#v", result)
	}
	completed := readJournal(t, root)
	if completed.CurrentReleaseDigest != fixture.ManifestDigest ||
		completed.Last == nil || completed.Last.Outcome != lifecycle.OutcomeSucceeded {
		t.Fatalf("retried journal = %#v", completed)
	}
}

func TestInstallKeepsRollbackActiveWhileItsDependencyIsUnavailable(t *testing.T) {
	fixture := writeReleaseFixture(t)
	effects := &installEffects{
		failPhase:        lifecycle.PhaseStarting,
		failErr:          ErrEffectVerification,
		rollbackErr:      ErrEffectUnavailable,
		rollbackFailOnce: true,
	}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	request := installRequest(root, fixture)

	_, err := backend.Run(context.Background(), request)
	assertFault(t, err, cli.FaultUnavailable, "ROLLBACK_DEPENDENCY_UNAVAILABLE")
	interrupted := readJournal(t, root)
	if interrupted.Active == nil || interrupted.Active.Phase != lifecycle.PhaseRollingBack ||
		interrupted.CurrentReleaseID != "" {
		t.Fatalf("unavailable rollback journal = %#v", interrupted)
	}

	_, err = backend.Run(context.Background(), request)
	assertFault(t, err, cli.FaultVerification, "START_VERIFICATION_FAILED")
	completed := readJournal(t, root)
	if completed.Active != nil || completed.Last == nil ||
		completed.Last.Outcome != lifecycle.OutcomeRolledBack || effects.rollbackCalls != 2 {
		t.Fatalf("resumed rollback journal = %#v / calls=%d", completed, effects.rollbackCalls)
	}
}

func TestInstallRejectsAValidBundleFromAnotherTrustRoot(t *testing.T) {
	first := writeReleaseFixture(t)
	second := writeReleaseFixture(t)
	effects := &installEffects{}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(context.Background(), installRequest(root, first)); err != nil {
		t.Fatalf("install first release: %v", err)
	}

	_, err := backend.Run(context.Background(), installRequest(root, second))
	assertFault(t, err, cli.FaultConflict, "RELEASE_TRUST_CONFLICT")
}

func TestUpgradeBindsImmediatePredecessorAndBackupBeforePublishing(t *testing.T) {
	fixtures := writeReleaseSequence(t, 2)
	effects := &installEffects{}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(
		context.Background(), installRequest(root, fixtures[0]),
	); err != nil {
		t.Fatalf("install upgrade source: %v", err)
	}
	materializeInstalledRelease(t, root, fixtures[0])

	result, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionUpgrade, Root: root, Bundle: fixtures[1].Root,
	})
	if err != nil || result.ReleaseID != fixtures[1].Manifest.Release.ID ||
		result.PreviousID != fixtures[0].Manifest.Release.ID ||
		!result.Changed || result.BackupID == "" {
		t.Fatalf("upgrade result = %#v / %v", result, err)
	}
	wantPhases := []lifecycle.Phase{
		lifecycle.PhasePreflight, lifecycle.PhaseBackingUp, lifecycle.PhaseStaging,
		lifecycle.PhaseLoadingImages, lifecycle.PhaseConfiguring,
		lifecycle.PhaseMigrating, lifecycle.PhaseStarting, lifecycle.PhaseVerifying,
	}
	for _, phase := range wantPhases {
		if effects.upgradeCalls[phase] != 1 {
			t.Fatalf("upgrade phase %s calls = %d", phase, effects.upgradeCalls[phase])
		}
	}
	if effects.upgradePlan.Source.ReleaseID != fixtures[0].Manifest.Release.ID ||
		effects.upgradePlan.Target.Bundle.Manifest.Release.ID != fixtures[1].Manifest.Release.ID ||
		effects.upgradePlan.BackupID != result.BackupID ||
		effects.upgradePlan.CreatedAt.IsZero() {
		t.Fatalf("upgrade plan = %#v", effects.upgradePlan)
	}
	state := readJournal(t, root)
	if state.CurrentReleaseID != fixtures[1].Manifest.Release.ID ||
		state.CurrentReleaseDigest != fixtures[1].ManifestDigest ||
		state.PreviousRelease != fixtures[0].Manifest.Release.ID ||
		state.PreviousReleaseDigest != fixtures[0].ManifestDigest ||
		state.Last == nil || state.Last.Command.BackupID != result.BackupID {
		t.Fatalf("upgraded journal = %#v", state)
	}
}

func TestUpgradeUnknownOutcomeResumesAndDefinitiveFailureRestoresSource(t *testing.T) {
	fixtures := writeReleaseSequence(t, 2)
	effects := &installEffects{
		upgradeFailPhase: lifecycle.PhaseLoadingImages,
		upgradeFailErr:   ErrEffectOutcomeUnknown,
		upgradeFailOnce:  true,
	}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(
		context.Background(), installRequest(root, fixtures[0]),
	); err != nil {
		t.Fatalf("install upgrade replay source: %v", err)
	}
	materializeInstalledRelease(t, root, fixtures[0])
	request := cli.Request{
		Action: lifecycle.ActionUpgrade, Root: root, Bundle: fixtures[1].Root,
	}
	_, err := backend.Run(context.Background(), request)
	assertFault(t, err, cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
	active := readJournal(t, root)
	if active.Active == nil || active.Active.Phase != lifecycle.PhaseLoadingImages {
		t.Fatalf("unknown upgrade journal = %#v", active)
	}
	commandID := active.Active.Command.ID
	backupID := active.Active.Command.BackupID

	effects.upgradeFailPhase = lifecycle.PhaseStarting
	effects.upgradeFailErr = ErrEffectVerification
	effects.upgradeFailOnce = false
	_, err = backend.Run(context.Background(), request)
	assertFault(t, err, cli.FaultVerification, "START_VERIFICATION_FAILED")
	restored := readJournal(t, root)
	if restored.CurrentReleaseID != fixtures[0].Manifest.Release.ID ||
		restored.PreviousRelease != "" || restored.Active != nil || restored.Last == nil ||
		restored.Last.Command.ID != commandID || restored.Last.Command.BackupID != backupID ||
		restored.Last.Outcome != lifecycle.OutcomeRolledBack ||
		effects.upgradeRollbackCalls != 1 ||
		effects.upgradeCalls[lifecycle.PhaseLoadingImages] != 2 {
		t.Fatalf("automatically restored upgrade = %#v / effects=%#v", restored, effects)
	}
}

func TestUpgradeRejectsSkippedPredecessorWithoutStartingACommand(t *testing.T) {
	fixtures := writeReleaseSequence(t, 3)
	effects := &installEffects{}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(
		context.Background(), installRequest(root, fixtures[0]),
	); err != nil {
		t.Fatalf("install predecessor source: %v", err)
	}
	materializeInstalledRelease(t, root, fixtures[0])
	before := readJournal(t, root)
	_, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionUpgrade, Root: root, Bundle: fixtures[2].Root,
	})
	assertFault(t, err, cli.FaultPrecondition, "UPGRADE_PREDECESSOR_MISMATCH")
	if !reflect.DeepEqual(readJournal(t, root), before) || len(effects.upgradeCalls) != 0 {
		t.Fatal("skipped predecessor changed state or reached upgrade effects")
	}
}

func TestInstallRejectsNonRootReleaseWithoutStartingACommand(t *testing.T) {
	fixtures := writeReleaseSequence(t, 2)
	effects := &installEffects{}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")

	_, err := backend.Run(
		context.Background(), installRequest(root, fixtures[1]),
	)
	assertFault(t, err, cli.FaultPrecondition, "INSTALL_RELEASE_HAS_PREDECESSOR")
	if len(effects.calls) != 0 {
		t.Fatal("non-root installation reached installation effects")
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("non-root installation created installation state")
	}
}

func TestExplicitRollbackReplaysUnknownOutcomeAndCommitsOnlyTheSignedPredecessor(t *testing.T) {
	fixtures := writeReleaseSequence(t, 2)
	effects := &installEffects{
		observeReady:              true,
		explicitRollbackFailPhase: lifecycle.PhaseRollingBack,
		explicitRollbackFailErr:   ErrEffectOutcomeUnknown,
		explicitRollbackFailOnce:  true,
	}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(
		context.Background(), installRequest(root, fixtures[0]),
	); err != nil {
		t.Fatalf("install rollback source: %v", err)
	}
	materializeInstalledRelease(t, root, fixtures[0])
	if _, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionUpgrade, Root: root, Bundle: fixtures[1].Root,
	}); err != nil {
		t.Fatalf("upgrade rollback fixture: %v", err)
	}
	materializeInstalledRelease(t, root, fixtures[1])

	request := cli.Request{Action: lifecycle.ActionRollback, Root: root}
	_, err := backend.Run(context.Background(), request)
	assertFault(t, err, cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
	active := readJournal(t, root)
	if active.Active == nil || active.Active.Command.Action != lifecycle.ActionRollback ||
		active.Active.Phase != lifecycle.PhaseRollingBack ||
		active.CurrentReleaseID != fixtures[1].Manifest.Release.ID ||
		active.PreviousRelease != fixtures[0].Manifest.Release.ID {
		t.Fatalf("unknown rollback journal = %#v", active)
	}
	commandID := active.Active.Command.ID

	result, err := backend.Run(context.Background(), request)
	if err != nil || !result.Changed || result.State != "READY" ||
		result.ReleaseID != fixtures[0].Manifest.Release.ID || result.PreviousID != "" ||
		result.CorrelationID != commandID {
		t.Fatalf("resumed rollback result = %#v / %v", result, err)
	}
	for _, phase := range []lifecycle.Phase{
		lifecycle.PhaseRollingBack, lifecycle.PhaseStarting, lifecycle.PhaseVerifying,
	} {
		want := 1
		if phase == lifecycle.PhaseRollingBack {
			want = 2
		}
		if effects.explicitRollbackCalls[phase] != want {
			t.Fatalf("rollback phase %s calls = %d, want %d", phase, effects.explicitRollbackCalls[phase], want)
		}
	}
	if effects.observeCalls != 1 ||
		effects.explicitRollbackPlan.Current.Bundle.Manifest.Release.ID != fixtures[1].Manifest.Release.ID ||
		effects.explicitRollbackPlan.Previous.ReleaseID != fixtures[0].Manifest.Release.ID {
		t.Fatalf("rollback preflight/plan = calls:%d plan:%#v", effects.observeCalls, effects.explicitRollbackPlan)
	}
	completed := readJournal(t, root)
	if completed.CurrentReleaseID != fixtures[0].Manifest.Release.ID ||
		completed.CurrentReleaseDigest != fixtures[0].ManifestDigest ||
		completed.PreviousRelease != "" || completed.PreviousReleaseDigest != "" ||
		completed.Active != nil || completed.Last == nil ||
		completed.Last.Command.ID != commandID ||
		completed.Last.Outcome != lifecycle.OutcomeSucceeded {
		t.Fatalf("completed rollback journal = %#v", completed)
	}
}

func TestDifferentDatabaseProfilesRejectBeforeEffectsOrJournalChange(t *testing.T) {
	current := release.CurrentDatabaseProfile()
	legacy := release.DatabaseProfile{SchemaVersion: 1, Compatibility: "expand-contract-n-minus-one"}
	previousHostProfile := release.DatabaseProfile{
		Compatibility: "identical-authority-profile", ContractRevision: 1,
		Authorities: release.AuthoritySchemas{IAM: 2, Audit: 2, PaaS: 2},
	}
	revised := current
	revised.ContractRevision++
	profiles := []struct {
		name           string
		source, target release.DatabaseProfile
	}{
		{name: "published scalar to authorities", source: legacy, target: current},
		{name: "host release before session lineage", source: previousHostProfile, target: current},
		{name: "session lineage to prior host release", source: current, target: previousHostProfile},
		{name: "legacy scalar increase", source: legacy, target: release.DatabaseProfile{SchemaVersion: 2, Compatibility: legacy.Compatibility}},
		{name: "same schemas different authority contract", source: current, target: revised},
	}
	for _, authority := range []string{"IAM", "Audit", "PaaS"} {
		target := current
		switch authority {
		case "IAM":
			target.Authorities.IAM++
		case "Audit":
			target.Authorities.Audit++
		case "PaaS":
			target.Authorities.PaaS++
		}
		profiles = append(profiles, struct {
			name           string
			source, target release.DatabaseProfile
		}{name: authority + " only", source: current, target: target})
	}
	for _, profile := range profiles {
		for _, action := range []lifecycle.Action{lifecycle.ActionUpgrade, lifecycle.ActionRollback, lifecycle.ActionRecover} {
			t.Run(profile.name+"/"+string(action), func(t *testing.T) {
				fixtures, err := releasetest.WriteSequence(t.TempDir(), 2, profile.source, profile.target)
				if err != nil {
					t.Fatal(err)
				}
				effects := &installEffects{observeReady: true}
				backend := newTestBackend(t, effects)
				root := filepath.Join(t.TempDir(), "matrix")
				if _, err := backend.Run(context.Background(), installRequest(root, fixtures[0])); err != nil {
					t.Fatal(err)
				}
				materializeInstalledRelease(t, root, fixtures[0])
				if action == lifecycle.ActionRollback || action == lifecycle.ActionRecover {
					materializeInstalledRelease(t, root, fixtures[1])
					// A prior installer may have committed an unproved transition.
					// A sealed predecessor/backup does not admit another profile.
					state := readJournal(t, root)
					state.PreviousRelease, state.PreviousReleaseDigest = state.CurrentReleaseID, state.CurrentReleaseDigest
					state.CurrentReleaseID, state.CurrentReleaseDigest = fixtures[1].Manifest.Release.ID, fixtures[1].ManifestDigest
					state.Last = nil
					state.Version++
					session, err := journal.AcquireExisting(context.Background(), root)
					if err != nil {
						t.Fatal(err)
					}
					writeErr := session.Write(state)
					closeErr := session.Close()
					if writeErr != nil || closeErr != nil {
						t.Fatalf("seed committed predecessor: %v / %v", writeErr, closeErr)
					}
				}
				before := readJournal(t, root)
				request := cli.Request{Action: action, Root: root, Bundle: fixtures[1].Root}
				failureCode := string(action) + "_SCHEMA_INCOMPATIBLE"
				if action == lifecycle.ActionRecover {
					request.BackupID = "backup-" + strings.Repeat("d", 32)
					effects.recoverySource = RecoverySource{
						InstallationID: before.InstallationID, BackupID: request.BackupID,
						BackupDigest: "sha256:" + strings.Repeat("e", 64),
						ReleaseID:    fixtures[0].Manifest.Release.ID, ReleaseDigest: fixtures[0].ManifestDigest,
						Database: fixtures[0].Manifest.Database,
					}
					failureCode = "RECOVERY_SCHEMA_INCOMPATIBLE"
				}
				_, err = backend.Run(context.Background(), request)
				assertFault(t, err, cli.FaultPrecondition, failureCode)
				if !reflect.DeepEqual(readJournal(t, root), before) || len(effects.upgradeCalls) != 0 ||
					len(effects.explicitRollbackCalls) != 0 || len(effects.recoveryCalls) != 0 || effects.observeCalls != 0 {
					t.Fatal("incompatible profile changed state or reached lifecycle effects")
				}
			})
		}
	}
}

func TestPublishedScalarProfileStillAllowsItsOwnReleasePair(t *testing.T) {
	legacy := release.DatabaseProfile{SchemaVersion: 1, Compatibility: "expand-contract-n-minus-one"}
	fixtures, err := releasetest.WriteSequence(t.TempDir(), 2, legacy, legacy)
	if err != nil {
		t.Fatal(err)
	}
	backend := newTestBackend(t, &installEffects{observeReady: true})
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(context.Background(), installRequest(root, fixtures[0])); err != nil {
		t.Fatal(err)
	}
	materializeInstalledRelease(t, root, fixtures[0])
	if _, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionUpgrade, Root: root, Bundle: fixtures[1].Root}); err != nil {
		t.Fatalf("upgrade published profile pair: %v", err)
	}
	materializeInstalledRelease(t, root, fixtures[1])
	result, err := backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionRollback, Root: root})
	if err != nil || result.ReleaseID != fixtures[0].Manifest.Release.ID {
		t.Fatalf("rollback published profile pair: %#v / %v", result, err)
	}
}

func TestFrozenAdjacentProfilePairAllowsInstallUpgradeAndRollback(t *testing.T) {
	current := release.CurrentDatabaseProfile()
	predecessor := release.SupportedDatabasePredecessorProfile()
	fixtures, err := releasetest.WriteSequence(t.TempDir(), 2, predecessor, current)
	if err != nil {
		t.Fatal(err)
	}
	effects := &installEffects{observeReady: true}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	installed, err := backend.Run(context.Background(), installRequest(root, fixtures[0]))
	if err != nil || installed.ReleaseID != fixtures[0].Manifest.Release.ID || !installed.Changed {
		t.Fatalf("install adjacent profile release: %#v / %v", installed, err)
	}
	materializeInstalledRelease(t, root, fixtures[0])
	upgraded, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionUpgrade, Root: root, Bundle: fixtures[1].Root,
	})
	if err != nil || upgraded.ReleaseID != fixtures[1].Manifest.Release.ID || !upgraded.Changed {
		t.Fatalf("upgrade exact runtime profile pair: %#v / %v", upgraded, err)
	}
	materializeInstalledRelease(t, root, fixtures[1])
	rolledBack, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionRollback, Root: root,
	})
	if err != nil || rolledBack.ReleaseID != fixtures[0].Manifest.Release.ID || !rolledBack.Changed {
		t.Fatalf("rollback exact runtime profile pair: %#v / %v", rolledBack, err)
	}
	if len(effects.upgradeCalls) == 0 || len(effects.explicitRollbackCalls) == 0 {
		t.Fatal("exact profile pair bypassed release lifecycle effects")
	}
}

func TestPublishedExecutableRejectsNewManifestBeforeEffects(t *testing.T) {
	binary := os.Getenv("MATRIX_INSTALLATION_LEGACY_MX_BINARY")
	if binary == "" {
		t.Skip("requires the mx executable built from published commit c88a84f")
	}
	info, err := os.Lstat(binary)
	if err != nil || !filepath.IsAbs(binary) || !info.Mode().IsRegular() {
		t.Fatal("legacy mx must be an absolute regular executable")
	}
	legacy := release.DatabaseProfile{SchemaVersion: 1, Compatibility: "expand-contract-n-minus-one"}
	fixtures, err := releasetest.WriteSequence(t.TempDir(), 2, legacy, release.CurrentDatabaseProfile())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "not-an-installation")
	const sentinel = "unowned file must remain intact"
	if err := os.WriteFile(root, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	for index, fixture := range fixtures {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		command := exec.CommandContext(ctx, binary, "platform", "install", "--format", "json",
			"--root", root, "--bundle", fixture.Root, "--trust-key", fixture.TrustPath)
		output, runErr := command.CombinedOutput()
		cancel()
		var failure struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if runErr == nil || json.Unmarshal(output, &failure) != nil {
			t.Fatalf("legacy CLI did not reject safely: %v", runErr)
		}
		if index == 0 {
			// Both checks are after signature/payload authentication. Current
			// topology need not be a supported runtime for the published mx.
			if failure.Error.Code != "INSTALLATION_ROOT_INVALID" && failure.Error.Code != "TOPOLOGY_CONTRACT_UNSUPPORTED" {
				t.Fatalf("legacy manifest did not authenticate: %s", failure.Error.Code)
			}
		} else if failure.Error.Code != "RELEASE_BUNDLE_INVALID" {
			t.Fatalf("published mx accepted the new manifest format: %s", failure.Error.Code)
		}
		retained, err := os.ReadFile(root)
		if err != nil || string(retained) != sentinel {
			t.Fatal("legacy CLI changed the unowned root")
		}
	}
}

func TestExplicitRollbackRequiresReadyCurrentReleaseBeforePersistingIntent(t *testing.T) {
	fixtures := writeReleaseSequence(t, 2)
	effects := &installEffects{}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(
		context.Background(), installRequest(root, fixtures[0]),
	); err != nil {
		t.Fatalf("install rollback preflight source: %v", err)
	}
	materializeInstalledRelease(t, root, fixtures[0])
	if _, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionUpgrade, Root: root, Bundle: fixtures[1].Root,
	}); err != nil {
		t.Fatalf("upgrade rollback preflight fixture: %v", err)
	}
	materializeInstalledRelease(t, root, fixtures[1])
	before := readJournal(t, root)

	_, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionRollback, Root: root,
	})
	assertFault(t, err, cli.FaultPrecondition, "ROLLBACK_SOURCE_NOT_READY")
	if after := readJournal(t, root); !reflect.DeepEqual(after, before) ||
		len(effects.explicitRollbackCalls) != 0 {
		t.Fatalf("rollback precondition changed state: before=%#v after=%#v calls=%#v", before, after, effects.explicitRollbackCalls)
	}
}

func TestRecoveryBindsSelectedBackupAndResumesUnknownOutcome(t *testing.T) {
	fixtures := writeReleaseSequence(t, 2)
	effects := &installEffects{
		recoveryFailPhase: lifecycle.PhaseRecovering,
		recoveryFailErr:   ErrEffectOutcomeUnknown,
		recoveryFailOnce:  true,
	}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(
		context.Background(), installRequest(root, fixtures[0]),
	); err != nil {
		t.Fatalf("install recovery source: %v", err)
	}
	materializeInstalledRelease(t, root, fixtures[0])
	if _, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionUpgrade, Root: root, Bundle: fixtures[1].Root,
	}); err != nil {
		t.Fatalf("upgrade recovery fixture: %v", err)
	}
	materializeInstalledRelease(t, root, fixtures[1])
	installed := readJournal(t, root)
	backupID := "backup-" + strings.Repeat("d", 32)
	backupDigest := "sha256:" + strings.Repeat("e", 64)
	effects.recoverySource = RecoverySource{
		InstallationID: installed.InstallationID,
		BackupID:       backupID,
		BackupDigest:   backupDigest,
		ReleaseID:      fixtures[0].Manifest.Release.ID,
		ReleaseDigest:  fixtures[0].ManifestDigest,
		Database:       fixtures[0].Manifest.Database,
	}
	request := cli.Request{
		Action: lifecycle.ActionRecover, Root: root, BackupID: backupID,
	}

	_, err := backend.Run(context.Background(), request)
	assertFault(t, err, cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
	active := readJournal(t, root)
	if active.Active == nil || active.Active.Command.Action != lifecycle.ActionRecover ||
		active.Active.Phase != lifecycle.PhaseRecovering ||
		active.Active.Command.BackupID != backupID ||
		active.Active.Command.BackupDigest != backupDigest ||
		active.Active.Command.TargetReleaseID != fixtures[0].Manifest.Release.ID ||
		active.Active.Command.InputDigest != fixtures[0].ManifestDigest ||
		active.CurrentReleaseID != fixtures[1].Manifest.Release.ID {
		t.Fatalf("unknown recovery journal = %#v", active)
	}
	commandID := active.Active.Command.ID

	effects.recoverySource.BackupDigest = "sha256:" + strings.Repeat("f", 64)
	_, err = backend.Run(context.Background(), request)
	assertFault(t, err, cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")
	if changed := readJournal(t, root); !reflect.DeepEqual(changed, active) {
		t.Fatalf("changed backup altered active recovery: before=%#v after=%#v", active, changed)
	}
	effects.recoverySource.BackupDigest = backupDigest

	result, err := backend.Run(context.Background(), request)
	if err != nil || !result.Changed || result.State != "READY" ||
		result.ReleaseID != fixtures[0].Manifest.Release.ID || result.PreviousID != "" ||
		result.BackupID != backupID || result.CorrelationID != commandID {
		t.Fatalf("resumed recovery result = %#v / %v", result, err)
	}
	for _, phase := range []lifecycle.Phase{
		lifecycle.PhaseRecovering, lifecycle.PhaseStarting, lifecycle.PhaseVerifying,
	} {
		want := 1
		if phase == lifecycle.PhaseRecovering {
			want = 2
		}
		if effects.recoveryCalls[phase] != want {
			t.Fatalf("recovery phase %s calls = %d, want %d", phase, effects.recoveryCalls[phase], want)
		}
	}
	if effects.recoveryInspectCalls != 3 ||
		effects.recoveryPlan.Current.Bundle.Manifest.Release.ID != fixtures[1].Manifest.Release.ID ||
		effects.recoveryPlan.Target.Bundle.Manifest.Release.ID != fixtures[0].Manifest.Release.ID ||
		effects.recoveryPlan.BackupID != backupID ||
		effects.recoveryPlan.BackupDigest != backupDigest {
		t.Fatalf("recovery inspection/plan = calls:%d plan:%#v", effects.recoveryInspectCalls, effects.recoveryPlan)
	}
	completed := readJournal(t, root)
	if completed.CurrentReleaseID != fixtures[0].Manifest.Release.ID ||
		completed.CurrentReleaseDigest != fixtures[0].ManifestDigest ||
		completed.PreviousRelease != "" || completed.PreviousReleaseDigest != "" ||
		completed.Active != nil || completed.Last == nil ||
		completed.Last.Command.ID != commandID ||
		completed.Last.Outcome != lifecycle.OutcomeSucceeded {
		t.Fatalf("completed recovery journal = %#v", completed)
	}
}

func TestRecoveryRejectsUntrustedSourceBeforePersistingIntent(t *testing.T) {
	fixture := writeReleaseFixture(t)
	effects := &installEffects{}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(
		context.Background(), installRequest(root, fixture),
	); err != nil {
		t.Fatalf("install cross-install recovery fixture: %v", err)
	}
	materializeInstalledRelease(t, root, fixture)
	before := readJournal(t, root)
	backupID := "backup-" + strings.Repeat("a", 32)

	_, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionRecover, Root: root, BackupID: "../foreign-backup",
	})
	assertFault(t, err, cli.FaultInvalidArgument, "BACKUP_ID_INVALID")
	if after := readJournal(t, root); !reflect.DeepEqual(after, before) ||
		effects.recoveryInspectCalls != 0 {
		t.Fatalf("invalid recovery path changed state: before=%#v after=%#v effects=%#v", before, after, effects)
	}

	effects.recoverySource = RecoverySource{
		InstallationID: before.InstallationID,
		BackupID:       backupID,
		BackupDigest:   "sha256:" + strings.Repeat("c", 64),
		ReleaseID:      "matrix-v0.9.9-ffffffffffff",
		ReleaseDigest:  "sha256:" + strings.Repeat("f", 64),
		Database:       fixture.Manifest.Database,
	}
	_, err = backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionRecover, Root: root, BackupID: backupID,
	})
	assertFault(t, err, cli.FaultVerification, "RECOVERY_RELEASE_INVALID")
	if after := readJournal(t, root); !reflect.DeepEqual(after, before) ||
		effects.recoveryInspectCalls != 1 || len(effects.recoveryCalls) != 0 {
		t.Fatalf("unstaged recovery release changed state: before=%#v after=%#v effects=%#v", before, after, effects)
	}

	effects.recoverySource.InstallationID = "mxi-" + strings.Repeat("b", 32)
	effects.recoverySource.ReleaseID = fixture.Manifest.Release.ID
	effects.recoverySource.ReleaseDigest = fixture.ManifestDigest
	_, err = backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionRecover, Root: root, BackupID: backupID,
	})
	assertFault(t, err, cli.FaultVerification, "RECOVERY_SOURCE_INVALID")
	if after := readJournal(t, root); !reflect.DeepEqual(after, before) ||
		effects.recoveryInspectCalls != 2 || len(effects.recoveryCalls) != 0 {
		t.Fatalf("cross-install recovery changed state: before=%#v after=%#v effects=%#v", before, after, effects)
	}
	effects.recoverySource.InstallationID = before.InstallationID
	effects.recoverySource.Database.Authorities.Audit++
	_, err = backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionRecover, Root: root, BackupID: backupID,
	})
	assertFault(t, err, cli.FaultVerification, "RECOVERY_RELEASE_INVALID")
	if !reflect.DeepEqual(readJournal(t, root), before) || len(effects.recoveryCalls) != 0 {
		t.Fatal("backup profile substitution reached destructive recovery")
	}
}

func TestRecoveryDefinitiveFailureRequiresManualIntervention(t *testing.T) {
	fixture := writeReleaseFixture(t)
	effects := &installEffects{
		recoveryFailPhase: lifecycle.PhaseRecovering,
		recoveryFailErr:   ErrEffectVerification,
	}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(
		context.Background(), installRequest(root, fixture),
	); err != nil {
		t.Fatalf("install failed-recovery fixture: %v", err)
	}
	materializeInstalledRelease(t, root, fixture)
	before := readJournal(t, root)
	backupID := "backup-" + strings.Repeat("b", 32)
	effects.recoverySource = RecoverySource{
		InstallationID: before.InstallationID,
		BackupID:       backupID,
		BackupDigest:   "sha256:" + strings.Repeat("d", 64),
		ReleaseID:      fixture.Manifest.Release.ID,
		ReleaseDigest:  fixture.ManifestDigest,
		Database:       fixture.Manifest.Database,
	}

	_, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionRecover, Root: root, BackupID: backupID,
	})
	assertFault(t, err, cli.FaultVerification, "RECOVERY_VERIFICATION_FAILED")
	failed := readJournal(t, root)
	if failed.CurrentReleaseID != before.CurrentReleaseID ||
		failed.CurrentReleaseDigest != before.CurrentReleaseDigest ||
		failed.Active != nil || failed.Last == nil ||
		failed.Last.Command.Action != lifecycle.ActionRecover ||
		failed.Last.Outcome != lifecycle.OutcomeManualIntervention ||
		failed.Last.Phase != lifecycle.PhaseManualIntervention ||
		failed.Last.FailureCode != "RECOVERY_VERIFICATION_FAILED" ||
		effects.recoveryCalls[lifecycle.PhaseRecovering] != 1 {
		t.Fatalf("failed recovery journal = %#v / effects=%#v", failed, effects)
	}
}

func TestStatusIsReadOnlyForStableAndActiveInstallations(t *testing.T) {
	fixture := writeReleaseFixture(t)
	effects := &installEffects{observeReady: true}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(context.Background(), installRequest(root, fixture)); err != nil {
		t.Fatalf("install status fixture: %v", err)
	}
	before := readJournal(t, root)

	result, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionStatus, Root: root,
	})
	if err != nil || result.State != "READY" || result.Changed ||
		result.ReleaseID != before.CurrentReleaseID || effects.observeCalls != 1 {
		t.Fatalf("ready status = %#v / %v / calls=%d", result, err, effects.observeCalls)
	}
	effects.observeReady = false
	result, err = backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionStatus, Root: root,
	})
	if err != nil || result.State != "NOT_READY" || effects.observeCalls != 2 {
		t.Fatalf("not-ready status = %#v / %v / calls=%d", result, err, effects.observeCalls)
	}
	if after := readJournal(t, root); !reflect.DeepEqual(after, before) {
		t.Fatalf("status changed the sealed journal: before=%#v after=%#v", before, after)
	}

	activeEffects := &installEffects{
		failPhase: lifecycle.PhaseLoadingImages,
		failErr:   ErrEffectOutcomeUnknown,
		failOnce:  true,
	}
	activeBackend := newTestBackend(t, activeEffects)
	activeRoot := filepath.Join(t.TempDir(), "matrix")
	_, err = activeBackend.Run(
		context.Background(), installRequest(activeRoot, writeReleaseFixture(t)),
	)
	assertFault(t, err, cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
	activeBefore := readJournal(t, activeRoot)
	result, err = activeBackend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionStatus, Root: activeRoot,
	})
	if err != nil || activeBefore.Active == nil ||
		result.State != string(activeBefore.Active.Phase) ||
		result.CorrelationID != activeBefore.Active.Command.ID ||
		activeEffects.observeCalls != 0 {
		t.Fatalf("active status = %#v / %v / journal=%#v", result, err, activeBefore)
	}
	if after := readJournal(t, activeRoot); !reflect.DeepEqual(after, activeBefore) {
		t.Fatal("active status changed the sealed journal")
	}
}

func TestStatusDoesNotCreateAMissingInstallation(t *testing.T) {
	effects := &installEffects{}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	_, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionStatus, Root: root,
	})
	assertFault(t, err, cli.FaultPrecondition, "PLATFORM_NOT_INSTALLED")
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("status created installation state: %v", err)
	}
}

func TestVerifyCommitsOnlyItsExecutionAndResumesUnknownOutcome(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fixture := writeReleaseFixture(t)
		effects := &installEffects{}
		backend := newTestBackend(t, effects)
		root := filepath.Join(t.TempDir(), "matrix")
		if _, err := backend.Run(context.Background(), installRequest(root, fixture)); err != nil {
			t.Fatalf("install verification fixture: %v", err)
		}
		before := readJournal(t, root)
		result, err := backend.Run(context.Background(), cli.Request{
			Action: lifecycle.ActionVerify, Root: root,
		})
		if err != nil || result.State != "READY" || result.Changed ||
			result.ReleaseID != before.CurrentReleaseID || effects.verifyCalls != 1 {
			t.Fatalf("verification result = %#v / %v / calls=%d", result, err, effects.verifyCalls)
		}
		after := readJournal(t, root)
		if after.CurrentReleaseID != before.CurrentReleaseID ||
			after.CurrentReleaseDigest != before.CurrentReleaseDigest ||
			after.PreviousRelease != before.PreviousRelease ||
			after.PreviousReleaseDigest != before.PreviousReleaseDigest ||
			after.Active != nil || after.Last == nil ||
			after.Last.Command.Action != lifecycle.ActionVerify ||
			after.Last.Outcome != lifecycle.OutcomeSucceeded {
			t.Fatalf("verified journal = %#v", after)
		}
	})

	t.Run("definitive failure", func(t *testing.T) {
		fixture := writeReleaseFixture(t)
		effects := &installEffects{verifyErr: ErrEffectVerification}
		backend := newTestBackend(t, effects)
		root := filepath.Join(t.TempDir(), "matrix")
		if _, err := backend.Run(context.Background(), installRequest(root, fixture)); err != nil {
			t.Fatalf("install failure fixture: %v", err)
		}
		before := readJournal(t, root)
		_, err := backend.Run(context.Background(), cli.Request{
			Action: lifecycle.ActionVerify, Root: root,
		})
		assertFault(t, err, cli.FaultVerification, "PLATFORM_VERIFICATION_FAILED")
		after := readJournal(t, root)
		if after.CurrentReleaseID != before.CurrentReleaseID ||
			after.CurrentReleaseDigest != before.CurrentReleaseDigest ||
			after.Active != nil || after.Last == nil ||
			after.Last.Command.Action != lifecycle.ActionVerify ||
			after.Last.Outcome != lifecycle.OutcomeFailed {
			t.Fatalf("failed verification journal = %#v", after)
		}
	})

	t.Run("unknown outcome", func(t *testing.T) {
		fixture := writeReleaseFixture(t)
		effects := &installEffects{verifyErr: ErrEffectOutcomeUnknown}
		backend := newTestBackend(t, effects)
		root := filepath.Join(t.TempDir(), "matrix")
		if _, err := backend.Run(context.Background(), installRequest(root, fixture)); err != nil {
			t.Fatalf("install replay fixture: %v", err)
		}
		_, err := backend.Run(context.Background(), cli.Request{
			Action: lifecycle.ActionVerify, Root: root,
		})
		assertFault(t, err, cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
		active := readJournal(t, root)
		if active.Active == nil || active.Active.Command.Action != lifecycle.ActionVerify ||
			active.Active.Phase != lifecycle.PhaseVerifying {
			t.Fatalf("unknown verification journal = %#v", active)
		}
		commandID := active.Active.Command.ID
		effects.verifyErr = nil
		result, err := backend.Run(context.Background(), cli.Request{
			Action: lifecycle.ActionVerify, Root: root,
		})
		if err != nil || result.CorrelationID != commandID || effects.verifyCalls != 2 {
			t.Fatalf("resumed verification = %#v / %v / calls=%d", result, err, effects.verifyCalls)
		}
	})
}

func TestBackupBindsItsIdentityAndResumesUnknownOutcome(t *testing.T) {
	fixture := writeReleaseFixture(t)
	effects := &installEffects{backupErr: ErrEffectOutcomeUnknown}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(context.Background(), installRequest(root, fixture)); err != nil {
		t.Fatalf("install backup fixture: %v", err)
	}
	before := readJournal(t, root)

	_, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionBackup, Root: root,
	})
	assertFault(t, err, cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
	active := readJournal(t, root)
	if active.Active == nil || active.Active.Command.Action != lifecycle.ActionBackup ||
		active.Active.Phase != lifecycle.PhaseBackingUp ||
		active.Active.Command.BackupID == "" ||
		effects.backupPlan.BackupID != active.Active.Command.BackupID {
		t.Fatalf("active backup journal=%#v plan=%#v", active, effects.backupPlan)
	}
	commandID := active.Active.Command.ID
	backupID := active.Active.Command.BackupID
	effects.backupErr = nil
	result, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionBackup, Root: root,
	})
	if err != nil || result.State != "READY" || !result.Changed ||
		result.CorrelationID != commandID || result.BackupID != backupID ||
		effects.backupCalls != 2 {
		t.Fatalf("resumed backup result=%#v err=%v calls=%d", result, err, effects.backupCalls)
	}
	after := readJournal(t, root)
	if after.CurrentReleaseID != before.CurrentReleaseID ||
		after.CurrentReleaseDigest != before.CurrentReleaseDigest ||
		after.Active != nil || after.Last == nil ||
		after.Last.Command.BackupID != backupID ||
		after.Last.Outcome != lifecycle.OutcomeSucceeded {
		t.Fatalf("completed backup journal = %#v", after)
	}
}

func TestSupportBindsOwnedOutputWithoutPersistingItsPath(t *testing.T) {
	fixture := writeReleaseFixture(t)
	effects := &installEffects{supportErr: ErrEffectOutcomeUnknown}
	backend := newTestBackend(t, effects)
	root := filepath.Join(t.TempDir(), "matrix")
	if _, err := backend.Run(context.Background(), installRequest(root, fixture)); err != nil {
		t.Fatalf("install support fixture: %v", err)
	}
	before := readJournal(t, root)
	outside := filepath.Join(filepath.Dir(root), "support.json")
	_, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionSupport, Root: root, SupportOutput: outside,
	})
	assertFault(t, err, cli.FaultInvalidArgument, "SUPPORT_OUTPUT_INVALID")
	if effects.supportCalls != 0 || !reflect.DeepEqual(readJournal(t, root), before) {
		t.Fatal("invalid support output reached effects or changed the journal")
	}

	output := filepath.Join(root, filepath.FromSlash(layout.SupportDirectory), "evidence.json")
	_, err = backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionSupport, Root: root, SupportOutput: output,
	})
	assertFault(t, err, cli.FaultUnavailable, "EFFECT_OUTCOME_UNKNOWN")
	active := readJournal(t, root)
	if active.Active == nil || active.Active.Command.Action != lifecycle.ActionSupport ||
		active.Active.Command.InputDigest == "" ||
		strings.Contains(active.Active.Command.InputDigest, output) ||
		effects.supportPlan.Output != output {
		t.Fatalf("active support journal=%#v plan=%#v", active, effects.supportPlan)
	}
	commandID := active.Active.Command.ID
	changedOutput := filepath.Join(root, filepath.FromSlash(layout.SupportDirectory), "different.json")
	_, err = backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionSupport, Root: root, SupportOutput: changedOutput,
	})
	assertFault(t, err, cli.FaultConflict, "INSTALLATION_COMMAND_CONFLICT")

	effects.supportErr = nil
	result, err := backend.Run(context.Background(), cli.Request{
		Action: lifecycle.ActionSupport, Root: root, SupportOutput: output,
	})
	if err != nil || result.State != "READY" || !result.Changed ||
		result.CorrelationID != commandID || effects.supportCalls != 2 {
		t.Fatalf("resumed support result=%#v err=%v calls=%d", result, err, effects.supportCalls)
	}
	after := readJournal(t, root)
	if after.CurrentReleaseID != before.CurrentReleaseID ||
		after.CurrentReleaseDigest != before.CurrentReleaseDigest ||
		after.Active != nil || after.Last == nil ||
		after.Last.Command.Action != lifecycle.ActionSupport ||
		after.Last.Outcome != lifecycle.OutcomeSucceeded {
		t.Fatalf("completed support journal = %#v", after)
	}
}

type installEffects struct {
	calls                     map[lifecycle.Phase]int
	failPhase                 lifecycle.Phase
	failErr                   error
	failOnce                  bool
	failed                    bool
	rollbackCalls             int
	rollbackErr               error
	rollbackFailOnce          bool
	rollbackFailed            bool
	observeCalls              int
	observeReady              bool
	observeErr                error
	verifyCalls               int
	verifyErr                 error
	backupCalls               int
	backupErr                 error
	backupPlan                BackupPlan
	supportCalls              int
	supportErr                error
	supportPlan               SupportPlan
	upgradeCalls              map[lifecycle.Phase]int
	upgradePlan               UpgradePlan
	upgradeFailPhase          lifecycle.Phase
	upgradeFailErr            error
	upgradeFailOnce           bool
	upgradeFailed             bool
	upgradeRollbackCalls      int
	upgradeRollbackErr        error
	explicitRollbackCalls     map[lifecycle.Phase]int
	explicitRollbackPlan      RollbackPlan
	explicitRollbackFailPhase lifecycle.Phase
	explicitRollbackFailErr   error
	explicitRollbackFailOnce  bool
	explicitRollbackFailed    bool
	recoveryInspectCalls      int
	recoveryInspectErr        error
	recoverySource            RecoverySource
	recoveryCalls             map[lifecycle.Phase]int
	recoveryPlan              RecoveryPlan
	recoveryFailPhase         lifecycle.Phase
	recoveryFailErr           error
	recoveryFailOnce          bool
	recoveryFailed            bool
	credentialPlan            CredentialRecoveryPlan
	credentialPrepareErr      error
	credentialPrepareCalls    int
	credentialCalls           map[lifecycle.Phase]int
	credentialFailPhase       lifecycle.Phase
	credentialFailErr         error
	credentialFailOnce        bool
	credentialFailed          bool
	nodePlan                  NodeConnectionsPlan
	nodePrepareErr            error
	nodeCalls                 map[lifecycle.Phase]int
	nodeFailPhase             lifecycle.Phase
	nodeFailErr               error
}

func (effects *installEffects) NodeConnectionsDigest(_ context.Context, installed InstalledPlan) (string, error) {
	return nodeconfig.ControllerDigest(nodeconfig.EmptyController(installed.InstallationID))
}

func (effects *installEffects) PrepareNodeConnections(_ context.Context, installed InstalledPlan, _ string, _ string, previous *lifecycle.Execution) (NodeConnectionsPlan, error) {
	plan := effects.nodePlan
	plan.InstalledPlan = installed
	if previous != nil {
		plan.CommandID = previous.Command.ID
	}
	return plan, effects.nodePrepareErr
}

func (effects *installEffects) ApplyNodeConnectionsPhase(_ context.Context, plan NodeConnectionsPlan, phase lifecycle.Phase) error {
	if effects.nodeCalls == nil {
		effects.nodeCalls = map[lifecycle.Phase]int{}
	}
	effects.nodeCalls[phase]++
	if phase == effects.nodeFailPhase && effects.nodeFailErr != nil {
		err := effects.nodeFailErr
		effects.nodeFailErr = nil
		return err
	}
	return nil
}

func (effects *installEffects) PrepareCredentialRecovery(_ context.Context, installed InstalledPlan, _ string, _ *lifecycle.Execution) (CredentialRecoveryPlan, error) {
	effects.credentialPrepareCalls++
	plan := effects.credentialPlan
	plan.InstalledPlan = installed
	return plan, effects.credentialPrepareErr
}

func (effects *installEffects) ApplyCredentialRecoveryPhase(_ context.Context, plan CredentialRecoveryPlan, phase lifecycle.Phase) error {
	if effects.credentialCalls == nil {
		effects.credentialCalls = make(map[lifecycle.Phase]int)
	}
	effects.credentialCalls[phase]++
	effects.credentialPlan = plan
	if phase == effects.credentialFailPhase && effects.credentialFailErr != nil && (!effects.credentialFailOnce || !effects.credentialFailed) {
		effects.credentialFailed = true
		return effects.credentialFailErr
	}
	return nil
}

func (effects *installEffects) ApplyInstallPhase(
	_ context.Context,
	plan InstallPlan,
	phase lifecycle.Phase,
) error {
	if effects.calls == nil {
		effects.calls = make(map[lifecycle.Phase]int)
	}
	effects.calls[phase]++
	if plan.Root == "" || plan.InstallationID == "" || plan.Bundle.Manifest.Release.ID == "" ||
		plan.CorrelationID == "" || plan.Trust.KeyID == "" ||
		len(plan.TrustBytes) == 0 || plan.Port == 0 {
		return errors.New("install plan is incomplete")
	}
	if phase == effects.failPhase && effects.failErr != nil && (!effects.failOnce || !effects.failed) {
		effects.failed = true
		return effects.failErr
	}
	return nil
}

func (effects *installEffects) RollbackInstall(context.Context, InstallPlan) error {
	effects.rollbackCalls++
	if effects.rollbackErr != nil && (!effects.rollbackFailOnce || !effects.rollbackFailed) {
		effects.rollbackFailed = true
		return effects.rollbackErr
	}
	return nil
}

func (effects *installEffects) ApplyUpgradePhase(
	_ context.Context,
	plan UpgradePlan,
	phase lifecycle.Phase,
) error {
	if effects.upgradeCalls == nil {
		effects.upgradeCalls = make(map[lifecycle.Phase]int)
	}
	effects.upgradeCalls[phase]++
	effects.upgradePlan = plan
	if plan.Source.ReleaseID == "" || plan.Source.ReleaseDigest == "" ||
		plan.Target.Bundle.Manifest.Release.ID == "" || plan.BackupID == "" ||
		plan.CreatedAt.IsZero() || plan.Source.CorrelationID == "" ||
		plan.Source.CorrelationID != plan.Target.CorrelationID {
		return errors.New("upgrade plan is incomplete")
	}
	if phase == effects.upgradeFailPhase && effects.upgradeFailErr != nil &&
		(!effects.upgradeFailOnce || !effects.upgradeFailed) {
		effects.upgradeFailed = true
		return effects.upgradeFailErr
	}
	return nil
}

func (effects *installEffects) RollbackUpgrade(context.Context, UpgradePlan) error {
	effects.upgradeRollbackCalls++
	return effects.upgradeRollbackErr
}

func (effects *installEffects) ApplyRollbackPhase(
	_ context.Context,
	plan RollbackPlan,
	phase lifecycle.Phase,
) error {
	if effects.explicitRollbackCalls == nil {
		effects.explicitRollbackCalls = make(map[lifecycle.Phase]int)
	}
	effects.explicitRollbackCalls[phase]++
	effects.explicitRollbackPlan = plan
	if plan.Current.Bundle.Manifest.Release.ID == "" ||
		plan.Previous.ReleaseID == "" || plan.Previous.ReleaseDigest == "" ||
		plan.Current.CorrelationID == "" ||
		plan.Current.CorrelationID != plan.Previous.CorrelationID {
		return errors.New("explicit rollback plan is incomplete")
	}
	if phase == effects.explicitRollbackFailPhase &&
		effects.explicitRollbackFailErr != nil &&
		(!effects.explicitRollbackFailOnce || !effects.explicitRollbackFailed) {
		effects.explicitRollbackFailed = true
		return effects.explicitRollbackFailErr
	}
	return nil
}

func (effects *installEffects) InspectBackup(
	_ context.Context,
	plan InstalledPlan,
	backupID string,
) (RecoverySource, error) {
	effects.recoveryInspectCalls++
	if plan.Root == "" || plan.InstallationID == "" || plan.ReleaseID == "" ||
		plan.ReleaseDigest == "" || plan.TrustKeyID == "" || plan.TrustFingerprint == "" ||
		plan.Port == 0 || backupID == "" {
		return RecoverySource{}, errors.New("recovery inspection plan is incomplete")
	}
	if effects.recoveryInspectErr != nil {
		return RecoverySource{}, effects.recoveryInspectErr
	}
	return effects.recoverySource, nil
}

func (effects *installEffects) ApplyRecoveryPhase(
	_ context.Context,
	plan RecoveryPlan,
	phase lifecycle.Phase,
) error {
	if effects.recoveryCalls == nil {
		effects.recoveryCalls = make(map[lifecycle.Phase]int)
	}
	effects.recoveryCalls[phase]++
	effects.recoveryPlan = plan
	if plan.Current.Root == "" || plan.Current.Root != plan.Target.Root ||
		plan.Current.InstallationID == "" ||
		plan.Current.InstallationID != plan.Target.InstallationID ||
		plan.Current.Bundle.Manifest.Release.ID == "" ||
		plan.Target.Bundle.Manifest.Release.ID == "" ||
		plan.BackupID == "" || plan.BackupDigest == "" ||
		plan.Current.CorrelationID == "" ||
		plan.Current.CorrelationID != plan.Target.CorrelationID {
		return errors.New("recovery plan is incomplete")
	}
	if phase == effects.recoveryFailPhase && effects.recoveryFailErr != nil &&
		(!effects.recoveryFailOnce || !effects.recoveryFailed) {
		effects.recoveryFailed = true
		return effects.recoveryFailErr
	}
	return nil
}

func (effects *installEffects) ObserveInstallation(
	_ context.Context,
	plan InstalledPlan,
) (bool, error) {
	effects.observeCalls++
	if plan.Root == "" || plan.InstallationID == "" || plan.ReleaseID == "" ||
		plan.ReleaseDigest == "" || plan.TrustKeyID == "" || plan.TrustFingerprint == "" ||
		plan.Port == 0 {
		return false, errors.New("installed plan is incomplete")
	}
	return effects.observeReady, effects.observeErr
}

func (effects *installEffects) VerifyInstallation(
	_ context.Context,
	plan InstalledPlan,
) error {
	effects.verifyCalls++
	if plan.Root == "" || plan.InstallationID == "" || plan.ReleaseID == "" ||
		plan.ReleaseDigest == "" || plan.TrustKeyID == "" || plan.TrustFingerprint == "" ||
		plan.Port == 0 || plan.CorrelationID == "" {
		return errors.New("installed plan is incomplete")
	}
	return effects.verifyErr
}

func (effects *installEffects) CreateBackup(
	_ context.Context,
	plan BackupPlan,
) error {
	effects.backupCalls++
	effects.backupPlan = plan
	if plan.Root == "" || plan.InstallationID == "" || plan.ReleaseID == "" ||
		plan.BackupID == "" || plan.CreatedAt.IsZero() {
		return errors.New("backup plan is incomplete")
	}
	return effects.backupErr
}

func (effects *installEffects) WriteSupportEvidence(
	_ context.Context,
	plan SupportPlan,
) error {
	effects.supportCalls++
	effects.supportPlan = plan
	if plan.Root == "" || plan.InstallationID == "" || plan.ReleaseID == "" ||
		plan.Output == "" || plan.CorrelationID == "" || plan.GeneratedAt.IsZero() {
		return errors.New("support plan is incomplete")
	}
	return effects.supportErr
}

func effectingInstallPhases() []lifecycle.Phase {
	return []lifecycle.Phase{
		lifecycle.PhasePreflight,
		lifecycle.PhaseStaging,
		lifecycle.PhaseLoadingImages,
		lifecycle.PhaseConfiguring,
		lifecycle.PhaseMigrating,
		lifecycle.PhaseStarting,
		lifecycle.PhaseVerifying,
	}
}

func newTestBackend(t *testing.T, effects Effects) *Backend {
	t.Helper()
	backend, err := NewBackend(effects)
	if err != nil {
		t.Fatalf("create backend: %v", err)
	}
	return backend
}

func installRequest(root string, fixture releasetest.Fixture) cli.Request {
	return cli.Request{
		Action: lifecycle.ActionInstall, Root: root,
		Bundle: fixture.Root, TrustKey: fixture.TrustPath,
	}
}

func readJournal(t *testing.T, root string) lifecycle.Journal {
	t.Helper()
	session, err := journal.Acquire(context.Background(), root)
	if err != nil {
		t.Fatalf("acquire journal: %v", err)
	}
	defer session.Close()
	state, err := session.Read()
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	return state
}

func assertFault(t *testing.T, err error, class cli.FaultClass, code string) {
	t.Helper()
	var value *cli.Fault
	if !errors.As(err, &value) || value.Class != class || value.Code != code {
		t.Fatalf("fault = %#v / %v, want %s/%s", value, err, class, code)
	}
}

func writeReleaseFixture(t *testing.T) releasetest.Fixture {
	t.Helper()
	fixture, err := releasetest.Write(t.TempDir())
	if err != nil {
		t.Fatalf("write release fixture: %v", err)
	}
	return fixture
}

func writeReleaseSequence(t *testing.T, count int) []releasetest.Fixture {
	t.Helper()
	fixtures, err := releasetest.WriteSequence(t.TempDir(), count)
	if err != nil {
		t.Fatalf("write release fixture sequence: %v", err)
	}
	return fixtures
}

func materializeInstalledRelease(
	t *testing.T,
	root string,
	fixture releasetest.Fixture,
) {
	t.Helper()
	trustBytes, err := os.ReadFile(fixture.TrustPath)
	if err != nil {
		t.Fatalf("read fixture trust: %v", err)
	}
	verified, err := release.VerifyDirectory(fixture.Root, trustBytes)
	if err != nil {
		t.Fatalf("verify fixture release: %v", err)
	}
	releases := filepath.Join(root, "releases")
	if err := os.MkdirAll(releases, 0o700); err != nil {
		t.Fatalf("create installed release directory: %v", err)
	}
	trustTarget := filepath.Join(root, filepath.FromSlash(layout.ReleaseTrust))
	if err := os.MkdirAll(filepath.Dir(trustTarget), 0o700); err != nil {
		t.Fatalf("create installed trust directory: %v", err)
	}
	if err := os.WriteFile(
		trustTarget, trustBytes, 0o600,
	); err != nil {
		t.Fatalf("write installed trust: %v", err)
	}
	if _, err := release.StageDirectory(
		verified, trustBytes,
		filepath.Join(root, filepath.FromSlash(layout.ReleaseDirectory(fixture.Manifest.Release.ID))),
	); err != nil {
		t.Fatalf("stage installed release: %v", err)
	}
}

func seedPublishedInstalledRelease(t *testing.T, root string, fixture releasetest.Fixture) {
	t.Helper()
	state, err := lifecycle.New(
		"mxi-11111111111111111111111111111111",
		lifecycle.ReleaseTrust{
			KeyID: fixture.Trust.KeyID, Fingerprint: fixture.Trust.PublicKeyFingerprint,
		},
	)
	if err != nil {
		t.Fatalf("create published installation state: %v", err)
	}
	state.CurrentReleaseID = fixture.Manifest.Release.ID
	state.CurrentReleaseDigest = fixture.ManifestDigest
	session, err := journal.Acquire(context.Background(), root)
	if err != nil {
		t.Fatalf("acquire published installation journal: %v", err)
	}
	if err := session.Initialize(state); err != nil {
		_ = session.Close()
		t.Fatalf("initialize published installation journal: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close published installation journal: %v", err)
	}
	materializeInstalledRelease(t, root, fixture)
}
