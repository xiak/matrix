package platformcommand

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/release"
)

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
		SchemaVersion:  fixtures[0].Manifest.Database.SchemaVersion,
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
		SchemaVersion:  fixture.Manifest.Database.SchemaVersion,
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
		SchemaVersion:  fixture.Manifest.Database.SchemaVersion,
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
		plan.Trust.KeyID == "" || len(plan.TrustBytes) == 0 || plan.Port == 0 {
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
		plan.CreatedAt.IsZero() {
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
		plan.Previous.ReleaseID == "" || plan.Previous.ReleaseDigest == "" {
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
		plan.BackupID == "" || plan.BackupDigest == "" {
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
		plan.Port == 0 {
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
