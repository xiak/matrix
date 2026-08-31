package lifecycle

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestInstallUsesExactReplayAndPublishesOnlyAfterReady(t *testing.T) {
	journal := newJournal(t)
	command := lifecycleCommand(ActionInstall, releaseA, '1', 0)
	started, err := Start(journal, command)
	if err != nil || started.Replay != ReplayNone || started.Execution.Phase != PhasePreflight {
		t.Fatalf("start install = %#v / %v", started, err)
	}
	if started.Journal.CurrentReleaseID != "" {
		t.Fatal("install must not publish a release before verification and commit")
	}

	replayedCommand := command
	replayedCommand.RequestedAt = command.RequestedAt.Add(time.Hour)
	replayed, err := Start(started.Journal, replayedCommand)
	if err != nil || replayed.Replay != ReplayActive || replayed.Execution.StartedAt != command.RequestedAt {
		t.Fatalf("active replay = %#v / %v", replayed, err)
	}
	changed := replayedCommand
	changed.InputDigest = digest('2')
	if _, err := Start(started.Journal, changed); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed input replay error = %v, want conflict", err)
	}
	other := lifecycleCommand(ActionInstall, releaseA, '1', 1)
	if _, err := Start(started.Journal, other); !errors.Is(err, ErrCommandInProgress) {
		t.Fatalf("parallel command error = %v, want in progress", err)
	}

	completed := completeActive(t, started.Journal)
	if completed.CurrentReleaseID != releaseA || completed.CurrentReleaseDigest != digest('1') ||
		completed.PreviousRelease != "" || completed.PreviousReleaseDigest != "" ||
		completed.Active != nil || completed.Last == nil || completed.Last.Outcome != OutcomeSucceeded {
		t.Fatalf("completed install journal = %#v", completed)
	}
	replayed, err = Start(completed, replayedCommand)
	if err != nil || replayed.Replay != ReplayCompleted || replayed.Execution.Outcome != OutcomeSucceeded {
		t.Fatalf("completed replay = %#v / %v", replayed, err)
	}
}

func TestNodeLifecycleCannotEnterPlatformEffects(t *testing.T) {
	platform := newJournal(t)
	binding := NodeBinding{ExecutionTargetID: "target-a", ConfigurationDigest: digest('a')}
	node, err := NewNode(platform.InstallationID, platform.ReleaseTrust, binding)
	if err != nil {
		t.Fatal(err)
	}
	command := lifecycleCommand(ActionInstall, releaseA, '1', 0)
	started, err := Start(node, command)
	if err != nil {
		t.Fatal(err)
	}
	state := started.Journal
	for state.Active != nil {
		switch state.Active.Phase {
		case PhaseLoadingImages, PhaseMigrating, PhaseBackingUp, PhaseRecovering:
			t.Fatal("node workflow reached a platform-only effect")
		}
		next, ok := NextPhase(state)
		if !ok {
			t.Fatal("node install cannot reach a completed state")
		}
		state, err = Advance(state, command.ID, next, state.Active.UpdatedAt.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
	}
	if state.CurrentReleaseID != releaseA || state.Node == nil || *state.Node != binding {
		t.Fatal("node completion lost its release or enrollment commitment")
	}
	for _, action := range []Action{ActionRecover, ActionRecoverCredentials, ActionBackup, ActionSupport} {
		if _, err := Start(state, lifecycleCommand(action, releaseB, '2', 10)); err == nil {
			t.Fatal("node accepted a platform lifecycle action")
		}
	}
	started, err = Start(state, lifecycleCommand(ActionStart, "", 0, 11))
	if err != nil {
		t.Fatal(err)
	}
	restarted := completeActive(t, started.Journal)
	if restarted.CurrentReleaseID != state.CurrentReleaseID || *restarted.Node != binding {
		t.Fatal("node restart changed its authority or release")
	}
	if _, err := Start(installedJournal(t), lifecycleCommand(ActionStart, "", 0, 11)); err == nil {
		t.Fatal("node startup entered a platform root")
	}
}

func TestNodeReleaseTransitionsRetainEnrollmentAndLatestCredentials(t *testing.T) {
	base := newJournal(t)
	binding := NodeBinding{ExecutionTargetID: "target-a", ConfigurationDigest: digest('a')}
	state, err := NewNode(base.InstallationID, base.ReleaseTrust, binding)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := Start(state, lifecycleCommand(ActionInstall, releaseA, '1', 0))
	if err != nil {
		t.Fatal(err)
	}
	state = completeActive(t, installed.Journal)
	rotation := lifecycleCommand(ActionRotateCredentials, "", 'b', 10)
	rotation.ExpectedConfigurationDigest, rotation.RevokePreviousCredentials = binding.ConfigurationDigest, true
	rotated, err := Start(state, rotation)
	if err != nil {
		t.Fatal(err)
	}
	state = completeActive(t, rotated.Journal)
	retainedBinding, retainedRotation := *state.Node, *state.NodeCredentialRotation
	upgrade := lifecycleCommand(ActionUpgrade, releaseB, '2', 20)
	upgrade.BackupID = ""
	started, err := Start(state, upgrade)
	if err != nil {
		t.Fatalf("node upgrade rejected: %v", err)
	}
	if _, err := Start(started.Journal, lifecycleCommand(ActionStart, "", 0, 21)); !errors.Is(err, ErrCommandInProgress) {
		t.Fatal("another command replaced a pending node upgrade")
	}
	state = started.Journal
	for state.Active != nil {
		switch state.Active.Phase {
		case PhaseLoadingImages, PhaseBackingUp, PhaseMigrating, PhaseRecovering:
			t.Fatal("node upgrade entered a platform effect")
		}
		next, ok := NextPhase(state)
		if !ok {
			t.Fatal("node upgrade cannot complete")
		}
		after, err := Advance(state, upgrade.ID, next, state.Active.UpdatedAt.Add(time.Second))
		if err != nil || ValidateNodeTransition(state, after) != nil {
			t.Fatalf("node transition invalid: %v", err)
		}
		state = after
	}
	if state.CurrentReleaseID != releaseB || state.PreviousRelease != releaseA || *state.Node != retainedBinding || *state.NodeCredentialRotation != retainedRotation {
		t.Fatal("upgrade changed enrollment, latest credentials, or predecessor")
	}
	started, err = Start(state, lifecycleCommand(ActionRollback, "", 0, 30))
	if err != nil {
		t.Fatal(err)
	}
	state = completeActive(t, started.Journal)
	if state.CurrentReleaseID != releaseA || state.PreviousRelease != "" || *state.Node != retainedBinding || *state.NodeCredentialRotation != retainedRotation {
		t.Fatal("rollback restored old enrollment/credentials or failed to select the predecessor")
	}
	withBackup := lifecycleCommand(ActionUpgrade, releaseB, '2', 40)
	if _, err := Start(state, withBackup); err == nil {
		t.Fatal("node upgrade accepted a platform backup selector")
	}
}

func TestFailedNodeUpgradeRetainsSourceUntilRecoveryIsVerified(t *testing.T) {
	base := installedJournal(t)
	base.Node = &NodeBinding{ExecutionTargetID: "target-a", ConfigurationDigest: digest('a')}
	command := lifecycleCommand(ActionUpgrade, releaseB, '2', 10)
	command.BackupID = ""
	started, err := Start(base, command)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := Fail(started.Journal, command.ID, "NODE_VERIFICATION_FAILED", started.Execution.UpdatedAt.Add(time.Second))
	if err != nil || failed.Active == nil || failed.Active.Phase != PhaseRollingBack || failed.CurrentReleaseID != releaseA {
		t.Fatal("failed node upgrade did not retain source and rollback intent")
	}
	if _, err := Start(failed, lifecycleCommand(ActionRollback, "", 0, 20)); !errors.Is(err, ErrCommandInProgress) {
		t.Fatal("explicit rollback replaced automatic recovery")
	}
	recovered, err := Advance(failed, command.ID, PhaseReady, failed.Active.UpdatedAt.Add(time.Second))
	if err != nil || recovered.Last.Outcome != OutcomeRolledBack || recovered.CurrentReleaseID != releaseA || *recovered.Node != *base.Node {
		t.Fatal("verified recovery changed source or node identity")
	}
}

func TestPlatformCredentialRecoveryFinalizesWithoutReleaseOrRollbackEffects(t *testing.T) {
	base := installedJournal(t)
	upgraded, err := Start(base, lifecycleCommand(ActionUpgrade, releaseB, '2', 10))
	if err != nil {
		t.Fatal(err)
	}
	base = completeActive(t, upgraded.Journal)
	command := lifecycleCommand(ActionRecoverCredentials, "", 'c', 20)
	if _, err := Start(newJournal(t), command); !errors.Is(err, ErrPrecondition) {
		t.Fatal("credential recovery admitted an uninstalled root")
	}
	started, err := Start(base, command)
	if err != nil || started.Execution.Phase != PhaseStaging {
		t.Fatal("credential recovery did not retain an intent before staging input")
	}
	changed := command
	changed.InputDigest = digest('d')
	if _, err := Start(started.Journal, changed); !errors.Is(err, ErrCommandConflict) {
		t.Fatal("credential recovery replaced the sealed input commitment")
	}
	for _, phase := range []Phase{PhaseMigrating, PhaseStarting, PhaseRecovering, PhaseRollingBack, PhaseReady} {
		if _, err := Advance(started.Journal, command.ID, phase, command.RequestedAt.Add(time.Second)); !errors.Is(err, ErrInvalidTransition) {
			t.Fatal("credential recovery admitted an unrelated effect or premature completion")
		}
	}
	applying, err := Advance(started.Journal, command.ID, PhaseRecoveringCredentials, command.RequestedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	replay := command
	replay.RequestedAt = command.RequestedAt.Add(time.Hour)
	resumed, err := Start(applying, replay)
	if err != nil || resumed.Replay != ReplayActive || resumed.Execution.Command != command {
		t.Fatal("credential recovery resumed with a different intent")
	}
	committing, err := Advance(applying, command.ID, PhaseCommitting, applying.Active.UpdatedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Fail(committing, command.ID, "CLEANUP_UNAVAILABLE", committing.Active.UpdatedAt.Add(time.Second)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatal("cleanup failure converted a committed credential recovery into a rejection")
	}
	if _, err := Start(committing, lifecycleCommand(ActionVerify, "", 0, 21)); !errors.Is(err, ErrCommandInProgress) {
		t.Fatal("another command could discard pending credential cleanup")
	}
	completed := completeActive(t, committing)
	if completed.Last.Outcome != OutcomeSucceeded || completed.CurrentReleaseID != base.CurrentReleaseID ||
		completed.CurrentReleaseDigest != base.CurrentReleaseDigest || completed.PreviousRelease != base.PreviousRelease ||
		completed.PreviousReleaseDigest != base.PreviousReleaseDigest || ValidateJournal(completed) != nil {
		t.Fatal("credential recovery changed installed releases or lost its completion")
	}
	if replayed, err := Start(completed, command); err != nil || replayed.Replay != ReplayCompleted {
		t.Fatal("completed credential recovery did not retain exact replay")
	}
	corrupt := completed
	receipt := *completed.Last
	receipt.Outcome = OutcomeRolledBack
	corrupt.Last = &receipt
	if ValidateJournal(corrupt) == nil {
		t.Fatal("credential recovery claimed to roll back an applied password")
	}
	for _, rejectedAt := range []Phase{PhaseStaging, PhaseRecoveringCredentials} {
		t.Run(string(rejectedAt), func(t *testing.T) {
			state := started.Journal
			if rejectedAt == PhaseRecoveringCredentials {
				state = applying
			}
			rejected, err := Fail(state, command.ID, "RECOVERY_PRECONDITION_FAILED", state.Active.UpdatedAt.Add(time.Second))
			if err != nil || rejected.Active == nil || rejected.Active.Phase != PhaseCommitting ||
				rejected.Active.FailureCode != "RECOVERY_PRECONDITION_FAILED" || ValidateJournal(rejected) != nil {
				t.Fatal("definitive rejection did not retain cleanup without another apply")
			}
			if next, ok := NextPhase(rejected); !ok || next != PhaseReady {
				t.Fatal("rejected recovery can re-enter a credential effect")
			}
			failed := completeActive(t, rejected)
			if failed.Last.Outcome != OutcomeFailed || failed.Last.FailureCode != "RECOVERY_PRECONDITION_FAILED" ||
				failed.CurrentReleaseID != base.CurrentReleaseID || failed.PreviousRelease != base.PreviousRelease || ValidateJournal(failed) != nil {
				t.Fatal("cleanup discarded the definitive rejection or changed a release")
			}
		})
	}
}

func TestNodeCredentialRotationKeepsFailedIntentAndCommitsOnlyAfterVerification(t *testing.T) {
	platform := newJournal(t)
	node, err := NewNode(platform.InstallationID, platform.ReleaseTrust,
		NodeBinding{ExecutionTargetID: "target-a", ConfigurationDigest: digest('a')})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := Start(node, lifecycleCommand(ActionInstall, releaseA, '1', 0))
	if err != nil {
		t.Fatal(err)
	}
	node = completeActive(t, installed.Journal)
	command := lifecycleCommand(ActionRotateCredentials, "", 'b', 10)
	command.ExpectedConfigurationDigest, command.RevokePreviousCredentials = digest('a'), true
	if _, err := Start(installedJournal(t), command); err == nil {
		t.Fatal("credential rotation entered a platform root")
	}
	stale := command
	stale.ExpectedConfigurationDigest = digest('c')
	if _, err := Start(node, stale); !errors.Is(err, ErrPrecondition) {
		t.Fatal("stale node commitment admitted rotation")
	}
	started, err := Start(node, command)
	if err != nil {
		t.Fatal(err)
	}
	state := started.Journal
	for state.Active.Phase != PhaseConfiguring {
		next, _ := NextPhase(state)
		state, err = Advance(state, command.ID, next, state.Active.UpdatedAt.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
	}
	state, err = Fail(state, command.ID, "NODE_DEPENDENCY_UNAVAILABLE", state.Active.UpdatedAt.Add(time.Second))
	if err != nil || state.Active == nil || state.Active.Phase != PhaseConfiguring ||
		state.Node.ConfigurationDigest != digest('a') || state.NodeCredentialRotation != nil || ValidateJournal(state) != nil {
		t.Fatal("failed credential replacement lost its uncommitted forward intent")
	}
	changed := command
	changed.RevokePreviousCredentials = false
	if _, err := Start(state, changed); !errors.Is(err, ErrCommandConflict) {
		t.Fatal("rotation replay changed its retirement policy")
	}
	corrupt := state
	execution := *state.Active
	execution.Phase = PhaseRollingBack
	corrupt.Active = &execution
	if ValidateJournal(corrupt) == nil {
		t.Fatal("credential retirement admitted automatic rollback")
	}
	state = completeActive(t, state)
	if state.Node.ConfigurationDigest != digest('b') || node.Node.ConfigurationDigest != digest('a') ||
		state.CurrentReleaseID != node.CurrentReleaseID || state.CurrentReleaseDigest != node.CurrentReleaseDigest ||
		state.Node.ExecutionTargetID != node.Node.ExecutionTargetID || state.NodeCredentialRotation == nil ||
		*state.NodeCredentialRotation != command || state.Last.FailureCode != "" || ValidateJournal(state) != nil {
		t.Fatal("rotation changed identity/release, aliased prior state, or failed to commit its exact input")
	}
	replayed, err := Start(state, command)
	if err != nil || replayed.Replay != ReplayCompleted {
		t.Fatal("completed rotation could not replay")
	}
	restart, err := Start(state, lifecycleCommand(ActionStart, "", 0, 50))
	if err != nil {
		t.Fatal(err)
	}
	state = completeActive(t, restart.Journal)
	if state.NodeCredentialRotation == nil || *state.NodeCredentialRotation != command || ValidateJournal(state) != nil {
		t.Fatal("startup discarded the committed rotation receipt")
	}
	for _, mode := range []string{"remove receipt", "change policy", "change predecessor"} {
		t.Run(mode, func(t *testing.T) {
			altered := state
			receipt := *state.NodeCredentialRotation
			altered.NodeCredentialRotation, altered.Version = &receipt, state.Version+1
			switch mode {
			case "remove receipt":
				altered.NodeCredentialRotation = nil
			case "change policy":
				receipt.RevokePreviousCredentials = false
			case "change predecessor":
				receipt.ExpectedConfigurationDigest = digest('c')
			}
			if ValidateJournal(altered) != nil {
				t.Fatal("fixture is not a structurally valid journal")
			}
			if ValidateNodeTransition(state, altered) == nil {
				t.Fatal("an unrelated command could alter committed rotation evidence")
			}
		})
	}
}

func TestUpgradeFailureRollsBackWithoutPublishingCandidate(t *testing.T) {
	journal := installedJournal(t)
	command := lifecycleCommand(ActionUpgrade, releaseB, '2', 10)
	started, err := Start(journal, command)
	if err != nil {
		t.Fatalf("start upgrade: %v", err)
	}
	advanced, err := Advance(started.Journal, command.ID, PhaseBackingUp, command.RequestedAt.Add(time.Second))
	if err != nil {
		t.Fatalf("advance upgrade: %v", err)
	}
	failed, err := Fail(advanced, command.ID, "IMAGE_LOAD_FAILED", command.RequestedAt.Add(2*time.Second))
	if err != nil || failed.Active == nil || failed.Active.Phase != PhaseRollingBack {
		t.Fatalf("fail upgrade = %#v / %v", failed, err)
	}
	if failed.CurrentReleaseID != releaseA || failed.PreviousRelease != "" {
		t.Fatal("failed candidate must not change release pointers")
	}
	rolledBack, err := Advance(failed, command.ID, PhaseReady, command.RequestedAt.Add(3*time.Second))
	if err != nil {
		t.Fatalf("complete automatic rollback: %v", err)
	}
	if rolledBack.CurrentReleaseID != releaseA || rolledBack.PreviousRelease != "" ||
		rolledBack.Last == nil || rolledBack.Last.Outcome != OutcomeRolledBack {
		t.Fatalf("rolled-back upgrade journal = %#v", rolledBack)
	}
	changed := command
	changed.BackupID = "backup-" + strings.Repeat("f", 32)
	if _, err := Start(started.Journal, changed); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed upgrade backup replay error = %v", err)
	}
}

func TestManualInterventionAdmitsOnlyExactReplayOrRecovery(t *testing.T) {
	journal := installedJournal(t)
	upgrade := lifecycleCommand(ActionUpgrade, releaseB, '2', 10)
	started, err := Start(journal, upgrade)
	if err != nil {
		t.Fatalf("start upgrade: %v", err)
	}
	failed, err := Fail(
		started.Journal, upgrade.ID, "PLATFORM_VERIFICATION_FAILED",
		upgrade.RequestedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatalf("record upgrade failure: %v", err)
	}
	manual, err := Fail(
		failed, upgrade.ID, "AUTHENTICATED_RECOVERY_REQUIRED",
		upgrade.RequestedAt.Add(2*time.Second),
	)
	if err != nil || manual.Active != nil || manual.Last == nil ||
		manual.Last.Outcome != OutcomeManualIntervention {
		t.Fatalf("manual recovery state = %#v / %v", manual, err)
	}

	replayed, err := Start(manual, upgrade)
	if err != nil || replayed.Replay != ReplayCompleted ||
		replayed.Execution.FailureCode != "AUTHENTICATED_RECOVERY_REQUIRED" {
		t.Fatalf("exact manual replay = %#v / %v", replayed, err)
	}
	newUpgrade := lifecycleCommand(ActionUpgrade, releaseB, '2', 11)
	if _, err := Start(manual, newUpgrade); !errors.Is(err, ErrManualIntervention) {
		t.Fatalf("new command in manual state error = %v", err)
	}

	recovery := lifecycleCommand(ActionRecover, releaseA, '1', 12)
	recovery.BackupID = upgrade.BackupID
	recovery.BackupDigest = digest('3')
	recovering, err := Start(manual, recovery)
	if err != nil || recovering.Replay != ReplayNone ||
		recovering.Execution.Phase != PhaseRecovering {
		t.Fatalf("explicit recovery from manual state = %#v / %v", recovering, err)
	}
}

func TestSuccessfulUpgradeAndExplicitRollbackMaintainNMinusOne(t *testing.T) {
	journal := installedJournal(t)
	upgrade := lifecycleCommand(ActionUpgrade, releaseB, '2', 20)
	started, err := Start(journal, upgrade)
	if err != nil {
		t.Fatalf("start upgrade: %v", err)
	}
	upgraded := completeActive(t, started.Journal)
	if upgraded.CurrentReleaseID != releaseB || upgraded.CurrentReleaseDigest != digest('2') ||
		upgraded.PreviousRelease != releaseA || upgraded.PreviousReleaseDigest != digest('1') {
		t.Fatalf("upgrade pointers = %q / %q", upgraded.CurrentReleaseID, upgraded.PreviousRelease)
	}
	rollback := lifecycleCommand(ActionRollback, "", 0, 30)
	started, err = Start(upgraded, rollback)
	if err != nil || started.Execution.SourceRelease != releaseB || started.Execution.Phase != PhaseRollingBack {
		t.Fatalf("start rollback = %#v / %v", started, err)
	}
	rolledBack := completeActive(t, started.Journal)
	if rolledBack.CurrentReleaseID != releaseA || rolledBack.CurrentReleaseDigest != digest('1') ||
		rolledBack.PreviousRelease != "" || rolledBack.PreviousReleaseDigest != "" {
		t.Fatalf("explicit rollback pointers = %q / %q", rolledBack.CurrentReleaseID, rolledBack.PreviousRelease)
	}
}

func TestRecoveryBindsSelectedBackupAndPublishesOnlyAfterReady(t *testing.T) {
	journal := installedJournal(t)
	command := lifecycleCommand(ActionRecover, releaseA, '1', 35)
	command.BackupID = "backup-" + strings.Repeat("c", 32)
	command.BackupDigest = digest('b')
	started, err := Start(journal, command)
	if err != nil || started.Execution.Phase != PhaseRecovering ||
		started.Execution.Destination != releaseA ||
		started.Journal.CurrentReleaseID != releaseA {
		t.Fatalf("start recovery = %#v / %v", started, err)
	}
	changed := command
	changed.BackupDigest = digest('c')
	if _, err := Start(started.Journal, changed); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed recovery replay error = %v", err)
	}
	missingSource := started.Journal
	missingSourceExecution := *missingSource.Active
	missingSourceExecution.SourceRelease = ""
	missingSourceExecution.SourceDigest = ""
	missingSource.Active = &missingSourceExecution
	if err := ValidateJournal(missingSource); err == nil {
		t.Fatal("active recovery without its installed source must fail")
	}
	recovered := completeActive(t, started.Journal)
	if recovered.CurrentReleaseID != releaseA ||
		recovered.CurrentReleaseDigest != digest('1') ||
		recovered.PreviousRelease != "" || recovered.Active != nil ||
		recovered.Last == nil || recovered.Last.Outcome != OutcomeSucceeded {
		t.Fatalf("completed recovery journal = %#v", recovered)
	}

	empty := newJournal(t)
	if _, err := Start(empty, command); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("recovery without an installed identity error = %v", err)
	}
}

func TestJournalRejectsUnboundReleaseContentAndTrust(t *testing.T) {
	installed := installedJournal(t)

	missingDigest := installed
	missingDigest.CurrentReleaseDigest = ""
	if err := ValidateJournal(missingDigest); err == nil {
		t.Fatal("release identity without its manifest digest must fail")
	}

	changedTrust := installed
	changedTrust.ReleaseTrust.Fingerprint = "sha256:invalid"
	if err := ValidateJournal(changedTrust); err == nil {
		t.Fatal("invalid pinned trust fingerprint must fail")
	}
}

func TestInvalidTransitionAndFailedRollbackRequireManualIntervention(t *testing.T) {
	journal := installedJournal(t)
	upgrade := lifecycleCommand(ActionUpgrade, releaseB, '2', 40)
	started, err := Start(journal, upgrade)
	if err != nil {
		t.Fatalf("start upgrade: %v", err)
	}
	if _, err := Advance(started.Journal, upgrade.ID, PhaseLoadingImages, upgrade.RequestedAt.Add(time.Second)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("skipped phase error = %v, want invalid transition", err)
	}
	upgraded := completeActive(t, started.Journal)
	rollback := lifecycleCommand(ActionRollback, "", 0, 50)
	started, err = Start(upgraded, rollback)
	if err != nil {
		t.Fatalf("start rollback: %v", err)
	}
	manual, err := Fail(started.Journal, rollback.ID, "ROLLBACK_START_FAILED", rollback.RequestedAt.Add(time.Second))
	if err != nil || manual.Active != nil || manual.Last == nil ||
		manual.Last.Outcome != OutcomeManualIntervention || manual.Last.Phase != PhaseManualIntervention {
		t.Fatalf("failed rollback journal = %#v / %v", manual, err)
	}
	if manual.CurrentReleaseID != releaseB || manual.PreviousRelease != releaseA {
		t.Fatal("manual intervention must retain the last known release pointers")
	}
	tampered := manual
	tampered.CurrentReleaseID = releaseA
	tampered.CurrentReleaseDigest = digest('1')
	tampered.PreviousRelease = ""
	tampered.PreviousReleaseDigest = ""
	if err := ValidateJournal(tampered); err == nil {
		t.Fatal("manual intervention journal accepted a changed current release")
	}
}

func TestOperationalCommandsBindBackupAndSupportInputs(t *testing.T) {
	installed := installedJournal(t)
	backup := lifecycleCommand(ActionBackup, "", 0, 60)
	backup.BackupID = "backup-" + strings.Repeat("b", 32)
	started, err := Start(installed, backup)
	if err != nil || started.Execution.Phase != PhaseBackingUp {
		t.Fatalf("start bound backup = %#v / %v", started, err)
	}
	changedBackup := backup
	changedBackup.BackupID = "backup-" + strings.Repeat("c", 32)
	if _, err := Start(started.Journal, changedBackup); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed backup replay error = %v", err)
	}

	support := lifecycleCommand(ActionSupport, "", 'd', 61)
	started, err = Start(installed, support)
	if err != nil || started.Execution.Phase != PhaseVerifying {
		t.Fatalf("start bound support = %#v / %v", started, err)
	}
	changedSupport := support
	changedSupport.InputDigest = digest('e')
	if _, err := Start(started.Journal, changedSupport); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed support replay error = %v", err)
	}
}

const (
	releaseA = "matrix-v0.1.0-aaaaaaaaaaaa"
	releaseB = "matrix-v0.1.1-bbbbbbbbbbbb"
)

func newJournal(t *testing.T) Journal {
	t.Helper()
	journal, err := New(
		"mxi-"+strings.Repeat("a", 32),
		ReleaseTrust{KeyID: "xiak-release-2026", Fingerprint: "sha256:" + strings.Repeat("f", 64)},
	)
	if err != nil {
		t.Fatalf("create journal: %v", err)
	}
	return journal
}

func installedJournal(t *testing.T) Journal {
	t.Helper()
	journal := newJournal(t)
	command := lifecycleCommand(ActionInstall, releaseA, '1', 0)
	started, err := Start(journal, command)
	if err != nil {
		t.Fatalf("start fixture install: %v", err)
	}
	return completeActive(t, started.Journal)
}

func completeActive(t *testing.T, journal Journal) Journal {
	t.Helper()
	if journal.Active == nil {
		t.Fatal("fixture has no active execution")
	}
	sequence := workflow(journal.Active.Command.Action, journal.Node != nil)
	commandID := journal.Active.Command.ID
	at := journal.Active.UpdatedAt
	var err error
	for index := phaseIndex(sequence, journal.Active.Phase) + 1; index < len(sequence); index++ {
		at = at.Add(time.Second)
		journal, err = Advance(journal, commandID, sequence[index], at)
		if err != nil {
			t.Fatalf("advance to %s: %v", sequence[index], err)
		}
	}
	return journal
}

func lifecycleCommand(action Action, target string, digestByte byte, offset int) Command {
	command := Command{
		ID:              "cmd-" + strings.Repeat(string("0123456789abcdef"[offset%16]), 32),
		Action:          action,
		TargetReleaseID: target,
		RequestedAt:     time.Date(2026, 8, 25, 12, 0, offset, 0, time.UTC),
	}
	if digestByte != 0 {
		command.InputDigest = digest(digestByte)
	}
	if action == ActionUpgrade {
		command.BackupID = "backup-" + strings.Repeat(string("fedcba9876543210"[offset%16]), 32)
	}
	return command
}

func digest(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}
