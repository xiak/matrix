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
	if completed.CurrentReleaseID != releaseA || completed.PreviousRelease != "" ||
		completed.Active != nil || completed.Last == nil || completed.Last.Outcome != OutcomeSucceeded {
		t.Fatalf("completed install journal = %#v", completed)
	}
	replayed, err = Start(completed, replayedCommand)
	if err != nil || replayed.Replay != ReplayCompleted || replayed.Execution.Outcome != OutcomeSucceeded {
		t.Fatalf("completed replay = %#v / %v", replayed, err)
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
}

func TestSuccessfulUpgradeAndExplicitRollbackMaintainNMinusOne(t *testing.T) {
	journal := installedJournal(t)
	upgrade := lifecycleCommand(ActionUpgrade, releaseB, '2', 20)
	started, err := Start(journal, upgrade)
	if err != nil {
		t.Fatalf("start upgrade: %v", err)
	}
	upgraded := completeActive(t, started.Journal)
	if upgraded.CurrentReleaseID != releaseB || upgraded.PreviousRelease != releaseA {
		t.Fatalf("upgrade pointers = %q / %q", upgraded.CurrentReleaseID, upgraded.PreviousRelease)
	}
	rollback := lifecycleCommand(ActionRollback, "", 0, 30)
	started, err = Start(upgraded, rollback)
	if err != nil || started.Execution.SourceRelease != releaseB || started.Execution.Phase != PhaseRollingBack {
		t.Fatalf("start rollback = %#v / %v", started, err)
	}
	rolledBack := completeActive(t, started.Journal)
	if rolledBack.CurrentReleaseID != releaseA || rolledBack.PreviousRelease != "" {
		t.Fatalf("explicit rollback pointers = %q / %q", rolledBack.CurrentReleaseID, rolledBack.PreviousRelease)
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
}

const (
	releaseA = "matrix-v0.1.0-aaaaaaaaaaaa"
	releaseB = "matrix-v0.1.1-bbbbbbbbbbbb"
)

func newJournal(t *testing.T) Journal {
	t.Helper()
	journal, err := New("mxi-" + strings.Repeat("a", 32))
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
	sequence := workflow(journal.Active.Command.Action)
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
	return command
}

func digest(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}
