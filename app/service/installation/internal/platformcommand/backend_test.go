package platformcommand

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
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

type installEffects struct {
	calls         map[lifecycle.Phase]int
	failPhase     lifecycle.Phase
	failErr       error
	failOnce      bool
	failed        bool
	rollbackCalls int
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
	return nil
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
