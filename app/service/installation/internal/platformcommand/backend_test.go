package platformcommand

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

type installEffects struct {
	calls            map[lifecycle.Phase]int
	failPhase        lifecycle.Phase
	failErr          error
	failOnce         bool
	failed           bool
	rollbackCalls    int
	rollbackErr      error
	rollbackFailOnce bool
	rollbackFailed   bool
	observeCalls     int
	observeReady     bool
	observeErr       error
	verifyCalls      int
	verifyErr        error
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
