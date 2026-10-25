package nodecommand

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/cli"
	"github.com/xiak/matrix/app/service/installation/internal/journal"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/releasetest"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/installation/release"
)

func newNodeBackend(t *testing.T, effects *nodeEffects) *Backend {
	t.Helper()
	backend, err := NewBackend(effects, effects, effects, effects)
	if err != nil {
		t.Fatal(err)
	}
	return backend
}

func TestNodeEnrollmentFixtureProducesBoundRoleCertificates(t *testing.T) {
	request, _ := nodeRequest(t)
	join, err := readNodeEnrollmentJoin(request.Join)
	if err != nil {
		t.Fatal(err)
	}
	defer join.Clear()
	intent, err := newEnrollmentIntent(join.Join, "sha256:"+strings.Repeat("a", 64), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer intent.Clear()
	response, err := testEnrollmentExchangeResponse(join.Join, intent.exchangeRequest(join.Credential))
	if err != nil {
		t.Fatal(err)
	}
	if err := paasv1.ValidateNodeEnrollmentExchangeResponse(response); err != nil {
		t.Fatalf("response: %v", err)
	}
	if err := ValidateEnrollmentResponse(intent, response); err != nil {
		t.Fatal(err)
	}
}

func TestNodeEnrollmentRecoversLostExchangeWithoutBlindCredentialReplay(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{loseExchangeResponse: true}
	backend := newNodeBackend(t, effects)
	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_UNAVAILABLE")
	if effects.exchangeCalls != 1 || effects.enrollmentIntent == nil || !effects.enrollmentAttempted ||
		effects.enrollmentResponse != nil || effects.remoteExchange == nil {
		t.Fatal("unknown exchange outcome was not sealed for recovery")
	}
	join, err := readNodeEnrollmentJoin(request.Join)
	if err != nil {
		t.Fatal(err)
	}
	backend.now = func() time.Time { return join.Join.ExpiresAt.Add(time.Hour) }
	intentBytes, err := EncodeEnrollmentIntent(*effects.enrollmentIntent)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(intentBytes, []byte(join.Credential)) {
		t.Fatal("sealed enrollment intent retained the raw join credential")
	}
	clear(intentBytes)
	join.Clear()

	effects.recoveryChallengeFailure = ErrEnrollmentUnavailable
	_, err = backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_UNAVAILABLE")
	if effects.exchangeCalls != 1 || effects.recoveryCalls != 1 || effects.recoveryProofCalls != 0 {
		t.Fatal("unavailable recovery challenge caused a credential replay")
	}

	effects.recoveryChallengeFailure = nil
	result, err := backend.Run(context.Background(), request)
	if err != nil || result.State != "READY" {
		t.Fatalf("recover lost exchange: %#v / %v", result, err)
	}
	if effects.exchangeCalls != 1 || effects.recoveryCalls != 2 || effects.recoveryProofCalls != 1 ||
		effects.completionCalls != 1 || effects.enrollmentIntent != nil || effects.enrollmentResponse != nil {
		t.Fatal("lost response recovery resent the credential or retained bootstrap secrets")
	}
}

func TestNodeEnrollmentRecoversExchangeCommittedAfterNotExchangedObservation(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{enrollmentExchangeFailure: ErrEnrollmentUnavailable}
	backend := newNodeBackend(t, effects)
	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_UNAVAILABLE")
	if effects.exchangeCalls != 1 || effects.enrollmentIntent == nil || !effects.enrollmentAttempted {
		t.Fatal("unknown exchange was not made recoverable")
	}
	effects.enrollmentExchangeFailure = nil
	effects.exchangeRejectAfterCommit = true
	result, err := backend.Run(context.Background(), request)
	if err != nil || result.State != "READY" {
		t.Fatalf("recover exchange race: %#v / %v", result, err)
	}
	if effects.exchangeCalls != 2 || effects.recoveryCalls != 2 || effects.recoveryProofCalls != 1 ||
		effects.completionCalls != 1 || effects.enrollmentIntent != nil || effects.enrollmentResponse != nil {
		t.Fatal("exchange race discarded role keys or failed to recover the committed result")
	}
}

func TestNodeEnrollmentNeverReplaysExpiredCredentialWhenRecoveryProvesNoExchange(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{loseExchangeResponse: true}
	backend := newNodeBackend(t, effects)
	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_UNAVAILABLE")
	if effects.exchangeCalls != 1 || effects.enrollmentIntent == nil || !effects.enrollmentAttempted {
		t.Fatal("unknown exchange outcome was not sealed")
	}
	join, err := readNodeEnrollmentJoin(request.Join)
	if err != nil {
		t.Fatal(err)
	}
	backend.now = func() time.Time { return join.Join.ExpiresAt.Add(time.Hour) }
	join.Clear()
	// The recovery authority is definitive: the original request did not reach
	// the server. Once the credential has expired, it must not be sent again.
	effects.remoteExchange = nil
	effects.loseExchangeResponse = false
	_, err = backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_REJECTED")
	if effects.exchangeCalls != 1 || effects.recoveryCalls != 1 || effects.recoveryProofCalls != 0 ||
		effects.enrollmentIntent != nil || effects.enrollmentAttempted || effects.enrollmentResponse != nil {
		t.Fatal("expired credential was replayed or rejected intent was retained")
	}
}

func TestNodeEnrollmentCompletionUnavailableResumesWithoutReexchange(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{enrollmentCompletionFailure: ErrEnrollmentUnavailable}
	backend := newNodeBackend(t, effects)
	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_COMPLETION_PENDING")
	pending := nodeState(t, request.Root)
	if pending.Active == nil || pending.Active.Phase != lifecycle.PhaseCommitting || effects.exchangeCalls != 1 ||
		effects.completionCalls != 1 || effects.rollbacks != 0 || effects.enrollmentIntent == nil || effects.enrollmentResponse == nil {
		t.Fatal("retryable completion failure lost or rolled back the sealed enrollment")
	}

	effects.enrollmentCompletionFailure = nil
	effects.ready = false
	effects.failPhase, effects.failure = lifecycle.PhaseStarting, ErrVerification
	_, err = backend.Run(context.Background(), cli.Request{
		Subject: cli.SubjectNode, Action: lifecycle.ActionStart, Root: request.Root,
	})
	assertNodeFault(t, err, "NODE_VERIFICATION_FAILED")
	stillPending := nodeState(t, request.Root)
	if stillPending.Active == nil || stillPending.Active.Phase != lifecycle.PhaseCommitting ||
		effects.exchangeCalls != 1 || effects.completionCalls != 1 || effects.rollbacks != 0 ||
		effects.enrollmentIntent == nil || effects.enrollmentResponse == nil {
		t.Fatal("local resume failure after unknown completion rolled back possible remote success")
	}
	result, err := backend.Run(context.Background(), cli.Request{
		Subject: cli.SubjectNode, Action: lifecycle.ActionStart, Root: request.Root,
	})
	if err != nil || result.State != "READY" || result.CorrelationID != pending.Active.Command.ID {
		t.Fatalf("resume node enrollment completion: %#v / %v", result, err)
	}
	if effects.exchangeCalls != 1 || effects.completionCalls != 2 || effects.rollbacks != 0 ||
		effects.enrollmentIntent != nil || effects.enrollmentResponse != nil {
		t.Fatal("completion retry exchanged again, rolled back, or retained bootstrap state")
	}
}

func TestNodeEnrollmentHasNoFallibleEffectAfterRemotePublication(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{failPhase: lifecycle.PhaseCommitting, failure: ErrVerification}
	backend := newNodeBackend(t, effects)
	result, err := backend.Run(context.Background(), request)
	if err != nil || result.State != "READY" || effects.completionCalls != 1 || effects.failure == nil {
		t.Fatalf("node enrollment publication ordering: %#v / %v", result, err)
	}
	for _, phase := range effects.phases {
		if phase == lifecycle.PhaseCommitting {
			t.Fatal("node enrollment ran a local effect after remote publication")
		}
	}
}

func TestNodeEnrollmentSuccessfulCleanupResumesBeforeAnotherStart(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{cleanupFailure: ErrUnavailable}
	backend := newNodeBackend(t, effects)
	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_CLEANUP_PENDING")
	committed := nodeState(t, request.Root)
	if committed.Active != nil || committed.CurrentReleaseID == "" || committed.Last == nil ||
		committed.Last.Outcome != lifecycle.OutcomeSucceeded || effects.enrollmentIntent == nil ||
		effects.enrollmentResponse == nil || effects.exchangeCalls != 1 || effects.completionCalls != 1 {
		t.Fatal("successful enrollment cleanup failure lost its committed state")
	}
	effects.cleanupFailure = nil
	result, err := backend.Run(context.Background(), cli.Request{
		Subject: cli.SubjectNode, Action: lifecycle.ActionStart, Root: request.Root,
	})
	if err != nil || result.State != "READY" || effects.enrollmentIntent != nil ||
		effects.enrollmentResponse != nil || effects.exchangeCalls != 1 || effects.completionCalls != 1 {
		t.Fatalf("resume successful enrollment cleanup before start: %#v / %v", result, err)
	}
}

func TestNodeEnrollmentSuccessfulCleanupReportsSubstitutionAsConflict(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{cleanupFailure: ErrConflict}
	backend := newNodeBackend(t, effects)

	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_CLEANUP_CONFLICT")
	committed := nodeState(t, request.Root)
	if committed.Active != nil || committed.CurrentReleaseID == "" || committed.Last == nil ||
		committed.Last.Outcome != lifecycle.OutcomeSucceeded || effects.exchangeCalls != 1 ||
		effects.completionCalls != 1 || effects.enrollmentIntent == nil || effects.enrollmentResponse == nil {
		t.Fatal("cleanup substitution conflict changed the committed enrollment")
	}
}

func TestNodeEnrollmentCompletionRejectionRollsBackAndCleansOnlyEnrollment(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{enrollmentCompletionFailure: ErrEnrollmentRejected}
	backend := newNodeBackend(t, effects)
	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_REJECTED")
	failed := nodeState(t, request.Root)
	if failed.Active != nil || failed.Last == nil || failed.Last.Outcome != lifecycle.OutcomeRolledBack ||
		failed.CurrentReleaseID != "" || effects.rollbacks != 1 || effects.enrollmentCleanupCalls != 1 ||
		effects.exchangeCalls != 1 || effects.completionCalls != 1 || effects.enrollmentIntent != nil ||
		effects.enrollmentResponse != nil {
		t.Fatal("definitive completion rejection retained services, credentials, or a ready release")
	}
	before := journalBytes(t, request.Root)
	for _, replay := range []cli.Request{
		{Subject: cli.SubjectNode, Action: lifecycle.ActionStart, Root: request.Root},
		request,
	} {
		_, err = backend.Run(context.Background(), replay)
		assertNodeFault(t, err, lifecycle.NodeEnrollmentRejectedFailureCode)
	}
	if !bytes.Equal(before, journalBytes(t, request.Root)) || effects.rollbacks != 1 ||
		effects.enrollmentCleanupCalls != 1 || effects.exchangeCalls != 1 || effects.completionCalls != 1 {
		t.Fatal("completed rejection replay repeated cleanup, exchange, completion, or rollback")
	}
}

func TestNodeEnrollmentRejectedCleanupResumesAfterTerminalJournal(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{
		enrollmentCompletionFailure: ErrEnrollmentRejected,
		cleanupFailure:              ErrUnavailable,
	}
	backend := newNodeBackend(t, effects)
	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_CLEANUP_PENDING")
	terminal := nodeState(t, request.Root)
	if !rejectedEnrollmentCleanupPending(terminal) || effects.rollbacks != 1 ||
		effects.enrollmentCleanupCalls != 1 || effects.enrollmentIntent == nil || effects.enrollmentResponse == nil {
		t.Fatal("cleanup failure was not retained behind a terminal rollback journal")
	}
	before := journalBytes(t, request.Root)
	effects.cleanupFailure = nil
	_, err = backend.Run(context.Background(), cli.Request{
		Subject: cli.SubjectNode, Action: lifecycle.ActionStart, Root: request.Root,
	})
	assertNodeFault(t, err, "NODE_ENROLLMENT_REJECTED")
	if !bytes.Equal(before, journalBytes(t, request.Root)) || effects.rollbacks != 1 ||
		effects.enrollmentCleanupCalls != 1 || effects.enrollmentCleanupResumeCalls != 1 ||
		effects.exchangeCalls != 1 || effects.completionCalls != 1 ||
		effects.enrollmentIntent != nil || effects.enrollmentResponse != nil {
		t.Fatal("terminal cleanup replay changed lifecycle or repeated exchange/completion")
	}
}

func TestNodeEnrollmentExchangeRejectionDiscardsUnredeemableIntent(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{enrollmentExchangeFailure: ErrEnrollmentRejected}
	backend := newNodeBackend(t, effects)
	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_REJECTED")
	if effects.exchangeCalls != 1 || effects.enrollmentIntent != nil || effects.enrollmentAttempted ||
		effects.enrollmentResponse != nil || effects.completionCalls != 0 || len(effects.phases) != 0 {
		t.Fatal("definitively rejected exchange retained bootstrap authority or reached node effects")
	}
	session, err := journal.Acquire(context.Background(), request.Root)
	if err != nil {
		t.Fatal(err)
	}
	initialized, stateErr := session.Initialized()
	closeErr := session.Close()
	if stateErr != nil || initialized || closeErr != nil {
		t.Fatal("rejected exchange initialized an installation journal")
	}
}

func TestNodeInstallResumesUnknownStartupAndPinsEnrollment(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{failPhase: lifecycle.PhaseStarting, failure: ErrOutcomeUnknown}
	backend := newNodeBackend(t, effects)
	_, err := backend.Run(context.Background(), request)
	assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
	state := nodeState(t, request.Root)
	if state.Node == nil || state.Active == nil || state.Active.Phase != lifecycle.PhaseStarting || state.CurrentReleaseID != "" {
		t.Fatal("unknown startup was not retained as an uncommitted intent")
	}
	commandID := state.Active.Command.ID
	before := journalBytes(t, request.Root)
	originalJoin := request.Join
	conflicting, _ := nodeRequest(t)
	request.Join = conflicting.Join
	_, err = backend.Run(context.Background(), request)
	assertNodeFault(t, err, "NODE_ENROLLMENT_CONFLICT")
	if !bytes.Equal(before, journalBytes(t, request.Root)) {
		t.Fatal("conflicting enrollment changed the sealed journal")
	}
	request.Join = originalJoin
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

func TestNodeSupportPreservesJournalAndNeverReconcilesOrResumesAnIntent(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{supportCreated: true}
	backend := newNodeBackend(t, effects)
	installed, err := backend.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	before, phaseCount := journalBytes(t, request.Root), len(effects.phases)
	support := cli.Request{Subject: cli.SubjectNode, Action: lifecycle.ActionSupport, Root: request.Root,
		SupportOutput: filepath.Join(request.Root, layout.SupportDirectory, "snapshot.json")}
	outside := support
	outside.SupportOutput = filepath.Join(filepath.Dir(request.Root), "outside.json")
	_, err = backend.Run(context.Background(), outside)
	assertNodeFault(t, err, "SUPPORT_OUTPUT_INVALID")
	if effects.supportCalls != 0 || !bytes.Equal(before, journalBytes(t, request.Root)) {
		t.Fatal("unowned diagnostic output reached effects or changed the journal")
	}
	effects.cleanupFailure = ErrUnavailable
	result, err := backend.Run(context.Background(), support)
	if err != nil || result.State != "SUPPORT_WRITTEN" || !result.Changed || result.CorrelationID != installed.CorrelationID ||
		effects.supportCalls != 1 || effects.supportPlan.Journal.Version != nodeState(t, request.Root).Version ||
		effects.supportPlan.Installation.Binding.ConfigurationDigest != installed.ConfigurationDigest ||
		!bytes.Equal(before, journalBytes(t, request.Root)) || len(effects.phases) != phaseCount {
		t.Fatalf("diagnostic read changed lifecycle/credentials or reported current readiness: %#v / %v", result, err)
	}
	effects.supportCreated = false
	result, err = backend.Run(context.Background(), support)
	if err != nil || result.State != "SUPPORT_REPLAYED" || result.Changed || !bytes.Equal(before, journalBytes(t, request.Root)) {
		t.Fatal("diagnostic replay created an operation or fabricated fresh readiness")
	}
	effects.supportFailure = ErrOutcomeUnknown
	_, err = backend.Run(context.Background(), support)
	assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
	if !bytes.Equal(before, journalBytes(t, request.Root)) {
		t.Fatal("uncertain evidence write replaced the lifecycle intent")
	}
	effects.supportFailure = nil
	effects.failPhase, effects.failure = lifecycle.PhaseVerifying, ErrOutcomeUnknown
	_, err = backend.Run(context.Background(), cli.Request{Action: lifecycle.ActionVerify, Root: request.Root})
	assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
	pending, calls := journalBytes(t, request.Root), effects.supportCalls
	_, err = backend.Run(context.Background(), support)
	assertNodeFault(t, err, "INSTALLATION_COMMAND_CONFLICT")
	if effects.supportCalls != calls || !bytes.Equal(pending, journalBytes(t, request.Root)) {
		t.Fatal("support read resumed or replaced an accepted command")
	}
}

func TestNodeUpgradeResumesProtectedCandidateAndRollbackKeepsLatestCredentials(t *testing.T) {
	fixtures, err := releasetest.WriteNodeSequence(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	request, input := nodeRequest(t, fixtures[0])
	effects := &nodeEffects{}
	backend := newNodeBackend(t, effects)
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
		Configuration: rotationInput(request), ExpectedConfigurationDigest: before.Node.ConfigurationDigest, RevokePreviousCredentials: true}); err != nil {
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
				backend := newNodeBackend(t, effects)
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
	backend := newNodeBackend(t, effects)
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
	backend := newNodeBackend(t, effects)
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
	configuration, material, err := enrollment(request.Root, rotationInput(request))
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

func TestNodeReleasePlanAdmitsOnlyTheDeploymentRuntimePredecessorAsInstalledState(t *testing.T) {
	fixtures, err := releasetest.WriteNodeRuntimeSequence(
		t.TempDir(),
		nodeconfig.DeploymentRuntimePredecessorRevision,
		nodeconfig.RuntimeRevision,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := nodeRequest(t, fixtures[1])
	configuration, material, err := enrollment(request.Root, rotationInput(request))
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	trustBytes, trust, err := release.ReadTrustRootFile(request.TrustKey)
	if err != nil {
		t.Fatal(err)
	}
	predecessorBundle, err := release.VerifyDirectory(fixtures[0].Root, trustBytes)
	if err != nil {
		t.Fatal(err)
	}
	currentBundle, err := release.VerifyDirectory(fixtures[1].Root, trustBytes)
	if err != nil {
		t.Fatal(err)
	}
	if ValidateRelease(predecessorBundle) == nil || ValidateInstalledRelease(predecessorBundle) != nil ||
		ValidateRelease(currentBundle) != nil || ValidateInstalledRelease(currentBundle) != nil {
		t.Fatal("node target and installed profile boundaries are not exact")
	}
	binding, err := Binding(configuration, material)
	if err != nil {
		t.Fatal(err)
	}
	predecessor := Plan{
		Root: request.Root, Bundle: predecessorBundle, Configuration: configuration,
		Credentials: material, Trust: trust, TrustBytes: trustBytes, Binding: binding,
	}
	current := predecessor
	current.Bundle, current.ReleaseSource = currentBundle, &predecessor
	if err := ValidatePlan(current); err != nil {
		t.Fatalf("forward node runtime plan: %v", err)
	}
	rollback := predecessor
	rollback.ReleaseSource = &current
	current.ReleaseSource = nil
	if err := ValidatePlan(rollback); err != nil {
		t.Fatalf("rollback node runtime plan: %v", err)
	}
}

func TestNodeStartResumesOnlyConfiguredInstallWithoutNewEnrollment(t *testing.T) {
	for _, phase := range []lifecycle.Phase{lifecycle.PhasePreflight, lifecycle.PhaseStaging,
		lifecycle.PhaseConfiguring, lifecycle.PhaseStarting, lifecycle.PhaseVerifying} {
		t.Run(string(phase), func(t *testing.T) {
			request, _ := nodeRequest(t)
			effects := &nodeEffects{failPhase: phase, failure: ErrOutcomeUnknown}
			backend := newNodeBackend(t, effects)
			_, err := backend.Run(context.Background(), request)
			assertNodeFault(t, err, "EFFECT_OUTCOME_UNKNOWN")
			state := nodeState(t, request.Root)
			command := state.Active.Command
			before, calls := journalBytes(t, request.Root), len(effects.phases)
			effects.ready = false // A guest boot loses its transient services.
			for _, path := range []string{rotationInput(request), request.Join} {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
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
			backend := newNodeBackend(t, effects)
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
			backend := newNodeBackend(t, effects)
			if _, err := backend.Run(context.Background(), request); err == nil || len(effects.phases) != 0 || effects.rollbacks != 0 {
				t.Fatal("invalid node install reached effects")
			}
			if mode == "platform root" {
				if !bytes.Equal(before, journalBytes(t, request.Root)) {
					t.Fatal("node command changed a platform root")
				}
			} else if mode == "platform release" {
				if _, err := os.Lstat(request.Root); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("invalid release created a root")
				}
			} else {
				session, err := journal.Acquire(context.Background(), request.Root)
				if err != nil {
					t.Fatal("rejected enrollment root cannot be inspected")
				}
				initialized, stateErr := session.Initialized()
				closeErr := session.Close()
				if stateErr != nil || initialized || closeErr != nil {
					t.Fatal("invalid enrollment initialized a journal")
				}
			}
		})
	}
}

func TestNodeStoredCredentialSubstitutionAndUnsupportedActionsFailClosed(t *testing.T) {
	request, _ := nodeRequest(t)
	effects := &nodeEffects{}
	backend := newNodeBackend(t, effects)
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
	backend := newNodeBackend(t, effects)
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
			backend := newNodeBackend(t, effects)
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
				Root: request.Root, Configuration: rotationInput(request),
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
			if err := os.Remove(rotationInput(request)); err != nil {
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
			writeInput(t, rotationInput(request), input)
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
	backend := newNodeBackend(t, effects)
	if _, err := backend.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	original := nodeState(t, request.Root)
	if err := os.WriteFile(input.Node.PrivateKeyFile, []byte("replacement-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	rotation := cli.Request{Action: lifecycle.ActionRotateCredentials, Root: request.Root, Configuration: rotationInput(request),
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
			backend := newNodeBackend(t, effects)
			if _, err := backend.Run(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			rotation := cli.Request{Action: lifecycle.ActionRotateCredentials, Root: request.Root,
				Configuration: rotationInput(request), ExpectedConfigurationDigest: nodeState(t, request.Root).Node.ConfigurationDigest,
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
			writeInput(t, rotationInput(request), input)
			before, calls := journalBytes(t, request.Root), len(effects.phases)
			if _, err := backend.Run(context.Background(), rotation); err == nil || !bytes.Equal(before, journalBytes(t, request.Root)) || calls != len(effects.phases) {
				t.Fatal("invalid rotation changed intent or native effects")
			}
		})
	}
}

type nodeEffects struct {
	invalid                      bool
	ready                        bool
	failPhase                    lifecycle.Phase
	failure                      error
	cleanupFailure               error
	rollbackFailure              error
	phases                       []lifecycle.Phase
	rollbacks                    int
	supportCalls                 int
	supportPlan                  SupportPlan
	supportFailure               error
	supportCreated               bool
	enrollmentIntent             *EnrollmentIntent
	enrollmentAttempted          bool
	enrollmentResponse           *paasv1.NodeEnrollmentExchangeResponse
	enrollmentExchangeFailure    error
	exchangeRejectAfterCommit    bool
	enrollmentCompletionFailure  error
	recoveryChallengeFailure     error
	loseExchangeResponse         bool
	remoteExchange               *paasv1.NodeEnrollmentExchangeResponse
	exchangeCalls                int
	recoveryCalls                int
	recoveryProofCalls           int
	completionCalls              int
	enrollmentCleanupCalls       int
	enrollmentCleanupPending     bool
	enrollmentCleanupResumeCalls int
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
func (effects *nodeEffects) WriteSupportEvidence(_ context.Context, plan SupportPlan) (bool, error) {
	effects.supportCalls++
	effects.supportPlan = plan
	return effects.supportCreated, effects.supportFailure
}
func (effects *nodeEffects) ReadInstallation(root string) (nodeconfig.Configuration, Credentials, error) {
	return readFixtureNodeCredentials(root, "")
}
func (effects *nodeEffects) ReadRotation(root, digest string) (nodeconfig.Configuration, Credentials, error) {
	return readFixtureNodeCredentials(root, "fixture-rotation/"+digest[len("sha256:"):])
}
func (effects *nodeEffects) FinalizeRotation(context.Context, Plan, lifecycle.Command) error {
	return effects.cleanupFailure
}

func (effects *nodeEffects) MachineFingerprint(context.Context, string) (string, error) {
	return "sha256:" + strings.Repeat("a", 64), nil
}

func (effects *nodeEffects) ResumeEnrollmentCleanup(string) (bool, error) {
	if !effects.enrollmentCleanupPending {
		return false, nil
	}
	effects.enrollmentCleanupResumeCalls++
	if effects.cleanupFailure != nil {
		return false, effects.cleanupFailure
	}
	effects.enrollmentCleanupPending = false
	effects.clearEnrollmentState()
	return true, nil
}

func (effects *nodeEffects) ReadEnrollmentIntent(string) (EnrollmentIntent, bool, error) {
	if effects.enrollmentIntent == nil {
		return EnrollmentIntent{}, false, nil
	}
	value, err := cloneEnrollmentIntent(*effects.enrollmentIntent)
	return value, err == nil, err
}

func (effects *nodeEffects) CreateEnrollmentIntent(_ string, value EnrollmentIntent) error {
	if effects.enrollmentIntent != nil || ValidateEnrollmentIntent(value) != nil {
		return ErrConflict
	}
	cloned, err := cloneEnrollmentIntent(value)
	if err != nil {
		return ErrVerification
	}
	effects.enrollmentIntent = &cloned
	return nil
}

func (effects *nodeEffects) EnrollmentExchangeAttempted(_ string, value EnrollmentIntent) (bool, error) {
	if effects.enrollmentIntent == nil || !sameEnrollmentJoin(effects.enrollmentIntent.Join, value.Join) {
		return false, ErrConflict
	}
	return effects.enrollmentAttempted, nil
}

func (effects *nodeEffects) MarkEnrollmentExchangeAttempted(_ string, value EnrollmentIntent) error {
	if effects.enrollmentIntent == nil || !sameEnrollmentJoin(effects.enrollmentIntent.Join, value.Join) {
		return ErrConflict
	}
	effects.enrollmentAttempted = true
	return nil
}

func (effects *nodeEffects) ReadEnrollmentResponse(
	_ string,
	intent EnrollmentIntent,
) (paasv1.NodeEnrollmentExchangeResponse, bool, error) {
	if effects.enrollmentResponse == nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, false, nil
	}
	if ValidateEnrollmentResponse(intent, *effects.enrollmentResponse) != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, false, ErrVerification
	}
	return *effects.enrollmentResponse, true, nil
}

func (effects *nodeEffects) CreateEnrollmentResponse(
	_ string,
	intent EnrollmentIntent,
	response paasv1.NodeEnrollmentExchangeResponse,
) error {
	if effects.enrollmentResponse != nil || ValidateEnrollmentResponse(intent, response) != nil {
		return ErrConflict
	}
	effects.enrollmentResponse = &response
	return nil
}

func (effects *nodeEffects) DiscardEnrollmentIntent(_ string, intent EnrollmentIntent) error {
	if effects.enrollmentIntent == nil || effects.enrollmentResponse != nil ||
		!sameEnrollmentJoin(effects.enrollmentIntent.Join, intent.Join) {
		return ErrConflict
	}
	effects.enrollmentIntent.Clear()
	effects.enrollmentIntent = nil
	effects.enrollmentAttempted = false
	effects.remoteExchange = nil
	return nil
}

func (effects *nodeEffects) FinalizeEnrollment(
	_ string,
	intent EnrollmentIntent,
	response paasv1.NodeEnrollmentExchangeResponse,
) error {
	if effects.enrollmentIntent == nil || effects.enrollmentResponse == nil ||
		!sameEnrollmentJoin(effects.enrollmentIntent.Join, intent.Join) || *effects.enrollmentResponse != response {
		return ErrConflict
	}
	effects.enrollmentCleanupPending = true
	if effects.cleanupFailure != nil {
		return effects.cleanupFailure
	}
	effects.enrollmentCleanupPending = false
	effects.clearEnrollmentState()
	return nil
}

func (effects *nodeEffects) clearEnrollmentState() {
	if effects.enrollmentIntent != nil {
		effects.enrollmentIntent.Clear()
	}
	effects.enrollmentIntent = nil
	effects.enrollmentResponse = nil
	effects.enrollmentAttempted = false
	effects.remoteExchange = nil
}

func (effects *nodeEffects) CleanupRejectedEnrollment(
	_ context.Context,
	_ Plan,
	intent EnrollmentIntent,
	response paasv1.NodeEnrollmentExchangeResponse,
) error {
	effects.enrollmentCleanupCalls++
	return effects.FinalizeEnrollment("", intent, response)
}

func (effects *nodeEffects) Exchange(
	_ context.Context,
	join paasv1.NodeEnrollmentJoin,
	request paasv1.ExchangeNodeEnrollmentRequest,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	effects.exchangeCalls++
	if effects.enrollmentExchangeFailure != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, effects.enrollmentExchangeFailure
	}
	response, err := testEnrollmentExchangeResponse(join, request)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	if effects.exchangeRejectAfterCommit {
		effects.exchangeRejectAfterCommit = false
		effects.remoteExchange = &response
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrEnrollmentRejected
	}
	if effects.loseExchangeResponse {
		effects.remoteExchange = &response
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrEnrollmentUnavailable
	}
	return response, nil
}

func (effects *nodeEffects) CreateRecoveryChallenge(
	_ context.Context,
	_ paasv1.NodeEnrollmentJoin,
	request paasv1.CreateNodeEnrollmentRecoveryChallengeRequest,
) (paasv1.NodeEnrollmentRecoveryChallenge, error) {
	effects.recoveryCalls++
	if effects.recoveryChallengeFailure != nil {
		return paasv1.NodeEnrollmentRecoveryChallenge{}, effects.recoveryChallengeFailure
	}
	if effects.remoteExchange == nil {
		return paasv1.NodeEnrollmentRecoveryChallenge{}, ErrEnrollmentNotExchanged
	}
	issuedAt := time.Now().UTC().Truncate(time.Microsecond)
	challenge := paasv1.NodeEnrollmentRecoveryChallenge{
		APIVersion: request.APIVersion, Kind: paasv1.NodeEnrollmentRecoveryChallengeKind,
		EnrollmentID: request.EnrollmentID, InstallationID: request.InstallationID,
		ExecutionTargetID: request.ExecutionTargetID, ExchangeID: request.ExchangeID,
		MachineFingerprint: request.MachineFingerprint, RuntimeContractDigest: request.RuntimeContractDigest,
		NodePublicKeyFingerprint:      request.NodePublicKeyFingerprint,
		CollectorPublicKeyFingerprint: request.CollectorPublicKeyFingerprint,
		Challenge:                     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		IssuedAt:                      issuedAt, ExpiresAt: issuedAt.Add(time.Minute),
		Authenticator: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32)),
	}
	if paasv1.ValidateNodeEnrollmentRecoveryChallengeForRequest(challenge, request) != nil {
		return paasv1.NodeEnrollmentRecoveryChallenge{}, ErrEnrollmentRejected
	}
	return challenge, nil
}

func (effects *nodeEffects) RecoverExchange(
	_ context.Context,
	_ paasv1.NodeEnrollmentJoin,
	request paasv1.RecoverNodeEnrollmentExchangeRequest,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	effects.recoveryProofCalls++
	if effects.remoteExchange == nil || paasv1.ValidateRecoverNodeEnrollmentExchangeRequest(request) != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrEnrollmentRejected
	}
	proof, err := paasv1.NodeEnrollmentRecoveryProofSigningBytes(request.Challenge)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrEnrollmentRejected
	}
	verify := func(certificateText, signatureText string) bool {
		certificateDER, err := base64.RawURLEncoding.Strict().DecodeString(certificateText)
		if err != nil {
			return false
		}
		certificate, err := x509.ParseCertificate(certificateDER)
		if err != nil || certificate == nil {
			return false
		}
		signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(signatureText)
		public, ok := certificate.PublicKey.(ed25519.PublicKey)
		return signatureErr == nil && ok && ed25519.Verify(public, proof, signature)
	}
	if !verify(effects.remoteExchange.NodeCertificate, request.NodeSignature) ||
		!verify(effects.remoteExchange.CollectorCertificate, request.CollectorSignature) {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrEnrollmentRejected
	}
	return *effects.remoteExchange, nil
}

func (effects *nodeEffects) Complete(
	_ context.Context,
	_ paasv1.NodeEnrollmentJoin,
	request paasv1.CompleteNodeEnrollmentRequest,
) error {
	effects.completionCalls++
	if paasv1.ValidateCompleteNodeEnrollmentRequest(request) != nil {
		return ErrEnrollmentRejected
	}
	return effects.enrollmentCompletionFailure
}

func cloneEnrollmentIntent(value EnrollmentIntent) (EnrollmentIntent, error) {
	encoded, err := EncodeEnrollmentIntent(value)
	if err != nil {
		return EnrollmentIntent{}, err
	}
	defer clear(encoded)
	return DecodeEnrollmentIntent(encoded)
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

func testEnrollmentIssuer(installationID string) ([]byte, ed25519.PrivateKey, error) {
	seed := sha256.Sum256([]byte("matrix nodecommand enrollment test issuer"))
	private := ed25519.NewKeyFromSeed(seed[:])
	issuerURI, err := paasv1.NodeEnrollmentIssuerURI(installationID)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Matrix node enrollment test issuer"},
		NotBefore:             time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		URIs:     []*url.URL{issuerURI},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		return nil, nil, err
	}
	return certificate, private, nil
}

func testEnrollmentExchangeResponse(
	join paasv1.NodeEnrollmentJoin,
	request paasv1.ExchangeNodeEnrollmentRequest,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	if paasv1.ValidateExchangeNodeEnrollmentRequest(request) != nil || request.EnrollmentID != join.EnrollmentID ||
		request.InstallationID != join.InstallationID || request.ExecutionTargetID != join.ExecutionTargetID {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrEnrollmentRejected
	}
	issuerDER, err := base64.RawURLEncoding.Strict().DecodeString(join.IssuerCertificate)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	_, issuerPrivate, err := testEnrollmentIssuer(request.InstallationID)
	public, ok := issuer.PublicKey.(ed25519.PublicKey)
	if err != nil || !ok || !bytes.Equal(public, issuerPrivate.Public().(ed25519.PublicKey)) {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrEnrollmentRejected
	}
	nodePKIX, collectorPKIX, err := paasv1.NodeEnrollmentExchangePublicKeys(request)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	nodePublic, err := x509.ParsePKIXPublicKey(nodePKIX)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	collectorPublic, err := x509.ParsePKIXPublicKey(collectorPKIX)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	notBefore := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second)
	notAfter := notBefore.Add(24 * time.Hour)
	roleCertificate := func(role string, public any, address net.IP, usages []x509.ExtKeyUsage, serial int64) (string, error) {
		identity := &url.URL{Scheme: "spiffe", Host: "matrix.xiak.com",
			Path: "/installations/" + request.InstallationID + "/" + role + "/" + string(request.ExecutionTargetID)}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: notBefore, NotAfter: notAfter,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: usages, URIs: []*url.URL{identity}, IPAddresses: []net.IP{address},
		}
		certificate, err := x509.CreateCertificate(rand.Reader, template, issuer, public, issuerPrivate)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(certificate), nil
	}
	nodeCertificate, err := roleCertificate("nodes", nodePublic, net.ParseIP("192.168.50.10"),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, 2)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	collectorCertificate, err := roleCertificate("collectors", collectorPublic, net.ParseIP("127.0.0.1"),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 3)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	response := paasv1.NodeEnrollmentExchangeResponse{
		APIVersion: paasv1.NodeEnrollmentExchangeAPIVersion, Kind: paasv1.NodeEnrollmentExchangeResponseKind,
		EnrollmentID: request.EnrollmentID, InstallationID: request.InstallationID,
		ExecutionTargetID: request.ExecutionTargetID, ExchangeID: request.ExchangeID,
		MachineFingerprint: request.MachineFingerprint, RuntimeContractDigest: request.RuntimeContractDigest,
		ControllerID: "controller-a", BindingRef: "node-binding-" + strings.Repeat("a", 32),
		NodeListenAddress: "192.168.50.10:16443", CollectorEndpoint: "https://127.0.0.1:19100",
		NodeCertificate: nodeCertificate, CollectorCertificate: collectorCertificate,
		IssuerCertificate:    join.IssuerCertificate,
		CertificateNotBefore: notBefore, CertificateNotAfter: notAfter,
	}
	return response, nil
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
			ControllerID: "controller-a", BindingRef: "node-binding-" + strings.Repeat("a", 32), ExpectedFingerprint: "sha256:" + strings.Repeat("a", 64),
			ListenAddress: "192.168.50.10:16443", CollectorEndpoint: "https://127.0.0.1:19100", StoragePath: filepath.Join(root, "runtime", "executor"),
			CertificateFile: filepath.Join(base, files[0]), PrivateKeyFile: filepath.Join(base, files[1]), TrustFile: filepath.Join(base, files[2]),
			SystemReserve: nodeconfig.SelfEnrollmentSystemReserve()},
		CollectorCertificateFile: filepath.Join(base, files[3]), CollectorPrivateKeyFile: filepath.Join(base, files[4])}
	path := filepath.Join(base, "enrollment.json")
	writeInput(t, path, input)
	credential := []byte("0123456789abcdef0123456789abcdef")
	credentialDigest := sha256.Sum256(credential)
	issuer, issuerPrivate, err := testEnrollmentIssuer(input.Node.Identity.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentID := paasv1.ResourceID("node-enrollment-" + strings.Repeat("a", 32))
	join := paasv1.NodeEnrollmentJoin{
		APIVersion: paasv1.NodeEnrollmentJoinAPIVersion, Kind: paasv1.NodeEnrollmentJoinKind,
		EnrollmentID: enrollmentID, InstallationID: input.Node.Identity.InstallationID,
		ExecutionTargetID:  paasv1.ResourceID(input.Node.Identity.ExecutionTargetID),
		ControlPlaneURL:    "https://matrix.internal/api/paas/v1/node-enrollments/" + string(enrollmentID) + "/exchange",
		CredentialDigest:   "sha256:" + hex.EncodeToString(credentialDigest[:]),
		ExpiresAt:          time.Now().UTC().Add(15 * time.Minute).Truncate(time.Microsecond),
		IssuerCertificate:  base64.RawURLEncoding.EncodeToString(issuer),
		SignatureAlgorithm: paasv1.NodeJoinSignatureEd25519,
	}
	commitment, err := paasv1.NodeEnrollmentJoinSigningBytes(join)
	if err != nil {
		t.Fatal(err)
	}
	join.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerPrivate, commitment))
	joinInput := nodeconfig.JoinFile{
		APIVersion: nodeconfig.APIVersion, Kind: nodeconfig.JoinFileKind,
		Join: join, Credential: base64.RawURLEncoding.EncodeToString(credential),
	}
	joinBytes, err := json.Marshal(joinInput)
	if err != nil {
		t.Fatal(err)
	}
	joinPath := filepath.Join(base, "join.json")
	if err := os.WriteFile(joinPath, joinBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return cli.Request{Action: lifecycle.ActionInstall, Subject: cli.SubjectNode, Root: root,
		Bundle: fixture.Root, TrustKey: fixture.TrustPath, Join: joinPath}, input
}

func rotationInput(request cli.Request) string {
	return filepath.Join(filepath.Dir(request.Join), "enrollment.json")
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
