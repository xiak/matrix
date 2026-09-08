package runnerjournalfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

func TestJournalPersistsLifecycleAcrossRestart(t *testing.T) {
	root := journalRoot(t)
	runnerID := journalRunnerID('a')
	journal, err := New(root, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if journal.RunnerID() != runnerID {
		t.Fatalf("runner id = %q, want %q", journal.RunnerID(), runnerID)
	}
	if entries, err := journal.Entries(context.Background()); err != nil || len(entries) != 0 {
		t.Fatalf("initial entries = %#v / %v", entries, err)
	}

	request, archive := journalExecutionFixture(t, 'a', journalStart())
	assignment := journalAssignment(t, request, devopsbuildv1.AssignmentExecute, 1, 2*time.Minute)
	entry := commitJournalAssignment(t, journal, assignment, archive)
	if entry.Assignment != assignment || entry.Phase != PhaseReceived ||
		entry.EffectID == "" || entry.CancellationRequested ||
		entry.Steps != initialStepProgress(request) || entry.Receipt != nil {
		t.Fatalf("received entry = %#v", entry)
	}
	assertJournalArchive(t, journal, assignment.ExecutionID, archive)

	restarted, err := New(root, runnerID)
	if err != nil {
		t.Fatalf("restart journal: %v", err)
	}
	loaded, err := restarted.Load(context.Background(), assignment.ExecutionID)
	if err != nil || loaded.Assignment != assignment || loaded.Phase != PhaseReceived {
		t.Fatalf("restarted entry = %#v / %v", loaded, err)
	}
	started, err := restarted.MarkEffectStarted(
		context.Background(), assignment, request.StartedAt.Add(time.Second),
	)
	if err != nil || started.Phase != PhaseEffectStarted || started.EffectID != entry.EffectID {
		t.Fatalf("effect-started entry = %#v / %v", started, err)
	}
	replayed, err := restarted.MarkEffectStarted(
		context.Background(), assignment, request.StartedAt.Add(2*time.Second),
	)
	if err != nil || replayed.Phase != PhaseEffectStarted || replayed.EffectID != entry.EffectID {
		t.Fatalf("effect replay = %#v / %v", replayed, err)
	}
	started, err = restarted.MarkStepStarted(
		context.Background(), replayed.Assignment, request.Steps[0],
		request.StartedAt.Add(3*time.Second),
	)
	if err != nil || started.Steps[0].Phase != StepStarted {
		t.Fatalf("step-started entry = %#v / %v", started, err)
	}

	renewal := devopsbuildv1.Renewal{
		APIVersion:     devopsbuildv1.APIVersion,
		Kind:           devopsbuildv1.RenewalKind,
		ExecutionID:    assignment.ExecutionID,
		FencingToken:   assignment.FencingToken,
		LeaseExpiresAt: assignment.LeaseExpiresAt.Add(time.Minute),
	}
	renewed, err := restarted.ApplyRenewal(context.Background(), started.Assignment, renewal)
	if err != nil || renewed.Phase != PhaseEffectStarted ||
		!renewed.Assignment.LeaseExpiresAt.Equal(renewal.LeaseExpiresAt) {
		t.Fatalf("renewed entry = %#v / %v", renewed, err)
	}
	renewal.CancellationRequested = true
	cancelled, err := restarted.ApplyRenewal(context.Background(), renewed.Assignment, renewal)
	if err != nil || !cancelled.CancellationRequested {
		t.Fatalf("cancelled renewal = %#v / %v", cancelled, err)
	}
	cancelled, err = restarted.RecordStepConclusion(
		context.Background(), cancelled.Assignment, request.Steps[0],
		devopsbuildv1.StepConclusionCancelled,
	)
	if err != nil || cancelled.Steps[0].Phase != StepCancelled ||
		cancelled.Steps[1].Phase != StepPending {
		t.Fatalf("cancelled step = %#v / %v", cancelled, err)
	}

	receipt := journalReceipt(
		request, runnerID, devopsbuildv1.ConclusionCancelled,
		devopsbuildv1.StepConclusionCancelled, devopsbuildv1.StepConclusionNotRun,
	)
	terminal, err := restarted.RecordReceipt(context.Background(), cancelled.Assignment, receipt)
	if err != nil || terminal.Phase != PhaseTerminal || terminal.Receipt == nil ||
		*terminal.Receipt != receipt {
		t.Fatalf("terminal entry = %#v / %v", terminal, err)
	}
	replayed, err = restarted.RecordReceipt(context.Background(), cancelled.Assignment, receipt)
	if err != nil || replayed.Phase != PhaseTerminal || replayed.Receipt == nil ||
		*replayed.Receipt != receipt {
		t.Fatalf("terminal replay = %#v / %v", replayed, err)
	}
	acknowledged, err := restarted.Acknowledge(
		context.Background(), cancelled.Assignment, receipt,
	)
	if err != nil || acknowledged.Phase != PhaseAcknowledged {
		t.Fatalf("acknowledged entry = %#v / %v", acknowledged, err)
	}
	replayed, err = restarted.Acknowledge(
		context.Background(), cancelled.Assignment, receipt,
	)
	if err != nil || replayed.Phase != PhaseAcknowledged {
		t.Fatalf("acknowledgement replay = %#v / %v", replayed, err)
	}

	finalJournal, err := New(root, runnerID)
	if err != nil {
		t.Fatalf("restart acknowledged journal: %v", err)
	}
	entries, err := finalJournal.Entries(context.Background())
	if err != nil || len(entries) != 1 || entries[0].Phase != PhaseAcknowledged ||
		entries[0].Receipt == nil || *entries[0].Receipt != receipt {
		t.Fatalf("final entries = %#v / %v", entries, err)
	}
	if _, err := New(root, journalRunnerID('b')); !errors.Is(err, ErrConflict) {
		t.Fatalf("different runner identity error = %v", err)
	}
}

func TestJournalPersistsOrderedStepProgressAcrossRestart(t *testing.T) {
	root := journalRoot(t)
	runnerID := journalRunnerID('9')
	journal, err := New(root, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := journalExecutionFixture(t, '9', journalStart())
	assignment := journalAssignment(t, request, devopsbuildv1.AssignmentExecute, 1, 2*time.Minute)
	commitJournalAssignment(t, journal, assignment, archive)
	started, err := journal.MarkEffectStarted(
		context.Background(), assignment, request.StartedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkStepStarted(
		context.Background(), started.Assignment, request.Steps[1],
		request.StartedAt.Add(2*time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("second step before first error = %v", err)
	}
	started, err = journal.MarkStepStarted(
		context.Background(), started.Assignment, request.Steps[0],
		request.StartedAt.Add(2*time.Second),
	)
	if err != nil || started.Steps[0].Phase != StepStarted {
		t.Fatalf("first step started = %#v / %v", started, err)
	}
	replayed, err := journal.MarkStepStarted(
		context.Background(), started.Assignment, request.Steps[0],
		request.StartedAt.Add(2*time.Second),
	)
	if err != nil || replayed.Steps != started.Steps {
		t.Fatalf("first step replay = %#v / %v", replayed, err)
	}
	passed, err := journal.RecordStepConclusion(
		context.Background(), started.Assignment, request.Steps[0],
		devopsbuildv1.StepConclusionPassed,
	)
	if err != nil || passed.Steps[0].Phase != StepPassed ||
		passed.Steps[1].Phase != StepPending {
		t.Fatalf("first step passed = %#v / %v", passed, err)
	}

	restarted, err := New(root, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	observe := journalAssignment(
		t, request, devopsbuildv1.AssignmentObserve, 2, 3*time.Minute,
	)
	loaded := commitJournalAssignment(t, restarted, observe, nil)
	if loaded.Assignment != observe || loaded.Steps != passed.Steps {
		t.Fatalf("recovered progress = %#v", loaded)
	}
	second, err := restarted.MarkStepStarted(
		context.Background(), loaded.Assignment, request.Steps[1],
		request.StartedAt.Add(4*time.Second),
	)
	if err != nil || second.Steps[1].Phase != StepStarted {
		t.Fatalf("second step started = %#v / %v", second, err)
	}
	failed, err := restarted.RecordStepConclusion(
		context.Background(), second.Assignment, request.Steps[1],
		devopsbuildv1.StepConclusionFailed,
	)
	if err != nil || failed.Steps[1].Phase != StepFailed {
		t.Fatalf("second step failed = %#v / %v", failed, err)
	}
	if _, err := restarted.RecordStepConclusion(
		context.Background(), failed.Assignment, request.Steps[1],
		devopsbuildv1.StepConclusionPassed,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed step replay error = %v", err)
	}
	changedReceipt := journalReceipt(
		request, runnerID, devopsbuildv1.ConclusionPassed,
		devopsbuildv1.StepConclusionPassed, devopsbuildv1.StepConclusionPassed,
	)
	if _, err := restarted.RecordReceipt(
		context.Background(), failed.Assignment, changedReceipt,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("receipt contradicting step progress error = %v", err)
	}
	receipt := journalReceipt(
		request, runnerID, devopsbuildv1.ConclusionFailed,
		devopsbuildv1.StepConclusionPassed, devopsbuildv1.StepConclusionFailed,
	)
	terminal, err := restarted.RecordReceipt(context.Background(), failed.Assignment, receipt)
	if err != nil || terminal.Phase != PhaseTerminal || terminal.Receipt == nil ||
		*terminal.Receipt != receipt {
		t.Fatalf("terminal entry = %#v / %v", terminal, err)
	}
}

func TestJournalPersistsCanonicalStepStartWithoutRenewingItsClock(t *testing.T) {
	root := journalRoot(t)
	runnerID := journalRunnerID('8')
	journal, err := New(root, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := journalExecutionFixture(t, '8', journalStart())
	assignment := journalAssignment(
		t, request, devopsbuildv1.AssignmentExecute, 1, 2*time.Minute,
	)
	commitJournalAssignment(t, journal, assignment, archive)
	started, err := journal.MarkEffectStarted(
		context.Background(), assignment, request.StartedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		at   time.Time
		want error
	}{
		{name: "before request", at: request.StartedAt.Add(-time.Microsecond), want: ErrStale},
		{name: "at lease", at: assignment.LeaseExpiresAt, want: ErrStale},
		{name: "non canonical", at: request.StartedAt.Add(time.Nanosecond), want: ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := journal.MarkStepStarted(
				context.Background(), started.Assignment, request.Steps[0], test.at,
			); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}

	firstStart := request.StartedAt.Add(10 * time.Second)
	progress, err := journal.MarkStepStarted(
		context.Background(), started.Assignment, request.Steps[0], firstStart,
	)
	if err != nil || progress.Steps[0].StartedAt != firstStart {
		t.Fatalf("progress = %#v / %v", progress, err)
	}
	replayed, err := journal.MarkStepStarted(
		context.Background(), progress.Assignment, request.Steps[0], firstStart.Add(time.Second),
	)
	if err != nil || replayed.Steps != progress.Steps ||
		replayed.Steps[0].StartedAt != firstStart {
		t.Fatalf("replayed progress = %#v / %v", replayed, err)
	}
	passed, err := journal.RecordStepConclusion(
		context.Background(), replayed.Assignment, request.Steps[0],
		devopsbuildv1.StepConclusionPassed,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkStepStarted(
		context.Background(), passed.Assignment, request.Steps[1], firstStart.Add(-time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("earlier second-step start error = %v", err)
	}

	restarted, err := New(root, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.Load(context.Background(), assignment.ExecutionID)
	if err != nil || loaded.Steps[0].StartedAt != firstStart ||
		loaded.Steps[0].Phase != StepPassed {
		t.Fatalf("loaded progress = %#v / %v", loaded, err)
	}
}

func TestJournalRecoveryAdvancesFenceWithoutReplacingArchive(t *testing.T) {
	root := journalRoot(t)
	runnerID := journalRunnerID('c')
	journal, err := New(root, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := journalExecutionFixture(t, 'c', journalStart())
	execute := journalAssignment(t, request, devopsbuildv1.AssignmentExecute, 1, 2*time.Minute)
	commitJournalAssignment(t, journal, execute, archive)

	observe := journalAssignment(t, request, devopsbuildv1.AssignmentObserve, 2, 3*time.Minute)
	observed := commitJournalAssignment(t, journal, observe, nil)
	if observed.Assignment != observe || observed.Phase != PhaseReceived ||
		observed.CancellationRequested {
		t.Fatalf("observed recovery = %#v", observed)
	}
	assertJournalArchive(t, journal, execute.ExecutionID, archive)
	if _, err := journal.MarkEffectStarted(
		context.Background(), observe, request.StartedAt.Add(time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("observe assignment started a new effect: %v", err)
	}

	claim := beginJournalClaim(t, journal, observe, nil)
	if _, err := claim.Commit(context.Background()); !errors.Is(err, ErrStale) {
		t.Fatalf("equal recovery fence error = %v", err)
	}
	if err := claim.Abort(); err != nil {
		t.Fatalf("abort stale recovery: %v", err)
	}

	changedRequest := request
	changedRequest.SourceExpandedBytes++
	changedExecutionID, err := devopsbuildv1.ExecutionID(changedRequest)
	if err != nil || changedExecutionID != execute.ExecutionID {
		t.Fatalf("changed request identity = %q / %v, want %q", changedExecutionID, err, execute.ExecutionID)
	}
	changed := journalAssignment(
		t, changedRequest, devopsbuildv1.AssignmentObserve, 3, 4*time.Minute,
	)
	claim = beginJournalClaim(t, journal, changed, nil)
	if _, err := claim.Commit(context.Background()); !errors.Is(err, ErrStale) {
		t.Fatalf("changed recovery request error = %v", err)
	}
	if err := claim.Abort(); err != nil {
		t.Fatalf("abort changed recovery: %v", err)
	}

	cancel := journalAssignment(t, request, devopsbuildv1.AssignmentCancel, 3, 4*time.Minute)
	cancelled := commitJournalAssignment(t, journal, cancel, nil)
	if !cancelled.CancellationRequested || cancelled.Assignment != cancel {
		t.Fatalf("cancel recovery = %#v", cancelled)
	}
	afterCancel := journalAssignment(t, request, devopsbuildv1.AssignmentObserve, 4, 5*time.Minute)
	claim = beginJournalClaim(t, journal, afterCancel, nil)
	if _, err := claim.Commit(context.Background()); !errors.Is(err, ErrStale) {
		t.Fatalf("observe after cancellation error = %v", err)
	}
	if err := claim.Abort(); err != nil {
		t.Fatalf("abort observe after cancellation: %v", err)
	}
	cancelled, err = journal.RecordStepConclusion(
		context.Background(), cancelled.Assignment, request.Steps[0],
		devopsbuildv1.StepConclusionCancelled,
	)
	if err != nil || cancelled.Phase != PhaseReceived ||
		cancelled.Steps[0].Phase != StepCancelled {
		t.Fatalf("cancel before effect = %#v / %v", cancelled, err)
	}
	cancelReceipt := journalReceipt(
		request, runnerID, devopsbuildv1.ConclusionCancelled,
		devopsbuildv1.StepConclusionCancelled, devopsbuildv1.StepConclusionNotRun,
	)
	terminal, err := journal.RecordReceipt(
		context.Background(), cancelled.Assignment, cancelReceipt,
	)
	if err != nil || terminal.Phase != PhaseTerminal {
		t.Fatalf("terminal cancellation before effect = %#v / %v", terminal, err)
	}

	missingRequest, _ := journalExecutionFixture(t, 'd', journalStart().Add(time.Second))
	missing := journalAssignment(
		t, missingRequest, devopsbuildv1.AssignmentObserve, 2, 3*time.Minute,
	)
	claim = beginJournalClaim(t, journal, missing, nil)
	if _, err := claim.Commit(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing recovery error = %v", err)
	}
	if err := claim.Abort(); err != nil {
		t.Fatalf("abort missing recovery: %v", err)
	}

	claim = beginJournalClaim(t, journal, execute, archive)
	if _, err := claim.Commit(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate execute error = %v", err)
	}
	if err := claim.Abort(); err != nil {
		t.Fatalf("abort duplicate execute: %v", err)
	}
}

func TestJournalRemovesAbandonedClaimBeforeRecovery(t *testing.T) {
	root := journalRoot(t)
	runnerID := journalRunnerID('e')
	journal, err := New(root, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	request, archive := journalExecutionFixture(t, 'e', journalStart())
	assignment := journalAssignment(t, request, devopsbuildv1.AssignmentExecute, 1, 2*time.Minute)
	claim, err := journal.BeginClaim(context.Background())
	if err != nil {
		t.Fatalf("begin abandoned claim: %v", err)
	}
	destination, err := claim.Destination(assignment)
	if err != nil || destination == nil {
		t.Fatalf("stage abandoned assignment: %v", err)
	}
	if _, err := destination.Write(archive[:len(archive)/2]); err != nil {
		t.Fatalf("write partial abandoned archive: %v", err)
	}
	if err := claim.archive.Close(); err != nil {
		t.Fatal(err)
	}
	claim.archive = nil

	restarted, err := New(root, runnerID)
	if err != nil {
		t.Fatalf("recover abandoned claim: %v", err)
	}
	entries, err := restarted.Entries(context.Background())
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries after abandoned claim = %#v / %v", entries, err)
	}
	rootEntries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range rootEntries {
		if strings.HasPrefix(entry.Name(), ".claim-") {
			t.Fatalf("abandoned claim remains: %s", entry.Name())
		}
	}
}

func beginJournalClaim(
	t *testing.T,
	journal *Journal,
	assignment devopsbuildv1.Assignment,
	archive []byte,
) *Claim {
	t.Helper()
	claim, err := journal.BeginClaim(context.Background())
	if err != nil {
		t.Fatalf("begin claim: %v", err)
	}
	var frame bytes.Buffer
	var archiveReader io.Reader
	if archive != nil {
		archiveReader = bytes.NewReader(archive)
	}
	if err := devopsbuildv1.WriteAssignment(&frame, assignment, archiveReader); err != nil {
		_ = claim.Abort()
		t.Fatalf("frame assignment: %v", err)
	}
	decoded, err := devopsbuildv1.ReadAssignment(&frame, claim.Destination)
	if err != nil || decoded != assignment {
		_ = claim.Abort()
		t.Fatalf("read assignment = %#v / %v, want %#v", decoded, err, assignment)
	}
	return claim
}

func commitJournalAssignment(
	t *testing.T,
	journal *Journal,
	assignment devopsbuildv1.Assignment,
	archive []byte,
) Entry {
	t.Helper()
	claim := beginJournalClaim(t, journal, assignment, archive)
	entry, err := claim.Commit(context.Background())
	if err != nil {
		_ = claim.Abort()
		t.Fatalf("commit assignment: %v", err)
	}
	return entry
}

func assertJournalArchive(t *testing.T, journal *Journal, executionID string, want []byte) {
	t.Helper()
	archive, err := journal.OpenArchive(context.Background(), executionID)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	content, readErr := io.ReadAll(archive)
	closeErr := archive.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(content, want) {
		t.Fatalf("archive = %x / %v / %v, want %x", content, readErr, closeErr, want)
	}
}

func journalRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func journalRunnerID(identity byte) string {
	return "runner-" + strings.Repeat(string(identity), sha256.Size*2)
}

func journalStart() time.Time {
	return time.Date(2026, 9, 8, 10, 11, 12, 123000, time.UTC)
}

func journalExecutionFixture(
	t *testing.T,
	identity byte,
	startedAt time.Time,
) (devopsbuildv1.Request, []byte) {
	t.Helper()
	fileContent := []byte("module example.invalid/project\n\ngo 1.26.0\n")
	var archive bytes.Buffer
	content, err := sourcearchive.Write(
		context.Background(),
		&archive,
		[]sourcearchive.File{{
			Path: "go.mod", Size: int64(len(fileContent)),
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(fileContent)), nil
			},
		}},
	)
	if err != nil {
		t.Fatalf("create source archive: %v", err)
	}
	runID := devopsv1.ResourceID("pipeline-run-" + strings.Repeat(string(identity), 48))
	request := devopsbuildv1.Request{
		TenantID: "tenant-one", RunID: runID,
		CommandID:           string(runID) + ":verify:1",
		InputDigest:         "sha256:" + strings.Repeat("1", 64),
		SourceArchiveDigest: journalDigest(archive.Bytes()),
		SourceArchiveBytes:  int64(archive.Len()),
		SourceExpandedBytes: content.ExpandedBytes,
		SourcePathCount:     content.PathCount,
		PipelineRevisionID: "pipeline-revision-" +
			devopsv1.ResourceID(strings.Repeat(string(identity), 48)),
		PipelineRevisionDigest: "sha256:" + strings.Repeat("2", 64),
		VerificationProfile:    devopsv1.VerificationGo126OfflineV1,
		ExecutorProfile:        devopsv1.ExecutorMatrixNativeIsolatedV1,
		ToolchainImageDigest:   devopsv1.Go126OfflineToolchainImageDigest,
		DependencyEgress:       devopsv1.DependencyEgressNone,
		Steps: [2]devopsv1.VerificationStep{
			{Ordinal: 1, Kind: devopsv1.VerificationStepGoTest},
			{Ordinal: 2, Kind: devopsv1.VerificationStepGoVet},
		},
		Limits: devopsv1.FixedVerificationLimits(), StartedAt: startedAt,
		DeadlineAt: startedAt.Add(
			time.Duration(devopsv1.FixedRunTimeoutSeconds) * time.Second,
		),
	}
	if err := devopsbuildv1.ValidateRequest(request); err != nil {
		t.Fatalf("validate execution fixture: %v", err)
	}
	return request, append([]byte(nil), archive.Bytes()...)
}

func journalAssignment(
	t *testing.T,
	request devopsbuildv1.Request,
	mode devopsbuildv1.AssignmentMode,
	fence uint64,
	leaseAfterStart time.Duration,
) devopsbuildv1.Assignment {
	t.Helper()
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		t.Fatalf("execution identity: %v", err)
	}
	assignment := devopsbuildv1.Assignment{
		APIVersion: devopsbuildv1.APIVersion, Kind: devopsbuildv1.AssignmentKind,
		Mode: mode, ExecutionID: executionID, FencingToken: fence,
		LeaseExpiresAt: request.StartedAt.Add(leaseAfterStart), Request: request,
	}
	if err := devopsbuildv1.ValidateAssignment(assignment); err != nil {
		t.Fatalf("validate assignment: %v", err)
	}
	return assignment
}

func journalReceipt(
	request devopsbuildv1.Request,
	runnerID string,
	conclusion devopsbuildv1.Conclusion,
	first devopsbuildv1.StepConclusion,
	second devopsbuildv1.StepConclusion,
) devopsbuildv1.Receipt {
	receipt := devopsbuildv1.Receipt{
		TenantID: request.TenantID, RunID: request.RunID, CommandID: request.CommandID,
		InputDigest: request.InputDigest, SourceArchiveDigest: request.SourceArchiveDigest,
		PipelineRevisionID:     request.PipelineRevisionID,
		PipelineRevisionDigest: request.PipelineRevisionDigest,
		ExecutorID:             runnerID, ExecutorProfile: request.ExecutorProfile,
		ToolchainImageDigest: request.ToolchainImageDigest, Conclusion: conclusion,
		Steps: [2]devopsbuildv1.StepReceipt{
			{Ordinal: request.Steps[0].Ordinal, Kind: request.Steps[0].Kind, Conclusion: first},
			{Ordinal: request.Steps[1].Ordinal, Kind: request.Steps[1].Kind, Conclusion: second},
		},
	}
	receipt.ContentDigest = devopsbuildv1.DigestReceipt(receipt)
	return receipt
}

func journalDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func journalExecutionPath(root, executionID string) string {
	return filepath.Join(root, strings.TrimPrefix(executionID, "sha256:"))
}
