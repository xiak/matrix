package runnerexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/runnerjournalfile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/data/runnerworkspacefile"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
)

func TestRunnerExecutesTwoStepsPublishesLogsAndAcknowledges(t *testing.T) {
	harness := newRunnerHarness(t, '1')
	result, err := harness.service.WorkOnce(context.Background())
	if err != nil || !result.Claimed || !result.Acknowledged || result.Deferred ||
		result.ExecutionID != harness.assignment.ExecutionID ||
		harness.sandbox.preflightCount() != 1 {
		t.Fatalf("result = %#v / %v", result, err)
	}
	entry, err := harness.journal.Load(context.Background(), harness.assignment.ExecutionID)
	if err != nil || entry.Phase != port.RunnerJournalAcknowledged ||
		entry.Steps[0].Phase != port.RunnerStepPassed ||
		entry.Steps[1].Phase != port.RunnerStepPassed ||
		entry.LogProgress.LastSequence != 2 {
		t.Fatalf("final entry = %#v / %v", entry, err)
	}
	if len(harness.gateway.completions) != 1 ||
		harness.gateway.completions[0].Conclusion != devopsbuildv1.ConclusionPassed {
		t.Fatalf("completions = %#v", harness.gateway.completions)
	}
	if got := harness.sandbox.callSnapshot(); !equalStrings(got, []string{
		"observe:1", "create:1", "start:1", "observe:1", "follow:1", "delete:1",
		"observe:2", "create:2", "start:2", "observe:2", "follow:2", "delete:2",
	}) {
		t.Fatalf("sandbox calls = %#v", got)
	}
	if chunks := harness.logs.snapshot(); len(chunks) != 2 ||
		chunks[0].Sequence != 1 || chunks[1].Sequence != 2 {
		t.Fatalf("published chunks = %#v", chunks)
	}
}

func TestRunnerPreflightFailsClosedBeforeClaim(t *testing.T) {
	harness := newRunnerHarness(t, '2')
	harness.sandbox.preflightErr = errors.New("unsafe runner host")

	result, err := harness.service.WorkOnce(context.Background())
	if result != (Result{}) || !errors.Is(err, ErrUnavailable) ||
		harness.sandbox.preflightCount() != 1 || len(harness.gateway.queue) != 1 ||
		len(harness.sandbox.callSnapshot()) != 0 || len(harness.gateway.completions) != 0 {
		t.Fatalf(
			"preflight result=%#v err=%v checks=%d queue=%d calls=%#v completions=%#v",
			result, err, harness.sandbox.preflightCount(), len(harness.gateway.queue),
			harness.sandbox.callSnapshot(), harness.gateway.completions,
		)
	}
}

func TestRunnerRecoveryObservesBeforeCreatingStartedStep(t *testing.T) {
	harness := newRunnerHarness(t, '2')
	received := commitRunnerAssignment(
		t, harness.journal, harness.assignment, harness.archive,
	)
	started, err := harness.journal.MarkEffectStarted(
		context.Background(), received.Assignment, harness.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := harness.now.Add(time.Second)
	if _, err := harness.journal.MarkStepStarted(
		context.Background(), started.Assignment,
		harness.request.Steps[0], startedAt,
	); err != nil {
		t.Fatal(err)
	}
	recoveryNow := harness.assignment.LeaseExpiresAt.Add(time.Microsecond)
	recovery := harness.assignment
	recovery.Mode = devopsbuildv1.AssignmentObserve
	recovery.FencingToken++
	recovery.LeaseExpiresAt = recoveryNow.Add(30 * time.Second)
	harness.gateway.queue = []gatewayAssignment{{assignment: recovery}}
	harness.service.now = func() time.Time { return recoveryNow }

	result, err := harness.service.WorkOnce(context.Background())
	if err != nil || !result.Acknowledged {
		t.Fatalf("recovery result = %#v / %v", result, err)
	}
	calls := harness.sandbox.callSnapshot()
	if len(calls) < 3 || calls[0] != "observe:1" || calls[1] != "create:1" ||
		calls[2] != "start:1" {
		t.Fatalf("recovery calls = %#v", calls)
	}
	entry, err := harness.journal.Load(context.Background(), recovery.ExecutionID)
	if err != nil || entry.Steps[0].StartedAt != startedAt ||
		entry.Assignment.FencingToken != recovery.FencingToken {
		t.Fatalf("recovered entry = %#v / %v", entry, err)
	}
}

func TestRunnerRenewalCancellationKillsRunningStep(t *testing.T) {
	harness := newRunnerHarness(t, '3')
	harness.gateway.cancelOnRenewal = true
	harness.gateway.cancellationReady = harness.sandbox.following
	harness.sandbox.blockUntilCancel = true
	harness.service.renewalInterval = time.Millisecond
	harness.service.cancelGrace = time.Second

	result, err := harness.service.WorkOnce(context.Background())
	if err != nil || !result.Acknowledged {
		t.Fatalf("cancelled result = %#v / %v", result, err)
	}
	entry, err := harness.journal.Load(context.Background(), harness.assignment.ExecutionID)
	if err != nil || entry.Steps[0].Phase != port.RunnerStepCancelled ||
		entry.Steps[1].Phase != port.RunnerStepPending ||
		entry.Phase != port.RunnerJournalAcknowledged {
		t.Fatalf("cancelled entry = %#v / %v", entry, err)
	}
	if harness.gateway.renewalCount() == 0 || harness.sandbox.cancelCount() != 1 ||
		len(harness.gateway.completions) != 1 ||
		harness.gateway.completions[0].Conclusion != devopsbuildv1.ConclusionCancelled {
		t.Fatalf(
			"renewals=%d cancels=%d completions=%#v",
			harness.gateway.renewalCount(), harness.sandbox.cancelCount(),
			harness.gateway.completions,
		)
	}
}

func TestRunnerRenewsLeaseBeforeStartingSandbox(t *testing.T) {
	harness := newRunnerHarness(t, 'a')
	harness.gateway.renewFailure = errors.New("renewal unavailable")
	harness.service.renewalInterval = time.Hour

	result, err := harness.service.WorkOnce(context.Background())
	if !result.Claimed || result.Acknowledged || !errors.Is(err, ErrOutcomeUnknown) ||
		harness.gateway.renewalCount() != 1 || len(harness.sandbox.callSnapshot()) != 0 ||
		len(harness.gateway.completions) != 0 {
		t.Fatalf(
			"initial-renewal result=%#v err=%v renewals=%d calls=%#v completions=%#v",
			result, err, harness.gateway.renewalCount(), harness.sandbox.callSnapshot(),
			harness.gateway.completions,
		)
	}
	entry, loadErr := harness.journal.Load(
		context.Background(), harness.assignment.ExecutionID,
	)
	if loadErr != nil || entry.Phase != port.RunnerJournalEffectStarted ||
		entry.Steps[0].Phase != port.RunnerStepPending || entry.Receipt != nil {
		t.Fatalf("initial-renewal entry=%#v error=%v", entry, loadErr)
	}
}

func TestRunnerDoesNotConcludeWhenLogPublicationFails(t *testing.T) {
	harness := newRunnerHarness(t, '4')
	harness.logs.fail = true
	result, err := harness.service.WorkOnce(context.Background())
	if !result.Claimed || result.Acknowledged || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("result = %#v / %v", result, err)
	}
	entry, loadErr := harness.journal.Load(
		context.Background(), harness.assignment.ExecutionID,
	)
	if loadErr != nil || entry.Phase != port.RunnerJournalEffectStarted ||
		entry.Steps[0].Phase != port.RunnerStepStarted ||
		entry.LogProgress != (runnerlog.Progress{}) {
		t.Fatalf("entry after log failure = %#v / %v", entry, loadErr)
	}
	if len(harness.gateway.completions) != 0 || containsString(
		harness.sandbox.callSnapshot(), "delete:1",
	) {
		t.Fatalf(
			"completion=%#v calls=%#v",
			harness.gateway.completions, harness.sandbox.callSnapshot(),
		)
	}
}

func TestRunnerStepDeadlineFailsRatherThanInventingUserCancellation(t *testing.T) {
	harness := newRunnerHarness(t, '5')
	received := commitRunnerAssignment(
		t, harness.journal, harness.assignment, harness.archive,
	)
	started, err := harness.journal.MarkEffectStarted(
		context.Background(), received.Assignment, harness.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	stepStartedAt := harness.request.StartedAt.Add(time.Second)
	if _, err := harness.journal.MarkStepStarted(
		context.Background(), started.Assignment,
		harness.request.Steps[0], stepStartedAt,
	); err != nil {
		t.Fatal(err)
	}
	harness.sandbox.setState(1, port.RunnerSandboxRunning)
	recoveryNow := stepStartedAt.Add(
		time.Duration(devopsv1.FixedStepTimeoutSeconds)*time.Second + time.Microsecond,
	)
	recovery := harness.assignment
	recovery.Mode = devopsbuildv1.AssignmentObserve
	recovery.FencingToken++
	recovery.LeaseExpiresAt = recoveryNow.Add(30 * time.Second)
	harness.gateway.queue = []gatewayAssignment{{assignment: recovery}}
	harness.service.now = func() time.Time { return recoveryNow }

	result, err := harness.service.WorkOnce(context.Background())
	if err != nil || !result.Acknowledged {
		t.Fatalf("deadline result = %#v / %v", result, err)
	}
	if len(harness.gateway.completions) != 1 ||
		harness.gateway.completions[0].Conclusion != devopsbuildv1.ConclusionFailed ||
		harness.gateway.completions[0].Steps[0].Conclusion !=
			devopsbuildv1.StepConclusionFailed {
		t.Fatalf("deadline receipt = %#v", harness.gateway.completions)
	}
}

func TestRunnerDefersObserveRecoveryBeforeAnyEffect(t *testing.T) {
	harness := newRunnerHarness(t, '6')
	commitRunnerAssignment(t, harness.journal, harness.assignment, harness.archive)
	recoveryNow := harness.assignment.LeaseExpiresAt.Add(time.Microsecond)
	recovery := harness.assignment
	recovery.Mode = devopsbuildv1.AssignmentObserve
	recovery.FencingToken++
	recovery.LeaseExpiresAt = recoveryNow.Add(30 * time.Second)
	harness.gateway.queue = []gatewayAssignment{{assignment: recovery}}
	harness.service.now = func() time.Time { return recoveryNow }

	result, err := harness.service.WorkOnce(context.Background())
	if err != nil || !result.Claimed || !result.Deferred || result.Acknowledged ||
		len(harness.sandbox.callSnapshot()) != 0 || len(harness.gateway.completions) != 0 {
		t.Fatalf(
			"deferred result=%#v err=%v calls=%#v completions=%#v",
			result, err, harness.sandbox.callSnapshot(), harness.gateway.completions,
		)
	}
}

func TestRunnerCancellationBeforeEffectTouchesNoSandbox(t *testing.T) {
	harness := newRunnerHarness(t, '7')
	commitRunnerAssignment(t, harness.journal, harness.assignment, harness.archive)
	recoveryNow := harness.assignment.LeaseExpiresAt.Add(time.Microsecond)
	recovery := harness.assignment
	recovery.Mode = devopsbuildv1.AssignmentCancel
	recovery.FencingToken++
	recovery.LeaseExpiresAt = recoveryNow.Add(30 * time.Second)
	harness.gateway.queue = []gatewayAssignment{{assignment: recovery}}
	harness.service.now = func() time.Time { return recoveryNow }

	result, err := harness.service.WorkOnce(context.Background())
	if err != nil || !result.Acknowledged || len(harness.sandbox.callSnapshot()) != 0 ||
		len(harness.logs.snapshot()) != 0 || len(harness.gateway.completions) != 1 ||
		harness.gateway.completions[0].Conclusion != devopsbuildv1.ConclusionCancelled {
		t.Fatalf(
			"cancel-before-effect result=%#v err=%v calls=%#v logs=%#v completions=%#v",
			result, err, harness.sandbox.callSnapshot(), harness.logs.snapshot(),
			harness.gateway.completions,
		)
	}
}

func TestRunnerReplaysLocalTerminalBeforeClaiming(t *testing.T) {
	harness := newRunnerHarness(t, '8')
	received := commitRunnerAssignment(
		t, harness.journal, harness.assignment, harness.archive,
	)
	started, err := harness.journal.MarkEffectStarted(
		context.Background(), received.Assignment, harness.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	started, err = harness.journal.MarkStepStarted(
		context.Background(), started.Assignment,
		harness.request.Steps[0], harness.now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := harness.journal.RecordStepConclusion(
		context.Background(), started.Assignment, harness.request.Steps[0],
		devopsbuildv1.StepConclusionFailed, runnerlog.Progress{},
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := receiptFor(failed, harness.gateway.RunnerID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.journal.RecordReceipt(
		context.Background(), failed.Assignment, receipt,
	); err != nil {
		t.Fatal(err)
	}
	harness.gateway.queue = nil

	result, err := harness.service.WorkOnce(context.Background())
	if err != nil || result.Claimed || len(harness.gateway.completions) != 1 {
		t.Fatalf("terminal replay result=%#v error=%v", result, err)
	}
	entry, err := harness.journal.Load(context.Background(), harness.assignment.ExecutionID)
	if err != nil || entry.Phase != port.RunnerJournalAcknowledged {
		t.Fatalf("replayed entry=%#v error=%v", entry, err)
	}
}

func TestRunnerLeaseLossContainsEffectWithoutInventingConclusion(t *testing.T) {
	harness := newRunnerHarness(t, '9')
	harness.gateway.renewFailure = errors.New("renewal unavailable")
	harness.gateway.failureReady = harness.sandbox.following
	harness.sandbox.blockUntilCancel = true
	harness.service.renewalInterval = time.Millisecond
	harness.service.cancelGrace = time.Second

	result, err := harness.service.WorkOnce(context.Background())
	if !result.Claimed || result.Acknowledged || !errors.Is(err, ErrOutcomeUnknown) ||
		harness.sandbox.cancelCount() == 0 || len(harness.gateway.completions) != 0 {
		t.Fatalf(
			"lease-loss result=%#v err=%v cancels=%d completions=%#v",
			result, err, harness.sandbox.cancelCount(), harness.gateway.completions,
		)
	}
	entry, loadErr := harness.journal.Load(
		context.Background(), harness.assignment.ExecutionID,
	)
	if loadErr != nil || entry.Phase != port.RunnerJournalEffectStarted ||
		entry.Steps[0].Phase != port.RunnerStepStarted || entry.Receipt != nil {
		t.Fatalf("lease-loss entry=%#v error=%v", entry, loadErr)
	}
}

type runnerHarness struct {
	now        time.Time
	request    devopsbuildv1.Request
	assignment devopsbuildv1.Assignment
	archive    []byte
	gateway    *fakeRunnerGateway
	journal    *runnerjournalfile.Journal
	sandbox    *fakeRunnerSandbox
	logs       *fakeRunnerLogs
	service    *Service
}

func newRunnerHarness(t *testing.T, identity byte) *runnerHarness {
	t.Helper()
	runnerID := "runner-" + strings.Repeat("a", sha256.Size*2)
	startedAt := time.Date(2026, 9, 8, 12, 0, int(identity-'0'), 0, time.UTC)
	now := startedAt.Add(2 * time.Second)
	request, archive := runnerRequestFixture(t, identity, startedAt)
	executionID, err := devopsbuildv1.ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	assignment := devopsbuildv1.Assignment{
		APIVersion: devopsbuildv1.APIVersion, Kind: devopsbuildv1.AssignmentKind,
		Mode: devopsbuildv1.AssignmentExecute, ExecutionID: executionID,
		FencingToken: 1, LeaseExpiresAt: now.Add(30 * time.Second), Request: request,
	}
	if err := devopsbuildv1.ValidateAssignment(assignment); err != nil {
		t.Fatal(err)
	}
	journalRoot := privateRunnerRoot(t)
	journal, err := runnerjournalfile.New(journalRoot, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	workspaceRoot := privateRunnerRoot(t)
	workspaces, err := runnerworkspacefile.New(workspaceRoot, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := workspaces.Close(); err != nil {
			t.Errorf("close workspace: %v", err)
		}
	})
	gateway := &fakeRunnerGateway{
		runnerID: runnerID,
		queue:    []gatewayAssignment{{assignment: assignment, archive: archive}},
	}
	sandbox := newFakeRunnerSandbox()
	logs := &fakeRunnerLogs{}
	service, err := NewService(gateway, journal, workspaces, sandbox, logs)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	return &runnerHarness{
		now: now, request: request, assignment: assignment, archive: archive,
		gateway: gateway, journal: journal, sandbox: sandbox, logs: logs,
		service: service,
	}
}

type gatewayAssignment struct {
	assignment devopsbuildv1.Assignment
	archive    []byte
}

type fakeRunnerGateway struct {
	mutex             sync.Mutex
	runnerID          string
	queue             []gatewayAssignment
	renewals          int
	cancelOnRenewal   bool
	cancellationReady <-chan struct{}
	renewFailure      error
	failureReady      <-chan struct{}
	completions       []devopsbuildv1.Receipt
}

func (gateway *fakeRunnerGateway) RunnerID() string { return gateway.runnerID }

func (gateway *fakeRunnerGateway) Claim(
	_ context.Context,
	destination devopsbuildv1.AssignmentDestination,
) (devopsbuildv1.Assignment, bool, error) {
	gateway.mutex.Lock()
	defer gateway.mutex.Unlock()
	if len(gateway.queue) == 0 {
		return devopsbuildv1.Assignment{}, false, nil
	}
	next := gateway.queue[0]
	gateway.queue = gateway.queue[1:]
	var frame bytes.Buffer
	var archive io.Reader
	if next.assignment.Mode == devopsbuildv1.AssignmentExecute {
		archive = bytes.NewReader(next.archive)
	}
	if err := devopsbuildv1.WriteAssignment(&frame, next.assignment, archive); err != nil {
		return devopsbuildv1.Assignment{}, false, err
	}
	decoded, err := devopsbuildv1.ReadAssignment(&frame, destination)
	return decoded, err == nil, err
}

func (gateway *fakeRunnerGateway) Renew(
	_ context.Context,
	assignment devopsbuildv1.Assignment,
) (devopsbuildv1.Renewal, error) {
	gateway.mutex.Lock()
	defer gateway.mutex.Unlock()
	gateway.renewals++
	if gateway.renewFailure != nil {
		ready := gateway.failureReady == nil
		if !ready {
			select {
			case <-gateway.failureReady:
				ready = true
			default:
			}
		}
		if ready {
			return devopsbuildv1.Renewal{}, gateway.renewFailure
		}
	}
	expiresAt := assignment.LeaseExpiresAt.Add(30 * time.Second)
	if expiresAt.After(assignment.Request.DeadlineAt) {
		expiresAt = assignment.Request.DeadlineAt
	}
	cancellationRequested := false
	if gateway.cancelOnRenewal {
		if gateway.cancellationReady == nil {
			cancellationRequested = true
		} else {
			select {
			case <-gateway.cancellationReady:
				cancellationRequested = true
			default:
			}
		}
	}
	return devopsbuildv1.Renewal{
		APIVersion: devopsbuildv1.APIVersion, Kind: devopsbuildv1.RenewalKind,
		ExecutionID: assignment.ExecutionID, FencingToken: assignment.FencingToken,
		LeaseExpiresAt: expiresAt, CancellationRequested: cancellationRequested,
	}, nil
}

func (gateway *fakeRunnerGateway) Complete(
	_ context.Context,
	_ devopsbuildv1.Assignment,
	receipt devopsbuildv1.Receipt,
) error {
	gateway.mutex.Lock()
	defer gateway.mutex.Unlock()
	gateway.completions = append(gateway.completions, receipt)
	return nil
}

func (gateway *fakeRunnerGateway) renewalCount() int {
	gateway.mutex.Lock()
	defer gateway.mutex.Unlock()
	return gateway.renewals
}

type fakeRunnerSandbox struct {
	mutex            sync.Mutex
	states           map[uint32]port.RunnerSandboxState
	calls            []string
	preflights       int
	preflightErr     error
	blockUntilCancel bool
	cancelled        chan struct{}
	following        chan struct{}
	cancelOnce       sync.Once
	followOnce       sync.Once
	cancels          int
}

func (sandbox *fakeRunnerSandbox) Preflight(_ context.Context) error {
	sandbox.mutex.Lock()
	defer sandbox.mutex.Unlock()
	sandbox.preflights++
	return sandbox.preflightErr
}

func newFakeRunnerSandbox() *fakeRunnerSandbox {
	return &fakeRunnerSandbox{
		states:    make(map[uint32]port.RunnerSandboxState),
		cancelled: make(chan struct{}), following: make(chan struct{}),
	}
}

func (sandbox *fakeRunnerSandbox) Create(
	_ context.Context,
	reference port.RunnerStepReference,
) error {
	sandbox.mutex.Lock()
	defer sandbox.mutex.Unlock()
	sandbox.call("create", reference.Step.Ordinal)
	if sandbox.states[reference.Step.Ordinal] != port.RunnerSandboxAbsent &&
		sandbox.states[reference.Step.Ordinal] != "" {
		return errors.New("already exists")
	}
	sandbox.states[reference.Step.Ordinal] = port.RunnerSandboxCreated
	return nil
}

func (sandbox *fakeRunnerSandbox) Start(
	_ context.Context,
	reference port.RunnerStepReference,
) error {
	sandbox.mutex.Lock()
	defer sandbox.mutex.Unlock()
	sandbox.call("start", reference.Step.Ordinal)
	if sandbox.states[reference.Step.Ordinal] != port.RunnerSandboxCreated {
		return errors.New("not created")
	}
	sandbox.states[reference.Step.Ordinal] = port.RunnerSandboxRunning
	return nil
}

func (sandbox *fakeRunnerSandbox) Observe(
	_ context.Context,
	reference port.RunnerStepReference,
) (port.RunnerSandboxState, error) {
	sandbox.mutex.Lock()
	defer sandbox.mutex.Unlock()
	sandbox.call("observe", reference.Step.Ordinal)
	state := sandbox.states[reference.Step.Ordinal]
	if state == "" {
		state = port.RunnerSandboxAbsent
	}
	return state, nil
}

func (sandbox *fakeRunnerSandbox) Follow(
	ctx context.Context,
	reference port.RunnerStepReference,
	progress runnerlog.Progress,
) (port.RunnerSandboxResult, error) {
	sandbox.mutex.Lock()
	sandbox.call("follow", reference.Step.Ordinal)
	block := sandbox.blockUntilCancel
	sandbox.followOnce.Do(func() { close(sandbox.following) })
	sandbox.mutex.Unlock()
	if block {
		select {
		case <-sandbox.cancelled:
		case <-ctx.Done():
			return port.RunnerSandboxResult{}, ctx.Err()
		}
	}
	sandbox.mutex.Lock()
	state := sandbox.states[reference.Step.Ordinal]
	if state == port.RunnerSandboxRunning {
		state = port.RunnerSandboxPassed
		sandbox.states[reference.Step.Ordinal] = state
	}
	sandbox.mutex.Unlock()
	if state != port.RunnerSandboxPassed && state != port.RunnerSandboxFailed {
		return port.RunnerSandboxResult{}, errors.New("not terminal")
	}
	content := fmt.Sprintf("[stdout] step-%d\n", reference.Step.Ordinal)
	next := runnerlog.Progress{
		NativeBytes:     progress.NativeBytes + 3,
		NormalizedBytes: progress.NormalizedBytes + int64(len(content)),
		LastSequence:    progress.LastSequence + 1,
	}
	return port.RunnerSandboxResult{
		State:       state,
		Chunks:      []runnerlog.Chunk{{Sequence: next.LastSequence, Content: content}},
		LogProgress: next,
	}, nil
}

func (sandbox *fakeRunnerSandbox) Cancel(
	_ context.Context,
	reference port.RunnerStepReference,
) (port.RunnerSandboxState, error) {
	sandbox.mutex.Lock()
	defer sandbox.mutex.Unlock()
	sandbox.call("cancel", reference.Step.Ordinal)
	sandbox.cancels++
	state := sandbox.states[reference.Step.Ordinal]
	switch state {
	case "", port.RunnerSandboxAbsent:
		return port.RunnerSandboxAbsent, nil
	case port.RunnerSandboxCreated:
		sandbox.states[reference.Step.Ordinal] = port.RunnerSandboxAbsent
		return port.RunnerSandboxCancelled, nil
	case port.RunnerSandboxRunning:
		sandbox.states[reference.Step.Ordinal] = port.RunnerSandboxFailed
		sandbox.cancelOnce.Do(func() { close(sandbox.cancelled) })
		return port.RunnerSandboxCancelled, nil
	case port.RunnerSandboxPassed, port.RunnerSandboxFailed:
		return state, nil
	default:
		return "", errors.New("invalid state")
	}
}

func (sandbox *fakeRunnerSandbox) Delete(
	_ context.Context,
	reference port.RunnerStepReference,
) error {
	sandbox.mutex.Lock()
	defer sandbox.mutex.Unlock()
	sandbox.call("delete", reference.Step.Ordinal)
	if sandbox.states[reference.Step.Ordinal] == port.RunnerSandboxRunning {
		return errors.New("still running")
	}
	sandbox.states[reference.Step.Ordinal] = port.RunnerSandboxAbsent
	return nil
}

func (sandbox *fakeRunnerSandbox) call(action string, ordinal uint32) {
	sandbox.calls = append(sandbox.calls, fmt.Sprintf("%s:%d", action, ordinal))
}

func (sandbox *fakeRunnerSandbox) callSnapshot() []string {
	sandbox.mutex.Lock()
	defer sandbox.mutex.Unlock()
	return append([]string(nil), sandbox.calls...)
}

func (sandbox *fakeRunnerSandbox) preflightCount() int {
	sandbox.mutex.Lock()
	defer sandbox.mutex.Unlock()
	return sandbox.preflights
}

func (sandbox *fakeRunnerSandbox) setState(
	ordinal uint32,
	state port.RunnerSandboxState,
) {
	sandbox.mutex.Lock()
	defer sandbox.mutex.Unlock()
	sandbox.states[ordinal] = state
}

func (sandbox *fakeRunnerSandbox) cancelCount() int {
	sandbox.mutex.Lock()
	defer sandbox.mutex.Unlock()
	return sandbox.cancels
}

type fakeRunnerLogs struct {
	mutex  sync.Mutex
	chunks []runnerlog.Chunk
	fail   bool
}

func (logs *fakeRunnerLogs) Publish(
	_ context.Context,
	_ devopsbuildv1.Assignment,
	_ devopsv1.VerificationStep,
	_ runnerlog.Progress,
	_ runnerlog.Progress,
	chunks []runnerlog.Chunk,
) error {
	logs.mutex.Lock()
	defer logs.mutex.Unlock()
	if logs.fail {
		return errors.New("log sink unavailable")
	}
	logs.chunks = append(logs.chunks, chunks...)
	return nil
}

func (logs *fakeRunnerLogs) snapshot() []runnerlog.Chunk {
	logs.mutex.Lock()
	defer logs.mutex.Unlock()
	return append([]runnerlog.Chunk(nil), logs.chunks...)
}

func commitRunnerAssignment(
	t *testing.T,
	journal *runnerjournalfile.Journal,
	assignment devopsbuildv1.Assignment,
	archive []byte,
) port.RunnerJournalEntry {
	t.Helper()
	claim, err := journal.BeginClaim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	var archiveReader io.Reader
	if assignment.Mode == devopsbuildv1.AssignmentExecute {
		archiveReader = bytes.NewReader(archive)
	}
	if err := devopsbuildv1.WriteAssignment(&frame, assignment, archiveReader); err != nil {
		_ = claim.Abort()
		t.Fatal(err)
	}
	decoded, err := devopsbuildv1.ReadAssignment(&frame, claim.Destination)
	if err != nil || decoded != assignment {
		_ = claim.Abort()
		t.Fatalf("decoded assignment = %#v / %v", decoded, err)
	}
	entry, err := claim.Commit(context.Background())
	if err != nil {
		_ = claim.Abort()
		t.Fatal(err)
	}
	return entry
}

func runnerRequestFixture(
	t *testing.T,
	identity byte,
	startedAt time.Time,
) (devopsbuildv1.Request, []byte) {
	t.Helper()
	fileContent := []byte("module example.invalid/project\n\ngo 1.26.0\n")
	var archive bytes.Buffer
	content, err := sourcearchive.Write(
		context.Background(), &archive, []sourcearchive.File{{
			Path: "go.mod", Size: int64(len(fileContent)),
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(fileContent)), nil
			},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	runID := devopsv1.ResourceID("pipeline-run-" + strings.Repeat(string(identity), 48))
	request := devopsbuildv1.Request{
		TenantID: "tenant-one", RunID: runID,
		CommandID:           string(runID) + ":verify:1",
		InputDigest:         "sha256:" + strings.Repeat("1", 64),
		SourceArchiveDigest: digestRunnerBytes(archive.Bytes()),
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
		t.Fatal(err)
	}
	return request, append([]byte(nil), archive.Bytes()...)
}

func privateRunnerRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func digestRunnerBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
