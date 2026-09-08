package buildexecution

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	devopsbuildv1 "github.com/xiak/matrix/api/adapter/devopsbuild/v1"
	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/domain"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/port"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
)

func TestBuildWorkerExecutesClosedCommandAndHandsPassedOrFailedReceiptToReporter(t *testing.T) {
	for _, conclusion := range []devopsbuildv1.Conclusion{
		devopsbuildv1.ConclusionPassed,
		devopsbuildv1.ConclusionFailed,
	} {
		t.Run(string(conclusion), func(t *testing.T) {
			command := buildCommand(t, runlifecycle.ClaimExecute)
			repository := newBuildRepository(command)
			archives := &fakeArchiveReader{content: []byte("source archive")}
			executor := &fakeBuildExecutor{conclusion: conclusion}
			service := buildService(t, repository, archives, executor)

			result, err := service.BuildOnce(context.Background())
			if err != nil || !result.Claimed || result.CommandID != command.Lease.Intent.CommandID ||
				result.Run.Status.State != devopsv1.PipelineRunReporting {
				t.Fatalf("build result=%#v err=%v", result, err)
			}
			if archives.openCalls != 1 || executor.executeCalls != 1 ||
				executor.observeCalls != 0 || executor.cancelCalls != 0 ||
				repository.completeCalls != 1 || repository.completion.Receipt == nil ||
				repository.completion.Receipt.Conclusion != conclusion ||
				!bytes.Equal(executor.archive, archives.content) {
				t.Fatalf(
					"build boundaries archive=%d execute=%d observe=%d cancel=%d completion=%#v",
					archives.openCalls,
					executor.executeCalls,
					executor.observeCalls,
					executor.cancelCalls,
					repository.completion,
				)
			}
			if devopsbuildv1.ValidateRequest(executor.request) != nil ||
				executor.request.SourceArchiveDigest != command.Archive.ArchiveDigest ||
				executor.request.PipelineRevisionDigest != command.Revision.ContentDigest {
				t.Fatalf("executor request=%#v", executor.request)
			}
		})
	}
}

func TestRecoveredBuildOnlyObservesTheDeterministicCommand(t *testing.T) {
	command := buildCommand(t, runlifecycle.ClaimObserve)
	repository := newBuildRepository(command)
	archives := &fakeArchiveReader{content: []byte("must not be opened")}
	executor := &fakeBuildExecutor{
		conclusion: devopsbuildv1.ConclusionPassed, observeFound: true,
	}
	service := buildService(t, repository, archives, executor)

	result, err := service.BuildOnce(context.Background())
	if err != nil || result.Run.Status.State != devopsv1.PipelineRunReporting ||
		archives.openCalls != 0 || executor.executeCalls != 0 || executor.observeCalls != 1 ||
		repository.completeCalls != 1 {
		t.Fatalf(
			"recovered result=%#v err=%v open=%d execute=%d observe=%d complete=%d",
			result,
			err,
			archives.openCalls,
			executor.executeCalls,
			executor.observeCalls,
			repository.completeCalls,
		)
	}
}

func TestCancellationDoesNotStartAndRecoveredEffectIsCancelled(t *testing.T) {
	requestedAt := time.Now().UTC().Truncate(time.Microsecond)
	for _, mode := range []runlifecycle.ClaimMode{
		runlifecycle.ClaimExecute,
		runlifecycle.ClaimObserve,
	} {
		t.Run(string(mode), func(t *testing.T) {
			command := buildCommand(t, mode)
			command.Lease.Run.Status.CancellationRequestedAt = &requestedAt
			command.Lease.Run.Status.ObservedAt = requestedAt
			command.Lease.Run.UpdatedAt = requestedAt
			if !command.StartedAt.After(requestedAt) {
				command.StartedAt = requestedAt.Add(time.Microsecond)
				command.DeadlineAt = command.StartedAt.Add(ExecutionDeadline)
				command.Lease.LeaseExpiresAt = command.StartedAt.Add(LeaseDuration)
			}
			repository := newBuildRepository(command)
			archives := &fakeArchiveReader{content: []byte("must not be opened")}
			executor := &fakeBuildExecutor{
				conclusion:  devopsbuildv1.ConclusionCancelled,
				cancelFound: mode == runlifecycle.ClaimObserve,
			}
			service := buildService(t, repository, archives, executor)

			result, err := service.BuildOnce(context.Background())
			if err != nil || result.Run.Status.State != devopsv1.PipelineRunCancelled ||
				archives.openCalls != 0 || executor.executeCalls != 0 ||
				executor.cancelCalls != map[bool]int{false: 0, true: 1}[mode == runlifecycle.ClaimObserve] ||
				repository.completeCalls != 1 {
				t.Fatalf(
					"cancel result=%#v err=%v open=%d execute=%d cancel=%d completion=%#v",
					result,
					err,
					archives.openCalls,
					executor.executeCalls,
					executor.cancelCalls,
					repository.completion,
				)
			}
			if (mode == runlifecycle.ClaimObserve) != (repository.completion.Receipt != nil) {
				t.Fatalf("cancel receipt=%#v", repository.completion.Receipt)
			}
		})
	}
}

func TestExecutorUncertaintyRetainsIntentWithoutLeakingNativeFailure(t *testing.T) {
	command := buildCommand(t, runlifecycle.ClaimExecute)
	repository := newBuildRepository(command)
	secret := "native failure contained token-secret-value"
	executor := &fakeBuildExecutor{executeErr: errors.New(secret)}
	service := buildService(
		t,
		repository,
		&fakeArchiveReader{content: []byte("source archive")},
		executor,
	)

	result, err := service.BuildOnce(context.Background())
	if !errors.Is(err, ErrExecutionUncertain) || strings.Contains(err.Error(), secret) ||
		!result.Claimed || repository.completeCalls != 0 {
		t.Fatalf("uncertain result=%#v err=%v complete=%d", result, err, repository.completeCalls)
	}
}

func TestDefinitiveExecutorAbsenceAndInvalidReceiptFailClosed(t *testing.T) {
	for name, executor := range map[string]*fakeBuildExecutor{
		"unavailable": {executeErr: port.ErrBuildUnavailable},
		"invalid receipt": {
			conclusion: devopsbuildv1.ConclusionPassed,
			mutateReceipt: func(value *devopsbuildv1.Receipt) {
				value.SourceArchiveDigest = "sha256:" + strings.Repeat("f", 64)
				value.ContentDigest = devopsbuildv1.DigestReceipt(*value)
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			command := buildCommand(t, runlifecycle.ClaimExecute)
			repository := newBuildRepository(command)
			service := buildService(
				t,
				repository,
				&fakeArchiveReader{content: []byte("source archive")},
				executor,
			)
			result, err := service.BuildOnce(context.Background())
			if err != nil || result.Run.Status.State != devopsv1.PipelineRunFailed ||
				result.Run.Status.Reason != devopsv1.PipelineRunReasonExecutorUnavailable ||
				repository.completeCalls != 1 || repository.completion.Receipt != nil {
				t.Fatalf("failed-closed result=%#v err=%v completion=%#v", result, err, repository.completion)
			}
		})
	}
}

func TestUnavailableSourceArchiveFailsClosedWithoutLeakingAdapterFailure(t *testing.T) {
	command := buildCommand(t, runlifecycle.ClaimExecute)
	repository := newBuildRepository(command)
	secret := "archive path contained credential-secret-value"
	archives := &fakeArchiveReader{err: errors.New(secret)}
	executor := &fakeBuildExecutor{}
	service := buildService(t, repository, archives, executor)

	result, err := service.BuildOnce(context.Background())
	if err != nil || strings.Contains(string(result.Run.Status.Reason), secret) ||
		result.Run.Status.State != devopsv1.PipelineRunFailed ||
		result.Run.Status.Reason != devopsv1.PipelineRunReasonExecutorUnavailable ||
		archives.openCalls != 1 || executor.executeCalls != 0 ||
		repository.completeCalls != 1 {
		t.Fatalf(
			"archive failure result=%#v err=%v open=%d execute=%d complete=%d",
			result,
			err,
			archives.openCalls,
			executor.executeCalls,
			repository.completeCalls,
		)
	}
}

func TestExpiredRecoveredBuildCancelsBeforeCommittingDeadline(t *testing.T) {
	command := buildCommand(t, runlifecycle.ClaimObserve)
	shift := -ExecutionDeadline - 2*time.Minute
	command.Revision.ActivatedAt = command.Revision.ActivatedAt.Add(shift)
	command.Lease.Run.CreatedAt = command.Lease.Run.CreatedAt.Add(shift)
	command.Lease.Run.UpdatedAt = command.Lease.Run.UpdatedAt.Add(shift)
	command.Lease.Run.Status.ObservedAt = command.Lease.Run.Status.ObservedAt.Add(shift)
	command.StartedAt = command.StartedAt.Add(shift)
	command.DeadlineAt = command.DeadlineAt.Add(shift)
	command.Lease.LeaseExpiresAt = time.Now().UTC().Add(LeaseDuration).Truncate(time.Microsecond)
	repository := newBuildRepository(command)
	executor := &fakeBuildExecutor{
		conclusion: devopsbuildv1.ConclusionCancelled, cancelFound: true,
	}
	service := buildService(
		t,
		repository,
		&fakeArchiveReader{content: []byte("must not be opened")},
		executor,
	)

	result, err := service.BuildOnce(context.Background())
	if err != nil || result.Run.Status.State != devopsv1.PipelineRunFailed ||
		result.Run.Status.Reason != devopsv1.PipelineRunReasonDeadlineExceeded ||
		executor.cancelCalls != 1 || executor.observeCalls != 0 ||
		repository.completion.Receipt == nil {
		t.Fatalf("expired result=%#v err=%v completion=%#v", result, err, repository.completion)
	}
}

func TestBuildRenewsLeaseDuringExecutorCall(t *testing.T) {
	command := buildCommand(t, runlifecycle.ClaimExecute)
	repository := newBuildRepository(command)
	executor := &fakeBuildExecutor{
		conclusion: devopsbuildv1.ConclusionPassed, delay: 40 * time.Millisecond,
	}
	service := buildService(
		t,
		repository,
		&fakeArchiveReader{content: []byte("source archive")},
		executor,
	)
	service.renewalInterval = 5 * time.Millisecond

	result, err := service.BuildOnce(context.Background())
	if err != nil || result.Run.Status.State != devopsv1.PipelineRunReporting ||
		repository.renewCalls() == 0 {
		t.Fatalf("renewed build result=%#v err=%v renewals=%d", result, err, repository.renewCalls())
	}
}

func TestBuildLeaseLossCancelsEffectAndRetainsIntentForObservation(t *testing.T) {
	command := buildCommand(t, runlifecycle.ClaimExecute)
	repository := newBuildRepository(command)
	secret := "stale lease contained database-secret-value"
	repository.renewErr = errors.New(secret)
	executor := &fakeBuildExecutor{
		conclusion: devopsbuildv1.ConclusionPassed, delay: time.Second,
	}
	service := buildService(
		t,
		repository,
		&fakeArchiveReader{content: []byte("source archive")},
		executor,
	)
	service.renewalInterval = 5 * time.Millisecond

	result, err := service.BuildOnce(context.Background())
	if !errors.Is(err, ErrExecutionUncertain) || strings.Contains(err.Error(), secret) ||
		!result.Claimed || executor.executeCalls != 1 || repository.renewCalls() == 0 ||
		repository.completeCalls != 0 {
		t.Fatalf(
			"lease loss result=%#v err=%v execute=%d renewals=%d complete=%d",
			result,
			err,
			executor.executeCalls,
			repository.renewCalls(),
			repository.completeCalls,
		)
	}
}

func TestBuildCommandBindsRunRevisionArchiveAndDeadlineBeforeEffects(t *testing.T) {
	valid := buildCommand(t, runlifecycle.ClaimExecute)
	if err := ValidateCommand(valid); err != nil {
		t.Fatalf("validate build command: %v", err)
	}
	mutations := map[string]func(*Command){
		"state": func(value *Command) {
			value.Lease.Run.Status.State = devopsv1.PipelineRunQueued
		},
		"revision": func(value *Command) {
			value.Revision.ContentDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"archive run": func(value *Command) {
			value.Archive.RunID = "pipeline-run-" + devopsv1.ResourceID(strings.Repeat("e", 48))
		},
		"archive digest": func(value *Command) {
			value.Archive.ArchiveDigest = "invalid"
		},
		"started before run": func(value *Command) {
			value.StartedAt = value.Lease.Run.UpdatedAt.Add(-time.Microsecond)
		},
		"deadline": func(value *Command) {
			value.DeadlineAt = value.DeadlineAt.Add(time.Second)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			repository := newBuildRepository(candidate)
			archives := &fakeArchiveReader{content: []byte("source archive")}
			executor := &fakeBuildExecutor{}
			service := buildService(t, repository, archives, executor)

			if _, err := service.BuildOnce(context.Background()); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("invalid command error=%v", err)
			}
			if archives.openCalls != 0 || executor.executeCalls != 0 ||
				executor.observeCalls != 0 || executor.cancelCalls != 0 ||
				repository.completeCalls != 0 {
				t.Fatalf(
					"invalid command caused effects open=%d execute=%d observe=%d cancel=%d complete=%d",
					archives.openCalls,
					executor.executeCalls,
					executor.observeCalls,
					executor.cancelCalls,
					repository.completeCalls,
				)
			}
		})
	}
}

func TestBuildServiceRejectsOpenConfiguration(t *testing.T) {
	command := buildCommand(t, runlifecycle.ClaimExecute)
	repository := newBuildRepository(command)
	archives := &fakeArchiveReader{}
	executor := &fakeBuildExecutor{}
	valid := Config{
		WorkerID: "build-worker-one", LeaseDuration: LeaseDuration,
		Deadline: ExecutionDeadline, CancelGrace: CancellationGrace,
	}
	for name, mutate := range map[string]func(*Config){
		"worker":       func(value *Config) { value.WorkerID = "invalid worker" },
		"lease":        func(value *Config) { value.LeaseDuration++ },
		"deadline":     func(value *Config) { value.Deadline++ },
		"cancel grace": func(value *Config) { value.CancelGrace++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := NewService(repository, archives, executor, candidate); err == nil {
				t.Fatal("open build configuration was accepted")
			}
		})
	}
	if _, err := NewService(nil, archives, executor, valid); err == nil {
		t.Fatal("nil build repository was accepted")
	}
}

type fakeBuildRepository struct {
	mu            sync.Mutex
	command       Command
	claimed       bool
	completion    Completion
	completeCalls int
	renewCount    int
	renewErr      error
	lastExpiry    time.Time
}

func newBuildRepository(command Command) *fakeBuildRepository {
	return &fakeBuildRepository{command: command, lastExpiry: command.Lease.LeaseExpiresAt}
}

func (repository *fakeBuildRepository) Heartbeat(context.Context, string) (time.Time, error) {
	return time.Now().UTC().Truncate(time.Microsecond), nil
}

func (repository *fakeBuildRepository) Claim(
	context.Context,
	string,
	time.Duration,
) (Command, bool, error) {
	if repository.claimed {
		return Command{}, false, nil
	}
	repository.claimed = true
	return repository.command, true, nil
}

func (repository *fakeBuildRepository) Renew(
	context.Context,
	runlifecycle.LeaseGuard,
	time.Duration,
) (time.Time, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.renewCount++
	if repository.renewErr != nil {
		return time.Time{}, repository.renewErr
	}
	repository.lastExpiry = repository.lastExpiry.Add(LeaseDuration)
	return repository.lastExpiry, nil
}

func (repository *fakeBuildRepository) renewCalls() int {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.renewCount
}

func (repository *fakeBuildRepository) Complete(
	_ context.Context,
	completion Completion,
) (devopsv1.PipelineRun, error) {
	repository.completeCalls++
	repository.completion = completion
	return domain.AdvancePipelineRun(
		completion.Command.Lease.Run,
		completion.State,
		completion.Reason,
		completion.Command.Lease.Run.UpdatedAt.Add(time.Microsecond),
	)
}

func (repository *fakeBuildRepository) Readiness(context.Context) (devopsv1.Readiness, error) {
	return devopsv1.Readiness{
		APIVersion:    devopsv1.APIVersion,
		Kind:          "Readiness",
		State:         devopsv1.ReadinessReady,
		SchemaVersion: 1,
		CheckedAt:     time.Now().UTC().Truncate(time.Microsecond),
	}, nil
}

type fakeArchiveReader struct {
	content   []byte
	err       error
	openCalls int
}

func (reader *fakeArchiveReader) Open(
	context.Context,
	sourcearchive.Receipt,
) (io.ReadCloser, error) {
	reader.openCalls++
	if reader.err != nil {
		return nil, reader.err
	}
	return io.NopCloser(bytes.NewReader(reader.content)), nil
}

type fakeBuildExecutor struct {
	conclusion    devopsbuildv1.Conclusion
	executeErr    error
	observeErr    error
	cancelErr     error
	observeFound  bool
	cancelFound   bool
	delay         time.Duration
	mutateReceipt func(*devopsbuildv1.Receipt)
	executeCalls  int
	observeCalls  int
	cancelCalls   int
	request       devopsbuildv1.Request
	archive       []byte
}

func (executor *fakeBuildExecutor) Execute(
	ctx context.Context,
	request devopsbuildv1.Request,
	archive io.Reader,
) (devopsbuildv1.Receipt, error) {
	executor.executeCalls++
	executor.request = request
	executor.archive, _ = io.ReadAll(archive)
	if executor.delay > 0 {
		select {
		case <-ctx.Done():
			return devopsbuildv1.Receipt{}, ctx.Err()
		case <-time.After(executor.delay):
		}
	}
	if executor.executeErr != nil {
		return devopsbuildv1.Receipt{}, executor.executeErr
	}
	return executor.receipt(request), nil
}

func (executor *fakeBuildExecutor) Observe(
	_ context.Context,
	request devopsbuildv1.Request,
) (devopsbuildv1.Receipt, bool, error) {
	executor.observeCalls++
	executor.request = request
	if executor.observeErr != nil {
		return devopsbuildv1.Receipt{}, executor.observeFound, executor.observeErr
	}
	if !executor.observeFound {
		return devopsbuildv1.Receipt{}, false, nil
	}
	return executor.receipt(request), true, nil
}

func (executor *fakeBuildExecutor) Cancel(
	_ context.Context,
	request devopsbuildv1.Request,
) (devopsbuildv1.Receipt, bool, error) {
	executor.cancelCalls++
	executor.request = request
	if executor.cancelErr != nil {
		return devopsbuildv1.Receipt{}, executor.cancelFound, executor.cancelErr
	}
	if !executor.cancelFound {
		return devopsbuildv1.Receipt{}, false, nil
	}
	return executor.receipt(request), true, nil
}

func (executor *fakeBuildExecutor) receipt(request devopsbuildv1.Request) devopsbuildv1.Receipt {
	conclusion := executor.conclusion
	if conclusion == "" {
		conclusion = devopsbuildv1.ConclusionPassed
	}
	first := devopsbuildv1.StepConclusionPassed
	second := devopsbuildv1.StepConclusionPassed
	switch conclusion {
	case devopsbuildv1.ConclusionFailed:
		second = devopsbuildv1.StepConclusionFailed
	case devopsbuildv1.ConclusionCancelled:
		first = devopsbuildv1.StepConclusionCancelled
		second = devopsbuildv1.StepConclusionNotRun
	}
	receipt := devopsbuildv1.Receipt{
		TenantID:               request.TenantID,
		RunID:                  request.RunID,
		CommandID:              request.CommandID,
		InputDigest:            request.InputDigest,
		SourceArchiveDigest:    request.SourceArchiveDigest,
		PipelineRevisionID:     request.PipelineRevisionID,
		PipelineRevisionDigest: request.PipelineRevisionDigest,
		ExecutorID:             "executor-one",
		ExecutorProfile:        request.ExecutorProfile,
		ToolchainImageDigest:   request.ToolchainImageDigest,
		Conclusion:             conclusion,
		Steps: [2]devopsbuildv1.StepReceipt{
			{Ordinal: request.Steps[0].Ordinal, Kind: request.Steps[0].Kind, Conclusion: first},
			{Ordinal: request.Steps[1].Ordinal, Kind: request.Steps[1].Kind, Conclusion: second},
		},
	}
	if executor.mutateReceipt != nil {
		executor.mutateReceipt(&receipt)
	}
	if receipt.ContentDigest == "" {
		receipt.ContentDigest = devopsbuildv1.DigestReceipt(receipt)
	}
	return receipt
}

func buildService(
	t *testing.T,
	repository Repository,
	archives ArchiveReader,
	executor port.BuildExecutor,
) *Service {
	t.Helper()
	service, err := NewService(repository, archives, executor, Config{
		WorkerID:      "build-worker-one",
		LeaseDuration: LeaseDuration,
		Deadline:      ExecutionDeadline,
		CancelGrace:   CancellationGrace,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func buildCommand(t *testing.T, mode runlifecycle.ClaimMode) Command {
	t.Helper()
	base := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	scope := devopsv1.ResourceScope{TenantID: "tenant-one"}
	pipelineID := devopsv1.ResourceID("pipeline-one")
	projectID := devopsv1.ResourceID("project-one")
	repositoryBindingID := devopsv1.ResourceID("binding-one")
	repositoryBindingDigest := "sha256:" + strings.Repeat("1", 64)
	revisionSpec := devopsv1.PipelineRevisionSpec{
		RepositoryBindingID:     repositoryBindingID,
		RepositoryBindingDigest: repositoryBindingDigest,
		TriggerPolicy:           devopsv1.TriggerChange,
		VerificationProfile:     devopsv1.VerificationGo126OfflineV1,
		ExecutorProfile:         devopsv1.ExecutorMatrixNativeIsolatedV1,
		ToolchainImageDigest:    devopsv1.Go126OfflineToolchainImageDigest,
		DependencyEgress:        devopsv1.DependencyEgressNone,
		ReporterPolicy:          devopsv1.ReporterChangeCheckV1,
		Steps:                   devopsv1.FixedVerificationSteps(),
		Limits:                  devopsv1.FixedVerificationLimits(),
	}
	revisionDigest := devopsv1.PipelineRevisionSpecDigest(revisionSpec)
	revisionID, err := devopsv1.PipelineRevisionID(scope, pipelineID, 1, revisionDigest)
	if err != nil {
		t.Fatal(err)
	}
	revision := devopsv1.PipelineRevision{
		APIVersion:    devopsv1.APIVersion,
		Kind:          "PipelineRevision",
		ID:            revisionID,
		Scope:         scope,
		PipelineID:    pipelineID,
		ProjectID:     projectID,
		Revision:      1,
		Spec:          revisionSpec,
		ContentDigest: revisionDigest,
		ActivatedBy:   devopsv1.SubjectRef{Kind: devopsv1.SubjectUser, ID: "user-one"},
		ActivatedAt:   base,
	}
	input := devopsv1.PipelineRunInput{
		SourceEventID:           "source-event-" + devopsv1.ResourceID(strings.Repeat("2", 48)),
		SourceEventDigest:       "sha256:" + strings.Repeat("3", 64),
		PipelineRevisionID:      revision.ID,
		PipelineRevisionDigest:  revision.ContentDigest,
		RepositoryBindingID:     repositoryBindingID,
		RepositoryBindingDigest: repositoryBindingDigest,
		Change: devopsv1.ChangeIdentity{
			Number:            7,
			Action:            devopsv1.ChangeUpdated,
			HeadCommit:        strings.Repeat("4", 40),
			TrustedBaseCommit: strings.Repeat("5", 40),
		},
	}
	inputDigest := devopsv1.PipelineRunInputDigest(input)
	runID, err := devopsv1.PipelineRunID(scope, input.SourceEventID, revision.ID, inputDigest)
	if err != nil {
		t.Fatal(err)
	}
	updatedAt := base.Add(time.Second)
	run := devopsv1.PipelineRun{
		APIVersion:  devopsv1.APIVersion,
		Kind:        "PipelineRun",
		ID:          runID,
		Scope:       scope,
		ProjectID:   projectID,
		PipelineID:  pipelineID,
		Input:       input,
		InputDigest: inputDigest,
		Status: devopsv1.PipelineRunStatus{
			State:           devopsv1.PipelineRunVerifying,
			Stage:           devopsv1.PipelineRunStageVerify,
			ResourceVersion: 3,
			ObservedAt:      updatedAt,
		},
		CreatedAt: base,
		UpdatedAt: updatedAt,
	}
	startedAt := updatedAt.Add(time.Microsecond)
	intent := runlifecycle.TaskIntent{
		RunID:       run.ID,
		InputDigest: run.InputDigest,
		Stage:       devopsv1.PipelineRunStageVerify,
		Attempt:     1,
	}
	intent.CommandID = runlifecycle.TaskCommandID(intent.RunID, intent.Stage, intent.Attempt)
	fence := uint64(1)
	if mode == runlifecycle.ClaimObserve {
		fence = 2
	}
	return Command{
		Lease: runlifecycle.Lease{
			TenantID:       scope.TenantID,
			Run:            run,
			Intent:         intent,
			Mode:           mode,
			WorkerID:       "build-worker-one",
			FencingToken:   fence,
			LeaseExpiresAt: time.Now().UTC().Add(LeaseDuration).Truncate(time.Microsecond),
		},
		Revision: revision,
		Archive: sourcearchive.Receipt{
			TenantID:          scope.TenantID,
			RunID:             run.ID,
			CommandID:         runlifecycle.TaskCommandID(run.ID, devopsv1.PipelineRunStageFetch, 1),
			InputDigest:       run.InputDigest,
			HeadCommit:        run.Input.Change.HeadCommit,
			TrustedBaseCommit: run.Input.Change.TrustedBaseCommit,
			MediaType:         sourcearchive.MediaType,
			ArchiveDigest:     "sha256:" + strings.Repeat("6", 64),
			ArchiveBytes:      1024,
			ExpandedBytes:     4096,
			PathCount:         3,
		},
		StartedAt:  startedAt,
		DeadlineAt: startedAt.Add(ExecutionDeadline),
	}
}
