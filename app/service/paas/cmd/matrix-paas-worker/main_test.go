package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	localmachineadapter "github.com/xiak/matrix/app/adapter/infrastructure/localmachine"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/refreshexecutionprofile"
)

type loopWorker struct {
	mu        sync.Mutex
	processed int
	failure   error
}

func (worker *loopWorker) ProcessNext(context.Context, string) (bool, error) {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.failure != nil {
		return false, worker.failure
	}
	if worker.processed == 0 {
		worker.processed++
		return true, nil
	}
	return false, nil
}

func TestWorkerLoopProcessesAvailableWorkAndStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	worker := &loopWorker{}
	result := make(chan error, 1)
	go func() {
		result <- runWorkerLoop(
			ctx,
			worker.ProcessNext,
			func(context.Context) error { return nil },
			"worker-a",
			time.Hour,
			time.Hour,
		)
	}()
	deadline := time.After(2 * time.Second)
	for {
		worker.mu.Lock()
		processed := worker.processed
		worker.mu.Unlock()
		if processed > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("worker did not process available work")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("stop worker loop: %v", err)
	}
}

func TestWorkerLoopNormalizesCycleFailure(t *testing.T) {
	native := errors.New("database password and /host/path must not escape")
	worker := &loopWorker{failure: native}
	err := runWorkerLoop(
		context.Background(),
		worker.ProcessNext,
		func(context.Context) error { return nil },
		"worker-a",
		time.Hour,
		time.Hour,
	)
	if err == nil || errors.Is(err, native) || err.Error() != "PaaS reconciliation cycle failed" {
		t.Fatalf("worker loop error = %v", err)
	}
}

func TestWorkerLoopPreservesOnlyClosedFailureStage(t *testing.T) {
	err := runWorkerLoop(
		context.Background(),
		func(context.Context, string) (bool, error) {
			return false, failWorker(workerFailureManagedServiceCycle)
		},
		func(context.Context) error { return nil },
		"worker-a",
		time.Hour,
		time.Hour,
	)
	if code := workerFailureCode(err); code != workerFailureManagedServiceCycle {
		t.Fatalf("worker failure code = %q", code)
	}
	if err == nil || err.Error() != string(workerFailureManagedServiceCycle) {
		t.Fatalf("worker failure = %v", err)
	}
}

func TestWorkerLoopRetriesTransientRefreshWithoutRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	refreshCalls := 0
	processCallsBeforeRecovery := 0
	processCallsAfterRecovery := 0
	refreshFailed := false
	recovered := false
	err := runWorkerLoop(
		ctx,
		func(context.Context, string) (bool, error) {
			if refreshFailed && !recovered {
				processCallsBeforeRecovery++
			}
			if recovered {
				processCallsAfterRecovery++
				cancel()
			}
			return false, nil
		},
		func(context.Context) error {
			refreshCalls++
			if refreshCalls < 3 {
				refreshFailed = true
				return failWorker(workerFailureExecutionEngineTimeout)
			}
			recovered = true
			return nil
		},
		"worker-a",
		time.Millisecond,
		5*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("worker loop after transient refresh failures: %v", err)
	}
	if refreshCalls != 3 {
		t.Fatalf("refresh calls = %d, want 3", refreshCalls)
	}
	if processCallsBeforeRecovery != 0 || processCallsAfterRecovery != 1 {
		t.Fatalf(
			"process calls before/after recovery = %d/%d, want 0/1",
			processCallsBeforeRecovery,
			processCallsAfterRecovery,
		)
	}
}

func TestWorkerLoopPersistentTransientRefreshUsesBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var refreshTimes []time.Time
	processCallsAfterFailure := 0
	refreshFailed := false
	err := runWorkerLoop(
		ctx,
		func(context.Context, string) (bool, error) {
			if refreshFailed {
				processCallsAfterFailure++
			}
			return false, nil
		},
		func(context.Context) error {
			refreshTimes = append(refreshTimes, time.Now())
			refreshFailed = true
			if len(refreshTimes) == 3 {
				cancel()
			}
			return failWorker(workerFailureExecutionObserveDown)
		},
		"worker-a",
		time.Millisecond,
		10*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("worker loop after persistent transient refresh failures: %v", err)
	}
	if len(refreshTimes) != 3 {
		t.Fatalf("refresh calls = %d, want 3", len(refreshTimes))
	}
	if processCallsAfterFailure != 0 {
		t.Fatalf("process calls during failed refresh = %d, want 0", processCallsAfterFailure)
	}
	for index := 1; index < len(refreshTimes); index++ {
		if elapsed := refreshTimes[index].Sub(refreshTimes[index-1]); elapsed < 8*time.Millisecond {
			t.Fatalf("refresh backoff = %s, want approximately 10ms", elapsed)
		}
	}
}

func TestWorkerLoopStopsOnTerminalRefreshFailure(t *testing.T) {
	refreshCalls := 0
	err := runWorkerLoop(
		context.Background(),
		func(context.Context, string) (bool, error) { return false, nil },
		func(context.Context) error {
			refreshCalls++
			return failWorker(workerFailureExecutionValidate)
		},
		"worker-a",
		time.Nanosecond,
		time.Hour,
	)
	if code := workerFailureCode(err); code != workerFailureExecutionValidate {
		t.Fatalf("worker failure code = %q", code)
	}
	if refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", refreshCalls)
	}
}

func TestWorkerLoopDoesNotExposeUnexpectedRefreshFailure(t *testing.T) {
	native := errors.New("database password and /host/path must not escape")
	err := runWorkerLoop(
		context.Background(),
		func(context.Context, string) (bool, error) { return false, nil },
		func(context.Context) error { return native },
		"worker-a",
		time.Nanosecond,
		time.Hour,
	)
	if err == nil || errors.Is(err, native) || err.Error() != "PaaS execution target refresh failed" {
		t.Fatalf("worker refresh error = %v", err)
	}
}

func TestWorkerFailureCodeDoesNotExposeUnexpectedError(t *testing.T) {
	native := errors.New("database password and /host/path must not escape")
	if code := workerFailureCode(native); code != workerFailureUnexpected {
		t.Fatalf("unexpected worker failure code = %q", code)
	}
}

func TestExecutionProfileRefreshStageFailureUsesOnlyClosedCodes(t *testing.T) {
	tests := []struct {
		name         string
		stage        refreshexecutionprofile.RefreshFailureStage
		adapterClass paasv1.AdapterErrorClass
		want         workerFailureStage
	}{
		{
			name: "observe timeout", stage: refreshexecutionprofile.RefreshFailureObserve,
			adapterClass: paasv1.AdapterErrorTimeout, want: workerFailureExecutionObserveTimeout,
		},
		{
			name: "observe unavailable", stage: refreshexecutionprofile.RefreshFailureObserve,
			adapterClass: paasv1.AdapterErrorUnavailable, want: workerFailureExecutionObserveDown,
		},
		{
			name: "observe rejected", stage: refreshexecutionprofile.RefreshFailureObserve,
			adapterClass: paasv1.AdapterErrorValidation, want: workerFailureExecutionObserveReject,
		},
		{
			name: "unexpected adapter", stage: refreshexecutionprofile.RefreshFailureObserve,
			adapterClass: paasv1.AdapterErrorInternal,
			want:         workerFailureExecutionProfileRefresh,
		},
		{
			name: "validate", stage: refreshexecutionprofile.RefreshFailureValidate,
			want: workerFailureExecutionValidate,
		},
		{
			name: "load", stage: refreshexecutionprofile.RefreshFailureLoad,
			want: workerFailureExecutionLoad,
		},
		{
			name: "build", stage: refreshexecutionprofile.RefreshFailureBuild,
			want: workerFailureExecutionBuild,
		},
		{
			name: "save", stage: refreshexecutionprofile.RefreshFailureSave,
			want: workerFailureExecutionSave,
		},
		{
			name: "transaction", stage: refreshexecutionprofile.RefreshFailureTransaction,
			want: workerFailureExecutionTransaction,
		},
		{
			name: "unknown", stage: refreshexecutionprofile.RefreshFailureUnknown,
			want: workerFailureExecutionProfileRefresh,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := executionProfileRefreshStageFailure(test.stage, test.adapterClass); got != test.want {
				t.Fatalf("refresh failure code = %q, want %q", got, test.want)
			}
		})
	}

	native := errors.New("database password and /host/path must not escape")
	if got := executionProfileRefreshFailure(native); got != workerFailureExecutionProfileRefresh {
		t.Fatalf("unexpected refresh failure code = %q", got)
	}
}

type rejectedExecutionProbe struct {
	failure error
	calls   int
}

func (probe *rejectedExecutionProbe) Inspect(context.Context, string) (localmachineadapter.HostFacts, error) {
	probe.calls++
	return localmachineadapter.HostFacts{}, probe.failure
}

type unusedExecutionProfileRepository struct {
	calls int
}

func (repository *unusedExecutionProfileRepository) WithinTransaction(
	context.Context,
	paasv1.TenantID,
	func(context.Context, refreshexecutionprofile.Transaction) error,
) error {
	repository.calls++
	return errors.New("failed observation must not start a profile transaction")
}

func TestExecutionProfileRefreshRetainsClosedProbeTimeoutCode(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure error
		want    workerFailureStage
	}{
		{
			name:    "engine timeout",
			failure: localmachineadapter.ProbeFailure{Kind: localmachineadapter.ProbeFailureTimeout, ID: string(localmachineadapter.ProbeDockerEngine)},
			want:    "PAAS_WORKER_EXECUTION_PROFILE_DOCKER_ENGINE_TIMEOUT",
		},
		{
			name:    "compose timeout",
			failure: localmachineadapter.ProbeFailure{Kind: localmachineadapter.ProbeFailureTimeout, ID: string(localmachineadapter.ProbeComposePlugin)},
			want:    "PAAS_WORKER_EXECUTION_PROFILE_COMPOSE_PLUGIN_TIMEOUT",
		},
		{
			name:    "unknown probe timeout",
			failure: localmachineadapter.ProbeFailure{Kind: localmachineadapter.ProbeFailureTimeout, ID: "password=must-not-leak /host/private"},
			want:    workerFailureExecutionObserveTimeout,
		},
		{
			name:    "engine unavailable is not timeout",
			failure: localmachineadapter.ProbeFailure{Kind: localmachineadapter.ProbeFailureUnavailable, ID: string(localmachineadapter.ProbeDockerEngine)},
			want:    workerFailureExecutionObserveDown,
		},
		{
			name:    "compose rejected is not timeout",
			failure: localmachineadapter.ProbeFailure{Kind: localmachineadapter.ProbeFailureValidation, ID: string(localmachineadapter.ProbeComposePlugin)},
			want:    workerFailureExecutionObserveReject,
		},
		{
			name:    "native error does not escape",
			failure: errors.New("password=must-not-leak /host/private"),
			want:    workerFailureExecutionProfileRefresh,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding, err := localmachineadapter.NewMachineBinding(localmachineadapter.MachineBindingSpec{
				ID: "local", Kind: localmachineadapter.BindingLocal,
				AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
			})
			if err != nil {
				t.Fatal(err)
			}
			bindings, err := localmachineadapter.NewStaticBindingResolver(binding)
			if err != nil {
				t.Fatal(err)
			}
			probe := &rejectedExecutionProbe{failure: test.failure}
			adapter, err := localmachineadapter.New(localmachineadapter.Config{Bindings: bindings, LocalProbe: probe})
			if err != nil {
				t.Fatal(err)
			}
			repository := &unusedExecutionProfileRepository{}
			service, err := refreshexecutionprofile.New(adapter, repository, refreshexecutionprofile.Config{
				TenantID: "organization-default", IDs: localExecutionProfileIDs,
				MachineBindingRef: "local", ObservationTimeout: executionTargetTimeout,
				MaximumObservationAge: executionTargetMaximumAge, MaxTransactionAttempts: 5,
			})
			if err != nil {
				t.Fatal(err)
			}
			failure := service.Refresh(context.Background())
			if probe.calls != 1 || repository.calls != 0 {
				t.Fatalf("failed observation: probe calls=%d, transaction calls=%d", probe.calls, repository.calls)
			}
			code := workerFailureCode(failWorker(executionProfileRefreshFailure(failure)))
			if code != test.want {
				t.Fatalf("worker failure code = %q, want %q", code, test.want)
			}
		})
	}
}

func TestExecutionProfileStartupRetriesOnlyTransientClosedFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		failures  []workerFailureStage
		attempts  int
		wantCalls int
		want      workerFailureStage
	}{
		{
			name: "engine warmup converges",
			failures: []workerFailureStage{
				workerFailureExecutionEngineTimeout,
				workerFailureExecutionEngineTimeout,
			},
			attempts: 4, wantCalls: 3,
		},
		{
			name: "temporarily unavailable converges",
			failures: []workerFailureStage{
				workerFailureExecutionObserveDown,
			},
			attempts: 3, wantCalls: 2,
		},
		{
			name: "compose warmup converges",
			failures: []workerFailureStage{
				workerFailureExecutionComposeTimeout,
			},
			attempts: 3, wantCalls: 2,
		},
		{
			name: "observation timeout converges",
			failures: []workerFailureStage{
				workerFailureExecutionObserveTimeout,
			},
			attempts: 3, wantCalls: 2,
		},
		{
			name: "validation fails once",
			failures: []workerFailureStage{
				workerFailureExecutionValidate,
			},
			attempts: 4, wantCalls: 1, want: workerFailureExecutionValidate,
		},
		{
			name: "transient failure is bounded",
			failures: []workerFailureStage{
				workerFailureExecutionEngineTimeout,
				workerFailureExecutionEngineTimeout,
				workerFailureExecutionEngineTimeout,
				workerFailureExecutionEngineTimeout,
			},
			attempts: 3, wantCalls: 3, want: workerFailureExecutionEngineTimeout,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			err := refreshExecutionProfileAtStartup(
				context.Background(),
				test.attempts,
				time.Nanosecond,
				func(context.Context) error {
					calls++
					if calls <= len(test.failures) {
						return failWorker(test.failures[calls-1])
					}
					return nil
				},
			)
			if calls != test.wantCalls {
				t.Fatalf("startup refresh calls = %d, want %d", calls, test.wantCalls)
			}
			if test.want == "" {
				if err != nil {
					t.Fatalf("startup refresh = %v", err)
				}
				return
			}
			if code := workerFailureCode(err); code != test.want {
				t.Fatalf("startup refresh code = %q, want %q", code, test.want)
			}
		})
	}
}

func TestExecutionProfileStartupCancellationStopsRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := refreshExecutionProfileAtStartup(
		ctx,
		6,
		time.Hour,
		func(context.Context) error {
			calls++
			cancel()
			return failWorker(workerFailureExecutionEngineTimeout)
		},
	)
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled startup refresh: calls=%d error=%v", calls, err)
	}
}

func TestRunClassifiesIncompleteConfiguration(t *testing.T) {
	for _, variable := range []string{
		databaseDSNFileEnvironment,
		workerIDEnvironment,
		bindingRefEnvironment,
		bindingRootEnvironment,
		secretRootEnvironment,
		artifactCatalogEnvironment,
		executionTenantEnvironment,
		machineBindingEnvironment,
		listenAddressEnvironment,
		managedPostgresImageEnvironment,
		managedMySQLImageEnvironment,
		managedElasticsearchImageEnvironment,
		managedRabbitMQImageEnvironment,
	} {
		t.Setenv(variable, "")
	}
	err := run(context.Background())
	if code := workerFailureCode(err); code != workerFailureConfiguration {
		t.Fatalf("configuration failure code = %q", code)
	}
}
