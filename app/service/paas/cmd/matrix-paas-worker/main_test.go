package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
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
	)
	if code := workerFailureCode(err); code != workerFailureManagedServiceCycle {
		t.Fatalf("worker failure code = %q", code)
	}
	if err == nil || err.Error() != string(workerFailureManagedServiceCycle) {
		t.Fatalf("worker failure = %v", err)
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
