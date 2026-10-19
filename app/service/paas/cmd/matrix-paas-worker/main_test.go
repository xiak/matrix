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
