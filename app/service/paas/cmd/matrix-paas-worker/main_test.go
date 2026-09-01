package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
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
			func(context.Context) (bool, error) { return false, nil },
			"worker-a",
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
		func(context.Context) (bool, error) { return false, nil },
		"worker-a",
		time.Hour,
	)
	if err == nil || errors.Is(err, native) || err.Error() != "PaaS reconciliation cycle failed" {
		t.Fatalf("worker loop error = %v", err)
	}
}

func TestWorkerLoopDoesNotStarveRuntimeRefreshWhenOperationsRemain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtimeCalled := make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() {
		result <- runWorkerLoop(
			ctx,
			func(context.Context, string) (bool, error) { return true, nil },
			func(context.Context) error { return nil },
			func(context.Context) (bool, error) {
				select {
				case runtimeCalled <- struct{}{}:
				default:
				}
				return true, nil
			},
			"worker-a",
			time.Hour,
		)
	}()
	select {
	case <-runtimeCalled:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("runtime refresh was starved by available Operations")
	}
	if err := <-result; err != nil {
		t.Fatalf("stop worker loop: %v", err)
	}
}

func TestWorkerLoopRetriesExecutionTargetObservationWithoutRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	native := errors.New("Docker socket and provider path must not escape")
	recovered := make(chan struct{})
	result := make(chan error, 1)
	attempts := 0
	go func() {
		result <- runWorkerLoop(
			ctx,
			func(context.Context, string) (bool, error) { return false, nil },
			func(context.Context) error {
				attempts++
				if attempts == 1 {
					return native
				}
				if attempts == 2 {
					close(recovered)
				}
				return nil
			},
			func(context.Context) (bool, error) { return false, nil },
			"worker-a",
			10*time.Millisecond,
		)
	}()
	select {
	case <-recovered:
		cancel()
	case err := <-result:
		if errors.Is(err, native) {
			t.Fatal("worker leaked the provider failure")
		}
		t.Fatalf("worker stopped after a transient target observation: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not retry the target observation")
	}
	if err := <-result; err != nil {
		t.Fatalf("stop worker loop: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("target observation attempts = %d, want 2", attempts)
	}
}
