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
