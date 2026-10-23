package compose

import (
	"context"
	"errors"
	"testing"
)

func TestLocalRuntimeReadyProofRunsOneLiveProbePerRequest(t *testing.T) {
	calls := 0
	runtime := &LocalRuntime{readiness: func(context.Context) error {
		calls++
		return nil
	}}

	baseContext, cancel := context.WithCancel(context.Background())
	requestContext, err := runtime.ProveReady(baseContext)
	if err != nil {
		t.Fatalf("prove runtime ready: %v", err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		if err := runtime.Ready(requestContext); err != nil {
			t.Fatalf("reuse runtime readiness proof: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("live runtime readiness probes in one request = %d, want 1", calls)
	}
	cancel()
	if err := runtime.Ready(requestContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled readiness proof = %v, want context cancellation", err)
	}

	if err := runtime.Ready(context.Background()); err != nil {
		t.Fatalf("probe runtime for next request: %v", err)
	}
	if calls != 2 {
		t.Fatalf("live runtime readiness probes across two requests = %d, want 2", calls)
	}
}

func TestLocalRuntimeReadyProofIsBoundToSuccessfulRuntime(t *testing.T) {
	unavailable := &LocalRuntime{readiness: func(context.Context) error {
		return ErrRuntimeUnavailable
	}}
	if requestContext, err := unavailable.ProveReady(context.Background()); requestContext != nil || !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("failed runtime proof: context=%v error=%v", requestContext, err)
	}

	readyCalls := 0
	ready := &LocalRuntime{readiness: func(context.Context) error {
		readyCalls++
		return nil
	}}
	requestContext, err := ready.ProveReady(context.Background())
	if err != nil {
		t.Fatalf("prove first runtime ready: %v", err)
	}
	otherCalls := 0
	other := &LocalRuntime{readiness: func(context.Context) error {
		otherCalls++
		return nil
	}}
	if err := other.Ready(requestContext); err != nil {
		t.Fatalf("probe other runtime: %v", err)
	}
	if readyCalls != 1 || otherCalls != 1 {
		t.Fatalf("runtime-bound proof calls = %d/%d, want 1/1", readyCalls, otherCalls)
	}
}
