package observehost

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type hostFunc func(context.Context, paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error)

func (fn hostFunc) ObserveExecutionTarget(ctx context.Context, request paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error) {
	return fn(ctx, request)
}

func sample(now time.Time) paasv1.ExecutionTargetObservation {
	return paasv1.ExecutionTargetObservation{
		ExecutionTargetID: "target-a", IdentityFingerprint: "sha256:" + strings.Repeat("a", 64),
		Labels:      map[string]string{"matrix-os": "linux"},
		Capacity:    paasv1.Capacity{CPUMillis: 2000, MemoryBytes: 8000, StorageBytes: 10000, WorkloadSlots: 2},
		Allocatable: paasv1.Capacity{CPUMillis: 2000, MemoryBytes: 1000, StorageBytes: 1000, WorkloadSlots: 2},
		Health:      paasv1.ExecutionTargetHealthReady, SupportedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
		ObservedAt: now,
	}
}

func samplingConfig() Config {
	return Config{
		Identity:   nodev1.Identity{InstallationID: "installation-a", ExecutionTargetID: "target-a"},
		BindingRef: "binding-a", ExpectedFingerprint: "sha256:" + strings.Repeat("a", 64),
		SystemReserve: paasv1.Capacity{CPUMillis: 100, MemoryBytes: 200, StorageBytes: 500},
	}
}

func TestCurrentPreservesFreshnessIdentityAndSchedulingBudget(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	value := sample(now)
	var nativeError error
	calls := 0
	config := samplingConfig()
	config.Clock = func() time.Time { return now }
	service, err := New(hostFunc(func(_ context.Context, request paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error) {
		calls++
		if paasv1.ValidateObserveExecutionTargetRequest(request) != nil || request.Command.BindingRef != config.BindingRef {
			t.Fatal("sampler did not preserve the local binding contract")
		}
		return value, nativeError
	}), config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := service.Current(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("empty cache reported ready")
	}
	if err := service.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := service.Current(ctx)
	if err != nil || current.Allocatable.MemoryBytes != 7800 || current.Allocatable.StorageBytes != 9500 || calls != 1 {
		t.Fatalf("current capacity was confused with actual free resources: %#v, %v", current, err)
	}
	current.Labels["matrix-os"] = "changed"
	current.SupportedIsolationGuarantees[0] = "changed"
	current, _ = service.Current(ctx)
	if current.Labels["matrix-os"] != "linux" || current.SupportedIsolationGuarantees[0] != paasv1.IsolationWorkload || calls != 1 {
		t.Fatal("reading the sample mutated or resampled cached state")
	}
	now = now.Add(15 * time.Second)
	if _, err := service.Current(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("sample at expiry remained fresh")
	}
	value.ObservedAt = now
	value.IdentityFingerprint = "sha256:" + strings.Repeat("b", 64)
	if err := service.Refresh(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("different host identity accepted")
	}
	if _, err := service.Current(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("old sample hid an identity failure")
	}
	value.IdentityFingerprint = config.ExpectedFingerprint
	nativeError = errors.New("provider secret=password /private/path")
	if err := service.Refresh(ctx); err != ErrUnavailable {
		t.Fatalf("provider error escaped: %v", err)
	}
	nativeError = nil
	if err := service.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if current, err := service.Current(ctx); err != nil || current.ObservedAt != now {
		t.Fatal("node did not recover with a new sample")
	}
	// A new process uses the persisted installation pin, never a new first-use
	// fingerprint learned from the restarted host.
	value.IdentityFingerprint = "sha256:" + strings.Repeat("c", 64)
	restarted, err := New(service.host, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Refresh(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("restart discarded the identity pin")
	}
}

func TestSamplingContinuesWithoutAnyReaders(t *testing.T) {
	samples := make(chan time.Time, 4)
	config := samplingConfig()
	config.Interval, config.ProbeTimeout, config.MaximumAge = time.Second, 200*time.Millisecond, 3*time.Second
	service, err := New(hostFunc(func(context.Context, paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error) {
		value := sample(time.Now().UTC().Truncate(time.Microsecond))
		samples <- value.ObservedAt
		return value, nil
	}), config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	timeout := time.NewTimer(4 * time.Second)
	defer timeout.Stop()
	var first, second time.Time
	for _, target := range []*time.Time{&first, &second} {
		select {
		case *target = <-samples:
		case <-timeout.C:
			t.Fatal("background sampling stopped without readers")
		}
	}
	if !second.After(first) {
		t.Fatal("background sample was restamped rather than refreshed")
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		current, err := service.Current(context.Background())
		if err == nil && current.ObservedAt == second {
			break
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("new sample never became visible")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("sampler did not stop on cancellation")
	}
}
