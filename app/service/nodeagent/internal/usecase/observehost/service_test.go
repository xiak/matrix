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

type usageFunc func(context.Context) (paasv1.ExecutionTargetUsage, error)

func (fn usageFunc) ObserveExecutionTargetUsage(ctx context.Context) (paasv1.ExecutionTargetUsage, error) {
	return fn(ctx)
}

var noUsage = usageFunc(func(context.Context) (paasv1.ExecutionTargetUsage, error) {
	return paasv1.ExecutionTargetUsage{}, errors.New("collector unavailable")
})

func TestUsageFailureAndRecoveryDoNotChangeHostCapacity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	config := samplingConfig()
	config.Clock = func() time.Time { return now }
	var fail bool
	usage := usageFunc(func(context.Context) (paasv1.ExecutionTargetUsage, error) {
		if fail {
			return paasv1.ExecutionTargetUsage{}, errors.New("collector /private/key unavailable")
		}
		return paasv1.ExecutionTargetUsage{
			ObservedAt: now, ValidUntil: now.Add(time.Second),
			CPU:              paasv1.CPUUsage{State: paasv1.MeasurementWarmingUp},
			Memory:           paasv1.MemoryUsage{State: paasv1.MeasurementAvailable, Value: &paasv1.MemoryUsageValue{TotalBytes: 8000, AvailableBytes: 1000, UsedBytes: 7000}},
			FilesystemsState: paasv1.MeasurementUnavailable,
		}, nil
	})
	service, err := New(hostFunc(func(context.Context, paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error) {
		return sample(now), nil
	}), usage, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := service.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := service.Current(ctx)
	if err != nil || first.Usage.Memory.Value.UsedBytes != 7000 || first.Allocatable.MemoryBytes != 7800 {
		t.Fatal("usage replaced the placement budget")
	}
	first.Usage.Memory.Value.UsedBytes = 0
	now = now.Add(time.Second)
	stale, err := service.Current(ctx)
	if err != nil || stale.Usage.Memory.State != paasv1.MeasurementStale || stale.Usage.Memory.Value.UsedBytes != 7000 {
		t.Fatal("usage freshness was hidden by a healthy host or reader mutation")
	}
	fail = true
	if err := service.Refresh(ctx); err != nil {
		t.Fatal("metrics failure made the host unavailable")
	}
	missing, err := service.Current(ctx)
	if err != nil || missing.Health != paasv1.ExecutionTargetHealthReady || missing.Allocatable != first.Allocatable ||
		missing.Usage.Memory.State != paasv1.MeasurementUnavailable || missing.Usage.Memory.Value != nil {
		t.Fatal("failed metrics fabricated zero usage or changed host capacity")
	}
	fail = false
	now = now.Add(time.Second)
	if err := service.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, err := service.Current(ctx)
	if err != nil || recovered.Usage.Memory.State != paasv1.MeasurementAvailable || !recovered.Usage.ObservedAt.After(stale.Usage.ObservedAt) {
		t.Fatal("collector did not recover with a new measurement")
	}
}

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

func TestDefaultSamplingBudgetLeavesHeadroomForOneCPUHosts(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	config := samplingConfig()
	config.Clock = func() time.Time { return now }
	service, err := New(hostFunc(func(ctx context.Context, _ paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error) {
		deadline, found := ctx.Deadline()
		if !found || time.Until(deadline) < 5*time.Second {
			return paasv1.ExecutionTargetObservation{}, errors.New("host probe budget is too short")
		}
		return sample(now), nil
	}), noUsage, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Refresh(context.Background()); err != nil {
		t.Fatal("default sampling budget rejected a bounded one-CPU observation")
	}
	if service.config.Interval != defaultSamplingInterval ||
		service.config.ProbeTimeout != defaultProbeTimeout ||
		2*service.config.Interval > service.config.MaximumAge {
		t.Fatal("default sampling policy exceeds the freshness contract")
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
	}), noUsage, config)
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
	restarted, err := New(service.host, service.usage, config)
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
	}), noUsage, config)
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
