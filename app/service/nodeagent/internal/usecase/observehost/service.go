package observehost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var ErrUnavailable = errors.New("current node observation is unavailable")

type HostObserver interface {
	ObserveExecutionTarget(context.Context, paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error)
}

type UsageObserver interface {
	ObserveExecutionTargetUsage(context.Context) (paasv1.ExecutionTargetUsage, error)
}

type Config struct {
	Identity            nodev1.Identity
	BindingRef          string
	ExpectedFingerprint string
	// SystemReserve is installation policy, not measured usage or a workload
	// reservation. Sampling never returns busy resources to the placement ledger.
	SystemReserve paasv1.Capacity
	Interval      time.Duration
	ProbeTimeout  time.Duration
	MaximumAge    time.Duration
	Clock         func() time.Time
}

type Service struct {
	host      HostObserver
	usage     UsageObserver
	config    Config
	mu        sync.RWMutex
	current   paasv1.ExecutionTargetObservation
	available bool
	refreshMu sync.Mutex
}

func New(host HostObserver, usage UsageObserver, config Config) (*Service, error) {
	if config.Interval == 0 {
		config.Interval = 5 * time.Second
	}
	if config.ProbeTimeout == 0 {
		config.ProbeTimeout = 4 * time.Second
	}
	if config.MaximumAge == 0 {
		config.MaximumAge = nodev1.MaximumObservationAge
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	reserve := config.SystemReserve
	if host == nil || usage == nil || nodev1.ValidateIdentity(config.Identity) != nil ||
		paasv1.ValidateID("bindingRef", config.BindingRef) != nil ||
		paasv1.ValidateDigest("expectedFingerprint", config.ExpectedFingerprint) != nil ||
		config.Interval < time.Second || config.Interval > 30*time.Second ||
		config.ProbeTimeout <= 0 || config.ProbeTimeout >= config.Interval ||
		config.MaximumAge < 2*config.Interval || config.MaximumAge > nodev1.MaximumObservationAge ||
		reserve.CPUMillis < 0 || reserve.MemoryBytes < 0 || reserve.StorageBytes < 0 || reserve.WorkloadSlots < 0 {
		return nil, errors.New("node sampling configuration is invalid")
	}
	return &Service{host: host, usage: usage, config: config}, nil
}

// Run samples without any request or open UI. A failed observation makes the
// node unavailable until a successful sample; it does not terminate workloads.
func (service *Service) Run(ctx context.Context) error {
	_ = service.Refresh(ctx)
	ticker := time.NewTicker(service.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = service.Refresh(ctx)
		}
	}
}

func (service *Service) Refresh(ctx context.Context) error {
	service.refreshMu.Lock()
	defer service.refreshMu.Unlock()
	probeContext, cancel := context.WithTimeout(ctx, service.config.ProbeTimeout)
	defer cancel()
	type usageResult struct {
		value paasv1.ExecutionTargetUsage
		err   error
	}
	usageDone := make(chan usageResult, 1)
	go func() {
		value, err := service.usage.ObserveExecutionTargetUsage(probeContext)
		usageDone <- usageResult{value: value, err: err}
	}()
	digest := sha256.Sum256([]byte(service.config.Identity.InstallationID + "\x00" +
		string(service.config.Identity.ExecutionTargetID) + "\x00" + service.config.BindingRef))
	id := hex.EncodeToString(digest[:])
	command := paasv1.AdapterCommandEnvelope{
		OperationID: paasv1.OperationID("node-observe-" + id), CommandID: paasv1.CommandID("node-observe-" + id),
		Attempt: 1, Action: paasv1.AdapterObserveExecutionTarget,
		Scope:             paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
		ExecutionTargetID: service.config.Identity.ExecutionTargetID, BindingRef: service.config.BindingRef,
		RequestDigest: "sha256:" + id, Deadline: service.now().Add(service.config.ProbeTimeout).Truncate(time.Microsecond),
	}
	value, err := service.host.ObserveExecutionTarget(probeContext, paasv1.ObserveExecutionTargetRequest{Command: command})
	hostAvailable := err == nil && probeContext.Err() == nil
	var usage usageResult
	select {
	case usage = <-usageDone:
	case <-probeContext.Done():
		usage.err = ErrUnavailable
	}
	now := service.now()
	valid := hostAvailable && ctx.Err() == nil && paasv1.ValidateExecutionTargetObservation(value) == nil &&
		value.ExecutionTargetID == service.config.Identity.ExecutionTargetID &&
		value.IdentityFingerprint == service.config.ExpectedFingerprint &&
		!value.ObservedAt.After(now) && now.Before(value.ObservedAt.Add(service.config.MaximumAge))
	if valid {
		// Availability from /proc or a filesystem probe is actual usage. It must
		// not be subtracted again from already-reserved scheduling capacity.
		reserve := service.config.SystemReserve
		value.Allocatable = paasv1.Capacity{
			CPUMillis:     value.Capacity.CPUMillis - reserve.CPUMillis,
			MemoryBytes:   value.Capacity.MemoryBytes - reserve.MemoryBytes,
			StorageBytes:  value.Capacity.StorageBytes - reserve.StorageBytes,
			WorkloadSlots: value.Capacity.WorkloadSlots - reserve.WorkloadSlots,
		}
		valid = paasv1.ValidateExecutionTargetObservation(value) == nil
	}
	// A metrics outage is not an infrastructure identity failure and never
	// changes capacity/reservations or stops accepted workloads.
	if usage.err != nil || paasv1.ValidateExecutionTargetUsage(usage.value) != nil ||
		usage.value.ObservedAt.After(now) || !now.Before(usage.value.ValidUntil) ||
		!now.Before(usage.value.ObservedAt.Add(service.config.MaximumAge)) {
		usage.value = paasv1.ExecutionTargetUsage{
			ObservedAt: now, ValidUntil: now.Add(service.config.MaximumAge),
			CPU:              paasv1.CPUUsage{State: paasv1.MeasurementUnavailable},
			Memory:           paasv1.MemoryUsage{State: paasv1.MeasurementUnavailable},
			FilesystemsState: paasv1.MeasurementUnavailable,
		}
	} else if maximum := usage.value.ObservedAt.Add(service.config.MaximumAge); usage.value.ValidUntil.After(maximum) {
		usage.value.ValidUntil = maximum
	}
	value.Usage = &usage.value
	service.mu.Lock()
	defer service.mu.Unlock()
	service.available = valid
	if !valid {
		return ErrUnavailable
	}
	service.current = cloneObservation(value)
	return nil
}

func (service *Service) Current(ctx context.Context) (paasv1.ExecutionTargetObservation, error) {
	if ctx.Err() != nil {
		return paasv1.ExecutionTargetObservation{}, ErrUnavailable
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	now := service.now()
	if !service.available || now.Before(service.current.ObservedAt) ||
		!now.Before(service.current.ObservedAt.Add(service.config.MaximumAge)) {
		return paasv1.ExecutionTargetObservation{}, ErrUnavailable
	}
	value := cloneObservation(service.current)
	if value.Usage != nil {
		usage := value.Usage.Snapshot(now)
		value.Usage = &usage
	}
	return value, nil
}

func (service *Service) now() time.Time {
	return service.config.Clock().UTC().Truncate(time.Microsecond)
}

func cloneObservation(value paasv1.ExecutionTargetObservation) paasv1.ExecutionTargetObservation {
	value.Labels = maps.Clone(value.Labels)
	value.SupportedIsolationGuarantees = slices.Clone(value.SupportedIsolationGuarantees)
	if value.Usage != nil {
		usage := value.Usage.Snapshot(value.Usage.ObservedAt)
		value.Usage = &usage
	}
	return value
}
