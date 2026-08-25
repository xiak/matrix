package localmachine

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	paasv1 "matrix/api/paas/v1"
)

const (
	adapterName            = "localmachine"
	adapterContractVersion = "v1"
)

type Clock func() time.Time

type Config struct {
	Bindings    BindingResolver
	LocalProbe  HostProbe
	RemoteProbe RemoteHostProbe
	Clock       Clock
}

type Adapter struct {
	bindings    BindingResolver
	localProbe  HostProbe
	remoteProbe RemoteHostProbe
	clock       Clock
}

func New(config Config) (*Adapter, error) {
	if config.Bindings == nil {
		return nil, errors.New("machine binding resolver is required")
	}
	if config.LocalProbe == nil {
		config.LocalProbe = NewLocalHostProbe()
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Adapter{
		bindings:    config.Bindings,
		localProbe:  config.LocalProbe,
		remoteProbe: config.RemoteProbe,
		clock:       config.Clock,
	}, nil
}

func (adapter *Adapter) Capabilities(
	ctx context.Context,
) (paasv1.AdapterCapabilitiesContract, error) {
	if err := ctx.Err(); err != nil {
		return paasv1.AdapterCapabilitiesContract{}, err
	}
	value := paasv1.AdapterCapabilitiesContract{
		Adapter: paasv1.AdapterRef{
			Kind:            paasv1.AdapterInfrastructure,
			Name:            adapterName,
			ContractVersion: adapterContractVersion,
		},
		Actions: []paasv1.AdapterAction{
			paasv1.AdapterCapabilities,
			paasv1.AdapterInspectTarget,
			paasv1.AdapterObserveTarget,
		},
		IsolationClasses: []paasv1.IsolationClass{
			paasv1.IsolationDedicatedCompose,
			paasv1.IsolationSharedCompose,
		},
		ObservedAt: adapter.now(),
	}
	if err := paasv1.ValidateAdapterCapabilities(value); err != nil {
		return paasv1.AdapterCapabilitiesContract{}, err
	}
	return value, nil
}

func (adapter *Adapter) InspectTarget(
	ctx context.Context,
	request paasv1.InspectTargetRequest,
) (paasv1.TargetObservation, error) {
	if err := paasv1.ValidateInspectTargetRequest(request); err != nil {
		return paasv1.TargetObservation{}, invalidRequestFault()
	}
	return adapter.inspect(ctx, request.Command)
}

func (adapter *Adapter) ObserveTarget(
	ctx context.Context,
	request paasv1.ObserveTargetRequest,
) (paasv1.TargetObservation, error) {
	if err := paasv1.ValidateObserveTargetRequest(request); err != nil {
		return paasv1.TargetObservation{}, invalidRequestFault()
	}
	return adapter.inspect(ctx, request.Command)
}

func (adapter *Adapter) inspect(
	ctx context.Context,
	command paasv1.AdapterCommandEnvelope,
) (paasv1.TargetObservation, error) {
	operationContext, cancel := context.WithDeadline(ctx, command.Deadline)
	defer cancel()
	binding, err := adapter.bindings.Resolve(operationContext, command.BindingRef)
	if err != nil {
		return paasv1.TargetObservation{}, resolveFault(command.BindingRef, err)
	}
	if err := ValidateMachineBinding(binding); err != nil {
		return paasv1.TargetObservation{}, invalidBindingFault(binding.id)
	}
	var facts HostFacts
	switch binding.kind {
	case BindingLocal:
		facts, err = adapter.localProbe.Inspect(operationContext, binding.storagePath)
	case BindingSSH:
		if adapter.remoteProbe == nil {
			return paasv1.TargetObservation{}, unsupportedBindingFault(binding.id)
		}
		facts, err = adapter.remoteProbe.Inspect(operationContext, binding)
	default:
		return paasv1.TargetObservation{}, invalidBindingFault(binding.id)
	}
	if err != nil {
		return paasv1.TargetObservation{}, normalizeProbeFault(binding.id, err)
	}
	observation, err := adapter.observation(command.RuntimeTargetID, binding, facts)
	if err != nil {
		return paasv1.TargetObservation{}, internalObservationFault(binding.id)
	}
	if expected := binding.expectedMachineFingerprint; expected != "" &&
		expected != observation.IdentityFingerprint {
		return paasv1.TargetObservation{}, identityConflictFault(binding.id)
	}
	return observation, nil
}

func (adapter *Adapter) observation(
	runtimeTargetID paasv1.ResourceID,
	binding MachineBinding,
	facts HostFacts,
) (paasv1.TargetObservation, error) {
	if err := validateHostFacts(facts); err != nil {
		return paasv1.TargetObservation{}, err
	}
	if facts.MemoryTotalBytes > math.MaxInt64 ||
		facts.MemoryAvailableBytes > math.MaxInt64 ||
		facts.StorageTotalBytes > math.MaxInt64 ||
		facts.StorageAvailableBytes > math.MaxInt64 {
		return paasv1.TargetObservation{}, errors.New("host capacity exceeds v1 integer range")
	}
	fingerprint, err := DeriveMachineFingerprint(facts)
	if err != nil {
		return paasv1.TargetObservation{}, err
	}
	cpuMillis := int64(facts.LogicalCPUs) * 1000
	workloadSlots := int64(facts.LogicalCPUs)
	labels := map[string]string{
		"matrix-arch": facts.Architecture,
		"matrix-os":   facts.OperatingSystem,
	}
	for key, value := range binding.labels {
		labels[key] = value
	}
	health := paasv1.TargetHealthDegraded
	var isolationClasses []paasv1.IsolationClass
	if facts.DockerEngineReady && facts.ComposePluginReady {
		health = paasv1.TargetHealthReady
		isolationClasses = binding.AllowedIsolationClasses()
	}
	value := paasv1.TargetObservation{
		RuntimeTargetID:     runtimeTargetID,
		IdentityFingerprint: fingerprint,
		Labels:              labels,
		Capacity: paasv1.Capacity{
			CPUMillis:     cpuMillis,
			MemoryBytes:   int64(facts.MemoryTotalBytes),
			StorageBytes:  int64(facts.StorageTotalBytes),
			WorkloadSlots: workloadSlots,
		},
		Allocatable: paasv1.Capacity{
			CPUMillis:     cpuMillis,
			MemoryBytes:   int64(facts.MemoryAvailableBytes),
			StorageBytes:  int64(facts.StorageAvailableBytes),
			WorkloadSlots: workloadSlots,
		},
		Health:                    health,
		SupportedIsolationClasses: isolationClasses,
		ObservedAt:                adapter.now(),
	}
	if err := paasv1.ValidateTargetObservation(value); err != nil {
		return paasv1.TargetObservation{}, err
	}
	return value, nil
}

func (adapter *Adapter) now() time.Time {
	return adapter.clock().UTC().Truncate(time.Microsecond)
}

func invalidRequestFault() paasv1.AdapterFault {
	return newAdapterFault(
		paasv1.AdapterErrorValidation,
		paasv1.ErrorInvalidArgument,
		"localmachine adapter request is invalid",
		false,
	)
}

func invalidBindingFault(id string) paasv1.AdapterFault {
	return newAdapterFault(
		paasv1.AdapterErrorValidation,
		paasv1.ErrorInvalidArgument,
		fmt.Sprintf("machine binding %s is invalid", id),
		false,
	)
}

func unsupportedBindingFault(id string) paasv1.AdapterFault {
	return newAdapterFault(
		paasv1.AdapterErrorValidation,
		paasv1.ErrorCapabilityUnsupported,
		fmt.Sprintf("machine binding %s requires an unavailable transport", id),
		false,
	)
}

func identityConflictFault(id string) paasv1.AdapterFault {
	return newAdapterFault(
		paasv1.AdapterErrorConflict,
		paasv1.ErrorConflict,
		fmt.Sprintf("machine binding %s resolved to an unexpected identity", id),
		false,
	)
}

func internalObservationFault(id string) paasv1.AdapterFault {
	return newAdapterFault(
		paasv1.AdapterErrorInternal,
		paasv1.ErrorInternal,
		fmt.Sprintf("machine binding %s produced an invalid observation", id),
		false,
	)
}

func resolveFault(id string, err error) paasv1.AdapterFault {
	switch {
	case errors.Is(err, ErrBindingNotFound):
		return newAdapterFault(
			paasv1.AdapterErrorNotFound,
			paasv1.ErrorNotFound,
			fmt.Sprintf("machine binding %s was not found", id),
			false,
		)
	case errors.Is(err, context.DeadlineExceeded):
		return timeoutFault(id)
	default:
		return newAdapterFault(
			paasv1.AdapterErrorUnavailable,
			paasv1.ErrorTargetUnavailable,
			fmt.Sprintf("machine binding %s could not be resolved", id),
			true,
		)
	}
}

func normalizeProbeFault(id string, err error) paasv1.AdapterFault {
	var failure ProbeFailure
	if !errors.As(err, &failure) {
		return newAdapterFault(
			paasv1.AdapterErrorInternal,
			paasv1.ErrorInternal,
			fmt.Sprintf("machine binding %s probe failed", id),
			false,
		)
	}
	switch failure.Kind {
	case ProbeFailureValidation:
		return newAdapterFault(
			paasv1.AdapterErrorValidation,
			paasv1.ErrorAdapterRejected,
			fmt.Sprintf("machine binding %s returned an invalid observation", id),
			false,
		)
	case ProbeFailureTimeout:
		return timeoutFault(id)
	case ProbeFailureUnavailable:
		return newAdapterFault(
			paasv1.AdapterErrorUnavailable,
			paasv1.ErrorTargetUnavailable,
			fmt.Sprintf("machine binding %s is unavailable", id),
			true,
		)
	case ProbeFailurePermission:
		return newAdapterFault(
			paasv1.AdapterErrorPermissionDenied,
			paasv1.ErrorPermissionDenied,
			fmt.Sprintf("machine binding %s credential was rejected", id),
			false,
		)
	case ProbeFailureHostKey:
		return newAdapterFault(
			paasv1.AdapterErrorPermissionDenied,
			paasv1.ErrorAdapterRejected,
			fmt.Sprintf("machine binding %s host identity was rejected", id),
			false,
		)
	default:
		return newAdapterFault(
			paasv1.AdapterErrorInternal,
			paasv1.ErrorInternal,
			fmt.Sprintf("machine binding %s probe failed", id),
			false,
		)
	}
}

func timeoutFault(id string) paasv1.AdapterFault {
	return newAdapterFault(
		paasv1.AdapterErrorTimeout,
		paasv1.ErrorDeadlineExceeded,
		fmt.Sprintf("machine binding %s probe exceeded its deadline", id),
		true,
	)
}

func newAdapterFault(
	class paasv1.AdapterErrorClass,
	code paasv1.ErrorCode,
	message string,
	retryable bool,
) paasv1.AdapterFault {
	normalized := paasv1.NormalizedAdapterError{
		Class:     class,
		Code:      code,
		Message:   message,
		Retryable: retryable,
	}
	if err := paasv1.ValidateNormalizedAdapterError(normalized); err != nil {
		return paasv1.AdapterFault{
			Normalized: paasv1.NormalizedAdapterError{
				Class:     paasv1.AdapterErrorInternal,
				Code:      paasv1.ErrorInternal,
				Message:   "localmachine adapter produced an invalid normalized failure",
				Retryable: false,
			},
		}
	}
	return paasv1.AdapterFault{Normalized: normalized}
}
