package localmachine

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	paasv1 "matrix/api/paas/v1"
)

type infrastructureContract interface {
	Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error)
	InspectTarget(context.Context, paasv1.InspectTargetRequest) (paasv1.TargetObservation, error)
	ObserveTarget(context.Context, paasv1.ObserveTargetRequest) (paasv1.TargetObservation, error)
}

var _ infrastructureContract = (*Adapter)(nil)

type fakeHostProbe struct {
	facts HostFacts
	err   error
	calls int
}

func (probe *fakeHostProbe) Inspect(
	_ context.Context,
	_ string,
) (HostFacts, error) {
	probe.calls++
	return probe.facts, probe.err
}

func TestAdapterCapabilitiesAreVersionedAndExact(t *testing.T) {
	adapter := mustAdapter(t, mustLocalBinding(t, ""), &fakeHostProbe{
		facts: validHostFacts(),
	})
	capabilities, err := adapter.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities() error = %v", err)
	}
	if err := paasv1.ValidateAdapterCapabilities(capabilities); err != nil {
		t.Fatalf("capabilities contract is invalid: %v", err)
	}
	if capabilities.Adapter.Kind != paasv1.AdapterInfrastructure ||
		capabilities.Adapter.Name != adapterName ||
		capabilities.Adapter.ContractVersion != adapterContractVersion {
		t.Fatalf("adapter identity = %+v", capabilities.Adapter)
	}
	if !reflect.DeepEqual(capabilities.Actions, []paasv1.AdapterAction{
		paasv1.AdapterCapabilities,
		paasv1.AdapterInspectTarget,
		paasv1.AdapterObserveTarget,
	}) {
		t.Fatalf("adapter actions = %v", capabilities.Actions)
	}
}

func TestInspectTargetProducesStableReadyObservation(t *testing.T) {
	probe := &fakeHostProbe{facts: validHostFacts()}
	adapter := mustAdapter(t, mustLocalBinding(t, ""), probe)
	request := validInspectTargetRequest()

	first, err := adapter.InspectTarget(context.Background(), request)
	if err != nil {
		t.Fatalf("first InspectTarget() error = %v", err)
	}
	second, err := adapter.InspectTarget(context.Background(), request)
	if err != nil {
		t.Fatalf("second InspectTarget() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated observations differ:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if probe.calls != 2 {
		t.Fatalf("read-only probe calls = %d, want 2", probe.calls)
	}
	if err := paasv1.ValidateTargetObservation(first); err != nil {
		t.Fatalf("target observation is invalid: %v", err)
	}
	if first.Health != paasv1.TargetHealthReady {
		t.Fatalf("target health = %q, want READY", first.Health)
	}
	if first.RuntimeTargetID != request.Command.RuntimeTargetID {
		t.Fatalf("runtime target id = %q", first.RuntimeTargetID)
	}
	if first.Labels["location"] != "local" ||
		first.Labels["matrix-os"] != probe.facts.OperatingSystem ||
		first.Labels["matrix-arch"] != probe.facts.Architecture {
		t.Fatalf("normalized labels = %v", first.Labels)
	}
	if !reflect.DeepEqual(first.SupportedIsolationClasses, []paasv1.IsolationClass{
		paasv1.IsolationDedicatedCompose,
		paasv1.IsolationSharedCompose,
	}) {
		t.Fatalf("isolation classes = %v", first.SupportedIsolationClasses)
	}
}

func TestAdapterInspectsTheRealLocalHostThroughVersionedContract(t *testing.T) {
	checker := &recordingCapabilityChecker{available: map[CapabilityProbeID]bool{}}
	adapter := mustAdapter(
		t,
		mustLocalBinding(t, ""),
		newLocalHostProbe(checker),
	)
	observation, err := adapter.InspectTarget(
		context.Background(),
		validInspectTargetRequest(),
	)
	if err != nil {
		t.Fatalf("real local InspectTarget() error = %v", err)
	}
	if err := paasv1.ValidateTargetObservation(observation); err != nil {
		t.Fatalf("real local observation is invalid: %v", err)
	}
	if observation.IdentityFingerprint == "" ||
		observation.Capacity.CPUMillis <= 0 ||
		observation.Capacity.MemoryBytes <= 0 ||
		observation.Capacity.StorageBytes <= 0 {
		t.Fatalf("real local observation is incomplete: %+v", observation)
	}
	if observation.Health != paasv1.TargetHealthDegraded ||
		len(observation.SupportedIsolationClasses) != 0 {
		t.Fatalf("disabled Compose capability must fail closed: %+v", observation)
	}
}

func TestInspectTargetWithMissingDockerIsDegradedWithoutIsolation(t *testing.T) {
	facts := validHostFacts()
	facts.DockerEngineReady = false
	adapter := mustAdapter(t, mustLocalBinding(t, ""), &fakeHostProbe{facts: facts})

	observation, err := adapter.InspectTarget(context.Background(), validInspectTargetRequest())
	if err != nil {
		t.Fatalf("InspectTarget() error = %v", err)
	}
	if observation.Health != paasv1.TargetHealthDegraded {
		t.Fatalf("target health = %q, want DEGRADED", observation.Health)
	}
	if len(observation.SupportedIsolationClasses) != 0 {
		t.Fatalf("degraded target advertised isolation: %v", observation.SupportedIsolationClasses)
	}
}

func TestInspectTargetFailsOnUnexpectedMachineIdentity(t *testing.T) {
	binding := mustLocalBinding(
		t,
		"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	)
	adapter := mustAdapter(t, binding, &fakeHostProbe{facts: validHostFacts()})

	_, err := adapter.InspectTarget(context.Background(), validInspectTargetRequest())
	fault := requireAdapterFault(t, err)
	if fault.Normalized.Class != paasv1.AdapterErrorConflict ||
		fault.Normalized.Code != paasv1.ErrorConflict ||
		fault.Normalized.Retryable {
		t.Fatalf("identity conflict = %+v", fault.Normalized)
	}
}

func TestInspectTargetNormalizesBindingAndProbeFailures(t *testing.T) {
	adapter := mustAdapter(t, mustLocalBinding(t, ""), &fakeHostProbe{
		err: errors.New("password=must-not-leak endpoint=10.0.0.9"),
	})
	_, err := adapter.InspectTarget(context.Background(), validInspectTargetRequest())
	fault := requireAdapterFault(t, err)
	if fault.Normalized.Code != paasv1.ErrorInternal {
		t.Fatalf("native probe code = %q, want INTERNAL", fault.Normalized.Code)
	}
	if strings.Contains(strings.ToLower(fault.Error()), "password") ||
		strings.Contains(fault.Error(), "10.0.0.9") {
		t.Fatalf("normalized fault leaked native error: %q", fault.Error())
	}

	timeoutAdapter := mustAdapter(t, mustLocalBinding(t, ""), &fakeHostProbe{
		err: ProbeFailure{Kind: ProbeFailureTimeout, ID: "host"},
	})
	_, err = timeoutAdapter.InspectTarget(context.Background(), validInspectTargetRequest())
	fault = requireAdapterFault(t, err)
	if fault.Normalized.Class != paasv1.AdapterErrorTimeout ||
		fault.Normalized.Code != paasv1.ErrorDeadlineExceeded ||
		!fault.Normalized.Retryable {
		t.Fatalf("timeout fault = %+v", fault.Normalized)
	}
}

func TestInspectTargetRejectsUnknownAndUnavailableBindings(t *testing.T) {
	resolver, err := NewStaticBindingResolver()
	if err != nil {
		t.Fatalf("NewStaticBindingResolver() error = %v", err)
	}
	adapter, err := New(Config{
		Bindings:   resolver,
		LocalProbe: &fakeHostProbe{facts: validHostFacts()},
		Clock:      fixedClock,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = adapter.InspectTarget(context.Background(), validInspectTargetRequest())
	fault := requireAdapterFault(t, err)
	if fault.Normalized.Class != paasv1.AdapterErrorNotFound ||
		fault.Normalized.Code != paasv1.ErrorNotFound {
		t.Fatalf("missing binding fault = %+v", fault.Normalized)
	}

	sshBinding, err := NewMachineBinding(MachineBindingSpec{
		ID:                      "local",
		Kind:                    BindingSSH,
		Endpoint:                "node.example.internal:22",
		CredentialRef:           "credential-node",
		HostKeySHA256:           "SHA256:" + strings.Repeat("A", 43),
		AllowedIsolationClasses: []paasv1.IsolationClass{paasv1.IsolationSharedCompose},
	})
	if err != nil {
		t.Fatalf("NewMachineBinding(SSH) error = %v", err)
	}
	adapter = mustAdapter(t, sshBinding, &fakeHostProbe{facts: validHostFacts()})
	_, err = adapter.InspectTarget(context.Background(), validInspectTargetRequest())
	fault = requireAdapterFault(t, err)
	if fault.Normalized.Code != paasv1.ErrorCapabilityUnsupported {
		t.Fatalf("Gate A SSH fault = %+v", fault.Normalized)
	}
}

func TestInspectAndObserveRequireTheirExactActions(t *testing.T) {
	adapter := mustAdapter(t, mustLocalBinding(t, ""), &fakeHostProbe{
		facts: validHostFacts(),
	})
	inspect := validInspectTargetRequest()
	inspect.Command.Action = paasv1.AdapterObserveTarget
	_, err := adapter.InspectTarget(context.Background(), inspect)
	if fault := requireAdapterFault(t, err); fault.Normalized.Code != paasv1.ErrorInvalidArgument {
		t.Fatalf("inspect action fault = %+v", fault.Normalized)
	}

	observe := paasv1.ObserveTargetRequest{Command: validInspectTargetRequest().Command}
	observe.Command.Action = paasv1.AdapterObserveTarget
	if _, err := adapter.ObserveTarget(context.Background(), observe); err != nil {
		t.Fatalf("ObserveTarget() error = %v", err)
	}
}

func TestVersionedObservationCannotCarryMachineAccessMaterial(t *testing.T) {
	observation := reflect.TypeOf(paasv1.TargetObservation{})
	forbidden := []string{
		"endpoint",
		"credential",
		"username",
		"password",
		"ssh",
		"command",
		"script",
		"hostpath",
		"privatekey",
		"rawoutput",
	}
	for index := 0; index < observation.NumField(); index++ {
		field := observation.Field(index)
		normalized := strings.ToLower(
			field.Name + strings.Split(field.Tag.Get("json"), ",")[0],
		)
		for _, marker := range forbidden {
			if strings.Contains(normalized, marker) {
				t.Errorf("TargetObservation field %q contains forbidden marker %q", field.Name, marker)
			}
		}
	}
}

func mustAdapter(
	t *testing.T,
	binding MachineBinding,
	probe HostProbe,
) *Adapter {
	t.Helper()
	resolver, err := NewStaticBindingResolver(binding)
	if err != nil {
		t.Fatalf("NewStaticBindingResolver() error = %v", err)
	}
	adapter, err := New(Config{
		Bindings:   resolver,
		LocalProbe: probe,
		Clock:      fixedClock,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return adapter
}

func fixedClock() time.Time {
	return time.Date(2026, 8, 25, 12, 0, 0, 123456000, time.UTC)
}

func validInspectTargetRequest() paasv1.InspectTargetRequest {
	return paasv1.InspectTargetRequest{
		Command: paasv1.AdapterCommandEnvelope{
			OperationID:     "operation-register-target-001",
			CommandID:       "command-inspect-target-001",
			Attempt:         1,
			Action:          paasv1.AdapterInspectTarget,
			Scope:           paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
			RuntimeTargetID: "target-local-001",
			RequestDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			BindingRef:      "local",
			Deadline:        time.Date(2099, 8, 25, 12, 5, 0, 0, time.UTC),
		},
	}
}

func requireAdapterFault(t *testing.T, err error) paasv1.AdapterFault {
	t.Helper()
	if err == nil {
		t.Fatal("expected adapter fault, got nil")
	}
	var fault paasv1.AdapterFault
	if !errors.As(err, &fault) {
		t.Fatalf("error type = %T, want paasv1.AdapterFault", err)
	}
	if validationErr := paasv1.ValidateNormalizedAdapterError(fault.Normalized); validationErr != nil {
		t.Fatalf("normalized adapter fault is invalid: %v", validationErr)
	}
	return fault
}
