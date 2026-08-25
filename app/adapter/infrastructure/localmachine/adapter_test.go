package localmachine

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type infrastructureContract interface {
	Capabilities(context.Context) (paasv1.AdapterCapabilitiesContract, error)
	InspectExecutionTarget(context.Context, paasv1.InspectExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error)
	ObserveExecutionTarget(context.Context, paasv1.ObserveExecutionTargetRequest) (paasv1.ExecutionTargetObservation, error)
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
		paasv1.AdapterInspectExecutionTarget,
		paasv1.AdapterObserveExecutionTarget,
	}) {
		t.Fatalf("adapter actions = %v", capabilities.Actions)
	}
}

func TestInspectExecutionTargetProducesStableReadyObservation(t *testing.T) {
	probe := &fakeHostProbe{facts: validHostFacts()}
	adapter := mustAdapter(t, mustLocalBinding(t, ""), probe)
	request := validInspectExecutionTargetRequest()

	first, err := adapter.InspectExecutionTarget(context.Background(), request)
	if err != nil {
		t.Fatalf("first InspectExecutionTarget() error = %v", err)
	}
	second, err := adapter.InspectExecutionTarget(context.Background(), request)
	if err != nil {
		t.Fatalf("second InspectExecutionTarget() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated observations differ:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if probe.calls != 2 {
		t.Fatalf("read-only probe calls = %d, want 2", probe.calls)
	}
	if err := paasv1.ValidateExecutionTargetObservation(first); err != nil {
		t.Fatalf("target observation is invalid: %v", err)
	}
	if first.Health != paasv1.ExecutionTargetHealthReady {
		t.Fatalf("target health = %q, want READY", first.Health)
	}
	if first.ExecutionTargetID != request.Command.ExecutionTargetID {
		t.Fatalf("execution target id = %q", first.ExecutionTargetID)
	}
	if first.Labels["location"] != "local" ||
		first.Labels["matrix-os"] != probe.facts.OperatingSystem ||
		first.Labels["matrix-arch"] != probe.facts.Architecture {
		t.Fatalf("normalized labels = %v", first.Labels)
	}
	if !reflect.DeepEqual(first.SupportedIsolationGuarantees, []paasv1.IsolationGuarantee{
		paasv1.IsolationWorkload,
	}) {
		t.Fatalf("isolation guarantees = %v", first.SupportedIsolationGuarantees)
	}
}

func TestAdapterInspectsTheRealLocalHostThroughVersionedContract(t *testing.T) {
	checker := &recordingCapabilityChecker{available: map[CapabilityProbeID]bool{}}
	adapter := mustAdapter(
		t,
		mustLocalBinding(t, ""),
		newLocalHostProbe(checker),
	)
	observation, err := adapter.InspectExecutionTarget(
		context.Background(),
		validInspectExecutionTargetRequest(),
	)
	if err != nil {
		t.Fatalf("real local InspectExecutionTarget() error = %v", err)
	}
	if err := paasv1.ValidateExecutionTargetObservation(observation); err != nil {
		t.Fatalf("real local observation is invalid: %v", err)
	}
	if observation.IdentityFingerprint == "" ||
		observation.Capacity.CPUMillis <= 0 ||
		observation.Capacity.MemoryBytes <= 0 ||
		observation.Capacity.StorageBytes <= 0 {
		t.Fatalf("real local observation is incomplete: %+v", observation)
	}
	if observation.Health != paasv1.ExecutionTargetHealthDegraded ||
		len(observation.SupportedIsolationGuarantees) != 0 {
		t.Fatalf("disabled Compose capability must fail closed: %+v", observation)
	}
}

func TestInspectExecutionTargetWithMissingDockerIsDegradedWithoutIsolation(t *testing.T) {
	facts := validHostFacts()
	facts.DockerEngineReady = false
	adapter := mustAdapter(t, mustLocalBinding(t, ""), &fakeHostProbe{facts: facts})

	observation, err := adapter.InspectExecutionTarget(context.Background(), validInspectExecutionTargetRequest())
	if err != nil {
		t.Fatalf("InspectExecutionTarget() error = %v", err)
	}
	if observation.Health != paasv1.ExecutionTargetHealthDegraded {
		t.Fatalf("target health = %q, want DEGRADED", observation.Health)
	}
	if len(observation.SupportedIsolationGuarantees) != 0 {
		t.Fatalf("degraded target advertised isolation: %v", observation.SupportedIsolationGuarantees)
	}
}

func TestInspectExecutionTargetFailsOnUnexpectedMachineIdentity(t *testing.T) {
	binding := mustLocalBinding(
		t,
		"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	)
	adapter := mustAdapter(t, binding, &fakeHostProbe{facts: validHostFacts()})

	_, err := adapter.InspectExecutionTarget(context.Background(), validInspectExecutionTargetRequest())
	fault := requireAdapterFault(t, err)
	if fault.Normalized.Class != paasv1.AdapterErrorConflict ||
		fault.Normalized.Code != paasv1.ErrorConflict ||
		fault.Normalized.Retryable {
		t.Fatalf("identity conflict = %+v", fault.Normalized)
	}
}

func TestInspectExecutionTargetNormalizesBindingAndProbeFailures(t *testing.T) {
	adapter := mustAdapter(t, mustLocalBinding(t, ""), &fakeHostProbe{
		err: errors.New("password=must-not-leak endpoint=10.0.0.9"),
	})
	_, err := adapter.InspectExecutionTarget(context.Background(), validInspectExecutionTargetRequest())
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
	_, err = timeoutAdapter.InspectExecutionTarget(context.Background(), validInspectExecutionTargetRequest())
	fault = requireAdapterFault(t, err)
	if fault.Normalized.Class != paasv1.AdapterErrorTimeout ||
		fault.Normalized.Code != paasv1.ErrorDeadlineExceeded ||
		!fault.Normalized.Retryable {
		t.Fatalf("timeout fault = %+v", fault.Normalized)
	}
}

func TestInspectExecutionTargetRejectsUnknownAndUnavailableBindings(t *testing.T) {
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
	_, err = adapter.InspectExecutionTarget(context.Background(), validInspectExecutionTargetRequest())
	fault := requireAdapterFault(t, err)
	if fault.Normalized.Class != paasv1.AdapterErrorNotFound ||
		fault.Normalized.Code != paasv1.ErrorNotFound {
		t.Fatalf("missing binding fault = %+v", fault.Normalized)
	}

	sshBinding, err := NewMachineBinding(MachineBindingSpec{
		ID:                         "local",
		Kind:                       BindingSSH,
		Endpoint:                   "node.example.internal:22",
		CredentialRef:              "credential-node",
		HostKeySHA256:              "SHA256:" + strings.Repeat("A", 43),
		AllowedIsolationGuarantees: []paasv1.IsolationGuarantee{paasv1.IsolationWorkload},
	})
	if err != nil {
		t.Fatalf("NewMachineBinding(SSH) error = %v", err)
	}
	adapter = mustAdapter(t, sshBinding, &fakeHostProbe{facts: validHostFacts()})
	_, err = adapter.InspectExecutionTarget(context.Background(), validInspectExecutionTargetRequest())
	fault = requireAdapterFault(t, err)
	if fault.Normalized.Code != paasv1.ErrorCapabilityUnsupported {
		t.Fatalf("Gate A SSH fault = %+v", fault.Normalized)
	}
}

func TestInspectAndObserveRequireTheirExactActions(t *testing.T) {
	adapter := mustAdapter(t, mustLocalBinding(t, ""), &fakeHostProbe{
		facts: validHostFacts(),
	})
	inspect := validInspectExecutionTargetRequest()
	inspect.Command.Action = paasv1.AdapterObserveExecutionTarget
	_, err := adapter.InspectExecutionTarget(context.Background(), inspect)
	if fault := requireAdapterFault(t, err); fault.Normalized.Code != paasv1.ErrorInvalidArgument {
		t.Fatalf("inspect action fault = %+v", fault.Normalized)
	}

	observe := paasv1.ObserveExecutionTargetRequest{Command: validInspectExecutionTargetRequest().Command}
	observe.Command.Action = paasv1.AdapterObserveExecutionTarget
	if _, err := adapter.ObserveExecutionTarget(context.Background(), observe); err != nil {
		t.Fatalf("ObserveExecutionTarget() error = %v", err)
	}
}

func TestVersionedObservationCannotCarryMachineAccessMaterial(t *testing.T) {
	observation := reflect.TypeOf(paasv1.ExecutionTargetObservation{})
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
				t.Errorf("ExecutionTargetObservation field %q contains forbidden marker %q", field.Name, marker)
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

func validInspectExecutionTargetRequest() paasv1.InspectExecutionTargetRequest {
	return paasv1.InspectExecutionTargetRequest{
		Command: paasv1.AdapterCommandEnvelope{
			OperationID:       "operation-register-target-001",
			CommandID:         "command-inspect-target-001",
			Attempt:           1,
			Action:            paasv1.AdapterInspectExecutionTarget,
			Scope:             paasv1.ResourceScope{Kind: paasv1.AuthorityPlatform},
			ExecutionTargetID: "target-local-001",
			RequestDigest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			BindingRef:        "local",
			Deadline:          time.Date(2099, 8, 25, 12, 5, 0, 0, time.UTC),
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
