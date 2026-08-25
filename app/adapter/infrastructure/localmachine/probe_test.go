package localmachine

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type recordingCapabilityChecker struct {
	available map[CapabilityProbeID]bool
	calls     []CapabilityProbeID
}

func (checker *recordingCapabilityChecker) Available(
	_ context.Context,
	id CapabilityProbeID,
) bool {
	checker.calls = append(checker.calls, id)
	return checker.available[id]
}

func TestLocalHostProbeUsesClosedCapabilityIdentifiers(t *testing.T) {
	checker := &recordingCapabilityChecker{
		available: map[CapabilityProbeID]bool{
			ProbeDockerEngine:  true,
			ProbeComposePlugin: true,
		},
	}
	probe := newLocalHostProbe(checker)
	facts, err := probe.Inspect(context.Background(), "")
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !facts.DockerEngineReady || !facts.ComposePluginReady {
		t.Fatal("capability facts did not preserve fixed probe results")
	}
	if !reflect.DeepEqual(checker.calls, []CapabilityProbeID{
		ProbeDockerEngine,
		ProbeComposePlugin,
	}) {
		t.Fatalf("capability probe calls = %v", checker.calls)
	}
}

func TestLocalHostProbeRespectsCancelledContextBeforeHostAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newLocalHostProbe(&recordingCapabilityChecker{}).Inspect(ctx, "")
	var failure ProbeFailure
	if !errors.As(err, &failure) {
		t.Fatalf("cancelled probe error = %T, want ProbeFailure", err)
	}
	if failure.Kind != ProbeFailureUnavailable {
		t.Fatalf("cancelled probe kind = %q, want %q", failure.Kind, ProbeFailureUnavailable)
	}
}

func TestExecCapabilityCheckerRejectsUnknownProbeWithoutExecution(t *testing.T) {
	checker := execCapabilityChecker{timeout: time.Second}
	if checker.Available(context.Background(), CapabilityProbeID("caller-command")) {
		t.Fatal("unknown capability probe must fail closed")
	}
}

func TestRealLocalHostInspectionHasStableIdentityAndPositiveCapacity(t *testing.T) {
	checker := &recordingCapabilityChecker{available: map[CapabilityProbeID]bool{}}
	probe := newLocalHostProbe(checker)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	first, err := probe.Inspect(ctx, "")
	if err != nil {
		t.Fatalf("first real host Inspect() error = %v", err)
	}
	second, err := probe.Inspect(ctx, "")
	if err != nil {
		t.Fatalf("second real host Inspect() error = %v", err)
	}
	firstIdentity, err := DeriveMachineFingerprint(first)
	if err != nil {
		t.Fatalf("first real identity error = %v", err)
	}
	secondIdentity, err := DeriveMachineFingerprint(second)
	if err != nil {
		t.Fatalf("second real identity error = %v", err)
	}
	if firstIdentity != secondIdentity {
		t.Fatalf("real host identity changed: %q and %q", firstIdentity, secondIdentity)
	}
	if first.LogicalCPUs <= 0 ||
		first.MemoryTotalBytes == 0 ||
		first.StorageTotalBytes == 0 {
		t.Fatalf("real host capacity is incomplete: %+v", first)
	}
	if first.MachineID == "" || first.OperatingSystem == "" || first.Architecture == "" {
		t.Fatalf("real host identity facts are incomplete: %+v", first)
	}
}
