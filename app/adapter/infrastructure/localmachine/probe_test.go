package localmachine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingCapabilityChecker struct {
	mu        sync.Mutex
	available map[CapabilityProbeID]bool
	calls     []CapabilityProbeID
}

func (checker *recordingCapabilityChecker) Available(
	_ context.Context,
	id CapabilityProbeID,
) bool {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	checker.calls = append(checker.calls, id)
	return checker.available[id]
}

func (checker *recordingCapabilityChecker) recordedCalls() []CapabilityProbeID {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	return append([]CapabilityProbeID(nil), checker.calls...)
}

type synchronizedCapabilityChecker struct {
	started chan CapabilityProbeID
	release chan struct{}
}

func (checker synchronizedCapabilityChecker) Available(ctx context.Context, id CapabilityProbeID) bool {
	select {
	case checker.started <- id:
	case <-ctx.Done():
		return false
	}
	select {
	case <-checker.release:
		return true
	case <-ctx.Done():
		return false
	}
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
	calls := checker.recordedCalls()
	slices.Sort(calls)
	expected := []CapabilityProbeID{
		ProbeDockerEngine,
		ProbeComposePlugin,
	}
	slices.Sort(expected)
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("capability probe calls = %v", calls)
	}
}

func TestLocalHostProbeObservesIndependentCapabilitiesConcurrently(t *testing.T) {
	started := make(chan CapabilityProbeID, 2)
	release := make(chan struct{})
	checker := synchronizedCapabilityChecker{started: started, release: release}
	probe := newLocalHostProbe(checker)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type inspection struct {
		facts HostFacts
		err   error
	}
	done := make(chan inspection, 1)
	go func() {
		facts, err := probe.Inspect(ctx, "")
		done <- inspection{facts: facts, err: err}
	}()
	seen := map[CapabilityProbeID]bool{}
	for len(seen) != 2 {
		select {
		case id := <-started:
			seen[id] = true
		case <-ctx.Done():
			close(release)
			t.Fatal("independent capability probes did not start within one observation")
		}
	}
	close(release)
	result := <-done
	if result.err != nil || !result.facts.DockerEngineReady || !result.facts.ComposePluginReady ||
		!seen[ProbeDockerEngine] || !seen[ProbeComposePlugin] {
		t.Fatalf("concurrent capability observation = %+v / %v / %v", result.facts, result.err, seen)
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

func TestDefaultCapabilityProbeBudgetAccommodatesConstrainedNodes(t *testing.T) {
	if defaultCapabilityProbeTimeout <= 3*time.Second ||
		defaultCapabilityProbeTimeout >= 6*time.Second {
		t.Fatalf(
			"default capability probe timeout = %s, want more than three seconds inside the six-second observation deadline",
			defaultCapabilityProbeTimeout,
		)
	}
	probe := NewLocalHostProbe()
	checker, ok := probe.capabilities.(execCapabilityChecker)
	if !ok || checker.timeout != 0 {
		t.Fatalf("default local probe capability checker = %#v", probe.capabilities)
	}
}

func TestHostFactsFormattingRedactsRawMachineIdentity(t *testing.T) {
	facts := validHostFacts()
	facts.MachineID = "secret-machine-id-must-not-leak"
	rendered := fmt.Sprintf("%v %#v", facts, facts)
	if strings.Contains(rendered, facts.MachineID) {
		t.Fatalf("host facts formatting leaked raw machine ID: %q", rendered)
	}
	if !strings.Contains(rendered, "<redacted>") {
		t.Fatalf("host facts formatting is not visibly redacted: %q", rendered)
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
