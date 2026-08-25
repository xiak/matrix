package runtime

import (
	"testing"

	paasv1 "matrix/api/paas/v1"
)

func TestOperationTransitionsAreExact(t *testing.T) {
	allowed := map[paasv1.OperationState][]paasv1.OperationState{
		paasv1.OperationAccepted: {
			paasv1.OperationPlanning,
			paasv1.OperationFailed,
			paasv1.OperationCancelled,
		},
		paasv1.OperationPlanning: {
			paasv1.OperationQueued,
			paasv1.OperationFailed,
			paasv1.OperationCancelled,
		},
		paasv1.OperationQueued: {
			paasv1.OperationExecuting,
			paasv1.OperationFailed,
			paasv1.OperationCancelled,
		},
		paasv1.OperationExecuting: {
			paasv1.OperationVerifying,
			paasv1.OperationReconciling,
			paasv1.OperationFailed,
			paasv1.OperationCancelled,
		},
		paasv1.OperationVerifying: {
			paasv1.OperationSucceeded,
			paasv1.OperationReconciling,
			paasv1.OperationFailed,
		},
		paasv1.OperationReconciling: {
			paasv1.OperationExecuting,
			paasv1.OperationVerifying,
			paasv1.OperationFailed,
			paasv1.OperationCancelled,
			paasv1.OperationManualIntervention,
		},
	}

	for _, from := range paasv1.OperationStates() {
		for _, to := range paasv1.OperationStates() {
			want := containsOperationState(allowed[from], to)
			if got := CanTransitionOperation(from, to); got != want {
				t.Errorf("CanTransitionOperation(%q, %q) = %v, want %v", from, to, got, want)
			}
			err := ValidateOperationTransition(from, to)
			if (err == nil) != want {
				t.Errorf("ValidateOperationTransition(%q, %q) error = %v, want allowed %v", from, to, err, want)
			}
		}
	}
}

func TestOperationTerminalStatesAreExactAndImmutable(t *testing.T) {
	terminal := map[paasv1.OperationState]bool{
		paasv1.OperationSucceeded:          true,
		paasv1.OperationFailed:             true,
		paasv1.OperationCancelled:          true,
		paasv1.OperationManualIntervention: true,
	}
	for _, state := range paasv1.OperationStates() {
		if got := IsTerminalOperationState(state); got != terminal[state] {
			t.Errorf("IsTerminalOperationState(%q) = %v, want %v", state, got, terminal[state])
		}
		if !terminal[state] {
			continue
		}
		for _, next := range paasv1.OperationStates() {
			if CanTransitionOperation(state, next) {
				t.Errorf("terminal state %q unexpectedly transitions to %q", state, next)
			}
		}
	}
}

func TestOperationTransitionRejectsUnknownStates(t *testing.T) {
	unknown := paasv1.OperationState("FUTURE_STATE")
	if CanTransitionOperation(unknown, paasv1.OperationFailed) {
		t.Fatal("unknown source state must fail closed")
	}
	if err := ValidateOperationTransition(unknown, paasv1.OperationFailed); err == nil {
		t.Fatal("unknown source state must be rejected")
	}
	if err := ValidateOperationTransition(paasv1.OperationAccepted, unknown); err == nil {
		t.Fatal("unknown destination state must be rejected")
	}
}

func TestReleaseTransitionsAreExact(t *testing.T) {
	allowed := map[paasv1.ReleasePhase][]paasv1.ReleasePhase{
		paasv1.ReleasePending: {
			paasv1.ReleasePlacing,
			paasv1.ReleaseFailed,
		},
		paasv1.ReleasePlacing: {
			paasv1.ReleaseApplying,
			paasv1.ReleaseFailed,
		},
		paasv1.ReleaseApplying: {
			paasv1.ReleaseReady,
			paasv1.ReleaseDegraded,
			paasv1.ReleaseFailed,
		},
		paasv1.ReleaseReady: {
			paasv1.ReleaseDegraded,
			paasv1.ReleaseFailed,
			paasv1.ReleaseStopping,
		},
		paasv1.ReleaseDegraded: {
			paasv1.ReleaseReady,
			paasv1.ReleaseFailed,
			paasv1.ReleaseStopping,
		},
		paasv1.ReleaseStopping: {
			paasv1.ReleaseStopped,
			paasv1.ReleaseFailed,
		},
	}

	for _, from := range paasv1.ReleasePhases() {
		for _, to := range paasv1.ReleasePhases() {
			want := containsReleasePhase(allowed[from], to)
			if got := CanTransitionRelease(from, to); got != want {
				t.Errorf("CanTransitionRelease(%q, %q) = %v, want %v", from, to, got, want)
			}
			err := ValidateReleaseTransition(from, to)
			if (err == nil) != want {
				t.Errorf("ValidateReleaseTransition(%q, %q) error = %v, want allowed %v", from, to, err, want)
			}
		}
	}
}

func TestReleaseTerminalPhasesAreExactAndImmutable(t *testing.T) {
	terminal := map[paasv1.ReleasePhase]bool{
		paasv1.ReleaseFailed:  true,
		paasv1.ReleaseStopped: true,
	}
	for _, phase := range paasv1.ReleasePhases() {
		if got := IsTerminalReleasePhase(phase); got != terminal[phase] {
			t.Errorf("IsTerminalReleasePhase(%q) = %v, want %v", phase, got, terminal[phase])
		}
		if !terminal[phase] {
			continue
		}
		for _, next := range paasv1.ReleasePhases() {
			if CanTransitionRelease(phase, next) {
				t.Errorf("terminal phase %q unexpectedly transitions to %q", phase, next)
			}
		}
	}
}

func TestReleaseTransitionRejectsUnknownPhases(t *testing.T) {
	unknown := paasv1.ReleasePhase("FUTURE_PHASE")
	if CanTransitionRelease(unknown, paasv1.ReleaseFailed) {
		t.Fatal("unknown source phase must fail closed")
	}
	if err := ValidateReleaseTransition(unknown, paasv1.ReleaseFailed); err == nil {
		t.Fatal("unknown source phase must be rejected")
	}
	if err := ValidateReleaseTransition(paasv1.ReleasePending, unknown); err == nil {
		t.Fatal("unknown destination phase must be rejected")
	}
}

func containsOperationState(values []paasv1.OperationState, target paasv1.OperationState) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsReleasePhase(values []paasv1.ReleasePhase, target paasv1.ReleasePhase) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
