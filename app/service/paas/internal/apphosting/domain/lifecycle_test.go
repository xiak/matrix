package domain

import (
	"testing"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
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

func TestDeploymentTransitionsAreExact(t *testing.T) {
	allowed := map[paasv1.DeploymentPhase][]paasv1.DeploymentPhase{
		paasv1.DeploymentPending: {
			paasv1.DeploymentPlacing,
			paasv1.DeploymentFailed,
		},
		paasv1.DeploymentPlacing: {
			paasv1.DeploymentApplying,
			paasv1.DeploymentFailed,
		},
		paasv1.DeploymentApplying: {
			paasv1.DeploymentReady,
			paasv1.DeploymentDegraded,
			paasv1.DeploymentFailed,
		},
		paasv1.DeploymentReady: {
			paasv1.DeploymentDegraded,
			paasv1.DeploymentFailed,
			paasv1.DeploymentStopping,
		},
		paasv1.DeploymentDegraded: {
			paasv1.DeploymentReady,
			paasv1.DeploymentFailed,
			paasv1.DeploymentStopping,
		},
		paasv1.DeploymentStopping: {
			paasv1.DeploymentStopped,
			paasv1.DeploymentFailed,
		},
	}

	for _, from := range paasv1.DeploymentPhases() {
		for _, to := range paasv1.DeploymentPhases() {
			want := containsDeploymentPhase(allowed[from], to)
			if got := CanTransitionDeployment(from, to); got != want {
				t.Errorf("CanTransitionDeployment(%q, %q) = %v, want %v", from, to, got, want)
			}
			err := ValidateDeploymentTransition(from, to)
			if (err == nil) != want {
				t.Errorf("ValidateDeploymentTransition(%q, %q) error = %v, want allowed %v", from, to, err, want)
			}
		}
	}
}

func TestDeploymentTerminalPhasesAreExactAndImmutable(t *testing.T) {
	terminal := map[paasv1.DeploymentPhase]bool{
		paasv1.DeploymentFailed:  true,
		paasv1.DeploymentStopped: true,
	}
	for _, phase := range paasv1.DeploymentPhases() {
		if got := IsTerminalDeploymentPhase(phase); got != terminal[phase] {
			t.Errorf("IsTerminalDeploymentPhase(%q) = %v, want %v", phase, got, terminal[phase])
		}
		if !terminal[phase] {
			continue
		}
		for _, next := range paasv1.DeploymentPhases() {
			if CanTransitionDeployment(phase, next) {
				t.Errorf("terminal phase %q unexpectedly transitions to %q", phase, next)
			}
		}
	}
}

func TestDeploymentTransitionRejectsUnknownPhases(t *testing.T) {
	unknown := paasv1.DeploymentPhase("FUTURE_PHASE")
	if CanTransitionDeployment(unknown, paasv1.DeploymentFailed) {
		t.Fatal("unknown source phase must fail closed")
	}
	if err := ValidateDeploymentTransition(unknown, paasv1.DeploymentFailed); err == nil {
		t.Fatal("unknown source phase must be rejected")
	}
	if err := ValidateDeploymentTransition(paasv1.DeploymentPending, unknown); err == nil {
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

func containsDeploymentPhase(values []paasv1.DeploymentPhase, target paasv1.DeploymentPhase) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
