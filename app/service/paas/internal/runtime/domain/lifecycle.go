package domain

import (
	"fmt"

	paasv1 "matrix/api/paas/v1"
)

var operationTransitions = map[paasv1.OperationState]map[paasv1.OperationState]struct{}{
	paasv1.OperationAccepted: {
		paasv1.OperationPlanning:  {},
		paasv1.OperationFailed:    {},
		paasv1.OperationCancelled: {},
	},
	paasv1.OperationPlanning: {
		paasv1.OperationQueued:    {},
		paasv1.OperationFailed:    {},
		paasv1.OperationCancelled: {},
	},
	paasv1.OperationQueued: {
		paasv1.OperationExecuting: {},
		paasv1.OperationFailed:    {},
		paasv1.OperationCancelled: {},
	},
	paasv1.OperationExecuting: {
		paasv1.OperationVerifying:   {},
		paasv1.OperationReconciling: {},
		paasv1.OperationFailed:      {},
		paasv1.OperationCancelled:   {},
	},
	paasv1.OperationVerifying: {
		paasv1.OperationSucceeded:   {},
		paasv1.OperationReconciling: {},
		paasv1.OperationFailed:      {},
	},
	paasv1.OperationReconciling: {
		paasv1.OperationExecuting:          {},
		paasv1.OperationVerifying:          {},
		paasv1.OperationFailed:             {},
		paasv1.OperationCancelled:          {},
		paasv1.OperationManualIntervention: {},
	},
}

var terminalOperationStates = map[paasv1.OperationState]struct{}{
	paasv1.OperationSucceeded:          {},
	paasv1.OperationFailed:             {},
	paasv1.OperationCancelled:          {},
	paasv1.OperationManualIntervention: {},
}

func CanTransitionOperation(from, to paasv1.OperationState) bool {
	allowed, found := operationTransitions[from]
	if !found {
		return false
	}
	_, found = allowed[to]
	return found
}

func ValidateOperationTransition(from, to paasv1.OperationState) error {
	if !knownOperationState(from) || !knownOperationState(to) {
		return fmt.Errorf("operation transition contains an unknown state: %q -> %q", from, to)
	}
	if !CanTransitionOperation(from, to) {
		return fmt.Errorf("illegal operation transition: %q -> %q", from, to)
	}
	return nil
}

func IsTerminalOperationState(state paasv1.OperationState) bool {
	_, found := terminalOperationStates[state]
	return found
}

func knownOperationState(state paasv1.OperationState) bool {
	for _, candidate := range paasv1.OperationStates() {
		if candidate == state {
			return true
		}
	}
	return false
}

var releaseTransitions = map[paasv1.ReleasePhase]map[paasv1.ReleasePhase]struct{}{
	paasv1.ReleasePending: {
		paasv1.ReleasePlacing: {},
		paasv1.ReleaseFailed:  {},
	},
	paasv1.ReleasePlacing: {
		paasv1.ReleaseApplying: {},
		paasv1.ReleaseFailed:   {},
	},
	paasv1.ReleaseApplying: {
		paasv1.ReleaseReady:    {},
		paasv1.ReleaseDegraded: {},
		paasv1.ReleaseFailed:   {},
	},
	paasv1.ReleaseReady: {
		paasv1.ReleaseDegraded: {},
		paasv1.ReleaseFailed:   {},
		paasv1.ReleaseStopping: {},
	},
	paasv1.ReleaseDegraded: {
		paasv1.ReleaseReady:    {},
		paasv1.ReleaseFailed:   {},
		paasv1.ReleaseStopping: {},
	},
	paasv1.ReleaseStopping: {
		paasv1.ReleaseStopped: {},
		paasv1.ReleaseFailed:  {},
	},
}

func CanTransitionRelease(from, to paasv1.ReleasePhase) bool {
	allowed, found := releaseTransitions[from]
	if !found {
		return false
	}
	_, found = allowed[to]
	return found
}

func ValidateReleaseTransition(from, to paasv1.ReleasePhase) error {
	if !knownReleasePhase(from) || !knownReleasePhase(to) {
		return fmt.Errorf("release transition contains an unknown phase: %q -> %q", from, to)
	}
	if !CanTransitionRelease(from, to) {
		return fmt.Errorf("illegal release transition: %q -> %q", from, to)
	}
	return nil
}

func IsTerminalReleasePhase(phase paasv1.ReleasePhase) bool {
	return phase == paasv1.ReleaseFailed || phase == paasv1.ReleaseStopped
}

func knownReleasePhase(phase paasv1.ReleasePhase) bool {
	for _, candidate := range paasv1.ReleasePhases() {
		if candidate == phase {
			return true
		}
	}
	return false
}
