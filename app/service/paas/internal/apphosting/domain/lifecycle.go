package domain

import (
	"fmt"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
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

var deploymentTransitions = map[paasv1.DeploymentPhase]map[paasv1.DeploymentPhase]struct{}{
	paasv1.DeploymentPending: {
		paasv1.DeploymentPlacing: {},
		paasv1.DeploymentFailed:  {},
	},
	paasv1.DeploymentPlacing: {
		paasv1.DeploymentApplying: {},
		paasv1.DeploymentFailed:   {},
	},
	paasv1.DeploymentApplying: {
		paasv1.DeploymentReady:    {},
		paasv1.DeploymentDegraded: {},
		paasv1.DeploymentFailed:   {},
	},
	paasv1.DeploymentReady: {
		paasv1.DeploymentDegraded: {},
		paasv1.DeploymentFailed:   {},
		paasv1.DeploymentStopping: {},
	},
	paasv1.DeploymentDegraded: {
		paasv1.DeploymentReady:    {},
		paasv1.DeploymentFailed:   {},
		paasv1.DeploymentStopping: {},
	},
	paasv1.DeploymentStopping: {
		paasv1.DeploymentStopped: {},
		paasv1.DeploymentFailed:  {},
	},
}

func CanTransitionDeployment(from, to paasv1.DeploymentPhase) bool {
	allowed, found := deploymentTransitions[from]
	if !found {
		return false
	}
	_, found = allowed[to]
	return found
}

func ValidateDeploymentTransition(from, to paasv1.DeploymentPhase) error {
	if !knownDeploymentPhase(from) || !knownDeploymentPhase(to) {
		return fmt.Errorf("deployment transition contains an unknown phase: %q -> %q", from, to)
	}
	if !CanTransitionDeployment(from, to) {
		return fmt.Errorf("illegal deployment transition: %q -> %q", from, to)
	}
	return nil
}

func IsTerminalDeploymentPhase(phase paasv1.DeploymentPhase) bool {
	return phase == paasv1.DeploymentFailed || phase == paasv1.DeploymentStopped
}

func knownDeploymentPhase(phase paasv1.DeploymentPhase) bool {
	for _, candidate := range paasv1.DeploymentPhases() {
		if candidate == phase {
			return true
		}
	}
	return false
}
