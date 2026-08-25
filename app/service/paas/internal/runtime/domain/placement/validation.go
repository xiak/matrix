package placement

import (
	"errors"
	"fmt"
	"time"

	paasv1 "matrix/api/paas/v1"
)

func (planner *Planner) validateInput(input Input) error {
	var problems []error
	if planner == nil {
		return errors.New("placement planner is nil")
	}
	if planner.maxObservationAge <= 0 ||
		planner.maxObservationAge%time.Microsecond != 0 {
		problems = append(problems, errors.New("planner observation age is invalid"))
	}
	problems = append(problems,
		paasv1.ValidateID("tenantId", string(input.TenantID)),
		paasv1.ValidateID("operationId", string(input.OperationID)),
		paasv1.ValidateID("decisionId", string(input.DecisionID)),
		paasv1.ValidateDigest("requestDigest", input.RequestDigest),
		paasv1.ValidateID("traceId", input.TraceID),
		validateContractTime("decidedAt", input.DecidedAt),
		paasv1.ValidateWorkloadRelease(input.Snapshot.Release),
		paasv1.ValidatePlacementPolicy(input.Snapshot.Policy),
	)
	if input.Snapshot.Release.Metadata.Scope.TenantID != input.TenantID {
		problems = append(problems, errors.New("workload release tenant does not match placement tenant"))
	}
	if input.Snapshot.Policy.Metadata.Scope.TenantID != input.TenantID {
		problems = append(problems, errors.New("placement policy tenant does not match placement tenant"))
	}

	pools := make(map[paasv1.ResourceID]struct{}, len(input.Snapshot.Pools))
	for index, pool := range input.Snapshot.Pools {
		if err := paasv1.ValidateResourcePool(pool); err != nil {
			problems = append(problems, fmt.Errorf("pools[%d]: %w", index, err))
		}
		if _, duplicate := pools[pool.Metadata.ID]; duplicate {
			problems = append(problems, fmt.Errorf("pools[%d].metadata.id is duplicated", index))
		}
		pools[pool.Metadata.ID] = struct{}{}
	}
	for index, poolID := range input.Snapshot.Policy.Spec.EligibleResourcePools {
		if _, found := pools[poolID]; !found {
			problems = append(
				problems,
				fmt.Errorf("policy eligible resource pool %d is absent from snapshot", index),
			)
		}
	}

	targets := make(map[paasv1.ResourceID]struct{}, len(input.Snapshot.Targets))
	for index, target := range input.Snapshot.Targets {
		if err := paasv1.ValidateRuntimeTarget(target); err != nil {
			problems = append(problems, fmt.Errorf("targets[%d]: %w", index, err))
		}
		if _, duplicate := targets[target.Metadata.ID]; duplicate {
			problems = append(problems, fmt.Errorf("targets[%d].metadata.id is duplicated", index))
		}
		targets[target.Metadata.ID] = struct{}{}
		if _, found := pools[target.Spec.ResourcePoolID]; !found {
			problems = append(problems, fmt.Errorf("targets[%d] references a missing resource pool", index))
		}
		if target.Status.ObservedAt.After(input.DecidedAt) {
			problems = append(problems, fmt.Errorf("targets[%d] observation is after decidedAt", index))
		}
	}

	claimIDs := make(map[paasv1.ResourceID]struct{}, len(input.Snapshot.CapacityClaims))
	for index, claim := range input.Snapshot.CapacityClaims {
		if err := validateCapacityClaim(claim); err != nil {
			problems = append(problems, fmt.Errorf("capacityClaims[%d]: %w", index, err))
		}
		if _, duplicate := claimIDs[claim.ID]; duplicate {
			problems = append(problems, fmt.Errorf("capacityClaims[%d].id is duplicated", index))
		}
		claimIDs[claim.ID] = struct{}{}
		if claim.State != CapacityClaimReleased {
			if _, found := targets[claim.RuntimeTargetID]; !found {
				problems = append(
					problems,
					fmt.Errorf("capacityClaims[%d] references a missing runtime target", index),
				)
			}
		}
	}

	return errors.Join(problems...)
}

func validateCapacityClaim(value CapacityClaim) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("id", string(value.ID)),
		paasv1.ValidateID("runtimeTargetId", string(value.RuntimeTargetID)),
		validateResources(value.Resources),
	)
	if !containsIsolation(paasv1.IsolationClasses(), value.Isolation) {
		problems = append(problems, errors.New("isolation class is invalid"))
	}
	if value.ResourceVersion == 0 {
		problems = append(problems, errors.New("resourceVersion must be positive"))
	}
	switch value.State {
	case CapacityClaimPending:
		problems = append(problems, validateContractTime("leaseExpiresAt", value.LeaseExpiresAt))
	case CapacityClaimActive, CapacityClaimReleased:
		if !value.LeaseExpiresAt.IsZero() {
			problems = append(problems, errors.New("only pending capacity claims may have leaseExpiresAt"))
		}
	default:
		problems = append(problems, fmt.Errorf("unknown capacity claim state %q", value.State))
	}
	return errors.Join(problems...)
}

func validateResources(value Resources) error {
	if value.CPUMillis < 0 || value.MemoryBytes < 0 || value.WorkloadSlots <= 0 {
		return errors.New("reserved resources require non-negative cpu/memory and positive workload slots")
	}
	return nil
}

func validateContractTime(name string, value time.Time) error {
	if value.IsZero() ||
		value.Location() != time.UTC ||
		value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return fmt.Errorf(
			"%s must be UTC with at most microsecond precision and no monotonic component",
			name,
		)
	}
	return nil
}

func containsIsolation(values []paasv1.IsolationClass, wanted paasv1.IsolationClass) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
