package placement

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	paasv1 "matrix/api/paas/v1"
)

func (planner *Planner) Plan(input Input) (Result, error) {
	if err := planner.validateInput(input); err != nil {
		return Result{}, fmt.Errorf("validate placement input: %w", err)
	}

	requirements, err := aggregateRequirements(input.Snapshot.Release)
	if err != nil {
		return Result{}, err
	}
	consuming := consumingReservations(input.Snapshot.Reservations, input.DecidedAt)
	reservedByTarget, err := aggregateReservations(consuming)
	if err != nil {
		return Result{}, err
	}

	pools := make(map[paasv1.ResourceID]paasv1.ResourcePool, len(input.Snapshot.Pools))
	for _, pool := range input.Snapshot.Pools {
		pools[pool.Metadata.ID] = pool
	}
	eligiblePools := make(
		map[paasv1.ResourceID]struct{},
		len(input.Snapshot.Policy.Spec.EligibleResourcePools),
	)
	for _, poolID := range input.Snapshot.Policy.Spec.EligibleResourcePools {
		eligiblePools[poolID] = struct{}{}
	}

	targets := append([]paasv1.RuntimeTarget(nil), input.Snapshot.Targets...)
	sort.Slice(targets, func(left, right int) bool {
		return targets[left].Metadata.ID < targets[right].Metadata.ID
	})
	evaluations := make([]candidateEvaluation, 0, len(targets))
	for _, target := range targets {
		pool := pools[target.Spec.ResourcePoolID]
		reserved := reservedByTarget[target.Metadata.ID]
		evaluation := candidateEvaluation{
			target:   target,
			pool:     pool,
			reserved: reserved,
		}
		evaluation.rejection = planner.evaluateCandidate(
			input,
			eligiblePools,
			target,
			pool,
			reserved,
			reservationsForTarget(consuming, target.Metadata.ID),
			requirements,
		)
		evaluations = append(evaluations, evaluation)
	}

	digest := planner.candidateSetDigest(input, requirements, evaluations, consuming)
	decision := newDecision(input, digest)
	eligible := make([]candidateEvaluation, 0, len(evaluations))
	for _, evaluation := range evaluations {
		if evaluation.rejection == CandidateEligible {
			eligible = append(eligible, evaluation)
		}
	}
	if len(eligible) == 0 {
		decision.Outcome = paasv1.PlacementUnschedulable
		decision.Reason = schedulingProblem(
			input.TraceID,
			planner.policies[input.Snapshot.Policy.Spec.RequiredIsolationClass] == nil,
		)
	} else {
		selected := selectCandidate(
			input.Snapshot.Policy.Spec.Strategy,
			eligible,
			requirements,
		)
		decision.Outcome = paasv1.PlacementScheduled
		decision.RuntimeTargetID = selected.target.Metadata.ID
		decision.RuntimeTargetResourceVersion = selected.target.Metadata.ResourceVersion
		decision.GrantedIsolation = input.Snapshot.Policy.Spec.RequiredIsolationClass
	}
	if err := paasv1.ValidatePlacementDecision(decision); err != nil {
		return Result{}, fmt.Errorf("planner produced an invalid placement decision: %w", err)
	}
	return Result{Decision: decision, Requirements: requirements}, nil
}

func (planner *Planner) evaluateCandidate(
	input Input,
	eligiblePools map[paasv1.ResourceID]struct{},
	target paasv1.RuntimeTarget,
	pool paasv1.ResourcePool,
	reserved Resources,
	reservations []Reservation,
	requirements Resources,
) RejectionCode {
	if _, eligible := eligiblePools[pool.Metadata.ID]; !eligible {
		return RejectPoolNotEligible
	}
	if pool.Status.Phase != paasv1.ResourcePoolReady {
		return RejectPoolNotReady
	}
	if target.Spec.DesiredState != paasv1.TargetActive {
		return RejectTargetNotActive
	}
	if target.Status.Health != paasv1.TargetHealthReady {
		return RejectTargetNotReady
	}
	if !labelsMatch(pool.Spec.TargetSelector.MatchLabels, target.Metadata.Labels) {
		return RejectPoolSelector
	}
	if !labelsMatch(input.Snapshot.Policy.Spec.TargetSelector.MatchLabels, target.Metadata.Labels) {
		return RejectPolicySelector
	}
	if input.DecidedAt.Sub(target.Status.ObservedAt) > planner.maxObservationAge {
		return RejectObservationStale
	}
	isolation := input.Snapshot.Policy.Spec.RequiredIsolationClass
	if !containsIsolation(pool.Spec.AllowedIsolationClasses, isolation) {
		return RejectPoolIsolation
	}
	if !containsIsolation(target.Status.SupportedIsolationClasses, isolation) {
		return RejectTargetIsolation
	}
	policy := planner.policies[isolation]
	if policy == nil {
		return RejectIsolationPolicyMissing
	}
	if !policy.Admit(IsolationContext{
		TenantID:             input.TenantID,
		WorkloadReleaseID:    input.Snapshot.Release.Metadata.ID,
		ReleaseContentDigest: input.Snapshot.Release.Spec.ContentDigest,
		RuntimeTargetID:      target.Metadata.ID,
		TargetLabels:         cloneLabels(target.Metadata.Labels),
		Reservations:         append([]Reservation(nil), reservations...),
	}) {
		return RejectIsolationPolicy
	}
	available := effectiveAvailability(target.Status.Allocatable, reserved)
	if !requirements.fitWithin(available) {
		return RejectInsufficientCapacity
	}
	return CandidateEligible
}

func aggregateRequirements(release paasv1.WorkloadRelease) (Resources, error) {
	var result Resources
	for index, component := range release.Spec.Components {
		replicas := int64(component.Replicas)
		cpu, ok := checkedMultiply(component.Resources.CPUMillis, replicas)
		if !ok {
			return Resources{}, fmt.Errorf("component %d cpu requirement overflows", index)
		}
		memory, ok := checkedMultiply(component.Resources.MemoryBytes, replicas)
		if !ok {
			return Resources{}, fmt.Errorf("component %d memory requirement overflows", index)
		}
		if result.CPUMillis, ok = checkedAdd(result.CPUMillis, cpu); !ok {
			return Resources{}, errors.New("aggregate cpu requirement overflows")
		}
		if result.MemoryBytes, ok = checkedAdd(result.MemoryBytes, memory); !ok {
			return Resources{}, errors.New("aggregate memory requirement overflows")
		}
		if result.WorkloadSlots, ok = checkedAdd(result.WorkloadSlots, replicas); !ok {
			return Resources{}, errors.New("aggregate workload slots overflow")
		}
	}
	return result, nil
}

func consumingReservations(values []Reservation, decidedAt time.Time) []Reservation {
	result := make([]Reservation, 0, len(values))
	for _, reservation := range values {
		if reservation.State == ReservationActive ||
			(reservation.State == ReservationPending && reservation.LeaseExpiresAt.After(decidedAt)) {
			result = append(result, reservation)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		return reservationLess(result[left], result[right])
	})
	return result
}

func reservationLess(left, right Reservation) bool {
	if left.RuntimeTargetID != right.RuntimeTargetID {
		return left.RuntimeTargetID < right.RuntimeTargetID
	}
	if left.TenantID != right.TenantID {
		return left.TenantID < right.TenantID
	}
	if left.ID != right.ID {
		return left.ID < right.ID
	}
	return left.DecisionID < right.DecisionID
}

func aggregateReservations(values []Reservation) (map[paasv1.ResourceID]Resources, error) {
	result := make(map[paasv1.ResourceID]Resources)
	for _, reservation := range values {
		current := result[reservation.RuntimeTargetID]
		var ok bool
		if current.CPUMillis, ok = checkedAdd(current.CPUMillis, reservation.Resources.CPUMillis); !ok {
			return nil, errors.New("reserved cpu capacity overflows")
		}
		if current.MemoryBytes, ok = checkedAdd(current.MemoryBytes, reservation.Resources.MemoryBytes); !ok {
			return nil, errors.New("reserved memory capacity overflows")
		}
		if current.WorkloadSlots, ok = checkedAdd(current.WorkloadSlots, reservation.Resources.WorkloadSlots); !ok {
			return nil, errors.New("reserved workload slots overflow")
		}
		result[reservation.RuntimeTargetID] = current
	}
	return result, nil
}

func reservationsForTarget(
	values []Reservation,
	targetID paasv1.ResourceID,
) []Reservation {
	result := make([]Reservation, 0)
	for _, reservation := range values {
		if reservation.RuntimeTargetID == targetID {
			result = append(result, reservation)
		}
	}
	return result
}

func effectiveAvailability(allocatable paasv1.Capacity, reserved Resources) Resources {
	return Resources{
		CPUMillis:     subtractClamp(allocatable.CPUMillis, reserved.CPUMillis),
		MemoryBytes:   subtractClamp(allocatable.MemoryBytes, reserved.MemoryBytes),
		WorkloadSlots: subtractClamp(allocatable.WorkloadSlots, reserved.WorkloadSlots),
	}
}

func subtractClamp(available, reserved int64) int64 {
	if reserved >= available {
		return 0
	}
	return available - reserved
}

func (resources Resources) fitWithin(available Resources) bool {
	return resources.CPUMillis <= available.CPUMillis &&
		resources.MemoryBytes <= available.MemoryBytes &&
		resources.WorkloadSlots <= available.WorkloadSlots
}

func checkedMultiply(left, right int64) (int64, bool) {
	if left < 0 || right < 0 {
		return 0, false
	}
	if left != 0 && right > math.MaxInt64/left {
		return 0, false
	}
	return left * right, true
}

func checkedAdd(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || right > math.MaxInt64-left {
		return 0, false
	}
	return left + right, true
}

func labelsMatch(selector, labels map[string]string) bool {
	for key, expected := range selector {
		if labels[key] != expected {
			return false
		}
	}
	return true
}

func cloneLabels(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func newDecision(input Input, candidateDigest string) paasv1.PlacementDecision {
	nameDigest := sha256.Sum256([]byte(input.DecisionID))
	return paasv1.PlacementDecision{
		APIVersion: paasv1.APIVersion,
		Kind:       "PlacementDecision",
		Metadata: paasv1.ResourceMetadata{
			ID:   input.DecisionID,
			Name: fmt.Sprintf("placement-%x", nameDigest[:10]),
			Scope: paasv1.ResourceScope{
				Kind:     paasv1.AuthorityTenant,
				TenantID: input.TenantID,
			},
			ResourceVersion: 1,
			CreatedAt:       input.DecidedAt,
			UpdatedAt:       input.DecidedAt,
		},
		WorkloadReleaseID:     input.Snapshot.Release.Metadata.ID,
		PlacementPolicyID:     input.Snapshot.Policy.Metadata.ID,
		PolicyResourceVersion: input.Snapshot.Policy.Metadata.ResourceVersion,
		RequestedIsolation:    input.Snapshot.Policy.Spec.RequiredIsolationClass,
		CandidateSetDigest:    candidateDigest,
		DecidedAt:             input.DecidedAt,
	}
}

func schedulingProblem(traceID string, capabilityUnsupported bool) *paasv1.Problem {
	if capabilityUnsupported {
		return &paasv1.Problem{
			Type:      "/problems/capability-unsupported",
			Title:     "Isolation capability is unavailable",
			Status:    422,
			Code:      paasv1.ErrorCapabilityUnsupported,
			Detail:    "The requested isolation capability is unavailable in this runtime release.",
			TraceID:   traceID,
			Retryable: false,
		}
	}
	return &paasv1.Problem{
		Type:      "/problems/unschedulable",
		Title:     "Workload cannot be scheduled",
		Status:    422,
		Code:      paasv1.ErrorUnschedulable,
		Detail:    "No eligible runtime target currently satisfies the placement policy.",
		TraceID:   traceID,
		Retryable: true,
	}
}
