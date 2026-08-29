package placement

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

func (planner *Planner) Plan(input Input) (Result, error) {
	if err := planner.validateInput(input); err != nil {
		return Result{}, fmt.Errorf("validate placement input: %w", err)
	}

	requirements, err := aggregateRequirements(
		input.Snapshot.Deployment,
		input.Snapshot.ApplicationRevision,
	)
	if err != nil {
		return Result{}, err
	}
	consuming := consumingCapacityClaims(input.Snapshot.CapacityClaims, input.DecidedAt)
	planningClaims := replacementCapacityClaims(consuming, input.Snapshot.ActivePlacement)
	reservedByTarget, err := aggregateCapacityClaims(planningClaims)
	if err != nil {
		return Result{}, err
	}

	pools := make(map[paasv1.ResourceID]paasv1.ExecutionPool, len(input.Snapshot.Pools))
	for _, pool := range input.Snapshot.Pools {
		pools[pool.Metadata.ID] = pool
	}
	eligiblePools := make(
		map[paasv1.ResourceID]struct{},
		len(input.Snapshot.Policy.Spec.EligibleExecutionPoolIDs),
	)
	for _, poolID := range input.Snapshot.Policy.Spec.EligibleExecutionPoolIDs {
		eligiblePools[poolID] = struct{}{}
	}

	targets := append([]paasv1.ExecutionTarget(nil), input.Snapshot.Targets...)
	sort.Slice(targets, func(left, right int) bool {
		return targets[left].Metadata.ID < targets[right].Metadata.ID
	})
	evaluations := make([]candidateEvaluation, 0, len(targets))
	for _, target := range targets {
		pool := pools[target.Spec.ExecutionPoolID]
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
			capacityClaimsForTarget(planningClaims, target.Metadata.ID),
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
			planner.policies[input.Snapshot.Policy.Spec.RequiredIsolationGuarantee] == nil,
		)
	} else {
		selected := selectCandidate(
			input.Snapshot.Policy.Spec.Strategy,
			eligible,
			requirements,
		)
		decision.Outcome = paasv1.PlacementScheduled
		decision.ExecutionTargetID = selected.target.Metadata.ID
		decision.ExecutionTargetResourceVersion = selected.target.Metadata.ResourceVersion
		decision.GrantedIsolationGuarantee = input.Snapshot.Policy.Spec.RequiredIsolationGuarantee
	}
	if err := paasv1.ValidatePlacementDecision(decision); err != nil {
		return Result{}, fmt.Errorf("planner produced an invalid placement decision: %w", err)
	}
	return Result{Decision: decision, Requirements: requirements}, nil
}

func (planner *Planner) evaluateCandidate(
	input Input,
	eligiblePools map[paasv1.ResourceID]struct{},
	target paasv1.ExecutionTarget,
	pool paasv1.ExecutionPool,
	reserved Resources,
	claims []CapacityClaim,
	requirements Resources,
) RejectionCode {
	if active := input.Snapshot.ActivePlacement; active != nil &&
		target.Metadata.ID != active.ExecutionTargetID {
		return RejectTargetNotCurrent
	}
	if _, eligible := eligiblePools[pool.Metadata.ID]; !eligible {
		return RejectPoolNotEligible
	}
	if pool.Status.Phase != paasv1.ExecutionPoolReady {
		return RejectPoolNotReady
	}
	if target.Spec.DesiredState != paasv1.ExecutionTargetActive {
		return RejectTargetNotActive
	}
	if target.Status.Health != paasv1.ExecutionTargetHealthReady {
		return RejectTargetNotReady
	}
	if !labelsMatch(pool.Spec.ExecutionTargetSelector.MatchLabels, target.Metadata.Labels) {
		return RejectPoolSelector
	}
	if !labelsMatch(input.Snapshot.Policy.Spec.ExecutionTargetSelector.MatchLabels, target.Metadata.Labels) {
		return RejectPolicySelector
	}
	if input.DecidedAt.Sub(target.Status.ObservedAt) > planner.maxObservationAge {
		return RejectObservationStale
	}
	isolation := input.Snapshot.Policy.Spec.RequiredIsolationGuarantee
	if !containsIsolation(pool.Spec.AllowedIsolationGuarantees, isolation) {
		return RejectPoolIsolation
	}
	if !containsIsolation(target.Status.SupportedIsolationGuarantees, isolation) {
		return RejectTargetIsolation
	}
	policy := planner.policies[isolation]
	if policy == nil {
		return RejectIsolationPolicyMissing
	}
	if !policy.Admit(IsolationContext{
		TenantID:                         input.TenantID,
		DeploymentID:                     input.Snapshot.Deployment.Metadata.ID,
		ApplicationRevisionID:            input.Snapshot.ApplicationRevision.Metadata.ID,
		ApplicationRevisionContentDigest: input.Snapshot.ApplicationRevision.Spec.ContentDigest,
		ExecutionTargetID:                target.Metadata.ID,
		TargetLabels:                     cloneLabels(target.Metadata.Labels),
		CapacityClaims:                   append([]CapacityClaim(nil), claims...),
	}) {
		return RejectIsolationPolicy
	}
	available := effectiveAvailability(target.Status.Allocatable, reserved)
	if !requirements.fitWithin(available) {
		return RejectInsufficientCapacity
	}
	return CandidateEligible
}

func aggregateRequirements(
	deployment paasv1.Deployment,
	revision paasv1.ApplicationRevision,
) (Resources, error) {
	var result Resources
	replicasByComponent := make(map[string]uint32, len(deployment.Spec.Components))
	for _, component := range deployment.Spec.Components {
		replicasByComponent[component.Name] = component.Replicas
	}
	for index, component := range revision.Spec.Components {
		replicas := int64(replicasByComponent[component.Name])
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

func consumingCapacityClaims(values []CapacityClaim, decidedAt time.Time) []CapacityClaim {
	result := make([]CapacityClaim, 0, len(values))
	for _, claim := range values {
		if claim.State == CapacityClaimActive ||
			(claim.State == CapacityClaimPending && claim.LeaseExpiresAt.After(decidedAt)) {
			result = append(result, claim)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		return capacityClaimLess(result[left], result[right])
	})
	return result
}

func replacementCapacityClaims(
	values []CapacityClaim,
	active *ActivePlacement,
) []CapacityClaim {
	if active == nil {
		return values
	}
	result := make([]CapacityClaim, 0, len(values)-1)
	for _, claim := range values {
		if claim.ID != active.CapacityClaimID {
			result = append(result, claim)
		}
	}
	return result
}

func capacityClaimLess(left, right CapacityClaim) bool {
	if left.ExecutionTargetID != right.ExecutionTargetID {
		return left.ExecutionTargetID < right.ExecutionTargetID
	}
	return left.ID < right.ID
}

func aggregateCapacityClaims(values []CapacityClaim) (map[paasv1.ResourceID]Resources, error) {
	result := make(map[paasv1.ResourceID]Resources)
	for _, claim := range values {
		current := result[claim.ExecutionTargetID]
		var ok bool
		if current.CPUMillis, ok = checkedAdd(current.CPUMillis, claim.Resources.CPUMillis); !ok {
			return nil, errors.New("reserved cpu capacity overflows")
		}
		if current.MemoryBytes, ok = checkedAdd(current.MemoryBytes, claim.Resources.MemoryBytes); !ok {
			return nil, errors.New("reserved memory capacity overflows")
		}
		if current.WorkloadSlots, ok = checkedAdd(current.WorkloadSlots, claim.Resources.WorkloadSlots); !ok {
			return nil, errors.New("reserved workload slots overflow")
		}
		result[claim.ExecutionTargetID] = current
	}
	return result, nil
}

func capacityClaimsForTarget(
	values []CapacityClaim,
	targetID paasv1.ResourceID,
) []CapacityClaim {
	result := make([]CapacityClaim, 0)
	for _, claim := range values {
		if claim.ExecutionTargetID == targetID {
			result = append(result, claim)
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
		DeploymentID:                input.Snapshot.Deployment.Metadata.ID,
		DeploymentGeneration:        input.Snapshot.Deployment.Generation,
		DeploymentResourceVersion:   input.Snapshot.Deployment.Metadata.ResourceVersion,
		ApplicationRevisionID:       input.Snapshot.ApplicationRevision.Metadata.ID,
		PlacementPolicyID:           input.Snapshot.Policy.Metadata.ID,
		PolicyResourceVersion:       input.Snapshot.Policy.Metadata.ResourceVersion,
		RequestedIsolationGuarantee: input.Snapshot.Policy.Spec.RequiredIsolationGuarantee,
		CandidateSetDigest:          candidateDigest,
		DecidedAt:                   input.DecidedAt,
	}
}

func schedulingProblem(traceID string, capabilityUnsupported bool) *paasv1.Problem {
	if capabilityUnsupported {
		return &paasv1.Problem{
			Type:      "/problems/capability-unsupported",
			Title:     "Isolation capability is unavailable",
			Status:    422,
			Code:      paasv1.ErrorCapabilityUnsupported,
			Detail:    "The requested isolation guarantee is unavailable in this platform release.",
			TraceID:   traceID,
			Retryable: false,
		}
	}
	return &paasv1.Problem{
		Type:      "/problems/unschedulable",
		Title:     "Deployment cannot be scheduled",
		Status:    422,
		Code:      paasv1.ErrorUnschedulable,
		Detail:    "No eligible execution target currently satisfies the placement policy.",
		TraceID:   traceID,
		Retryable: true,
	}
}
