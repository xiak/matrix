package placement

import (
	"time"

	paasv1 "matrix/api/paas/v1"
)

const AlgorithmVersion = "placement-v1"

type CapacityClaimState string

const (
	CapacityClaimPending  CapacityClaimState = "PENDING"
	CapacityClaimActive   CapacityClaimState = "ACTIVE"
	CapacityClaimReleased CapacityClaimState = "RELEASED"
)

// Resources is the capacity FEAT-003 reserves. Storage is intentionally not
// part of the v1 workload contract.
type Resources struct {
	CPUMillis     int64
	MemoryBytes   int64
	WorkloadSlots int64
}

// CapacityClaim is the tenant-neutral scheduling projection of consumed
// capacity. Tenant reservation ownership remains behind the repository's RLS
// boundary and is not needed by the Compose v0.1 placement policies.
type CapacityClaim struct {
	ID              paasv1.ResourceID
	RuntimeTargetID paasv1.ResourceID
	Isolation       paasv1.IsolationClass
	Resources       Resources
	State           CapacityClaimState
	LeaseExpiresAt  time.Time
	ResourceVersion uint64
}

type Snapshot struct {
	Release        paasv1.WorkloadRelease
	Policy         paasv1.PlacementPolicy
	Pools          []paasv1.ResourcePool
	Targets        []paasv1.RuntimeTarget
	CapacityClaims []CapacityClaim
}

// Input contains identities owned by the placement operation plus a single
// consistent resource snapshot. DecidedAt is injected; Gate B supplies the
// authoritative PostgreSQL transaction time.
type Input struct {
	TenantID      paasv1.TenantID
	OperationID   paasv1.OperationID
	DecisionID    paasv1.ResourceID
	RequestDigest string
	TraceID       string
	DecidedAt     time.Time
	Snapshot      Snapshot
}

type Result struct {
	Decision     paasv1.PlacementDecision
	Requirements Resources
}

type RejectionCode string

const (
	CandidateEligible            RejectionCode = "ELIGIBLE"
	RejectPoolNotEligible        RejectionCode = "POOL_NOT_ELIGIBLE"
	RejectPoolNotReady           RejectionCode = "POOL_NOT_READY"
	RejectTargetNotActive        RejectionCode = "TARGET_NOT_ACTIVE"
	RejectTargetNotReady         RejectionCode = "TARGET_NOT_READY"
	RejectPoolSelector           RejectionCode = "POOL_SELECTOR_MISMATCH"
	RejectPolicySelector         RejectionCode = "POLICY_SELECTOR_MISMATCH"
	RejectObservationStale       RejectionCode = "OBSERVATION_STALE"
	RejectPoolIsolation          RejectionCode = "POOL_ISOLATION_UNSUPPORTED"
	RejectTargetIsolation        RejectionCode = "TARGET_ISOLATION_UNSUPPORTED"
	RejectIsolationPolicyMissing RejectionCode = "ISOLATION_POLICY_UNREGISTERED"
	RejectIsolationPolicy        RejectionCode = "ISOLATION_POLICY_REJECTED"
	RejectInsufficientCapacity   RejectionCode = "INSUFFICIENT_CAPACITY"
)

// IsolationContext is a detached view: implementations cannot mutate the
// planner snapshot through it.
type IsolationContext struct {
	TenantID             paasv1.TenantID
	WorkloadReleaseID    paasv1.ResourceID
	ReleaseContentDigest string
	RuntimeTargetID      paasv1.ResourceID
	TargetLabels         map[string]string
	CapacityClaims       []CapacityClaim
}

// IsolationPolicy is version-qualified service policy. Implementations must
// be deterministic and side-effect free.
type IsolationPolicy interface {
	IsolationClass() paasv1.IsolationClass
	Version() string
	Admit(IsolationContext) bool
}

type Planner struct {
	maxObservationAge time.Duration
	policies          map[paasv1.IsolationClass]IsolationPolicy
}

type candidateEvaluation struct {
	target    paasv1.RuntimeTarget
	pool      paasv1.ResourcePool
	reserved  Resources
	rejection RejectionCode
}
