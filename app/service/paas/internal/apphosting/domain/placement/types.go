package placement

import (
	"time"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const AlgorithmVersion = "placement-v3"

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
	ID                paasv1.ResourceID
	ExecutionTargetID paasv1.ResourceID
	Isolation         paasv1.IsolationGuarantee
	Resources         Resources
	State             CapacityClaimState
	LeaseExpiresAt    time.Time
	ResourceVersion   uint64
}

// ActivePlacement identifies the exact active capacity claim that an update
// or rollback replaces in place. It is repository-derived from the persisted
// Deployment status and never accepts a caller-selected target.
type ActivePlacement struct {
	DecisionID        paasv1.ResourceID
	ExecutionTargetID paasv1.ResourceID
	CapacityClaimID   paasv1.ResourceID
}

type Snapshot struct {
	Deployment          paasv1.Deployment
	ApplicationRevision paasv1.ApplicationRevision
	Policy              paasv1.PlacementPolicy
	Pools               []paasv1.ExecutionPool
	Targets             []paasv1.ExecutionTarget
	CapacityClaims      []CapacityClaim
	ActivePlacement     *ActivePlacement
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
	RejectTargetNotCurrent       RejectionCode = "TARGET_NOT_CURRENT"
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
	TenantID                         paasv1.TenantID
	DeploymentID                     paasv1.ResourceID
	ApplicationRevisionID            paasv1.ResourceID
	ApplicationRevisionContentDigest string
	ExecutionTargetID                paasv1.ResourceID
	TargetLabels                     map[string]string
	CapacityClaims                   []CapacityClaim
}

// IsolationPolicy is version-qualified service policy. Implementations must
// be deterministic and side-effect free.
type IsolationPolicy interface {
	IsolationGuarantee() paasv1.IsolationGuarantee
	Version() string
	Admit(IsolationContext) bool
}

type Planner struct {
	maxObservationAge time.Duration
	policies          map[paasv1.IsolationGuarantee]IsolationPolicy
}

type candidateEvaluation struct {
	target    paasv1.ExecutionTarget
	pool      paasv1.ExecutionPool
	reserved  Resources
	rejection RejectionCode
}
