# FEAT-003: tenant placement and isolation policy

- Status: Gate A accepted; Gate B implementation pending
- Target release: Local Compose Runtime v0.1
- Placement algorithm version: `placement-v1`
- Target design date: 2026-08-25

## Outcome

Given an authenticated tenant scope, an immutable `WorkloadRelease`, a
tenant-owned `PlacementPolicy`, and the current platform target snapshot, the
PaaS produces and persists exactly one immutable `PlacementDecision`. A
scheduled decision reserves capacity on one `RuntimeTarget`; an
unschedulable decision records a stable, sanitized reason. The scheduler never
deploys a workload and never weakens the requested isolation class.

This target design is fixed before FEAT-003 donor implementation is reviewed.
Donor code may change implementation tactics only through a recorded
amendment.

## Incremental release gates

### Gate A: deterministic planning core

Status: Accepted on 2026-08-25.

Gate A is a pure, side-effect-free scheduler usable by FEAT-004 tests:

1. Validate tenant, release, policy, pool, target, and reservation snapshots
   before selection.
2. Derive checked aggregate CPU, memory, and workload-slot requirements from
   all component replicas.
3. Evaluate candidates in a canonical order using exact label, health,
   desired-state, freshness, capacity, pool, and isolation constraints.
4. Implement deterministic `FIRST_FIT`, `SPREAD`, and `BIN_PACK` strategies.
5. Return a valid scheduled or unschedulable v1 decision and a canonical
   candidate-set digest without mutating any input.
6. Expose isolation through a closed, version-qualified service policy
   interface. Runtime v0.1 registers only `SHARED_COMPOSE` and
   `DEDICATED_COMPOSE`.

Gate A does not claim durable persistence or concurrency safety.

### Gate B: tenant-safe transactional placement

Status: Pending.

Gate B completes FEAT-003:

1. A service use case loads the tenant-scoped release and policy plus
   platform pools, targets, and active reservations inside one placement
   transaction.
2. The immutable decision and a capacity reservation are committed atomically.
   Concurrent requests cannot over-reserve a target.
3. PostgreSQL persists placement resources with composite tenant keys,
   optimistic resource versions, database constraints, and forced row-level
   security for tenant-owned rows.
4. The runtime database role cannot bypass row-level security. Every tenant
   transaction establishes its tenant context with transaction-local state.
5. A repeated operation/request digest returns the exact prior decision;
   reusing an operation identity with different input returns
   `IDEMPOTENCY_CONFLICT`.
6. Pending reservation leases can be activated or released idempotently by
   FEAT-004. Expired pending reservations stop consuming capacity but never
   rewrite their immutable placement decision.
7. Tenant B cannot read, replay, activate, release, or collide with tenant A's
   decision or reservation, even when opaque resource IDs are guessed.

Gate B may be composed directly in integration tests before the northbound API
exists. FEAT-006 owns the executable control-plane composition and local
distribution.

## Authority and boundaries

Placement is service policy under `app/service/paas/internal/placement`.
Infrastructure and runtime adapters cannot select a target, tenant, strategy,
or isolation class.

- IAM supplies authenticated tenant and subject authority in FEAT-005.
- PaaS owns policies, decisions, reservations, and capacity accounting.
- Infrastructure adapters supply normalized target facts only.
- Runtime adapters consume an already selected target and exact granted
  isolation class in FEAT-004.
- Audit receives immutable placement evidence through the FEAT-005 outbox; it
  does not participate in scheduling.

No caller-provided label, target ID, or resource name is authority. Tenant
scope is an explicit input and must exactly match the release and policy scope.
Tenant lookup paths always include `tenantId`; an ID-only tenant repository
method is forbidden.

## Planning input and snapshot

The application input contains only service-owned identities and normalized
data:

| Field | Rule |
| --- | --- |
| `tenantId` | Required authenticated IAM organization identity. |
| `operationId` | Required idempotency owner. |
| `decisionId` | Required immutable result identity. |
| `workloadReleaseId` | Must resolve in the same tenant. |
| `placementPolicyId` | Must resolve in the same tenant. |
| `requestDigest` | Digest of the canonical placement request. |
| `traceId` | Safe opaque correlation identity used by normalized reasons. |

The repository supplies one consistent `PlacementSnapshot` containing the
release, policy, eligible pools, current targets, and active or unexpired
pending reservations. The domain planner accepts values, not repository or
driver handles, so it remains deterministic and exhaustively testable.

The v1 decision is refined additively with the selected runtime target's
resource version. Scheduled decisions require that version; unschedulable
decisions forbid it. The candidate digest captures all other resource versions
and evaluation inputs used by `placement-v1`.

## Resource requirements and reservations

For every component:

```text
cpuMillis   += component.cpuMillis   * replicas
memoryBytes += component.memoryBytes * replicas
slots       += replicas
```

All multiplication and addition is checked before it occurs. Overflow is an
invalid request, never a wrapped capacity value. Storage is not requested by
the v1 workload contract and therefore is not reserved by FEAT-003.

For a target, effective availability is its latest normalized allocatable
ceiling minus all active and unexpired pending reservations, clamped at zero.
The calculation is conservative: a provider observation may lower the ceiling
but can never erase a PaaS reservation. Reservation rows retain tenant,
release, decision, target, exact isolation class, requested capacity, state,
lease expiry, and resource version. They contain no machine binding or runtime
credential.

Reservation states are service-local and are not new public resources:

```text
PENDING --activate--> ACTIVE --release--> RELEASED
    |                     |
    +------expire---------+
```

Only `PENDING` and `ACTIVE` consume capacity. Expiry applies only to
`PENDING`; an active workload must be explicitly released.

## Candidate evaluation

Inputs are validated first. Pools and targets are then sorted by opaque ID.
Every target receives a stable eligibility result in this order:

1. its pool is listed by the policy;
2. the pool is `READY`;
3. the target is `ACTIVE` and `READY`;
4. pool and policy label selectors both match the target labels;
5. the target observation is within the configured maximum age;
6. both pool and target advertise the exact requested isolation class;
7. the registered isolation policy admits the candidate;
8. effective CPU, memory, and workload slots satisfy the release.

The order affects reason classification only, not authority. Candidate details
are never returned to another tenant or copied into a public `Problem`.

No eligible target yields one of the following stable outcomes:

| Condition | Public code | Retryable |
| --- | --- | --- |
| Isolation class has no v0.1 policy implementation | `CAPABILITY_UNSUPPORTED` | No |
| No matching/ready/fresh target | `UNSCHEDULABLE` | Yes |
| Insufficient effective capacity | `UNSCHEDULABLE` | Yes |

The public detail remains generic. Internal rejection counts may become
bounded Evidence attributes in FEAT-005, but never include credentials,
endpoints, native errors, or raw labels.

## Isolation policy seam

The planner depends on a service-owned `IsolationPolicy` selected by exact
`IsolationClass`. Its verdict is deterministic over the tenant, release,
candidate target, and normalized reservation snapshot. It cannot execute an
adapter or mutate infrastructure.

Runtime v0.1 policies mean:

- `SHARED_COMPOSE`: tenants may share a machine/runtime target; FEAT-004 must
  still create a stable workload runtime unit and tenant-controlled network
  boundary.
- `DEDICATED_COMPOSE`: a dedicated Compose runtime unit is reserved for the
  tenant workload on a potentially shared machine. It is not host or physical
  isolation.

`DEDICATED_HOST`, `K8S_NAMESPACE`, and `PHYSICAL_HOST` have no registered v0.1
policy and are always `UNSCHEDULABLE` with `CAPABILITY_UNSUPPORTED`. Later
policies may inspect tenant-attributed reservations and allocate host,
namespace, or provider capacity without changing the placement request,
decision, or runtime adapter boundaries.

## Deterministic strategies

Candidates that pass every constraint are ordered as follows:

- `FIRST_FIT`: lexicographically smallest opaque target ID.
- `SPREAD`: lowest dominant reserved utilization before this placement, then
  target ID.
- `BIN_PACK`: highest dominant reserved utilization after this placement, then
  target ID.

Dominant utilization is the maximum exact rational utilization of CPU, memory,
and workload slots against the target's allocatable ceiling. Zero-capacity
dimensions with zero usage contribute zero. Scores use integer/rational
comparison, never floating-point rounding. The algorithm version is included
in the candidate-set digest so a later scoring change cannot masquerade as the
same decision basis.

## Candidate-set digest

`CandidateSetDigest` is a lowercase SHA-256 digest over a length-prefixed,
versioned canonical stream containing:

- algorithm version and configured observation maximum age;
- tenant, release identity/content digest, and checked requirements;
- policy identity, resource version, exact requested isolation, selectors, and
  strategy;
- sorted pool identity, version, phase, selector, and isolation facts;
- sorted target identity, version, desired state, health, observation time,
  labels, allocatable ceiling, and isolation facts;
- sorted capacity-consuming reservations and stable eligibility/rejection
  codes.

The digest contains no JSON map iteration, wall-clock formatting ambiguity,
machine binding, credential, endpoint, or native provider value. Replanning an
identical snapshot produces the identical decision and digest.

## Transaction, idempotency, and concurrency

The PostgreSQL adapter runs placement at serializable isolation and locks
candidate target/allocation rows in canonical order. On serialization failure
the application may retry within the operation deadline using the same
operation and request identity.

The transaction performs:

1. set and verify transaction-local tenant context;
2. replay/idempotency lookup by `(tenant_id, operation_id)`;
3. load and validate the tenant release and policy;
4. lock the relevant platform target allocation rows in target-ID order;
5. load current capacity-consuming reservations;
6. invoke the pure planner exactly once for that snapshot;
7. insert the immutable decision;
8. for `SCHEDULED`, insert the pending reservation with its lease;
9. commit both or neither.

The same operation plus request digest returns the stored decision without
replanning. A different digest is a conflict. Unique and check constraints are
the final defense against duplicate decisions, impossible reservation values,
or cross-tenant references.

## Tenant isolation in PostgreSQL

Tenant-owned policy, release, decision, and reservation rows use composite
keys beginning with `tenant_id`; foreign keys include the tenant component.
Forced row-level security compares each row with a transaction-local tenant
setting. Migrations are owned by a non-runtime role so the application role is
subject to the policies and has no `BYPASSRLS` capability.

The repository still includes tenant predicates explicitly. Row-level
security is defense in depth, not a substitute for application scoping. A
missing or malformed transaction tenant context fails closed. Platform pools
and targets remain platform-owned tables and are never made tenant-owned by a
placement request.

## FEAT-003 acceptance evidence

### Gate A

1. Table tests cover every filter and stable unschedulable reason.
2. All three strategies are invariant to input ordering and deterministic
   under at least 100 repeated/shuffled runs.
3. Checked requirement arithmetic rejects multiplication and addition
   overflow.
4. Requested physical/host/Kubernetes isolation never selects a Compose
   target and never downgrades to a weaker class.
5. Candidate digest golden tests change for every decision-relevant input and
   remain unchanged for collection/map ordering only.
6. Planner tests prove all caller-owned maps/slices/resources remain unchanged.

### Gate B

1. PostgreSQL migrations apply from empty and roll forward repeatedly without
   drift; constraints and forced row-level-security policies are inspected.
2. Concurrent placement integration tests cannot exceed target CPU, memory, or
   slot capacity.
3. Same-operation replay returns an identical decision; a changed digest is an
   idempotency conflict.
4. Tenant B direct repository and runtime-role SQL attempts cannot observe or
   mutate tenant A rows.
5. Decision plus reservation commit atomically under injected failures.
6. Pending reservation expiry and activate/release operations are idempotent
   and tenant scoped.

### Common gates

- Donor decisions record fixed commits and `REUSE`, `ADAPT`, `REFERENCE`, or
  `REJECT` per reviewed slice.
- Unit, property/fuzz, race, architecture, migration, PostgreSQL integration,
  schema, and `git diff --check` gates pass.
- No donor repository is a build or runtime dependency.

## Gate A implementation evidence

The pure core is implemented under
`app/service/paas/internal/placement`. It imports only the public PaaS v1
contract and an explicit standard-library allowlist; an architecture test
prevents repositories, adapters, drivers, processes, or third-party libraries
from entering this package. Decision time is an explicit value input.

Delivered behavior:

- checked aggregate CPU, memory, and workload-slot requirements;
- canonical evaluation of pool, desired state, health, selectors, freshness,
  exact isolation, isolation policy, and effective capacity;
- version-qualified `SHARED_COMPOSE` and `DEDICATED_COMPOSE` policy
  implementations, with host, Kubernetes, and physical isolation failing as
  `CAPABILITY_UNSUPPORTED` without downgrade;
- exact-rational `FIRST_FIT`, `SPREAD`, and `BIN_PACK` selection;
- active/unexpired-pending reservation accounting with clamped availability;
- a length-prefixed `placement-v1` SHA-256 candidate-set digest and golden
  vector;
- valid immutable scheduled/unschedulable v1 decisions. Scheduled decisions
  bind both the target ID and `runtimeTargetResourceVersion`.

Acceptance evidence includes per-filter negative tables, checked-arithmetic
overflow cases, 100 shuffled-order repetitions, caller-input immutability,
concurrent planner calls, reservation expiry boundaries, schema conditionals,
and a real fuzz run. The following gates passed:

```text
go test ./...
go vet ./...
go test -race ./...
go test -count=10 ./...
go test -run '^$' -fuzz '^FuzzPlanOrderInvariant$' -fuzztime=5s ./app/service/paas/internal/placement
GOOS/GOARCH builds: windows/amd64, linux/amd64, linux/arm64, darwin/arm64
git diff --check
```

Gate A makes no persistence, capacity-locking, replay, or PostgreSQL RLS
claim. Those remain Gate B acceptance requirements.

## Deferred

Runtime effects, Compose project/network naming, rollback execution,
authorization calls, audit outbox delivery, northbound APIs, APISIX, UI,
tenant quotas, cloud provisioning, Kubernetes scheduling, and physical host
allocation remain owned by later features or releases. Reservation identities
and isolation-policy seams are retained so those additions do not require a
new placement boundary.

## Donor-informed amendments

The fixed-commit review is recorded in
[`docs/adoption/FEAT-003-placement-isolation.md`](../adoption/FEAT-003-placement-isolation.md).
It adds the following implementation constraints without changing the public
resource model:

1. PostgreSQL transaction time is authoritative for `DecidedAt`, pending-lease
   evaluation, and persisted transaction facts. Gate A receives time as an
   explicit deterministic input.
2. Exact semantic replay and all tenant, release, policy, target, and
   reservation revalidation occur inside the placement transaction.
3. Composite tenant keys and explicit tenant predicates are retained, with
   forced row-level security as an intentional improvement over the donor's
   storage boundary.
4. Caller-selected targets/provider bindings and the legacy ResourceKernel,
   Project, Environment, quota, and approval closure are rejected.
5. Senatria Audit's versioned-digest and golden-vector pattern is referenced
   for conformance testing; its audit shard algorithm is not reused.
