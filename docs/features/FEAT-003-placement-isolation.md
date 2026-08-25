# FEAT-003: tenant placement and isolation policy

- Status: Accepted
- Target release: Private Application PaaS v0.1
- Placement algorithm version: `placement-v2`
- Target design date: 2026-08-25

## Outcome

Given an authenticated tenant, a Deployment selecting an immutable
ApplicationRevision, a tenant-owned PlacementPolicy, and one consistent
platform-capacity snapshot, the PaaS persists exactly one immutable
PlacementDecision. A scheduled decision reserves capacity on one
ExecutionTarget; an unschedulable decision records a stable sanitized reason.
The scheduler never deploys an application and never weakens requested
isolation.

## Release gates

### Gate A: deterministic planner

Accepted on 2026-08-25. The pure planner:

1. validates the Deployment, ApplicationRevision, policy, pools, targets, and
   capacity claims before selection;
2. computes aggregate CPU, memory, and workload slots with checked arithmetic;
3. filters candidates in a canonical order using pool membership, health,
   labels, freshness, exact isolation, policy, and effective capacity;
4. implements deterministic `FIRST_FIT`, `SPREAD`, and `BIN_PACK`;
5. produces a version-qualified canonical candidate-set digest;
6. returns a valid immutable scheduled or unschedulable decision without
   mutating caller input.

### Gate B: transactional PostgreSQL placement

Gate B was accepted on 2026-08-25 after:

1. migrations apply twice on an empty supported PostgreSQL database and the
   structural/security verifier passes;
2. concurrent placements cannot exceed target CPU, memory, or workload slots;
3. an identical operation/request replays the exact stored decision while a
   changed digest returns `IDEMPOTENCY_CONFLICT`;
4. tenant B cannot read or mutate tenant A Deployment, decision, or reservation
   through repository or runtime-role SQL;
5. decision and reservation rows commit together or both roll back under an
   injected failure after writes;
6. pending reservation activate, release, and expiry transitions are
   idempotent, resource-versioned, and tenant scoped.

## Ownership and trust boundary

The apphosting context owns policy, selection, capacity accounting, and
PlacementDecision. Infrastructure adapters supply normalized ExecutionTarget
facts. DeploymentExecutor consumes an accepted decision later and does not
participate in scheduling. IAM authorizes the tenant operation; Audit receives
sanitized evidence through its owning FEAT.

The public placement command contains only:

| Field | Rule |
| --- | --- |
| `tenantId` | Exact authenticated IAM organization identity. |
| `operationId` | Durable idempotency owner. |
| `decisionId` | Immutable result identity. |
| `deploymentId` | Resolved inside the tenant transaction. |
| `requestDigest` | Canonical request digest. |
| `traceId` | Safe correlation identity for normalized reasons. |

Callers never select an ExecutionTarget, binding, provider, or isolation
implementation.

## Consistent planning snapshot

The repository supplies one `placement.Snapshot` containing:

- the exact Deployment and its `resourceVersion`;
- its immutable ApplicationRevision;
- its PlacementPolicy;
- every eligible ExecutionPool;
- current ExecutionTarget observations;
- all active or unexpired pending tenant-neutral capacity claims for those
  targets.

The transaction derives revision and policy identities from the Deployment.
It does not trust duplicated command fields. The domain planner receives
detached values, not repository handles, so planning remains deterministic and
side-effect free.

## Requirements and capacity

For each Deployment component:

```text
cpuMillis   += revision.component.cpuMillis   * deployment.component.replicas
memoryBytes += revision.component.memoryBytes * deployment.component.replicas
slots       += deployment.component.replicas
```

Multiplication and addition are checked before execution. Overflow is invalid
input. Storage is observed but is not reserved by placement-v2.

Effective availability is the target allocatable ceiling minus every active or
unexpired pending claim, clamped at zero. Provider observations may lower the
ceiling but cannot erase PaaS claims.

## Candidate evaluation

Pools and targets are sorted by opaque ID. Each target is evaluated in this
order:

1. policy lists its pool;
2. pool phase is `READY`;
3. target desired state is `ACTIVE` and health is `READY`;
4. pool and policy label selectors match;
5. observation is within the configured maximum age;
6. pool and target advertise the exact requested isolation guarantee;
7. the registered isolation policy admits the candidate;
8. effective CPU, memory, and workload slots satisfy requirements.

No candidate yields:

| Condition | Code | Retryable |
| --- | --- | --- |
| No v0.1 implementation for the requested guarantee | `CAPABILITY_UNSUPPORTED` | No |
| No matching, ready, or fresh target | `UNSCHEDULABLE` | Yes |
| Insufficient effective capacity | `UNSCHEDULABLE` | Yes |

Public details are generic. Candidate labels, bindings, credentials, endpoints,
native failures, and other tenant identities never enter a Problem.

## Isolation policy

- `WORKLOAD` has the `compose-workload-v1` deterministic policy and may
  schedule on a conforming Compose target.
- `TENANT` and `HOST` have no v0.1 policy and always return
  `CAPABILITY_UNSUPPORTED`.

An `IsolationPolicy` receives only detached tenant, Deployment,
ApplicationRevision, target-label, and claim facts. It cannot execute an
adapter or mutate infrastructure. Later executors may implement stronger
guarantees without changing the placement command or decision shape.

## Deterministic strategies and digest

- `FIRST_FIT`: lexicographically smallest eligible target ID.
- `SPREAD`: lowest dominant reserved utilization before placement, then ID.
- `BIN_PACK`: highest dominant utilization after placement, then ID.

Dominant utilization uses exact rational comparison across CPU, memory, and
workload slots; floating-point rounding is forbidden.

`CandidateSetDigest` is lowercase SHA-256 over a length-prefixed canonical
stream containing algorithm/version settings, tenant, Deployment and revision
identity/content, checked requirements, policy, sorted pools, sorted targets,
sorted consuming claims, and stable eligibility results. It excludes map
iteration order, bindings, credentials, endpoints, native payloads, and wall
clock formatting ambiguity.

## Transaction, replay, and concurrency

Placement runs at serializable isolation:

1. set and verify a transaction-local tenant context;
2. look up replay by `(tenant_id, operation_id)`;
3. read authoritative PostgreSQL transaction time;
4. load Deployment, revision, policy, pools, and targets in tenant scope;
5. lock target allocation rows in canonical target-ID order;
6. load consuming claims and run the pure planner once;
7. insert the immutable decision;
8. for `SCHEDULED`, insert a pending tenant-neutral claim and its tenant-owned
   reservation link;
9. commit all rows together.

Serialization/deadlock conflicts are retried within a bounded attempt budget
using the same operation and request identity. Equal replay returns the stored
decision without replanning. Unequal replay fails before a new effect.

## PostgreSQL tenant isolation

`applications`, `application_revisions`, `placement_policies`,
`deployments`, `placement_decisions`, and `capacity_reservations` use
tenant-leading keys, explicit tenant predicates, and forced row-level security.
The runtime group role owns no table, cannot bypass RLS, and cannot mutate
authoritative planning inputs.

`capacity_claims` deliberately contains no tenant, Deployment, decision, or
revision identity. A deferred reverse foreign key prevents orphan claims from
committing. The runtime role cannot update claims directly. Activate, release,
and expire call a security-definer function that resolves the tenant-owned
reservation link, checks transaction-local tenant and resource version, locks
both rows, and changes them atomically.

Reservation lifecycle is:

```text
PENDING --activate--> ACTIVE --release--> RELEASED
    |
    +------expire-----------------------> RELEASED
```

Only active and unexpired pending claims consume capacity.

## Acceptance evidence

- Pure planning and property tests live in
  `app/service/paas/internal/apphosting/domain/placement`.
- The transaction-owned workflow lives in
  `app/service/paas/internal/apphosting/usecase/createplacement`.
- Reservation transitions live in
  `app/service/paas/internal/apphosting/usecase/transitionreservation`.
- The pgx adapter, migration, verifier, and real PostgreSQL Gate B test live in
  `app/service/paas/internal/apphosting/data/postgres`.
- The PostgreSQL integration test applies the migration twice, runs the
  verifier, races two placements against one-target capacity, proves replay and
  conflict, executes direct runtime-role RLS attacks, injects failure after
  decision/claim/reservation writes, and verifies idempotent
  activate/release/expire behavior.
- Donor decisions and fixed commits are recorded in
  [`docs/adoption/FEAT-003-placement-isolation.md`](../adoption/FEAT-003-placement-isolation.md).

The common unit, vet, race, repeated, fuzz, architecture, schema, real
PostgreSQL 18, cross-platform build, Markdown-link, and `git diff --check`
gates passed on the same worktree. The real PostgreSQL test also ran under the
Go race detector without cached results.

## Deferred

Deployment execution, Compose rendering/project identity, rollback effects,
IAM/Audit calls, gateway routing, northbound handlers, tenant quotas, cloud
provisioning, Kubernetes scheduling, and host allocation are owned by later
FEATs.
