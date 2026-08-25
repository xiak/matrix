# FEAT-001: Runtime domain and versioned contracts

- Status: Pre-v1 model correction in progress
- Target release: Local Compose Runtime v0.1
- Contract version: `matrix.paas.io/paas/v1`
- Target design date: 2026-08-25

## Outcome

> Architecture amendment: the executable mechanisms and tests in this FEAT
> remain evidence, but its published vocabulary is not release-ready.
> The accepted product boundary requires Application, immutable
> ApplicationRevision, Deployment,
> ExecutionPool/ExecutionTarget, a domain-local DeploymentExecutor, and
> provider-neutral isolation before Gate B. No northbound v1 API has shipped,
> so compatibility aliases are forbidden.

Define the smallest stable control-plane contract that can place and operate a
tenant workload on a local machine today without coupling the product to
Compose, APISIX, Kubernetes, or a cloud-vendor payload. The same contract must
support dedicated hosts and Kubernetes targets later without changing tenant,
release, placement, operation, or evidence identity.

This target design was written before inspecting donor implementations for
FEAT-001. Donor review may change implementation tactics, but any contract
change requires an explicit design amendment and rationale.

## Non-negotiable invariants

1. `Tenant` is a PaaS projection of an IAM-owned identity. PaaS never becomes
   the user, membership, role, session, or permission authority.
2. `WorkloadRelease.spec` is immutable. An update creates a new release
   revision and operation rather than mutating deployed history.
3. A `PlacementDecision` is immutable and records requested and granted
   isolation. Unsupported isolation is `UNSCHEDULABLE`; it is never silently
   downgraded.
4. Public resources contain stable PaaS concepts only. Adapter configuration,
   Compose project names, APISIX Admin objects, SSH parameters, and vendor
   responses cannot become public fields.
5. Every mutating request creates or reuses a durable `Operation`. External
   effects are issued with a stable command identity and are safe to replay.
6. `Evidence` is append-only, ordered, integrity-addressed, and sanitized.
   Secrets, credentials, arbitrary command text, and raw provider payloads are
   forbidden.
7. Every tenant-owned read, mutation, operation, and evidence query is scoped
   by the authenticated IAM tenant before repository or adapter access.
8. Service policy is evaluated before an adapter is selected. An adapter may
   report capabilities and facts but cannot authorize, place, or weaken policy.

## Resource model

| Resource | Authority | Mutability | Purpose |
| --- | --- | --- | --- |
| `Tenant` | IAM; projected by PaaS | Status projection | Stable tenant identity and lifecycle used for scoping. |
| `ResourcePool` | PaaS | Versioned spec/status | Administrative grouping and allocation boundary for runtime targets. |
| `RuntimeTarget` | PaaS with infrastructure observations | Versioned spec/status | Addressable compute target, labels, capacity, health, and isolation capabilities. |
| `PlacementPolicy` | PaaS tenant scope | Versioned | Required isolation, eligible pools/labels, and deterministic selection strategy. |
| `PlacementDecision` | PaaS scheduler | Immutable | Selected target or normalized unschedulable reason with policy/resource versions. |
| `WorkloadRelease` | PaaS tenant scope | Immutable spec, observed status | Content-addressed workload revision and desired portable runtime shape. |
| `Operation` | PaaS | Durable state machine | Idempotent asynchronous mutation, attempts, terminal result, and failure. |
| `Evidence` | PaaS; forwarded to Audit as needed | Append-only | Sanitized policy, adapter-command, observation, and verification facts. |

All resources use opaque identifiers, UTC RFC 3339 timestamps, an explicit
`tenantId` when tenant-owned, and optimistic-concurrency `resourceVersion`
where mutable. Names and labels are display/selection data and never authority.
The PaaS `Tenant.id` is the exact opaque IAM organization identity; PaaS does
not allocate a second tenant identifier or infer one from a display name.

### Isolation classes

The versioned vocabulary is:

- `SHARED_COMPOSE`: multiple tenants may share a target; each workload has a
  stable isolated runtime unit and policy-controlled network/resources.
- `DEDICATED_COMPOSE`: a tenant receives a dedicated runtime unit on a shared
  target.
- `DEDICATED_HOST`: one tenant is allocated the host.
- `K8S_NAMESPACE`: namespace-level isolation on a Kubernetes target.
- `PHYSICAL_HOST`: a specifically allocated physical target.

Runtime v0.1 schedules only `SHARED_COMPOSE` and `DEDICATED_COMPOSE`. The other
classes remain contract values so policy can express future intent, but they
must return `UNSCHEDULABLE` until a capable target and adapter are registered.

## State machines

### Operation

```text
ACCEPTED -> PLANNING -> QUEUED -> EXECUTING -> VERIFYING -> SUCCEEDED
    |           |          |          |       |
    +-----------+----------+----------+-------+-----------> FAILED
                +----------+----------+------------------> CANCELLED
                                      |
                                      +--> RECONCILING --> VERIFYING
                                               |       \--> FAILED
                                               \----------> MANUAL_INTERVENTION
```

`SUCCEEDED`, `FAILED`, `CANCELLED`, and `MANUAL_INTERVENTION` are terminal.
`RECONCILING` is mandatory when a side effect may have occurred but no durable
result was committed. An attempt may be retried without creating another
operation only after reconciliation proves replay safety; each attempt uses
the same operation and command identity plus a monotonically increasing
attempt number. Recovery leases prevent concurrent workers from executing one
operation.

### WorkloadRelease status

```text
PENDING -> PLACING -> APPLYING -> READY -> DEGRADED
              |           |        |          |
              +-----------+--------+----------+--> FAILED
                          READY -> STOPPING -> STOPPED
```

Rollback is an `Operation` that selects an earlier immutable release; it does
not rewrite the failed release. Observations may move `READY` to `DEGRADED` and
back when the same deployed revision recovers.

### PlacementDecision outcome

A decision is created once with exactly one terminal outcome:

- `SCHEDULED`: includes the selected target, granted isolation class, and the
  resource/policy versions used by the scheduler.
- `UNSCHEDULABLE`: includes a stable reason code and safe human explanation;
  it never contains candidate credentials or vendor responses.

## Adapter ports

Adapters implement service-owned ports. The control plane and worker depend on
interfaces; only a composition root constructs concrete implementations.

### InfrastructureAdapter

| Operation | Responsibility |
| --- | --- |
| `Capabilities` | Report adapter version and supported target/isolation capabilities. |
| `InspectTarget` | Validate an internal target binding and return normalized identity, labels, capacity, and health. |
| `ObserveTarget` | Refresh normalized capacity, allocation, health, and observation time. |

It does not deploy workloads. Registration stores an internal credential or
connection reference; public APIs never accept or return raw credentials.

### RuntimeAdapter

| Operation | Responsibility |
| --- | --- |
| `Capabilities` | Report portable workload actions and isolation classes. |
| `ValidateRelease` | Validate the portable release against target capabilities without side effects. |
| `Apply` | Idempotently deploy a release selected by a placement decision. |
| `Observe` | Return normalized revision, readiness, health, and sanitized evidence. |
| `Stop` | Idempotently stop the selected deployed revision. |
| `Rollback` | Idempotently restore a specified earlier immutable release. |

It receives an allowlisted portable specification and secret references. It
never receives a caller-provided shell program, host path, Compose document,
SSH command, or raw credential.

### GatewayAdapter

| Operation | Responsibility |
| --- | --- |
| `Capabilities` | Report supported route, TLS, and traffic-policy features. |
| `ReconcileRoutes` | Idempotently converge normalized routes for a deployed release. |
| `ObserveRoutes` | Return normalized route readiness and sanitized evidence. |
| `DeleteRoutes` | Idempotently remove routes owned by a release. |

Gateway administration remains internal. Browser and customer credentials can
never invoke an APISIX or cloud-gateway administration API directly.

### Common command envelope

Every side-effecting adapter call carries:

- `operationId`, `commandId`, and `attempt`;
- an explicit `scope` (`PLATFORM` or exact IAM tenant), plus `workloadId`,
  `releaseId`, and selected `runtimeTargetId`;
- an absolute deadline and trace context;
- an opaque internal binding reference where infrastructure access is needed.

A successful replay returns the original receipt/result. A conflicting replay
returns `IDEMPOTENCY_CONFLICT`; it must not execute a second side effect.
The worker durably records the dispatch identity before external I/O. If it
cannot prove whether a call completed, it records an unknown outcome and
reconciles by `commandId` instead of blindly applying again.

## Error contract

HTTP errors use `application/problem+json` with `type`, `title`, `status`,
`code`, safe `detail`, `traceId`, `retryable`, and optional field violations.
The initial stable codes are:

- request/auth: `INVALID_ARGUMENT`, `UNAUTHENTICATED`, `PERMISSION_DENIED`;
- resource/concurrency: `NOT_FOUND`, `ALREADY_EXISTS`, `CONFLICT`,
  `RESOURCE_VERSION_CONFLICT`, `IDEMPOTENCY_CONFLICT`;
- scheduling/capability: `UNSCHEDULABLE`, `CAPABILITY_UNSUPPORTED`;
- execution: `TARGET_UNAVAILABLE`, `ADAPTER_UNAVAILABLE`,
  `ADAPTER_REJECTED`, `ADAPTER_OUTCOME_UNKNOWN`, `DEADLINE_EXCEEDED`,
  `OPERATION_FAILED`, `MANUAL_INTERVENTION_REQUIRED`;
- platform: `RATE_LIMITED`, `INTERNAL`.

Adapter-native failures are normalized into this vocabulary. Retryability is a
server decision constrained by the normalized class, attempt budget, and
deadline; it is not copied blindly from a provider message.

## Idempotency and concurrency

1. Every public mutation requires `Idempotency-Key`.
2. The key is scoped to authenticated tenant, principal, route, and action.
3. The server stores a canonical request digest and resulting operation in the
   same transaction as the mutation intent.
4. Replaying the same digest returns the original operation. Reusing the key
   with another digest returns `IDEMPOTENCY_CONFLICT`.
5. Mutable resource updates require `If-Match`/`resourceVersion` and return
   `RESOURCE_VERSION_CONFLICT` on stale writes.
6. Adapter commands use a deterministic `commandId` derived from operation,
   action, target, and release identity; attempts do not change side-effect
   identity.

## Version and compatibility rules

- The source contract lives under `api/paas/v1/`.
- New optional fields and enum values may be added within v1. Consumers must
  ignore unknown response fields and handle unknown enum values safely.
- Removing/renaming fields, changing meaning, weakening tenant/isolation
  guarantees, or making an optional request field required needs a new API
  version.
- Compose, APISIX, Kubernetes, SSH, and cloud-vendor schemas are confined to
  adapter-internal packages and deployment configuration.
- API examples and schemas are tested together; undocumented wire behavior is
  not a compatibility promise.

## FEAT-001 acceptance evidence

FEAT-001 is accepted only when all of the following are present and green:

1. A machine-readable `api/paas/v1` contract defines every resource, stable
   enum, problem response, idempotency header, and optimistic-concurrency rule
   described here.
2. Contract tests validate required fields, tenant scoping, enum uniqueness,
   terminal state sets, legal state transitions, immutable release/placement
   fields, and forbidden vendor-specific public names.
3. Executable adapter port contracts compile with a fake implementation and
   prove command replay identity and normalized errors.
4. The donor comparison records fixed commits and one of `REUSE`, `ADAPT`,
   `REFERENCE`, or `REJECT` for each relevant source slice.
5. Architecture and adoption documentation link to the implemented contract;
   formatting, tests, and repository boundary checks pass locally.

### Acceptance result

Accepted on 2026-08-25 with:

- 63 Draft 2020-12 schemas compiled by the repository test suite;
- ten wire examples validated by both JSON Schema and strict Go decoders;
- exhaustive Operation and WorkloadRelease transition-table tests;
- a compiling fake RuntimeAdapter proving one effect for a replay and
  `IDEMPOTENCY_CONFLICT` for a mismatched digest;
- source-boundary tests for API direction, service `internal/` ownership,
  deployment imports, and adapter composition roots;
- `go test ./...`, `go vet ./...`, `go test -race ./...`, and
  `git diff --check` passing on the acceptance branch.

## Deferred from FEAT-001

Database repositories, worker leases, real LocalMachine inspection, Compose
effects, IAM/Audit clients, APISIX routing, and northbound handler behavior are
implemented by FEAT-002 through FEAT-006. Their required identities and
failure semantics are fixed here so those slices compose without redesign.

## Donor-informed amendments

The fixed-commit review did not replace the target model. It produced two
explicit amendments:

1. Senatria IAM names the tenant authority `organization_id`; therefore the
   PaaS tenant ID is defined as that exact opaque identity rather than a new
   PaaS-generated alias.
2. The legacy operation/provider worker correctly models the crash window
   between external I/O and outcome commit. `RECONCILING`,
   `MANUAL_INTERVENTION`, durable pre-dispatch identity, and unknown-outcome
   errors were added so Runtime v0.1 cannot mistake an unknown effect for a
   safe failure.

The complete comparison and slice decisions are recorded in
[`docs/adoption/FEAT-001-runtime-contracts.md`](../adoption/FEAT-001-runtime-contracts.md).

## Implementation-informed amendment

The first concrete infrastructure adapter exposed that target registration and
resource-pool creation are platform operations. Requiring a `tenantId` on every
`Operation`, `Evidence`, and `AdapterCommandEnvelope` would force those
operations to invent a tenant authority. Before any v1 release, those fields
were replaced with the existing `ResourceScope`:

- `PLATFORM` scope carries no tenant ID and is required for target inspection;
- `TENANT` scope carries the exact IAM organization ID and remains mandatory
  for tenant workload operations;
- validators fail closed when a platform-only action is tenant scoped or a
  tenant-only action is platform scoped.
