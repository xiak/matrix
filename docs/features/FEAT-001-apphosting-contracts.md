# FEAT-001: application-hosting contracts

- Status: Accepted
- Target release: Private Application PaaS v0.1
- Contract version: `paas.matrix.xiak.com/v1`
- Target design date: 2026-08-25

## Outcome

Define the smallest stable PaaS contract that can deploy and operate an
application through Docker Compose without exposing Compose, SSH, APISIX,
Kubernetes, or provider payloads as tenant-facing product concepts. The
product boundary is fixed by
[`ADR-0002`](../architecture/ADR-0002-product-boundary.md).

No northbound v1 contract predates this FEAT. Superseded draft names and
technology-shaped isolation values are deleted rather than retained as
compatibility aliases.

## Invariants

1. `Tenant` is the PaaS projection of the exact IAM organization identity.
   PaaS does not own users, membership, roles, sessions, or authorization.
2. `ApplicationRevision` is immutable. `Deployment` selects one revision and
   owns replicas, exact configuration and secret versions, placement,
   desired/observed lifecycle, and rollback target.
3. `PlacementDecision` is immutable. Requested isolation is either granted
   exactly or the result is `UNSCHEDULABLE`; downgrade is forbidden.
4. Public resources contain provider-neutral PaaS concepts only. Compose
   documents, project names, machine access, host paths, and vendor-native
   payloads are adapter internals.
5. Every mutation creates or reuses a durable `Operation`. Adapter effects use
   stable command identity and exact replay semantics.
6. `Evidence` is append-only, ordered, integrity-addressed, bounded, and
   sanitized. It cannot contain secrets, credentials, arbitrary commands, or
   raw provider output.
7. Every tenant-owned read and mutation is scoped by the authenticated IAM
   tenant before repository or adapter access.
8. Service policy authorizes and places before adapter selection. Adapters
   report capabilities and observations; they do not authorize or weaken
   policy.

## Resource model

| Resource | Authority | Mutability | Purpose |
| --- | --- | --- | --- |
| `Tenant` | IAM, projected by PaaS | Status projection | Stable tenant scope. |
| `Application` | PaaS tenant scope | Metadata versioned | Stable application identity. |
| `ApplicationRevision` | PaaS tenant scope | Immutable | Digest-pinned components, endpoints, inputs, and per-replica resources. |
| `Configuration` | PaaS tenant scope | Metadata versioned | Stable application configuration identity. |
| `ConfigurationRevision` | PaaS tenant scope | Immutable | Canonical non-secret environment values and rollback identity. |
| `Deployment` | PaaS tenant scope | Spec/status versioned | Exact revision, replicas, bindings, placement policy, desired state, health, and rollback state. |
| `ExecutionPool` | PaaS platform scope | Spec/status versioned | Administrative target grouping and allocation boundary. |
| `ExecutionTarget` | PaaS platform scope | Spec/status versioned | Addressable capacity, health, labels, executor binding, and isolation guarantees. |
| `PlacementPolicy` | PaaS tenant scope | Versioned | Required isolation, eligible pools/labels, and deterministic strategy. |
| `PlacementDecision` | PaaS scheduler | Immutable | Exact Deployment snapshot and selected target or normalized unschedulable result. |
| `Operation` | PaaS operation mechanism | Durable state machine | Idempotent asynchronous mutation and recovery state. |
| `Evidence` | PaaS, forwarded to Audit | Append-only | Sanitized policy, command, observation, and verification facts. |

All resources use opaque identifiers and UTC RFC 3339 timestamps with at most
microsecond precision. Mutable resources use positive `resourceVersion`.
Names and labels are display or selection data, never authority.

## Isolation guarantees

- `WORKLOAD`: each Deployment receives a stable executor identity and
  policy-controlled network/resource boundary; targets and hosts may be
  shared. Compose v0.1 implements this guarantee.
- `TENANT`: an execution environment is not shared across tenants.
- `HOST`: the underlying host is reserved to one tenant.

Compose v0.1 schedules only `WORKLOAD`. `TENANT` and `HOST` remain valid
requests but return `CAPABILITY_UNSUPPORTED` until an executor and conformance
evidence provide the exact guarantee. Compose projects, Docker daemons,
Kubernetes namespaces, VMs, and physical machines are implementation
mechanisms, not isolation enum values.

## Configuration and injection

Configuration management is a default apphosting capability. Workloads do not
link a Matrix SDK or maintain a runtime control-plane connection.

1. Developers or automation create immutable `ConfigurationRevision`
   resources through the PaaS API.
2. An `ApplicationRevision` declares named inputs. A `Deployment` binds every
   required input to an exact configuration revision or secret version.
3. Compose v0.1 injects ordinary non-secret scalar values as allowlisted
   environment variables. Secret plaintext is delivered only through fixed
   read-only files.
4. A configuration change creates a new Deployment generation and Operation.
   Rollback restores a previously accepted complete snapshot; it never rewrites
   a revision.
5. Secret plaintext is forbidden from Configuration, Operation, Evidence,
   logs, and support bundles.

Arbitrary structured configuration files, mutable aliases, dynamic refresh,
Nacos, and Consul are deferred. A later internal provider may resolve an
external source to an exact immutable version without changing public
Deployment semantics.

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
Unknown external outcomes enter `RECONCILING`; they are never treated as safe
failures or blindly replayed.

### Deployment

```text
PENDING -> PLACING -> APPLYING -> READY <-> DEGRADED
   |          |           |          |          |
   +----------+-----------+----------+----------+--> FAILED
   |                                 |          |
   +-----------> STOPPING <----------+----------+
                   |
                   +--> STOPPED
```

Rollback is an Operation that selects an earlier immutable accepted snapshot.
It does not mutate ApplicationRevision history.

## Adapter ports

`InfrastructureAdapter` reports capabilities and implements
`InspectExecutionTarget` and `ObserveExecutionTarget`. It never deploys an
application.

`DeploymentExecutor` implements `ValidateDeployment`, `ApplyDeployment`,
`ObserveDeployment`, `StopDeployment`, and `RollbackDeployment` for the
bounded Matrix application profile. It cannot accept caller-provided shell,
Compose YAML, Kubernetes manifests, host paths, privileged settings,
credentials, or provider-native blobs.

`GatewayAdapter` reconciles, observes, and deletes normalized application
routes. APISIX administration remains internal and is never exposed to a
browser or tenant credential.

Every side-effecting adapter call carries an exact operation, command, action,
scope, Deployment, ApplicationRevision, ExecutionTarget, request digest,
binding reference, deadline, and trace context as required by that action. A
successful replay returns the original result; a conflicting replay returns
`IDEMPOTENCY_CONFLICT` without a second effect.

## Errors, idempotency, and concurrency

HTTP failures use `application/problem+json`. Stable codes cover request and
authorization failures, resource/version conflicts, unschedulable policy,
execution-target and adapter failures, unknown outcomes, deadlines, operation
failure, manual intervention, rate limiting, and internal defects.

Every public mutation requires `Idempotency-Key`. The service stores its
canonical request digest and Operation in the same transaction as mutation
intent. Mutable updates require `If-Match` or exact `resourceVersion`.
Adapter `commandId` is deterministic over the operation, action, target,
Deployment, and ApplicationRevision; retry attempts do not change effect
identity.

## Version rules

- The source contract lives under `api/paas/v1/` and is generated into
  OpenAPI 3.1 from the Go contract.
- Additive optional fields and enum values may enter v1. Removing or renaming
  fields, changing meaning, or weakening tenant/isolation guarantees requires
  a new API version.
- `apiVersion` identifies the contract; it is not a DNS lookup or customer
  installation address.
- Provider schemas stay inside their adapters.

## Acceptance

FEAT-001 is accepted only when:

1. generated OpenAPI defines every current resource, enum, problem,
   idempotency rule, and optimistic-concurrency field;
2. contract tests validate required fields, immutable resources, tenant scope,
   exact state transitions, enum uniqueness, safe text, and forbidden
   provider-specific public fields;
3. examples validate through both OpenAPI/JSON Schema and strict Go decoders;
4. adapter ports compile with fakes and prove stable replay identity and
   normalized failures;
5. architecture tests enforce source direction and apphosting ownership;
6. the fixed donor comparison records `REUSE`, `ADAPT`, `REFERENCE`, or
   `REJECT`, and no donor is a build or runtime dependency;
7. generation drift, unit, vet, race, repeated, schema, and repository-diff
   gates pass.

## Implementation evidence

- `api/paas/v1` contains the Go contract, validators, examples, deterministic
  OpenAPI generator, and schema/wire tests.
- `app/service/paas/internal/apphosting/port` owns service-facing adapter
  interfaces; concrete adapters remain outside the service `internal/` tree.
- `app/service/paas/internal/apphosting/domain` owns command identity and exact
  Operation/Deployment transitions.
- `test/architecture` enforces the dependency and naming rules.
- Donor provenance is recorded in
  [`docs/adoption/FEAT-001-apphosting-contracts.md`](../adoption/FEAT-001-apphosting-contracts.md).
- Acceptance completed on 2026-08-25 on one worktree with generation-drift,
  unit, vet, race, repeated, JSON Schema, architecture, cross-platform build,
  Markdown-link, and repository-diff gates passing.

Database repositories, worker leases, Compose effects, IAM/Audit clients,
gateway routing, and northbound handlers are accepted by their owning FEATs,
not by this contract FEAT.
