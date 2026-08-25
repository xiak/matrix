# FEAT-004: Compose application execution

- Status: Donor review complete; implementation pending
- Target release: Private Application PaaS v0.1
- Executor contract version: `v1`
- Target design date: 2026-08-25

## Outcome

Deliver the first user-visible application-hosting loop on one Docker Engine:
a developer creates immutable application and configuration revisions, changes
a Deployment desired generation, observes a durable Operation, and can stop or
roll back the application. The PaaS compiles the provider-neutral resources
into an adapter-owned Compose project; callers never submit Compose YAML,
commands, paths, Docker options, or secret plaintext to the executor.

This design is fixed before FEAT-004 donor inspection. Donor code may change
implementation tactics only through a recorded adoption decision.

## Scope and invariants

1. PostgreSQL is authoritative for Application, Configuration,
   ApplicationRevision, immutable Deployment generation, current Deployment,
   Operation, command intent, receipt, and observation.
2. Every desired-state mutation is tenant-scoped, idempotent, and committed
   with its Operation. A status update never changes desired state.
3. A new configuration, artifact, replica count, binding, desired state, or
   rollback produces a new immutable Deployment generation. Rollback copies a
   previously accepted snapshot into a new generation; history is not edited.
4. The worker places the exact generation before execution. It cannot accept a
   caller-selected target and cannot execute an unscheduled generation.
5. Ordinary configuration is resolved from exact ConfigurationRevision values
   and injected as environment variables. Conflicting keys fail before an
   external effect.
6. Secret bindings carry only exact SecretVersionReference values. A
   server-side SecretResolver supplies at most 1 MiB directly to an
   installation-owned file; plaintext never enters PostgreSQL, Compose JSON,
   Operation, Evidence, receipt, logs, or support output.
7. OCI artifacts remain identified publicly by digest. An internal
   ArtifactResolver maps a verified digest to an already-present Docker image;
   the executor always uses `--pull never` and `--no-build`.
8. Apply, observe, stop, and rollback are safe to retry. An unknown effect
   outcome enters reconciliation and is observed before another apply.
9. Compose v0.1 grants only `WORKLOAD`. It creates one deterministic project
   and default network per Deployment, applies CPU/memory/replica limits, uses
   no privileged mode or host network, and mounts no tenant-selected host path.
10. The control plane, worker, executor, installer, and release utilities are
    Go programs. Fixed Docker/Compose CLI calls are external provider effects;
    Python and mutable orchestration scripts are not product dependencies.

## Ownership and ports

| Concern | Owner |
| --- | --- |
| Desired resources, generations, lifecycle, placement coordination | `apphosting` |
| Generic Operation identity, lease, fencing, attempt, and terminal state | `operation` mechanism inside the PaaS modular monolith |
| Compose document, project/network identity, state directory, provider calls | `app/adapter/apphosting/compose` |
| Verified digest to local Docker image mapping | `ArtifactResolver` port |
| Exact secret-version material | `SecretResolver` port |
| Tenant authentication and authorization | IAM-facing `Authorizer` port |
| Audit retention and query | Audit-facing port; FEAT-004 retains only sanitized execution evidence |

The application use cases are create immutable resource, apply Deployment,
rollback Deployment, claim/reconcile Operation, and read current state. Their
transaction boundaries live in the use-case contracts; PostgreSQL and Compose
adapters do not own lifecycle decisions.

Concrete adapters cannot import a service `internal/` package. The existing
DeploymentExecutor method data therefore moves to versioned, internal-visible
`api/paas/v1` adapter schemas. The service-owned interface uses those schemas,
and an external conformance test proves the Compose adapter implements it.

## Deployment generations

A Deployment exposes positive `generation`; status exposes
`observedGeneration`. PostgreSQL stores an immutable snapshot for every
generation containing:

- tenant, Deployment, ApplicationRevision, and PlacementPolicy identity;
- desired state, component replicas, and exact input bindings;
- a canonical content digest and creation Operation;
- the accepted PlacementDecision and executor observation when available.

`resourceVersion` remains the optimistic-concurrency token for the mutable
Deployment resource. `generation` changes only when desired content changes.
Status-only writes advance resourceVersion without creating a generation.

An executor request contains the immutable generation snapshot, exact
ApplicationRevision, required ConfigurationRevision documents, accepted
PlacementDecision, and adapter command envelope. It contains secret references
but no secret bytes. An observation binds Deployment, generation,
ApplicationRevision, project receipt, component readiness, and normalized
network-local endpoint bindings.

## Minimal northbound workflow

The v0.1 HTTP surface admits only the commands needed for the loop:

- create Application and Configuration identities;
- create immutable ConfigurationRevision and ApplicationRevision resources;
- create or update a Deployment desired generation;
- roll back a Deployment to an accepted generation;
- read Application, revisions, Deployment, generation, and Operation state.

The authenticated tenant comes from the Authorizer context and must equal every
resource scope; a client header is never authority. Every mutation requires
`Idempotency-Key`; updates and rollback also require `If-Match`. Immutable
creation may complete its Operation in the request transaction. Deployment
effects return a queued Operation and never hold an HTTP transaction open.

Secret create/update APIs, dynamic configuration refresh, mutable aliases,
arbitrary structured files, Nacos, and Consul are outside this FEAT. The
default Phase 1 SecretResolver reads exact versions provisioned under an
installation-owned root with restrictive permissions. A future provider may
resolve the same reference without changing Deployment or executor contracts.

## Durable operation protocol

The implementation uses one explicit state machine, not a workflow DSL:

1. a tenant transaction validates desired input, stores immutable resources or
   a new generation, and creates/replays the Operation by request digest;
2. a worker claims a due Operation with a lease and monotonically increasing
   fencing token;
3. placement runs under its existing serializable transaction and stores the
   decision plus pending capacity reservation;
4. the worker stores a deterministic adapter command intent, commits, and
   calls the executor outside the database transaction;
5. a result is accepted only while the lease/fencing token is current;
6. successful apply is observed before the reservation is activated and the
   generation becomes READY;
7. definitive pre-effect failure releases a pending reservation and normalizes
   the Operation failure; uncertain effect failure enters RECONCILING;
8. stop removes the Compose project before capacity release; rollback creates
   and executes a new generation from an accepted snapshot.

Command identity excludes attempt number. Equal command replay returns the
stored receipt; unequal request digest is `IDEMPOTENCY_CONFLICT`. Expired
workers cannot commit status. Bounded attempts and deadlines end in FAILED or
MANUAL_INTERVENTION rather than infinite retry.

## Compose execution profile

The adapter derives a non-secret project key from tenant and Deployment IDs
and confines all state below one validated absolute binding root. It writes
deterministic Compose JSON and secret files atomically, with restrictive file
permissions, then invokes only closed command forms. It rejects symbolic-link
components in the managed root, fsyncs atomic state updates, and holds a
cross-process project lock around mutation and observation.

Apply uses detached, non-interactive Compose with build and pulls disabled,
orphan removal, a deadline, and readiness wait. Stop removes containers and
the project network but retains sanitized generation receipts. Rollback uses
the same apply mechanism with a prior accepted snapshot; there is no parallel
rollback implementation.

Each component becomes one service. Images come only from ArtifactResolver.
Configuration maps to service environment. Secret inputs mount read-only at
`/run/secrets/<input-name>`. Endpoints are exposed only on the project network;
application services never publish host ports. A later GatewayAdapter consumes
the normalized service/port observation without reading Compose files. Images
may supply Docker health checks; otherwise running replicas are the v0.1
readiness fact.

The adapter rejects unsupported artifact kinds, zero replicas for RUNNING,
duplicate environment keys, unresolved bindings, extra revisions or secrets,
unverified images, unsafe provider output, state-root escape, stale receipts,
and any requested isolation other than WORKLOAD.

## Persistence and isolation

A forward migration adds Configuration, ConfigurationRevision, immutable
Deployment generation, Operation, command, receipt, and observation tables.
Tenant-owned tables use tenant-leading keys, explicit predicates, and forced
RLS. Separate non-login API and worker group roles receive only their required
columns and functions; neither owns schema objects or bypasses RLS.

The API transaction can create desired resources and Operations but cannot
write placement decisions or executor observations. The worker can claim and
advance Operations, placement, receipts, observations, and Deployment status
but cannot rewrite immutable resources or generations. Structural verification
checks current schema invariants and privileges, not migration text or removed
pre-v1 names.

## Incremental acceptance

### Gate A: deterministic execution input

1. Generation and adapter schemas validate through Go and OpenAPI without
   exposing secret material or provider-native fields.
2. Canonical digests are stable under map/order variation and change for every
   desired execution input.
3. The Compose compiler produces semantically equivalent deterministic JSON,
   rejects unsupported input, and never admits build, pull, host path,
   privileged, host-network, or arbitrary-command capability.

### Gate B: durable application workflow

1. Migration apply-twice and structural/security verification pass on a clean
   supported PostgreSQL database.
2. API replay, changed-digest conflict, If-Match, tenant RLS, immutable
   generation, worker lease/fencing, and transaction fault injection pass
   against a non-bypass worker login.
3. Apply success, definitive failure, unknown outcome reconciliation, stop,
   and rollback drive only valid Operation/Deployment transitions and maintain
   reservation consistency.

### Gate C: real Compose vertical slice

1. A disposable real Docker project starts a digest-resolved fixture with
   `--pull never` and no build or registry dependency.
2. The fixture proves ordinary ENV configuration and a read-only secret file
   without returning secret plaintext.
3. A network-scoped probe verifies the fixture without adding a host port. A
   new configuration revision creates a new generation and observable value;
   rollback creates another generation and restores the earlier value.
4. Crash/timeout injection followed by observe reconciles without duplicate
   project identity; stop removes containers/network and releases capacity.
5. State and evidence contain no secret bytes, native error payloads, arbitrary
   command, or path outside the binding root.

Common generation-drift, unit, vet, race, repeated, architecture, schema,
real-PostgreSQL, real-Compose, cross-platform build, Markdown-link, stale-term,
and `git diff --check` gates must pass on one worktree. Tests assert behavior
and current schema invariants rather than Compose JSON formatting, SQL text,
file layout, command call order, or implementation counts.

## Deferred

APISIX route reconciliation, public UI/CLI convenience flows, dynamic config,
secret authoring, external secret providers, persistent application volumes,
stateful migrations, jobs/cron, remote Docker execution, Kubernetes, build
service, automatic image distribution, platform installation/upgrade, and
support bundles remain outside FEAT-004.

Fixed donor decisions and the resulting implementation constraints are
recorded in
[`docs/adoption/FEAT-004-compose-application-execution.md`](../adoption/FEAT-004-compose-application-execution.md).
