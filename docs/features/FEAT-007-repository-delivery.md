# FEAT-007: Repository change validation

- Status: In progress; UX, architecture, donor analysis, implementation
  baseline, Gate A project/Pipeline/source-resource contract, domain,
  configuration transaction/persistence, and shared authority slices complete;
  configuration HTTP/process integration complete; run lifecycle pending
- Target product: Matrix DevOps v0.1
- Contract: `devops.matrix.xiak.com/v1`
- Target design date: 2026-09-07
- Depends on: [FEAT-008 product foundation and shell](FEAT-008-product-foundation-shell.md)

## Outcome

Deliver the first independently useful Matrix DevOps vertical slice: a verified
change-request event from one self-hostable source provider selects an exact
commit and immutable pipeline revision, runs bounded verification on an
isolated Matrix Native executor, reports one source-provider check, and exposes
the correlated run and sanitized log evidence in the unified Matrix UI.

This slice proves CI control-plane authority without publishing an artifact or
deploying an application. Mainline OCI publication belongs to
[FEAT-009](FEAT-009-mainline-oci-publication.md); deployment belongs to
[FEAT-010](FEAT-010-paas-continuous-delivery.md); connecting an existing
CODING installation belongs to
[FEAT-011](FEAT-011-coding-connected-provider.md).

It is not hosted source control, a general DAG engine, arbitrary remote shell,
a Jenkins-compatible service, a Kubernetes-native API, a merge queue, or a
developer-project-management suite.

## Boundary and ownership

`delivery` is the DevOps product bounded context. The first implementation
may be composed in one service process, but it owns a schema, roles, ports, and
public contract separate from Application PaaS.

| Concern | Owner |
| --- | --- |
| DevOps project, source connection, repository binding, source event, pipeline and immutable revision, PipelineRun, task attempts, normalized logs, and check-report receipt | `delivery` |
| Organization, principal, service identity, role, session, and authorization decision | `iam` |
| Immutable security and DevOps facts | `audit` |
| Installed DevOps product discovery and readiness | `installation` |
| Provider webhook, source fetch, and commit-status protocol | One source-provider adapter behind delivery-owned ports |
| Untrusted verification execution | One `BuildExecutor` adapter behind a delivery-owned port |
| Application and deployment state | `apphosting`; unused by this slice |

Every stored row is tenant-leading and forced-row-level-security protected.
API and worker roles remain separate. Delivery never reads or writes IAM,
Audit, installation, or apphosting tables. Cross-context effects use versioned
HTTP contracts and narrowly authorized service identities.

## Product experience

The platform shell supplies login, organization context, installed-product
navigation, readiness, and safe global correlation. Selecting **DevOps** opens
a product-local navigation with **Code**, **Pipelines**, and **Runs**. Artifact
and Delivery navigation is absent until its owning FEAT is installed; an empty
screen must not imply a capability exists.

The first journey is:

```text
Connect repository -> create pipeline draft -> activate immutable revision
 -> open/change a pull request -> inspect run -> inspect exact check/log evidence
```

The pipeline page shows the bound repository, change trigger, current immutable
revision, executor profile, limits, connection health, and latest runs. The run
page keeps source and execution identity visible while navigating:

```text
RECEIVE -> FETCH -> VERIFY -> REPORT
```

Each stage exposes normalized state, bounded duration, current/terminal reason,
and authorized sanitized logs. The detail view shows the exact repository
identity, change number, head and trusted base commits, event identity,
pipeline revision, executor identity, check-report receipt, initiator, and
Audit correlation. Provider-native pages may be linked but never embedded as
Matrix authority.

Empty, loading, denied, unavailable, stale-provider, cancelled,
manual-intervention, and terminal failure states are designed states, not raw
error pages. Keyboard navigation, visible focus, WCAG AA contrast, reduced
motion, 360-pixel layout, and Chinese/English text expansion are acceptance
requirements.

## Resource and trust model

| Resource | Mutability | Purpose |
| --- | --- | --- |
| `DevOpsProject` | Metadata/status versioned | Organization-owned namespace for repositories, pipelines, and runs; it grants no infrastructure authority. |
| `SourceConnection` | Metadata/status versioned | Tenant-bound provider identity, endpoint allowlist, health, and secret references; never plaintext credentials. |
| `RepositoryBinding` | Spec/status versioned | Stable provider repository identity, fetch/report connection, and trusted default branch. |
| `Pipeline` | Metadata versioned | Stable identity plus one active immutable revision. |
| `PipelineRevision` | Immutable | Bound repository, `CHANGE` trigger policy, trusted verification profile, approved dependency egress, limits, and reporter policy. |
| `SourceEvent` | Immutable | Provider delivery identity, canonical payload digest, repository, change identity, exact head commit, trusted base commit, and admitted time. |
| `PipelineRun` | Immutable input/status versioned | Exact event and revision, deterministic stages, attempts, normalized result, and correlation. |

Names, branch names, labels, URLs, and display text are not authority. Provider
repository identity, immutable commits, PipelineRevision ID, canonical payload
digest, IAM-derived tenant/subject, and durable command identities are.

A draft is mutable only before activation. Activation creates a new
PipelineRevision and never changes a revision referenced by a run. The first
revision supports a closed ordered list of verification steps. Each step
selects an installation-approved, digest-pinned toolchain image; bounded argv,
working directory under the source root, non-secret literals, CPU, memory,
disk, process, log, and time limits; and one named egress policy. It cannot
select a host shell, host path, container socket, privileged mode, provider
object, credential, or deployment target.

## Admission and workflow

1. The webhook endpoint is bound to one SourceConnection. It enforces request
   size, media type, provider event kind, current/rotating signature, delivery
   identity, and any signed-time/replay rule supported by the selected
   protocol before decoding bounded fields.
2. Provider delivery identity plus canonical payload digest gives equal-replay
   success and changed-replay conflict. The transaction stores SourceEvent,
   selects the already-active PipelineRevision, creates the PipelineRun, and
   writes a sanitized Audit outbox fact before acknowledging the webhook.
3. The acquisition adapter fetches from the bound repository and proves the
   advertised head and trusted base commits. Redirects, submodules, large-file
   objects, commit mismatch, and unapproved endpoints fail closed. Its
   credential never enters the verification environment.
4. A worker claims each due stage with a lease and monotonic fencing token,
   stores deterministic command intent, commits, and calls the adapter outside
   the transaction. Only the current fence may commit a result.
5. Build code is untrusted and ephemeral. It receives the content-addressed
   source snapshot and closed verification profile, but no source-provider,
   reporter, IAM, Audit, PaaS, host, executor-control, or future registry
   credential.
6. The reporter sends one pending and one terminal check under a deterministic
   report identity. Timeout or connection loss is observed before retry; equal
   provider replay succeeds, while contradictory receipt enters reconciliation.
7. A manual replay selects the exact SourceEvent and PipelineRevision of an
   existing run and creates a linked new run. It cannot resolve a branch again
   or substitute a definition, commit, provider, or policy.

The state machine is:

```text
QUEUED -> FETCHING -> VERIFYING -> REPORTING -> SUCCEEDED
   |          |            |           |
   +----------+------------+-----------+-> FAILED
   +----------+------------+-----------+-> CANCELLED
                         uncertain external effect -> RECONCILING
                         exhausted reconciliation -> MANUAL_INTERVENTION
```

Cancellation prevents future stages and requests cancellation of active
execution. It never claims an unconfirmed external effect did not happen.
`SUCCEEDED`, `FAILED`, `CANCELLED`, and `MANUAL_INTERVENTION` are
terminal. Failure uses a closed safe class; native error text never crosses
the adapter boundary.

### Normalized admission contract

The provider adapter emits a `NormalizedChange` only after authenticating the
untouched request. `delivery` accepts exactly `OPENED`, `REOPENED`, or
`UPDATED`; the Gitea adapter maps `synchronized` to `UPDATED`. Delivery IDs are
canonical non-zero lowercase UUIDs. Git object identities are lowercase 40- or
64-hex strings; they are content identifiers rather than security digests.
Change numbers are positive JSON-safe integers. Provider users, URLs, labels,
branches other than the binding's trusted default branch, and raw payload
fields do not cross this boundary.

A `SourceEvent` ID is deterministically derived from tenant, SourceConnection,
and delivery ID, so changed content cannot escape replay detection by choosing
a new resource ID. Its content digest separately seals the project,
RepositoryBinding and binding digest, external repository identity, normalized
action/change number, exact head and base commits, and canonical raw-payload
digest. Equal `(SourceConnection, delivery ID, content digest)` replay returns
the original admission; the same identity with a changed digest conflicts.

Each matching active Pipeline revision produces one deterministic
`PipelineRun`, keyed by tenant, SourceEvent, immutable PipelineRevision, and
its sealed input digest. The run input repeats the exact event, binding, commit,
and revision digests needed for authorization, scheduling, and support without
re-resolving mutable configuration. A newly admitted run is resource version
1 in `QUEUED / RECEIVE / EVENT_ADMITTED`; no executor effect exists yet. Later
states follow the fixed state machine above and carry only closed safe reasons.
Multiple active Pipelines may share one SourceEvent, but admission is atomic
and must fit the tenant's fixed queue limit; partial fan-out is forbidden.

## Security, quota, and retention

- IAM receives closed actions for DevOps project, connection, repository,
  pipeline, run read/replay/cancel, and log read. Built-in DevOps administrator,
  developer, and viewer roles are organization-scoped; no provider membership
  becomes Matrix authority.
- Source fetch and check-report credentials are separate secret references,
  resolved only inside their adapters. Rotation and revocation affect the next
  effect without restarting the control plane.
- Tenant concurrency, queue depth, running time, resource use, stored log
  bytes, event rate, and replay rate are bounded. Scheduling is fair across
  tenants; webhook retries cannot bypass quota.
- Logs are bounded, chunked, ordered, and sanitized at ingestion. Secrets,
  tokens, environment dumps, raw webhook payloads, provider-native errors,
  arbitrary command lines, and absolute host paths are forbidden from API,
  UI, Audit, and support evidence.
- PipelineRun metadata and Audit facts survive cleanup of ephemeral source and
  executor state. Exact log retention and installation-owned storage are fixed
  before implementation; silent unbounded retention is rejected.

## Fixed implementation baseline

The first code slice uses the following closed baseline. Changing a version,
digest, limit, trust path, or retention class requires replacing this design
before the affected implementation is accepted; a mutable tag or runtime
default is never authority.

### Source-provider fixture and adapter

The one Gate B/C provider is Gitea `1.27.3`. Acceptance uses the official
rootless Linux/amd64 image
`docker.gitea.com/gitea@sha256:95b0ae18fb99b4a579b3dd383ea5ad8d8f77534c030c1fe554e6378ac8a5c496`.
Gitea remains a customer-owned connected source system and a test fixture; it
is not declared as a Matrix product, copied into the Matrix release, or given
Matrix IAM authority. Version `1.27.3` is the minimum tested protocol because
it fixes the hook-permission issue affecting `1.27.2` and earlier. The fixed
evidence is the official
[release](https://github.com/go-gitea/gitea/releases/tag/v1.27.3),
[security advisory](https://github.com/go-gitea/gitea/security/advisories/GHSA-pq8x-xpgp-rvmh),
[rootless image guidance](https://docs.gitea.com/installation/install-with-docker-rootless/),
[webhook contract](https://docs.gitea.com/usage/repository/webhooks/), and
[commit-status API](https://docs.gitea.com/api/operations/repo-create-status/)
as observed on the target design date.

Only endpoint-bound `pull_request` deliveries with action `opened`,
`reopened`, or `synchronized`, JSON media type, a canonical UUID
`X-Gitea-Delivery`, exact `X-Gitea-Event`, and a lowercase hexadecimal
`X-Gitea-Signature` HMAC-SHA256 over the untouched bounded body are admitted.
Gitea supplies no signed delivery time in this contract, so Matrix makes the
durable `(SourceConnection, delivery UUID, raw payload digest)` equality or
conflict decision before acknowledging; a caller timestamp is never used for
replay authority. One fetch token and one status-report token are separately
scoped to the bound repository. The adapter accepts no form body, compatibility
header fallback, payload secret, provider membership, provider role, or raw
provider object as Matrix authority.

The source adapter fetches only the binding's immutable head and trusted base
commits with system/global Git configuration, hooks, redirects, submodules,
and LFS disabled. It validates both objects, emits a deterministic archive of
the exact head tree without `.git`, and hashes that archive before handing it
to the executor. Fetch and report credentials remain in their respective
adapters and never enter the source archive, task environment, log, database,
Audit event, or support output.

### Matrix Native executor

Untrusted verification never runs on the Foundation/Application-PaaS host.
The accepted profile requires a dedicated Linux/amd64 runner node with no
tenant runtime or control-plane data, Docker `29.x`, and gVisor
`release-20260831.0` installed as the `runsc` runtime. Its fixed offline
x86-64 archive is
`sha256:b9ccc6e14ca4eb2c2e65ff66e011f3b7e79d3275fb12eab747b19f95caf8e891`.
The release page and checksummed multi-binary installation model are described
by the official gVisor
[release](https://github.com/google/gvisor/releases/tag/release-20260831.0),
[installation guide](https://gvisor.dev/docs/user_guide/install/), and
[Docker runtime guide](https://gvisor.dev/docs/user_guide/quick_start/docker/).
The runner installer consumes the release-carried archive and checksum; it
cannot download `latest`, invoke the package manager, or let `runsc install`
fetch missing sidecars.

The runner agent polls one mutually authenticated executor endpoint and may
receive only a current fenced task, its content-addressed source archive, and
closed profile identity. Its credential cannot call IAM, Audit, PaaS, source
provider, reporter, PostgreSQL, another runner, or an administrative executor
operation. The node firewall permits only that endpoint. Draining or losing a
runner stops new claims and leaves the control plane to reconcile the current
lease; registration or heartbeat alone is not evidence of isolation.

The sole first-release toolchain is `GO_1_26_OFFLINE_V1`, built from
`docker.io/library/golang@sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3`
(Linux/amd64 `1.26.8-alpine3.23`) and carried as an authenticated offline image.
It runs exactly `go test -mod=vendor -count=1 ./...` followed by
`go vet -mod=vendor ./...`, with `CGO_ENABLED=0`, `GOPROXY=off`,
`GOSUMDB=off`, an empty credential environment, and no caller-supplied argv.
Repositories using this profile must vendor every non-standard-library module.

Each step uses `runsc`, network `none`, a read-only root filesystem, UID/GID
`65532`, all capabilities dropped, `no-new-privileges`, no devices, no host or
container socket, no secret mount, and only a validated read-only source mount
plus fresh bounded tmpfs work/cache directories. The executor verifies the
runtime name and image ID from Docker inspection rather than trusting process
output from the sandbox. A missing runtime, changed image, unsupported host,
or failed negative isolation probe makes the executor ineligible.

### Egress, limits, storage, and retention

`NONE` is the only dependency-egress policy in this slice. Source acquisition
and status reporting occur in credential-isolated adapters; the verification
sandbox has no interface or DNS configuration. Proxy variables, host aliases,
registry access, package mirrors, persistent caches, and cross-run workspaces
are rejected. A future dependency proxy is a new reviewed profile, not a
configuration change to this one.

The first release fixes these maximums:

| Boundary | Limit |
| --- | ---: |
| Webhook body | 1 MiB |
| Source archive / expanded tree / paths | 64 MiB / 512 MiB / 20,000 |
| Verification steps | Exactly 2 sequential fixed steps |
| Per-step / whole-run wall time | 10 minutes / 20 minutes |
| Sandbox CPU / memory / writable tmpfs / processes | 2 cores / 2 GiB / 2 GiB / 256 |
| Log line / chunk / whole run | 16 KiB / 64 KiB / 8 MiB |
| Active runs per tenant / queued runs per tenant | 2 / 32 |
| Active runs per runner node | 4 |

The dedicated runner profile therefore requires at least 4 logical CPUs,
8 GiB memory, and 20 GiB installation-owned free storage after toolchain
import. The DevOps control-plane addition reserves 2 CPUs, 2 GiB memory, and
8 GiB free storage on the Matrix host. These are eligibility floors, not
capacity inferred from container registration or provider claims.

Sanitized UTF-8 log chunks are appended in the tenant-leading `delivery`
schema; there is no first-release object store. Control bytes, invalid UTF-8,
ANSI escape sequences, token-shaped values, absolute paths, and lines over the
fixed limit are rejected or replaced with a closed marker before commit.
Logs expire after 14 days, normalized SourceEvent/PipelineRun metadata after
90 days, and terminal runner source/work/cache state after one hour. Immutable
Audit facts remain under Audit's indefinite retention. Cleanup is a fenced
delivery-owned operation and cannot delete active/reconciling runs or Audit
records.

### IAM and Audit extension

IAM adds service purpose `DEVOPS` and built-in roles `DEVOPS_ADMIN`,
`DEVOPS_DEVELOPER`, and `DEVOPS_VIEWER`. The closed user-action catalog is:

- project `create|read`;
- source connection `create|read|update`;
- repository binding `create|read|update`;
- pipeline `create|read|update|activate`;
- run `read|replay|cancel`;
- log `read`.

Organization administrators receive the same DevOps product authority as a
DevOps administrator. Developers may read all listed resources, create and
update pipelines, activate revisions, replay/cancel runs, and read logs, but
cannot create/update provider connections or repository bindings. Viewers may
only read resources, runs, and logs. Product discovery remains the separate
Foundation action already granted to product roles. Service credentials may
request only their owning prefix and cannot impersonate a user or reuse an
installation/PaaS purpose.

Audit adds source `DEVOPS` and exact facts for project, connection, binding,
pipeline, and immutable revision creation; SourceEvent admission; PipelineRun
creation, replay, cancellation, and terminal completion; check-report receipt;
and authorized log read. User mutations carry the exact IAM decision and
Operation identity. Authenticated webhooks and fenced workers use their own
closed system/service actors and never invent a user decision. Facts contain
only Matrix IDs, canonical digests, closed outcomes/reasons, and correlation;
provider payloads, repository URLs, branches as authority, native errors,
logs, commands, credentials, and host paths are forbidden.

These choices close the four implementation prerequisites. They refine
adapters and release inventory without weakening the provider-neutral public
resource model. Gate A starts with public contracts and pure domain invariants;
no Gitea, Docker, gVisor, or PostgreSQL type may enter that domain.

## Implementation progress

The first Gate A slice implements the provider-neutral
[`api/devops/v1`](../../api/devops/v1/README.md) contract and the pure
`delivery` rules for DevOps project creation, Pipeline draft creation and
optimistic replacement, and immutable revision activation. The activated
revision resolves and seals the fixed toolchain digest, Matrix Native isolation
profile, ordered `GO_TEST`/`GO_VET` steps, `NONE` egress, reporter policy, and
resource limits. Caller-controlled tenant, actor, command, image, executor,
step, limit, provider payload, credential, and secret fields are absent from
mutation requests and rejected by strict decoding/OpenAPI schemas.

Activation binds the IAM-derived actor, tenant, Pipeline, project, monotonically
increasing revision number, canonical content digest, and UTC timestamp into a
deterministic revision identity. Stale resource versions, unchanged drafts,
non-monotonic time, version exhaustion, profile drift, cross-tenant activation
projections, and mutable fixed-profile catalogs fail closed. The domain imports
only standard-library packages and the public DevOps contract; it contains no
provider, executor, PaaS, persistence, or donor dependency.

The shared authority slice now registers `DEVOPS` as an optional service
identity and binds every DevOps IAM action to one resource kind, one service
owner, and the fixed administrator/developer/viewer privilege matrix. The
closed service-identity catalog is deliberately separate from the exact
five-service Foundation bootstrap inventory, so a Foundation-only installation
does not receive a dormant DevOps credential. PostgreSQL upgrades replace the
closed IAM role/purpose constraints in place while preserving both current and
legacy bootstrap replay shapes.

Audit now accepts the credential-derived `DEVOPS` source and the exact user
mutation facts for project, connection, binding, Pipeline draft, and immutable
revision activation. Go validation, canonical replay checks, generated OpenAPI,
and PostgreSQL use the same closed action contracts. The operation identity
index is generalized from PaaS-only to product operations without retaining a
parallel compatibility index. A clean PostgreSQL 18 fixture has applied IAM
and Audit migrations twice and exercised every IAM/Audit catalog entry.

The source-resource slice adds provider-neutral `SourceConnection` and
`RepositoryBinding` contracts, create/update commands, resource health, UI-safe
repository coordinates, and their declared HTTP contract surfaces. A
connection carries only an
opaque installed-adapter identity, one to eight sorted canonical HTTPS origins,
and three distinct secret-store references. The adapter identity and endpoint
allowlist cannot be replaced in place; an update may rotate only the webhook,
fetch, and report references and resets health to `PENDING`. Plaintext secrets,
provider objects, endpoint paths, loopback names, ambiguous ports, unsafe Git
branches, and repository path traversal fail closed.

RepositoryBinding mutations prove same-tenant project/connection authority and
seal the normalized connection ID, external repository ID, two-segment display
path, and trusted default branch into a canonical digest. Pipeline creation and
draft replacement require a binding owned by the same project. Activation
seals the binding digest into the immutable PipelineRevision, so a later
binding update cannot retarget an existing revision; activating the updated
binding creates a new revision even when the tenant-owned Pipeline draft did
not otherwise change. Resource and revision versions are capped at the largest
integer exactly representable by all JSON consumers.

The configuration workflow now carries the IAM decision as an action- and
resource-bound trusted value through eight exact mutations: project and source
connection creation, source credential-reference rotation, repository binding
creation/update, Pipeline creation/draft replacement, and immutable revision
activation. A delivery-internal durable command record derives its stable
identity from tenant, subject, command, target, and idempotency key. Equal
replay returns the original successful result snapshot even after later
updates; a changed request conflicts. This record is not a second public
Operation resource and does not expand the v1 API.

The delivery-owned PostgreSQL 18 schema stores projects, connections,
bindings, binding snapshots, Pipelines, immutable revisions, command records,
and sanitized Audit outbox facts. Every row is tenant-leading and protected by
forced RLS. Composite foreign keys prove same-tenant project, connection,
binding, and Pipeline ownership; each PipelineRevision references the exact
binding digest snapshot it sealed. The owner, migrator, API, and worker roles
are distinct: API writes only through one constrained security-definer
transaction, cannot read the Audit outbox, and worker currently has no table
access. The migration is repeatable and participates in the platform-wide
cross-schema credential boundary test.

The HTTP slice exposes only the generated nested resource paths, including
Pipeline-scoped revision reads and unauthenticated readiness. It derives every
request identity server-side, rejects caller authority headers, strictly
decodes bounded JSON, distinguishes media type, payload size, method,
precondition-required, and precondition-failed outcomes, and normalizes all
failures without native detail. Reads and writes authorize the exact IAM action
and resource before touching the repository; IAM alone derives tenant and
subject identity.

The IAM adapter authenticates DevOps with its own service credential while
forwarding the caller Bearer credential, binds correlation and trace context,
rejects authorization-response drift, and requires the `DEVOPS` service
identity for readiness. The Audit adapter and dispatcher claim durable outbox
facts with leases and fencing, accept only exact `ACCEPTED|DUPLICATE` receipts,
retry transient failure with a bounded backoff, and dead-letter terminal or
exhausted delivery. API and worker database identities remain table-blind
outside their security-definer functions, and readiness fails closed on an
exhausted or dead-lettered Audit fact.

The signed release now supplies an independently built DevOps image and selects
the DevOps API, Audit dispatcher, database identities, IAM/Audit credentials,
gateway route, and product-readiness endpoint as one closed topology slice.
An unselected inventory receives none of those runtime capabilities. Fresh
installation keeps the exact five-service Foundation bootstrap, starts IAM to
commit it, and only then uses the migration identity to idempotently enroll
`service-devops`; existing installations converge directly. Runtime roles
cannot call the release-service enrollment functions.

The real authority-process gate now builds and starts IAM, Audit, Application
PaaS, DevOps, and all three Audit dispatchers against one clean PostgreSQL 18
database. A real caller session creates a DevOps project, source connection,
repository binding, Pipeline draft, and immutable revision over HTTP. The gate
proves equal and conflicting command replay, exact ETags and nested revision
reads, cross-parent concealment, IAM-derived tenant and actor identity, DevOps
Viewer read-only access, IAM-outage readiness, five correlated DevOps Audit
facts, cross-schema role confinement, and unchanged PaaS behavior.

The normalized-admission contract now defines executable and generated
OpenAPI schemas plus validating examples for immutable `SourceEvent` and
`PipelineRun` projections. Framed digests and deterministic identities make a
changed delivery retain the original event identity while changing its sealed
content, and bind each run to one event and the exact active immutable
PipelineRevision. Pure domain constructors admit only ready same-tenant source
configuration and exact normalized commits, preserve the active revision when
an unrelated draft is later replaced, and derive the server-owned
`QUEUED / RECEIVE / EVENT_ADMITTED` state without invoking an executor.

The durable admission slice now resolves the current ready SourceConnection and
the unique `(SourceConnection, external repository)` binding, snapshots every
matching active revision in Pipeline identity order, and atomically commits one
SourceEvent, zero or more immutable PipelineRuns, and one Audit fact per stored
resource. Equal delivery replay returns that original admission before reading
mutable configuration; changed authenticated content conflicts. Both the use
case and the security-definer function enforce the fixed 32-run tenant queue
limit, while a tenant-scoped transaction lock plus serializable retry prevents
concurrent fan-out from exceeding it. API and worker roles cannot directly
write admission tables or read the internal generalized Audit-operation table.

These slices do not complete Gate A. The authenticated provider adapter, run
state transitions, logs, manual replay/cancellation, lease/fence/reconciliation,
remaining quotas, and pagination remain pending.

Current verification evidence:

- `go test ./...`
- `go vet ./...`
- `go test -race ./api/devops/v1/... ./app/service/devops/internal/delivery/domain`
- `go test -count=20 ./api/devops/v1/... ./app/service/devops/internal/delivery/domain`
- five-second native fuzz runs for draft/event digest framing and activation
  with untrusted repository-binding identifiers
- Linux/amd64 CGO-disabled cross-build of the new contract and domain packages
- deterministic OpenAPI generation-drift tests and `git diff --check`
- real PostgreSQL 18 double-apply and catalog integration tests for the IAM and
  Audit extensions, release-selected Platform/DevOps credential enrollment,
  equal replay, changed-credential rejection, and exact Audit facts
- full in-memory configuration journeys proving action-bound authorization,
  equal/changed replay, transaction retry, result snapshots, and binding-safe
  reactivation
- strict DevOps HTTP, IAM HTTP, Audit HTTP, outbox-dispatch, product discovery,
  signed topology-selection, and release-assembly tests
- real PostgreSQL 18 authority-process journey across IAM, Audit, PaaS,
  DevOps, and their Audit dispatchers, including authorization denial,
  idempotency conflict, immutable revision reads, readiness failure, and exact
  Audit correlation
- real PostgreSQL 18 configuration journeys proving double apply, exact
  runtime identities, forced cross-tenant isolation, function-only API writes,
  a table-blind worker, immutable binding/revision history, sanitized Audit
  outbox correlation, and the four-schema platform migration boundary
- real PostgreSQL 18 admission journeys proving deterministic two-Pipeline
  fan-out, equal replay after mutable configuration becomes unavailable,
  changed-replay conflict, atomic queue rejection, cross-tenant concealment,
  and exactly one success when two two-run events concurrently contend at 30
  queued runs; the same scenario passed on five additional fresh instances
- data-bearing migration reapply preserving 13 configuration mutations,
  16 SourceEvents, 32 PipelineRuns, and 61 generalized Audit operations/outbox
  facts, plus the real Audit authority accepting the two closed DevOps actions
- fixed `0d387dd` data-bearing upgrade preserving all 11 legacy mutations and
  outbox facts, backfilling current/revision external repository identities and
  generalized Audit operations, and removing every temporary upgrade policy

## Incremental acceptance

### Gate A: contract, domain, and persistence

1. Strict Go/OpenAPI contracts cover every resource, command, page/cursor,
   problem, enum, and example; unknown fields, duplicates, oversize bodies,
   tenant selectors, provider-native data, and unsafe text fail closed.
2. Immutable revision activation, event equality/conflict, deterministic run
   identity, state transitions, cancellation, replay, lease/fence,
   reconciliation, quota, and sanitized failure/log behavior pass unit, race,
   fuzz, and repeated tests.
3. Clean PostgreSQL applies the delivery schema twice and proves separate
   migration/API/worker roles, forced tenant isolation, database-time
   leases, stale-fence rejection, API-only writes, and no cross-schema access.
4. Architecture tests prove the delivery context owns its ports, depends only
   on public contracts, does not import Prow/provider implementations into the
   domain, and does not share the PaaS DeploymentExecutor.

### Gate B: real CI vertical slice

1. A real pinned source-provider fixture sends a signed change event. Equal
   delivery replay is one run; changed replay, forged/rotated signatures,
   wrong event, oversize body, endpoint redirect, and commit mismatch fail
   closed.
2. Real PostgreSQL, IAM, Audit, source fetch, isolated BuildExecutor, and check
   reporter run as process/network boundaries. The exact commit is verified,
   the immutable profile runs once, and one provider check plus Matrix Audit
   evidence correlate to the same run.
3. Malicious repositories attempt host/container-socket access, control-plane
   access, credential theft, cross-tenant reads, fork-bomb/resource escape,
   oversized logs, path traversal, symlink escape, and unapproved egress. The
   executor contains them without leaking native or secret data.
4. Kill/restart at every external-effect boundary proves lease recovery,
   fencing, observe-before-retry, cancellation, bounded reconciliation, no
   duplicate check outcome, and no acknowledged event loss.

### Gate C: product UI and offline release

1. Through the real APISIX edge and platform shell, an authorized user creates
   a DevOps project, connection, repository binding, draft, and immutable
   revision; a viewer cannot mutate them and another tenant cannot observe
   them.
2. A real change event drives the visible RECEIVE/FETCH/VERIFY/REPORT stages.
   Desktop and 360-pixel UI tests cover success, failure, cancellation,
   provider outage, stale data, denied log access, empty/loading states,
   keyboard use, focus, contrast, and no raw/secret/path leakage.
3. The signed offline release declares DevOps installed, starts its control
   plane and isolated executor integration without Internet access, verifies
   readiness through product discovery, and repeats the source-to-check flow
   against the local provider fixture.
4. Backup, upgrade, rollback, recovery, restart, and support evidence preserve
   or deliberately retire DevOps state under installation-owned policy without
   changing Application PaaS behavior.

Common generation-drift, schema, architecture, unit, vet, race, repeated,
cross-platform build, Markdown-link, stale-term, donor-dependency,
tenant-authority, vulnerability, license, accessibility, and
`git diff --check` gates pass on the same committed worktree.

## Adoption

The fixed Prow commit, CODING product benchmark, detailed
`REUSE`/`ADAPT`/`REFERENCE`/`REJECT` decisions, and evidence limits are
owned by the
[FEAT-007 adoption review](../adoption/FEAT-007-repository-delivery.md).
No donor code, API type, configuration, binary, image, or dependency is a
Matrix build/runtime input.

## Deferred

Mainline publication, artifact repository UX, Application PaaS delivery,
production approval, environment promotion, release forms, deployment
strategies, schedules, merge queues, source hosting, visual DAG editing,
arbitrary pipeline YAML/Jenkinsfile compatibility, persistent workspaces,
cross-run caches, native Kubernetes objects, and CODING-connected execution
remain outside this slice.
