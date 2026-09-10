# FEAT-007: Repository change validation

- Status: In progress; UX, architecture, donor analysis, implementation
  baseline, Gate A project/Pipeline/source-resource contract, domain,
  configuration transaction/persistence, shared authority, durable run
  admission, authenticated Gitea ingress, fenced run-lifecycle foundation,
  IAM-authorized run read/cancellation/manual replay, terminal Audit facts,
  source-readiness contract, installation-operator source credential
  lifecycle, source-observer runtime, source-acquisition runtime design,
  fenced acquisition use case, deterministic archive store, and real Gitea
  fetch protocol, source-acquisition persistence, isolated source-fetcher
  process, fenced BuildExecutor contract/use case, and table-blind PostgreSQL
  execution persistence, versioned admin/runner transport contract, durable
  executor-gateway spool, TLS 1.3 mTLS admin/runner HTTP boundary, and isolated
  executor-gateway process, ordered runner step journal, runner workspace
  publication, bounded native output normalization, closed sandbox container
  lifecycle, port-driven cross-step runner workflow, authenticated durable log
  relay, fenced tenant-leading normalized-log persistence, and IAM-authorized
  audited public log reads, physical runner process composition, and selected
  control-plane execution topology with installation-owned mTLS material
  complete; authenticated standalone runner-node release export and pinned-CA
  CSR enrollment complete; dedicated-node installer implementation,
  controlled-host Linux integration, and authentic-material evidence complete;
  isolated check-report process, persistence, and fixed-Gitea adapter complete;
  real Linux Docker/runsc source-archive-to-receipt integration, repository PID-
  quota exhaustion and control-plane/credential probes, unsafe-log normalization,
  whole-run oversized-log containment, and standalone PostgreSQL VERIFY-to-
  REPORTING gateway/build-worker/runner crash recovery complete; real Gitea
  observation, physical signed HTTP ingress, source-fetcher archive recovery,
  check-reporter status-acknowledgment recovery, physical provider reporting,
  and DevOps Audit delivery complete; the joined physical
  IAM/Audit/source/executor/report journey and its fetch, gateway-submission,
  runsc-effect, provider-status, and Audit-acknowledgment restart cases complete;
  Gate B complete; Gate C's guarded source-recheck API/persistence, unified
  DevOps browser-client baseline, and DevOps-selected offline-lifecycle access
  and operator-credential harness are complete; the endpoint-scoped private-
  provider CA UX, architecture, and acceptance contract is complete while its
  implementation, signed real-runtime execution, local-provider source-to-
  check journey, and the complete multi-role/state/accessibility UI matrix
  remain pending
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

Connecting a repository is deliberately split between a tenant administrator
and an installation operator. In **Code > Connections**, the administrator
selects the fixed Gitea adapter, enters one canonical HTTPS provider origin,
and assigns three opaque references for webhook verification, source fetch,
and check reporting. The browser never accepts or reveals a secret value. It
shows a copyable, non-secret `mx devops source-credential` command for each
reference; an operator runs those commands on the Matrix host with a private
input file. This follows CODING's useful credential-reference experience while
keeping secret custody outside the product API and untrusted execution.

If the exact provider origin is not signed by a system-trusted authority, the
same page also shows an optional, copyable `mx devops source-trust` command.
The command contains only the tenant and canonical endpoint origin plus a
private-file placeholder; the browser never accepts, stores, or renders CA
material. Installing or removing that trust does not forge readiness. The
administrator explicitly schedules **Recheck** after the operator completes
the command.

The connection and each repository binding show a closed health state, closed
reason, last observation time, and a **Recheck** affordance that only schedules
reconciliation. `PENDING` means configuration has not yet been proved,
`READY` means every required bounded observation succeeded recently, and
`UNAVAILABLE` means a safe actionable category failed. Provider response text,
user identity, token scope names, filesystem paths, and credential material are
never rendered. A stale `READY` observation is not admission authority: the UI
marks it stale and webhook admission fails closed until a fresh observation is
committed.

Each Recheck is a bodyless, idempotent `POST` to the exact connection or
binding's `/recheck` command endpoint. It requires a strong `If-Match`, uses a
separate administrator-only IAM action, returns `202` with the unchanged
resource snapshot, and emits one normalized `recheck-scheduled` Audit fact. It
may advance only the delivery-owned observation task's due time. It does not
change resource version, health, reason, or observation time; those remain
exclusive output of the fenced source observer. A request that arrives while
the observer holds the current lease preserves that lease, so it cannot revoke
or forge the in-flight observation.

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
| `SourceConnection` | Metadata/status versioned | Tenant-bound provider identity, exact endpoint origin, health, and secret references; never plaintext credentials. |
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
6. The reporter sends exactly one terminal check under a deterministic report
   identity. Timeout or connection loss is observed without another create;
   equal provider state completes the run, while contradictory state fails as
   a report conflict.
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

Each `FETCH`, `VERIFY`, or `REPORT` stage has one durable command intent whose
identity is exactly `<PipelineRun ID>:<lowercase stage>:<attempt>`. The first
lease of an intent authorizes `EXECUTE`; every expired-lease takeover retains
that identity and authorizes only `OBSERVE`. A definitive result completes the
intent and advances the public run once. An uncertain report retains the same
intent in `RECONCILING`; ten inconclusive observations exhaust automatic
reconciliation, after which and only after which the current fence may commit
`MANUAL_INTERVENTION`. Lease ownership, retries, and observation counts are
worker coordination and do not invent public PipelineRun status changes.

### Manual replay contract

The first replay surface is bodyless
`POST /v1/runs/{sourceRunId}/replay`. IAM authorizes
`devops.run.replay` against that exact source PipelineRun; `If-Match` must name
its current terminal resource version, and `Idempotency-Key` identifies one
user intent. A nonterminal or foreign source run, stale version, full tenant
queue, missing guard, and changed use of the same key fail closed. Equal replay
returns the originally created run without consulting current connection,
binding, Pipeline draft, active revision, branch, or provider state.

The new PipelineRun copies the source run's immutable `Input` and
`InputDigest` exactly. A separate immutable `replay` cause records the selected
source run, deterministic replay command, and IAM-authorized subject; it is
not part of the executor input digest. The new run identity is derived from
tenant, source run, command, and that unchanged input digest, so replaying a
replay is allowed and links to the immediately selected run without building
an unbounded embedded chain. It starts at resource version 1 in
`QUEUED / RECEIVE / EVENT_ADMITTED` and is subject to the same 32-run tenant
queue limit and later lifecycle rules.

One transaction locks the source run, serializes the tenant queue, inserts the
new run, a `REPLAY_PIPELINE_RUN` mutation result, and one
`devops.pipeline-run.replayed` Audit fact carrying the exact IAM decision and
new-run target. It starts no source, executor, or reporter effect. Admission
queries exclude replay descendants so an equal provider delivery continues to
return only the original deterministic event fan-out.

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

The northbound ingress is
`POST /api/devops/v1/source-ingress/{tenantId}/{sourceConnectionId}`. The path
values select an exact SourceConnection and its verification key; they grant no
tenant or user authority. A higher-priority APISIX route removes bearer,
caller-authority, idempotency, precondition, correlation, and trace headers
before forwarding, while the normal DevOps API route continues to carry the
caller Bearer credential to IAM. The service assigns the request and Audit
correlation identity, returns `204` only after the admission transaction
commits, gives equal replay the same response, and maps changed replay, stale
configuration, queue exhaustion, and temporary dependency failure to closed
`409`, `412`, `429`, and `503` outcomes.

An installed DevOps product owns three purpose-separated credential roots:
`secrets/devops/source-webhooks`, `secrets/devops/source-fetch`, and
`secrets/devops/source-report`. Each purpose, tenant, and opaque reference is
length-framed and SHA-256-derived into one portable directory name. Every
directory contains one mandatory private regular `material.json` file with a
strict canonical, versioned envelope. The envelope always has `current`; only
a webhook envelope may also have one distinct `previous` value during an
explicit rotation window. A single atomic replacement therefore publishes or
retires the complete accepted set without exposing a half-rotated pair to a
reader. Webhook values are 32--128 visible ASCII bytes and Gitea token values
are 32--256 visible ASCII bytes; none enters an environment variable or URL
component. A missing connection or webhook key has the same
unauthenticated outcome as a forged signature; unsafe files, invalid key
material, or backend failure make ingress unavailable without exposing a path
or secret.

### Source readiness and operator credential custody

`SourceConnection.spec.endpointOrigin` is one immutable canonical HTTPS origin,
not an ordered endpoint list. The fixed Gitea adapter constructs version,
identity, repository, fetch, and reporting requests from that origin and the
validated two-segment repository path. It never selects a first entry, follows
a redirect, or trusts a provider-returned URL as a new authority. Split API and
clone hosts require distinct SourceConnections in a later explicit adapter
contract; the first release supports a root-hosted Gitea instance only.

Private-provider CA trust is installation configuration, not a
`SourceConnection` field or tenant-held credential. A selected DevOps
installation owns `config/devops/source-trust`. Tenant and exact canonical
endpoint origin are length-framed and SHA-256-derived into one portable
directory name containing exactly one private regular `roots.pem`. The bundle
is at most 256 KiB and contains at most sixteen distinct, currently valid,
self-signed X.509 CA certificates with CA basic constraints and certificate-
signing usage. Input order and PEM formatting are normalized into one
deterministic certificate order; private keys, non-certificate blocks,
intermediate or leaf certificates, duplicate certificates, headers, trailing
content, symlinks, unsafe ownership, and unsafe modes fail closed.

Trust selection is exact and non-ambient. For a `(tenant, endpointOrigin)` with
no installed record, the source adapter uses the runtime's verified system
roots. When a record exists, it uses only that custom pool and never merges it
with system roots. TLS hostname verification still targets the endpoint's exact
host, TLS 1.2 or newer remains mandatory, proxies and redirects remain
disabled, and the custom authority cannot authenticate another tenant or
origin. The host system trust store, `SSL_CERT_FILE`, process-global TLS state,
webhook ingress, DevOps API, and untrusted executor are unchanged.

Only the source observer, source fetcher, and check reporter receive the same
read-only trust root and resolve it independently for each effect. Unsafe or
invalid installed material is a provider failure, not a system-root fallback:
the observer reports `UNAVAILABLE / PROVIDER_UNAVAILABLE`, while fetch and
report use their existing closed unavailable outcomes. Applying or removing a
record is serialized by the installation lock but does not mutate delivery
state or call PostgreSQL; the administrator's existing guarded Recheck is the
only way to advance the observation schedule.

Connection status has one of these valid state/reason pairs:

| Health | Reason | Meaning |
| --- | --- | --- |
| `PENDING` | `CONFIGURATION_CHANGED` | A create or credential-reference change has not been observed. |
| `READY` | `OBSERVED` | All credential files are safe, the provider version is supported, and both provider tokens authenticate. |
| `UNAVAILABLE` | `SECRET_UNAVAILABLE` | A required current credential is absent, unsafe, or invalid. |
| `UNAVAILABLE` | `PROVIDER_UNAVAILABLE` | Bounded TLS, HTTP, response, or timeout validation failed. |
| `UNAVAILABLE` | `PROVIDER_UNSUPPORTED` | The provider does not match the release-carried compatibility catalog. |
| `UNAVAILABLE` | `CREDENTIAL_REJECTED` | Either provider token did not authenticate. |

RepositoryBinding status has one of these valid state/reason pairs:

| Health | Reason | Meaning |
| --- | --- | --- |
| `PENDING` | `CONFIGURATION_CHANGED` | A create or repository retarget has not been observed. |
| `PENDING` | `CONNECTION_NOT_READY` | Its SourceConnection is pending or its last ready observation is stale. |
| `READY` | `OBSERVED` | Both credentials see the exact repository identity and trusted default branch; fetch can read and report can write. |
| `UNAVAILABLE` | `REPOSITORY_UNAVAILABLE` | The repository cannot be observed without retaining provider-native detail. |
| `UNAVAILABLE` | `IDENTITY_MISMATCH` | Provider ID, path, origin, or trusted default branch differs from the binding. |
| `UNAVAILABLE` | `FETCH_PERMISSION_DENIED` | The fetch identity lacks read authority. |
| `UNAVAILABLE` | `REPORT_PERMISSION_DENIED` | The reporting identity lacks write authority. |

The Gitea `1.27.3` observer performs only bounded read operations: one exact
`GET /api/v1/version`, authenticated `GET /api/v1/user` calls for the fetch and
report tokens, then an authenticated
`GET /api/v1/repos/{owner}/{repository}` with each token for a binding. It
requires strict JSON, a 64-KiB response ceiling, a five-second request deadline,
TLS verification, no redirects, the fixed supported version, exact repository
identity/path/default branch and returned URL origins, `pull` permission for
fetch, and `push` permission for reporting. It does not create a status as a
health test. One failed observation immediately fails closed; there is no
last-known-good admission fallback.

A separate `matrix-devops-source-observer` process owns this reconciliation.
It has a distinct table-blind `matrix_devops_source_observer` database identity,
read-only access to the three credential roots and endpoint-scoped source-trust
root, and provider egress only. It cannot call IAM or Audit, claim PipelineRun
tasks, mutate configuration specs, or read another Matrix schema. A
delivery-owned reconciliation table provides
oldest-due claims, a 30-second lease, monotonic fencing, and tenant-fair
selection. Create/update schedules an immediate observation; successful or
failed completion schedules the next check after 60 seconds. A connection
transition schedules all dependent bindings. The current fence and exact
resource version must still match when status is committed, so a stale probe
cannot make changed configuration ready. A ready observation is admission
authority for at most two minutes.

Status observations update `metadata.resourceVersion`, `metadata.updatedAt`,
`status.observedAt`, health, and reason atomically without changing a binding's
spec digest or immutable revision history. Equal observations refresh time;
only health/reason transitions emit a normalized delivery Audit fact through
the existing outbox. The closed actions are
`devops.source-connection.health-transitioned` and
`devops.repository-binding.health-transitioned`; the system actor is
`system-devops-source-observer`, and the request digest commits only the target
kind, target ID, resulting health, reason, resource version, and observation
time. Provider text and credential-derived identity are absent from both
status and Audit.

The observer writes its first database heartbeat before any claim, refreshes it
after completing work, and writes at least once every 10 seconds while idle.
Its own readiness requires
the last heartbeat to be no older than 30 seconds. The DevOps API readiness
endpoint applies that same 30-second limit whenever at least one
SourceConnection exists; an installation with no configured connection remains
ready before the observer's first heartbeat. Process startup writes the first
heartbeat only after the observer database role, all three credential roots,
and the fixed provider client have initialized. This liveness limit is separate
from the two-minute per-resource admission freshness limit. Product discovery
therefore does not advertise a healthy control plane that can no longer refresh
source authority.

The installation-owned CLI surface is exactly:

```text
mx devops source-credential apply --root <installation> --tenant <id>
  --purpose WEBHOOK|FETCH|REPORT --reference <id> --from-file <private-file>
mx devops source-credential retire-previous --root <installation>
  --tenant <id> --purpose WEBHOOK --reference <id>
mx devops source-trust apply --root <installation> --tenant <id>
  --endpoint-origin <canonical-https-origin> --from-file <private-ca-file>
mx devops source-trust remove --root <installation> --tenant <id>
  --endpoint-origin <canonical-https-origin>
```

Both commands acquire the installation lock, authenticate the committed
release state, require DevOps in the signed product inventory, reject symlinks
and non-private/non-regular input, and write only through an atomic private-file
replacement. `apply` leaves the input file untouched. For webhook rotation it
publishes the old `current` as `previous` in the same envelope replacement; for
fetch/report it replaces the envelope's sole `current`. Equal apply is a no-op.
`retire-previous` atomically removes `previous` and is the only supported way
to end dual webhook acceptance. Human and JSON output contain only the purpose,
tenant, reference, and `APPLIED|UNCHANGED|PREVIOUS_RETIRED` state. They never
contain a value, digest, path, provider response, or native error.

Both `source-trust` commands enforce the same installation lock, authenticated
committed release, selected-product, protected-input, no-follow, and atomic
publication boundaries. `apply` canonicalizes and replaces only the exact
tenant-and-origin bundle; an equal bundle is `UNCHANGED`. `remove` first proves
the derived directory contains exactly the canonical bundle, then deletes that
file and its now-empty directory; absence and repeated removal are the same
`REMOVED` result. Output contains only `APPLIED|UNCHANGED|REMOVED`, tenant, and
endpoint origin. It never contains CA bytes, fingerprints, input/storage paths,
native errors, or other tenant identities.

In-place verify, upgrade, rollback, and restart revalidate and preserve the
exact trust directory. A portable protected backup deliberately does not carry
this out-of-band provider authority to a replacement installation: recovery
creates an empty selected-product trust root, source observation fails closed,
and the operator must reapply the CA followed by an administrator Recheck.
Support evidence reports neither CA content, endpoint origins, derived names,
nor host paths.

The DevOps API receives only the webhook root. The source observer receives all
three credential roots plus the read-only source-trust root because proving
readiness is its sole side effect; later fetch and report workers receive only
their own purpose root plus that same read-only trust root. The source adapter
fetches only the binding's immutable head and trusted base
commits with system/global Git configuration, hooks, redirects, submodules,
and LFS disabled. It validates both objects, emits a deterministic archive of
the exact head tree without `.git`, and hashes that archive before handing it
to the executor. Fetch and report credentials remain in their respective
adapters and never enter the source archive, task environment, log, database,
Audit event, or support output.

### Source acquisition runtime

`matrix-devops-source-fetcher` is the only first-release process allowed to
turn an admitted change into a source archive. It has a distinct
`matrix_devops_source_fetcher` database role/login, the read-only `FETCH`
credential root, the read-only endpoint-scoped source-trust root, one
installation-owned archive root, and the internal control plus source-egress
networks. It receives no webhook/report credential, IAM or Audit service
credential, executor authority, container socket, PaaS state, or direct table
access. A ten-second database heartbeat with a thirty-second freshness limit
gates both its own readiness and DevOps API readiness.

The fixed implementation is pure Go
[`go-git` `v5.19.2`](https://github.com/go-git/go-git/releases/tag/v5.19.2)
at upstream commit `3eeb238da61eb9c7a324f3ee04f990ce89175642` and module sum
`h1:wkfn7vOlUBu8ivAWKBWisTiwJK4jYHzTF8Ndv1LyGqY=`. This is the first stable
release containing both the filesystem-reference and worktree-symlink fixes;
it also contains the earlier malformed-object and cross-host credential
redirect fixes documented in the upstream
[`GHSA-qgq7-7hm3-q39j`](https://github.com/go-git/go-git/security/advisories/GHSA-qgq7-7hm3-q39j),
[`GHSA-hc8v-wwc9-vgxm`](https://github.com/go-git/go-git/security/advisories/GHSA-hc8v-wwc9-vgxm),
[`GHSA-389r-gv7p-r3rp`](https://github.com/go-git/go-git/security/advisories/GHSA-389r-gv7p-r3rp),
and
[`GHSA-3xc5-wrhm-f963`](https://github.com/go-git/go-git/security/advisories/GHSA-3xc5-wrhm-f963).
Matrix uses only ephemeral in-memory object storage and never creates a Git
worktree. The fetch transport accepts only the exact canonical HTTPS origin,
resolves the exact tenant-and-origin custom-only pool or verified system roots,
requires TLS 1.2 or newer, disables proxies and every redirect, and never places
a credential in a URL. No system/global repository configuration, subprocess,
hook, submodule, LFS client, SSH/file/git protocol, tag, or caller-selected
refspec is consulted.

The fixed Gitea adapter supports only SHA-1 repositories in v0.1. The source
observer rejects another `object_format_name`, so unsupported repositories
cannot become admission-ready even though the provider-neutral public contract
continues to reserve 64-hex object identities for a future adapter. For one
change it fetches exactly the trusted `refs/heads/<default>` and Gitea
`refs/pull/<number>/head` tips at depth one, then proves that both advertised
tips and both decoded commit objects equal the immutable base/head identities
sealed into the run. Any ref movement or object mismatch is
`COMMIT_MISMATCH`; authentication, protocol, format, tree, limit, and storage
failures are `SOURCE_UNAVAILABLE`; the closed acquisition deadline is
`DEADLINE_EXCEEDED`.

The head tree is walked without checkout and encoded as one deterministic gzip
tar stream. Entries are byte-sorted safe UTF-8 relative paths; only regular
`0644` and executable `0755` blobs are accepted. `.git` path components,
absolute/parent paths, control characters, symlinks, gitlinks/submodules,
devices, and other modes fail closed. Headers carry zero time, fixed numeric
ownership, no host names, and no provider metadata. An LFS pointer remains its
ordinary Git blob and no LFS object is fetched. The writer enforces the fixed
64-MiB compressed archive, 512-MiB expanded-blob, and 20,000-path limits while
streaming. One archived path is at most 4,096 UTF-8 bytes and one component at
most 255 bytes. The preceding smart-HTTP advertisement is capped at 1 MiB and
the upload-pack response at 576 MiB, so an untrusted provider cannot turn the
in-memory object store into an unbounded protocol buffer.

The archive adapter stages a private directory below the validated archive
root, fsyncs the archive and canonical non-secret receipt, and atomically
renames the directory to a deterministic command-derived location. The archive
filename contains its SHA-256 content digest; the receipt binds tenant, run,
command, run-input digest, exact head/base commits, media type, archive digest
and byte size, expanded bytes, and path count. Neither the receipt nor the
database stores a host path. Re-observation rehashes and structurally validates
the published archive before returning the same receipt.

`delivery.source_archives` is an internal tenant-leading, forced-RLS receipt
table. A fetch success transaction verifies the current lease/fence and exact
run/source/binding identities, inserts that receipt, completes the durable
FETCH intent, and advances `FETCHING -> VERIFYING`; every other database path
is forbidden from making that transition without the matching receipt. A
terminal fetch failure/cancellation writes no receipt and uses the existing
atomic PipelineRun completion Audit fact.

The first lease may fetch and publish. A takeover after lease expiry remains
`OBSERVE` only: a valid final directory completes the same command, while a
missing, partial, changed, or invalid directory fails safely and never
recontacts Gitea. Publishing the directory before the database transaction
makes a crash recoverable; a database failure leaves the same immutable effect
available for the next fence. Temporary or orphan content is never executable
authority and is removed only by the later fenced retention operation. A
cancellation invalidates the old fence, prevents VERIFY, and terminates the run
as `CANCELLED` whether or not the final archive was observed.
Graceful source-fetcher shutdown cancels and waits for its active acquisition
cycle before the process exits, so archive staging cleanup or a durable-effect
observation cannot continue in an orphaned goroutine.

### Matrix Native executor

The delivery control plane creates a closed `VERIFY` command before any
executor effect. It binds the current lease/fencing token, immutable
PipelineRevision, stored source-archive receipt, database-created start time,
and fixed 20-minute deadline. The resulting provider-neutral `BuildRequest`
contains only tenant/run/command/input identities, archive digest and bounded
sizes, revision identity and digest, the fixed verification/executor/toolchain
profiles, `NONE` egress, the exact two ordered steps, fixed limits, and the two
times. Source paths, arbitrary argv or environment, credentials, provider
objects, report authority, and PaaS data cannot cross this port.

Only the first fence may call `Execute` with the archive stream. A takeover
fence calls `Observe` or `Cancel` against the same deterministic command and
never resubmits the archive. Transport ambiguity, caller shutdown, timeout
during an effect, or lease-renewal loss preserves the open command for fenced
observation. An already-expired recovered execution must be cancelled and its
absence or terminal receipt observed before the control plane may commit a
deadline outcome.

The normalized terminal receipt repeats the command/run/input/archive/revision
identities, executor and pinned profile identities, one closed conclusion, the
exact two step conclusions, and a deterministic content digest. Both `PASSED`
and verification `FAILED` receipts advance `VERIFYING -> REPORTING`; the later
CheckReporter owns the provider-visible terminal check and is the only stage
that converts that evidence into `SUCCEEDED` or
`FAILED / VERIFICATION_FAILED`. User cancellation may terminate without a
report. Native output, diagnostics, container identifiers, paths, and logs are
not receipt fields. The runner owns native-output normalization before handoff;
the separate normalized-log boundary persists that evidence before the build
worker may commit the receipt.

#### Check reporting runtime

`matrix-devops-check-reporter` is the only process allowed to turn a stored
build receipt into a provider-visible terminal check. It joins the internal
control network and the source-egress network, mounts only the read-only
`REPORT` credential root plus the endpoint-scoped source-trust root, and
receives a dedicated table-blind check-reporter DSN. It receives
no webhook or fetch credential, source archive, executor identity, runner or
Docker authority, IAM/Audit service credential, PaaS state, or authority to
change tenant configuration. The build worker correspondingly retains no
provider or report credential.

The reporter claims only `REPORT` intents. One claim atomically returns the
current SourceConnection, the immutable RepositoryBinding revision selected by
the run, the immutable PipelineRevision, and the stored normalized build
receipt. Validation binds their tenant, project, pipeline, source event,
repository identity, head commit, content digests, reporter policy, and build
conclusion before any provider call. The endpoint and adapter identity remain
immutable; the current report-credential reference may rotate without
changing the report command or placing a credential in persisted state.

For Gitea `1.27.3`, `CHANGE_CHECK_V1` creates exactly one terminal commit
status at
`POST /api/v1/repos/{owner}/{repository}/statuses/{headCommit}`. The body is a
closed JSON document: `context` is
`matrix/{pipelineId}/{runId}`, `description` is one fixed passed or failed
phrase, `state` is `success` or `failure`, and `target_url` is empty until the
product has an accepted externally reachable run URL. The token appears only
in the `Authorization` header. The adapter uses the exact configured HTTPS
origin, resolves the exact tenant-and-origin custom-only pool or verified
system roots, permits TLS 1.2 or newer, uses no proxy or redirect, enforces a
five-second deadline and 64-KiB response ceiling, and requires strict JSON plus
exact response echo validation. It
retains only a normalized positive provider status ID plus the command and
body digest; provider URLs, users, text, headers, and native errors are never
persisted, logged, audited, or returned northbound.

The first fencing token may create the status once. An acknowledgement loss,
timeout, malformed success response, connection loss after request dispatch,
or server failure is an uncertain external effect: the same intent moves to
`RECONCILING`, and no later fence may issue another POST. Recovery performs
only a bounded newest-first read of statuses for the exact head commit and
accepts one exact context/state/description/target match. An equal result
reconstructs the same normalized receipt; a matching context with changed
content is `REPORT_CONFLICT`; absence or provider unavailability is deferred
for sixty seconds. Ten inconclusive observations produce
`MANUAL_INTERVENTION / RECONCILIATION_EXHAUSTED` rather than a duplicate
status. A definitive authentication, permission, repository, or commit
rejection before an effect is `FAILED / REPORT_UNAVAILABLE`.

`delivery.check_receipts` stores one canonical normalized receipt per run. A
single fenced transaction verifies the current REPORT task and matching build
receipt, inserts or equality-checks that receipt, completes the task, advances
a passed build to `SUCCEEDED / COMPLETED` or a failed build to
`FAILED / VERIFICATION_FAILED`, and emits the existing terminal PipelineRun
Audit fact. No generic transition can produce either terminal outcome without
the receipt. A reporter heartbeat and integrity-aware readiness function gate
the process and DevOps product readiness whenever the product is selected.

#### Executor control and runner transport

The native adapter is split at the security boundary into three selected-only
processes. `matrix-devops-build-worker` owns the table-blind PostgreSQL lease,
the read-only source-archive mount, and an admin-client identity for one
executor gateway. `matrix-devops-executor-gateway` owns a private durable
execution spool and two mutually authenticated TLS listeners, but no
PostgreSQL, IAM, Audit, source-provider, reporter, PaaS, Docker-socket, or
source-archive authority. `matrix-devops-runner` lives only on an eligible
dedicated runner node, initiates outbound connections to the runner listener,
and owns the local Docker/runsc execution side effect. The build worker never
receives the runner's Docker authority, and the runner never joins a Matrix
product or database network.

The gateway's admin listener accepts only the build-worker certificate and
supports the three `BuildExecutor` operations—create-or-observe one
deterministic execution with its bounded source stream, observe it, and request
cancellation—plus exact-cursor `BuildLogSource` reads. The runner listener
trusts a separate runner-client root and supports only oldest-eligible
assignment claim, current-fence renewal with a cancellation flag,
current-fence normalized-log append, and current-fence terminal completion. It
exposes no admin operation. Both listeners require TLS 1.3, an exact configured
server identity, bounded headers and bodies, no proxy or redirect, and strict
canonical versioned documents from `api/adapter/devopsbuild/v1`; bearer tokens,
cookies, caller-selected URLs, native Docker data, paths, argv, and environment
fields are absent.

An admin create streams a length-framed canonical `BuildRequest` followed by
exactly the declared archive bytes. The gateway revalidates the closed request,
structurally inspects and hashes the archive, then fsyncs a private staging
directory and atomically publishes the execution before acknowledging. Its
identity is a framed SHA-256 over the command, immutable input, revision, and
archive digests. Equal create observes the existing execution; changed use of
the same command conflicts. `Execute`, `Observe`, and `Cancel` therefore survive
gateway or build-worker restart without creating a second execution.

The first runner assignment alone authorizes execution and receives the exact
request and archive. It has a database-independent 30-second lease and a
monotonic gateway fencing token. An expired assignment is never offered to a
different runner for execution: only the same certificate-bound runner may
recover it in `OBSERVE` or `CANCEL` mode from its private local journal;
otherwise the gateway reports an unknown outcome until the fixed deadline or
operator intervention. Renewal cannot extend the build deadline and carries
only the cancellation bit. A terminal receipt must match the current runner,
fence, request, fixed profile, step order, and digest before its atomic durable
publication; native output is rejected. Acknowledgement loss is equal replay,
while a changed terminal replay is a conflict.

Each completed step may append one canonical batch of complete normalized
`[stdout]`/`[stderr]` lines. The gateway binds it to the certificate-derived
runner, active gateway fence, immutable execution request, strict cumulative
native/normalized byte cursor, increasing step and sequence, and the fixed
two-batch maximum before atomically publishing it in the private spool. An
equal batch may replay under a later fence held by the same recovering runner;
changed content, reused or partial sequence, foreign identity, expired lease,
and changed request conflict. The terminal receipt remains log-free.

Before completing the database VERIFY intent, the build worker drains whole
batches from sequence zero while its database lease renewal remains active.
The table-blind `append_build_logs` function independently binds the current
VERIFY worker and fence, recomputes the execution, chunk, and batch digests,
enforces the normalized line grammar, proves the preceding cursor and step,
and inserts at most two batches into tenant-leading
`delivery.pipeline_run_logs`. Equal replay is idempotent, changed replay
conflicts, task completion closes the append authority, and every batch gets
the fixed 14-day expiry. A failed or unproved drain retains the VERIFY intent
for fenced observation instead of advancing with missing evidence.

The public read surface is
`GET /v1/runs/{runId}/logs[?afterSequence=<cursor>]`. IAM authorizes
`devops.log.read` against that exact `PipelineRun`; there is no separately
addressable `PipelineLog` authority resource. The query is either absent or
one canonical unsigned decimal cursor from zero through 8 MiB. Repeated,
empty, signed, zero-padded, unknown, or out-of-range query values fail before
authorization. A successful response is `PipelineRunLogPage`, is bounded to
four chunks and 640 KiB, carries `Cache-Control: no-store`, and exposes only
the run and cursors, ordered step/sequence, normalized content, chunk expiry,
continuation, retention truncation, and database read time. Executor and
container identities, native counters, commands, environment, paths, and
integrity digests remain private. `hasMore` comes from one bounded lookahead;
`truncated` reports that a chunk after the requested cursor has expired, so an
empty retained page is not confused with complete historical evidence.

The API database role can invoke only a table-blind `SECURITY DEFINER`
function. It derives the tenant and time from the transaction, conceals a
foreign run as missing, selects only unexpired normalized chunks, recomputes
the cursor-bound request and operation identities, and atomically writes one
IAM-bound `devops.pipeline-run.logs-read` Audit fact before returning the
page. The fact contains no log content or executor implementation data; an
independent resource kind, changed action, or injected log payload fails
closed inside PostgreSQL.

This adapts Prow's observe-before-create, state-specific timeout, bounded grace,
and durable result-marker behavior. It deliberately replaces Pod identity,
cluster/cache semantics, environment-carried job configuration, and storage
sidecars with Matrix command identity, a private spool, mTLS roles, leases,
fencing, and normalized receipts. No Prow package or object enters the
protocol.

Untrusted verification never runs on the Foundation/Application-PaaS host.
The accepted profile requires a dedicated Linux/amd64 runner node with no
tenant runtime or control-plane data, Docker `29.x`, and gVisor
`release-20260831.0` installed as the `runsc` runtime. Its fixed offline
x86-64 `.tar.zstd` archive is
`sha256:b9ccc6e14ca4eb2c2e65ff66e011f3b7e79d3275fb12eab747b19f95caf8e891`.
The release page and checksummed multi-binary installation model are described
by the official gVisor
[release](https://github.com/google/gvisor/releases/tag/release-20260831.0),
[installation guide](https://gvisor.dev/docs/user_guide/install/), and
[Docker runtime guide](https://gvisor.dev/docs/user_guide/quick_start/docker/).
The runner installer consumes the release-carried archive and checksum; it
cannot download `latest`, invoke the package manager, or let `runsc install`
fetch missing sidecars.

The installation-side export copies only the outer signed manifest/signature,
`mx`, the runner executable, the fixed toolchain image archive, and the fixed
gVisor archive/checksum into an independently verifiable directory. It also
reports the exact SHA-256 fingerprints of the installation's executor-server
and runner-client authorities. The operator transfers those fingerprints to
the runner through an independently trusted channel before CSR creation. Every
CSR request binds both fingerprints, and a signed enrollment response must
carry the exact pinned authorities; a response cannot bootstrap trust in a new
self-declared CA. Each slot's P-256 private key is generated and retained only
under its node-local private root, while the platform stores only the canonical
signed public enrollment record.

The runner agent polls one mutually authenticated executor endpoint and may
receive only a current fenced task, its content-addressed source archive, and
closed profile identity. Its credential cannot call IAM, Audit, PaaS, source
provider, reporter, PostgreSQL, another runner, or an administrative executor
operation. The node firewall permits only that endpoint. Draining or losing a
runner stops new claims and leaves the control plane to reconcile the current
lease; registration or heartbeat alone is not evidence of isolation.

One `matrix-devops-runner` process is one certificate-bound execution slot and
owns at most one active assignment. A selected runner-node installation may
compose at most four independently credentialed slots with disjoint journal
and workspace roots beneath the same private installation-owned storage root;
sharing a credential or either mutable root is forbidden. Before every claim,
the slot first replays any locally terminal receipt and then completes a
30-second-bounded Docker/runtime/resource/toolchain/storage/isolation preflight.
It does not become ready before that first successful no-error cycle. An
eligibility, gateway, journal, workspace, renewal, or orchestration failure
removes readiness and stops the process; an idle slot waits ten seconds before
re-proving eligibility and polling again, while a completed claim immediately
continues to the next cycle. The readiness listener is canonical loopback only
and grants no work or administrative operation.

The sole first-release toolchain is `GO_1_26_OFFLINE_V1`, built from
`docker.io/library/golang@sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3`
(Linux/amd64 `1.26.8-alpine3.23`) and carried as an authenticated offline image.
That value is the repository/OCI-manifest digest; the archive's independently
authenticated Docker configuration digest is
`sha256:2e6f40580dfa8312d4aab4f49e5ab214d0daa5999ed51be6eb6fe1f246378e4f`.
The installer loads the untagged signed archive and assigns only
`matrix.local/matrix-devops/go-1.26-offline-v1:07558d5472e9`. Docker 29's
containerd image store exposes the source digest as the image ID and the exact
same local repository at that digest; its classic image store instead exposes
the configuration digest as the image ID with no repository digest. The runner
accepts only those two complete, store-specific metadata profiles.
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

The runner's closed Engine adapter pins API `v1.46` over one configured,
root-owned, non-world-accessible Unix socket; it has no TCP, proxy, redirect,
CLI, or Docker SDK path. Before any task may be claimed it checks Docker
`29.x`, the daemon API range, Linux/amd64, `runsc`, kernel resource-limit
support, the CPU/memory floors, the installation-owned storage floor, and one
of the two exact authenticated local-tag/image metadata profiles. It then runs
only a randomized,
trusted probe from that pinned image and re-inspects the resulting container
through the Engine: the probe checks UID/GID, empty capabilities,
`no-new-privileges`, no non-loopback interface or route, a read-only root,
absence of the Docker socket and sensitive devices, and empty proxy and common
credential variables. The host-side inspection independently checks the
image, command, environment, `runsc`, network/IPC modes, read-only root,
capability/security flags, resources, mounts, logging mode, terminal state,
and network attachment before declaring the node eligible. Failure still
forces bounded container deletion under a 30-second preflight-cleanup
deadline.

The runner workspace adapter consumes the journal's verified archive into a
separate private root under an OS-exclusive, closed runner identity. It
independently rechecks compressed length and digest while the
shared archive codec retains canonical gzip/tar header, order, type, mode,
path, count, expanded-size, and trailing-byte validation. Regular files alone
are created beneath `os.Root`; parent directories are bounded, file/directory
collisions fail, every file is fsynced and sealed `0444` or `0555`, every
directory is sealed `0555`, and publication is one fsynced rename from an
unpredictable private staging directory. A canonical manifest binds the full
request digest, execution, runner, archive, counts, and a content-and-mode tree
digest. Equal reuse and restart read every file again and require the archive,
manifest, and globally sorted filesystem tree to agree; links, special files,
extra/empty directories, writable modes, filesystem-boundary changes, foreign
identity, changed requests, and partial staging fail closed. Native paths are
absent from the manifest and only the re-proved source root can enter the
sandbox adapter.

That sandbox adapter now derives and can drive the Docker lifecycle for either
of the two immutable step requests. Each has its exact command, pinned image,
numeric user, empty credential/proxy environment, `NONE` network, `runsc`, two
CPUs, 2 GiB memory
with no extra swap, 256 processes, and exactly 2 GiB of fresh tmpfs split into
a 512 MiB executable work directory and 1.5 GiB non-executable cache. The sole
host mount is the workspace adapter's canonical, non-recursive, read-only
source directory. Native Engine request fields remain private to the adapter.
Step containers use Docker's `local` log driver in blocking mode with
compression disabled and two 64 MiB rotated files; both creation and every
later inspection require that exact logging profile.

The same adapter owns one mutex-protected output budget shared by both fixed
steps. Its bounded Docker multiplex decoder accepts only complete stdout or
stderr frames, reconstructs per-stream lines across frame boundaries, and
emits run-monotonic UTF-8 chunks no larger than 64 KiB. Both native payload and
normalized output independently stop at 8 MiB. Invalid headers, truncated or
empty frames, counter corruption, sequence exhaustion, and either size limit
poison the budget so a partial untrusted parse cannot be resumed. Lines over
16 KiB, invalid UTF-8, ANSI escapes, control characters, credential-shaped
assignments or token formats, URL user information, and Unix, drive, or UNC
absolute paths are replaced in full by closed markers; native content is never
partially retained beside a marker.

The budget exposes only a validated cursor containing cumulative native and
normalized byte counts plus the last emitted sequence. That cursor restores
the next sequence and both 8 MiB run-wide limits after a runner restart;
partial, inconsistent, backwards, or poisoned progress is rejected. The
private journal commits this cursor atomically with a started step's conclusion
and does not retain native output.

The adapter creates a deterministic stopped container, revalidates every fixed
field before start, fixes that exact container ID across each effect, starts it,
streams its bounded multiplexed logs through the shared decoder, waits, and
re-inspects the terminal state. It closes ordinary nonzero and OOM exits as
step failures. Cancellation distinguishes a not-yet-started container from a
confirmed `SIGKILL`; terminal work wins the race. Mutating transport ambiguity,
same-name replacement, changed configuration or state, malformed responses,
and incomplete log bodies fail closed without exposing daemon text. Deletion
is allowed only after exact non-running inspection and succeeds only after the
deterministic name is proved absent; failure cleanup retains a fixed ten-second
deadline.

The port-driven runner workflow now commits a claimed assignment and its archive
before the first sandbox effect, renews its short lease synchronously before
workspace work and periodically thereafter, and serializes every renewal with
the journal transition that adopts its fence. It replays local terminal truth
before claiming, resumes an already-started step by observation before create,
never lets an `OBSERVE` recovery authorize a first effect, and treats a
`CANCEL` recovery before the effect marker without touching the sandbox. Each
fixed step is started durably, follows the deterministic container, publishes
an exactly validated run-leading log batch before atomically concluding the
step and its cursor, and deletes only concluded containers under the fixed
cleanup deadline. User cancellation closes as `CANCELLED`; the fixed step
deadline closes as `FAILED`; caller shutdown and lost lease authority leave an
observable open effect without inventing a conclusion. The normalized-log port
requires equal sequence replay without duplication and conflict on changed
content. A complete receipt is recorded locally before gateway completion and
is acknowledged only after that completion succeeds.

The outbound-only physical runner process now composes these ports. Shutdown
removes readiness, cancels the active cycle, and waits for that cycle to finish
its bounded observation and cleanup before the process exits. Its selected
release packaging, independently credentialed node topology, controlled-host
installation, and a real standalone process journey are complete below;
provider reporting and the joined end-to-end path remain later Gate B slices.

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
| Inconclusive report reconciliation observations | 10 |

The dedicated runner profile therefore requires at least 4 logical CPUs,
8 GiB memory, and 20 GiB installation-owned free storage after toolchain
import. The DevOps control-plane addition reserves 3 CPUs, 3 GiB memory, and
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
mutation facts for project, connection, binding, source recheck scheduling,
Pipeline draft, and immutable revision activation. Go validation, canonical
replay checks, generated OpenAPI, and PostgreSQL use the same closed action
contracts. The operation identity index is generalized from PaaS-only to
product operations without retaining a parallel compatibility index. A clean
PostgreSQL 18 fixture has applied IAM and Audit migrations twice and exercised
every IAM/Audit catalog entry.

The source-resource slice adds provider-neutral `SourceConnection` and
`RepositoryBinding` contracts, create/update commands, resource health, UI-safe
repository coordinates, and their declared HTTP contract surfaces. A
connection carries only an
opaque installed-adapter identity, one exact canonical HTTPS origin, and three
distinct secret-store references. The adapter identity and endpoint origin
cannot be replaced in place; an update may rotate only the webhook, fetch, and
report references and resets health to
`PENDING / CONFIGURATION_CHANGED`. Plaintext secrets, provider objects,
endpoint paths, loopback names, ambiguous ports, unsafe Git branches, and
repository path traversal fail closed. This pre-v1 replacement removes the
ambiguous endpoint list rather than retaining a compatibility alias: a later
fetch or report effect can now derive exactly one authorized provider target.

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
resource-bound trusted value through ten exact mutations: project and source
connection creation, source credential-reference rotation, connection recheck,
repository binding creation/update/recheck, Pipeline creation/draft replacement,
and immutable revision activation. A delivery-internal durable command record
derives its stable identity from tenant, subject, command, target, and
idempotency key. Equal replay returns the original successful result snapshot
even after later updates; a changed request conflicts. This record is not a
second public Operation resource and does not expand the resource model.

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
Pipeline-scoped revision reads, guarded connection/binding recheck commands,
and unauthenticated readiness. It derives every request identity server-side,
rejects caller authority headers and recheck bodies, strictly decodes bounded
JSON, distinguishes media type, payload size, method, precondition-required,
and precondition-failed outcomes, and normalizes all failures without native
detail. Reads and writes authorize the exact IAM action and resource before
touching the repository; IAM alone derives tenant and subject identity.

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

The authenticated ingress slice adds a provider-neutral orchestration boundary
in front of that transaction and a fixed Gitea `1.27.3` adapter behind it. The
adapter authenticates the untouched body against both rotation candidates
before interpreting JSON, rejects duplicate keys at any depth and bounded JSON
complexity, and accepts only the fixed delivery UUID, event, actions,
repository identity, HTTPS origins, object format, exact head/base commits, and
target branch. It emits no provider user, role, label, URL, or raw object.
Admission compares both the SourceConnection resource version used for HMAC
verification and the payload target branch with the current binding inside the
serializable transaction, closing secret-rotation and branch-retarget races;
equal replay still returns before mutable readiness or Pipeline state is used.

The runtime now wires the Gitea adapter, installation-owned file resolver,
tenant-isolated PostgreSQL SourceConnection read, and existing atomic admission
use case into the DevOps HTTP service. The selected release creates and mounts
the private source-secret root and exposes the isolated APISIX webhook route;
an installation without DevOps receives none of those resources. The
provider-native ingress remains an adapter protocol and is deliberately absent
from the provider-neutral public resource OpenAPI.

The run-lifecycle foundation now owns the closed provider-neutral transition
graph, stage-specific safe failure reasons, terminal immutability, monotonic
status versions, and cancellation completion rules. A delivery-owned task
queue stores the immutable run input digest and deterministic per-stage command
intent before any future adapter call. PostgreSQL database time grants
short-lived leases with monotonic fencing tokens; an expired intent can only be
claimed in observe-before-retry mode, and only the current unexpired fence can
advance the run. Report uncertainty keeps the original report identity through
a bounded ten-observation reconciliation cycle before manual intervention.

The worker remains table-blind and reaches this state solely through five
security-definer functions. Forced RLS covers the tenant-leading task table;
the API cannot read it or execute worker functions, and the worker cannot read
PipelineRuns or task rows directly. The migration backfills the relational
input digest of already-admitted runs and is repeatable with live task history.
The same tenant transaction lock used by admission serializes the fixed
two-active-run limit with queue claims, so concurrent admission and scheduling
cannot exceed either side of the tenant quota.

The source-acquisition slice now validates one closed command across the
PipelineRun lease, current SourceConnection, immutable RepositoryBinding
snapshot, PipelineRevision, and SourceEvent before any effect. A first fence
may invoke the fixed `go-git v5.19.2` Gitea adapter; a recovered fence can only
reprove an already-published archive. The pure archive codec sorts safe paths,
normalizes headers, rejects non-regular Git modes and ambiguous gzip/tar
content, and enforces every byte/path limit. Its filesystem adapter stages
private files, hashes and parses the complete archive, writes a canonical
path-free receipt, fsyncs both, and atomically renames the command directory;
equal publication is observed rather than overwritten. Lease-renewal loss or
caller shutdown leaves the intent open, while exact provider, commit, deadline,
and cancellation outcomes remain closed. The tenant-leading, forced-RLS
`source_archives` table stores only the canonical
`application/vnd.matrix.devops.source.v1+tar+gzip` receipt. The table-blind
source-fetcher role can call exactly five heartbeat/readiness/claim/renew/
complete functions; it alone can claim `FETCH`, and the general worker remains
limited to `VERIFY` and `REPORT`. Successful completion verifies the current
lease and fence, inserts the exact receipt, completes the durable command, and
advances `FETCHING -> VERIFYING` in one transaction. The generic transition
cannot bypass a missing receipt, while terminal source failure or cancellation
writes no receipt and keeps the existing atomic completion Audit fact.

The independently built `matrix-devops-source-fetcher` process uses that
distinct database login, resolves only fetch credentials, runs the fixed Gitea
adapter and archive store, renews leases during the bounded effect, and emits a
ten-second heartbeat even while fetching. Its selected-only installation
topology mounts one read-only DSN, the read-only fetch-purpose root, and one
private writable archive root; it joins only the internal control and
source-egress networks and receives no other product or execution authority.
Its process loop cancels and waits for one active acquisition cycle during
shutdown instead of exiting while filesystem or provider cleanup is still in
flight.

The BuildExecutor boundary, pure fenced `VERIFY` use case, and table-blind
PostgreSQL adapter now close the control-plane authority passed toward
untrusted execution. The use case validates the exact run, PipelineRevision,
source receipt, deadline, and worker before opening the archive; first claims
execute while recovered claims only observe or cancel. Database-time claims
bind and preserve the execution window, and a strict normalized receipt must
be stored atomically before `REPORTING` can be entered. Lease renewal, stale
fencing, receipt tampering, and the generic-transition bypass fail closed.

The versioned `api/adapter/devopsbuild/v1` boundary now owns the cross-process
request and normalized terminal receipt instead of duplicating them inside the
service-local port. It strictly encodes canonical submission/receipt
documents, derives a framed deterministic execution digest, and streams an
eight-byte-length-framed request followed by exactly the declared archive
bytes while independently enforcing the archive length and SHA-256 digest.
The admin control and runner assignment/renewal/completion documents are
separately closed: runner identity remains connection-derived, only the first
`EXECUTE` assignment carries an archive, and recovery assignments can only be
`OBSERVE` or `CANCEL`. The delivery port retains only executor capability and
outcome errors.

The executor gateway's private filesystem spool now atomically publishes an
inspected archive, canonical request, and initial state under its deterministic
execution digest. Immutable state generations form a strict consecutive
SHA-256 chain and are fsynced before acknowledgement. Equal create and
terminal completion replay observe the original state; changed authority or
receipt conflicts. The queue assigns the oldest eligible execution for 30
seconds with a monotonic fence, never gives an expired possible effect to a
different runner identity, and gives only the same runner an archive-free
`OBSERVE` or `CANCEL` recovery assignment. Renewal cannot cross the fixed build
deadline and carries the durable cancellation bit. Restart, partial staging
cleanup, canonical file modes/shapes, archive reinspection, and symlink/content
tamper fail closed. The strict TLS 1.3 admin client and separate admin/runner
mTLS HTTP handlers now drive this spool over real sockets. The independent
gateway process loads canonical protected key/certificate inputs, rejects
overlapping role trust roots, holds an OS-level exclusive spool lock, and
couples two explicit bounded TLS listeners so either failure stops the whole
process. The outbound-only runner client derives its opaque identity from the
runner certificate and can only claim, renew, and complete through that role's
listener. Its independent private journal binds the complete canonical request
before accepting archive bytes, reinspects the finished archive before atomic
publication, holds an OS-level exclusive directory lock, and persists strict
`RECEIVED`, `EFFECT_STARTED`, `TERMINAL`, and `ACKNOWLEDGED` generations with
request digests, recovery fences, cancellation, exact ordered `PENDING`,
`STARTED`, `PASSED`, `FAILED`, or `CANCELLED` step progress, the canonical first
start time of each invoked step, run-wide native/normalized log counts and last
emitted sequence, and normalized receipts. A step start and its
time are fsynced before its deterministic container side effect may be invoked;
replay preserves that first time, so recovery cannot renew the fixed per-step
clock. Step two cannot be authorized before durable step-one success or with a
start time earlier than step one. Log progress can advance only when a started
step reaches one fixed conclusion, advances all three cursor values together,
and must match on replay; pending cancellation cannot invent output. The
journal permits the same runner to
continue the next unstarted step after an archive-free increasing-fence
recovery, while an already-started step must first be observed by the later
runner orchestration. A locally terminal receipt whose gateway completion did
not arrive may also accept a same-runner increasing fence without changing its
steps, log cursor, or receipt, so completion remains replayable after lease
expiry. A cancellation before any sandbox effect durably cancels the next step
and can produce the closed terminal receipt without inventing an effect. The
port-driven runner use case now owns claim commit, initial and periodic renewal,
workspace publication, observe-before-create step recovery, ordered sandbox
execution, cancellation/deadline containment, validated log handoff,
concluded-container cleanup, and local-terminal-first completion. Its strict
architecture boundary imports only public runner contracts, pure log
invariants, and side-effect ports. The physical build-worker command now
composes only its table-blind PostgreSQL repository, read-only source archive,
exact mTLS admin identity, executor-gateway client, independent heartbeat, and
readiness endpoint. The dedicated runner command now derives its opaque runner
identity from protected mTLS material, takes OS-exclusive journal/workspace
ownership, composes the production runner gateway/log client and closed Docker
sandbox, requires a fresh bounded eligibility proof before every claim, and
exposes only loopback readiness after its first proved cycle. The selected
DevOps control-plane topology now includes the build worker and executor gateway
only when the signed product inventory selects DevOps. Staging atomically owns
a private durable spool and a canonical installation-bound PKI bundle with
separate server, admin-client, and runner-client authorities, a fixed five-year
validity, exact build-worker SPIFFE identity, and exact gateway DNS identity.
Only derived gateway and build-worker material is mounted read-only; authority
private keys never enter a runtime container. The build worker reaches the
gateway's unpublished admin listener over the internal control network, while
the gateway also joins the edge network so Docker can publish only the TLS 1.3
runner listener on fixed port `8444`; its health listener remains loopback-only.
PaaS-only staging and topology contain none of these files, directories,
processes, or ports. A DevOps-selected signed release now carries an exact
standalone Linux/amd64 runner subset: `mx`, `matrix-devops-runner`, the pinned
offline Go toolchain image, and the pinned gVisor `.tar.zstd` archive plus its
checksum. The operator CLI exports and re-verifies that subset, reports the
installation authority fingerprints, creates one-to-four disjoint node-local
keys and CSRs bound to those fingerprints, and signs matching certificates
without ever receiving runner private keys. Equal request/enrollment replay is
stable, while changed node use, changed authority pins, foreign installations,
tampered payloads, and PaaS-only releases fail closed. The node-side
`mx devops runner-node install` command now authenticates that exported subset
and the signed CSR-matching enrollment, rejects unsupported or unsafe hosts
before publishing runtime material, and atomically installs an exact
root-owned inventory. A pinned pure-Go
`github.com/klauspost/compress` `v1.20.0` zstd reader extracts and re-verifies
only the fixed gVisor archive entries without a package manager, network,
shell, or ambient decompressor. The Linux/amd64
adapter serializes convergence with one host lock, accepts only an absent or
exact dedicated Docker configuration, creates one non-shared system account
per slot, assigns disjoint private roots, validates nftables and systemd
profiles before publication, activates the UID-bound gateway-only firewall
before Docker or runner processes, loads and re-inspects one exact local
toolchain image identity, and requires exact loopback readiness. Runner units
are disabled before convergence and again after every failed activation, while
the fail-closed firewall remains active. A disposable WSL2 Linux/amd64 node
running systemd, Docker `29.6.2`, the authenticated offline toolchain image,
and the pinned `runsc` now proves canonical source-archive execution through
separate TLS 1.3 mTLS admin and runner listeners using the production clients,
handlers, spool, journal, workspace, and runner workflow. Both fixed Go steps
complete, normalized logs and the exact terminal receipt cross the authenticated
boundaries, the journal is acknowledged, and no container remains. A malicious
source archive additionally proves an empty sensitive environment; no Docker,
PostgreSQL, credential-file, or privileged-device access; read-only source and
root filesystems; loopback-only networking; failed reserved/private/metadata
egress; and actual process exhaustion below 384 attempts against the fixed 256-
PID profile. The pinned runsc reports that exhaustion as `ENOMEM`, while native
cgroups may report `EAGAIN`; either closed resource denial is accepted and an
unrelated failure is not. Secret-shaped, absolute-path, ANSI, control-byte,
invalid-UTF-8, and overlong native lines become their exact closed markers with
no raw sentinel retained. A separate real step emits more than the fixed 8 MiB
whole-run limit; `Follow` returns `ErrLogLimit` with no chunks or resumable
progress, then cancellation, deletion, and observation prove it absent. A
subsequent gate extends the successful execution into standalone gateway/build-
worker/runner processes backed by PostgreSQL and proves crash recovery. Another
gate drives a real fixed Gitea connection through the source observer, physical
DevOps webhook ingress, PostgreSQL, and standalone source-fetcher crash recovery.
The same runner storage now publishes a second tenant's immutable decoy source
workspace before the malicious execution. Even with its exact host path, the
repository cannot read or list it directly, reach or change it with `..`
traversal, or follow a writable-cache symlink into it. A control symlink from
the same cache to the repository's own source remains readable, proving symlink
support rather than treating blanket link failure as isolation evidence. The
trusted runner side then re-reads the unchanged decoy and proves both tenants'
step-container identities absent. Together with real PostgreSQL forced tenant
concealment on public run/log reads, this completes the Gate B malicious-
repository containment item. The joined recovery gate now reuses the physical
executor subjourney behind the real source flow, adds physical IAM and Audit
services, and closes the fetch, gateway-submission, runsc-effect,
provider-status, and Audit-acknowledgment restart cases. Their combined evidence
completes Gate B.

Every fenced worker transition now submits the exact next PipelineRun document
to the database boundary. A terminal transition atomically stores a distinct
Audit Operation and outbox fact with a normalized system actor, deterministic
identity, immutable run-input digest, and closed `outcome`/`reason`; a
nonterminal transition cannot submit one. Audit validates and canonicalizes
those fields only for `devops.pipeline-run.completed`, while cancellation
requests use the separate IAM-bound
`devops.pipeline-run.cancellation-requested` action. The legacy seven-argument
transition function is deleted on upgrade so a worker cannot bypass terminal
fact creation.

The public run-control slice now exposes IAM-authorized `GET /v1/runs/{runId}`
and bodyless `POST /v1/runs/{runId}/cancel`. Cancellation requires both an
exact `If-Match` resource version and `Idempotency-Key`; equal replay returns
the original PipelineRun snapshot, changed replay conflicts, and tenant-scoped
lookup conceals foreign runs. The atomic database boundary records the request
time, cancellation Operation and user Audit fact. A run with no possible
external effect becomes `CANCELLED` in that transaction and receives a
separate control-actor terminal fact. A run with a durable intent remains in
its current state, loses the old lease/fence, and makes that exact intent due
for `OBSERVE`; no future stage may begin after the request, but a definitive
observed success or failure remains truthful.

The same run-control boundary now exposes bodyless
`POST /v1/runs/{sourceRunId}/replay` for an exact terminal source version. A
successful command creates a distinct queued PipelineRun while copying the
source `Input` and `InputDigest` byte-for-byte; a separate top-level cause
records only the direct source run, deterministic command, and IAM-authorized
subject. The atomic transaction locks and revalidates the terminal source,
serializes the existing 32-run tenant queue, writes the new run and
`REPLAY_PIPELINE_RUN` mutation, and emits one IAM-bound
`devops.pipeline-run.replayed` fact before any worker intent exists. Equal
command replay returns its original creation snapshot even if that result has
since transitioned; changed replay conflicts. Replaying a terminal replay is
supported without embedding an ancestry chain, while provider-delivery reads
exclude all replay descendants and keep returning only the original fan-out.

The source-readiness contract slice now replaces the ambiguous endpoint array
with one immutable `endpointOrigin`, adds closed health/reason pairs to both
source resources, and makes a ready observation valid for admission for at
most two minutes. Pure domain observation transitions increment resource
versions, reject stale observations and invalid state/reason pairs, distinguish
state transitions from equal refreshes, and preserve RepositoryBinding spec
digests. The generated OpenAPI and examples expose only the replacement shape;
the removed array has no alias.

The repeatable PostgreSQL migration deterministically converts historical
single-origin connection documents and stored command results, adds reasons to
current and immutable binding snapshots, and refuses a legacy multi-origin
document instead of selecting an endpoint. Its narrowly scoped owner policies
exist only inside the migration transaction and are removed before runtime.
The installation-operator slice now exposes only the exact `apply` and
`retire-previous` commands under `mx devops source-credential`. It takes secret
material only through a protected regular input file, holds the installation
lock, authenticates the sealed journal, pinned trust root, committed signed
release, and selected DevOps product before touching storage, and emits only
closed non-secret result fields. The installer creates three purpose-separated
roots only for a selected DevOps product. A strict canonical `material.json`
envelope and one durable replacement make current/previous webhook rotation
atomic; equal apply and repeated retirement are idempotent. The DevOps API's
read-only webhook resolver consumes that replacement format, while the removed
two-file resolver has no compatibility alias.

The source observer is now a distinct runtime and database identity. Its
tenant-fair queue uses database-time 30-second leases and monotonic fencing;
configuration mutations schedule current resource versions, a connection
transition reschedules its bindings, and equal observations refresh health
without producing an Audit fact. The fixed Gitea `1.27.3` read adapter probes
only version, current user, and the exact repository; it rejects redirects,
ambiguous or oversized JSON, unsupported versions, identity/origin mismatch,
and missing fetch/report permission into closed reasons. The process mounts
only its DSN and the three read-only purpose roots, joins the internal control
network plus one provider-egress network, and has no IAM, Audit, executor, or
configuration-write capability. Its heartbeat gates both process readiness
and DevOps API readiness once any SourceConnection exists.

The next Gate C implementation slice is now designed as an installation-owned
endpoint-scoped CA boundary. It adds no public resource field, database row,
system trust mutation, or process-global TLS override. Its smallest vertical
slice is the strict CA codec and derived filesystem identity, the exact
`mx devops source-trust apply|remove` workflow, selected-only topology mounts,
per-effect source-adapter resolution, the optional safe UI command, and a real
local-provider TLS journey. Until those gates pass, private-provider trust is a
design contract rather than accepted runtime capability.

These slices do not complete Gate A. Source readiness, credential lifecycle,
observation, acquisition through an installed isolated process, the fenced
BuildExecutor boundary, and authenticated tenant-leading normalized-log
persistence, public log reads, and physical runner process composition are
complete together with the selected DevOps control-plane release topology.
Dedicated runner-node runtime installation, real isolated execution, reporting,
remaining runtime quotas, check-receipt Audit facts, and pagination for other
collection resources remain pending.

Current verification evidence:

- `go test ./...`
- `go vet ./...`
- `go test -race` and `go test -count=20` across the DevOps/Audit contracts,
  delivery domain, admission, run control, HTTP, and PostgreSQL adapter packages
- installation-operator command, material-codec, read-only resolver, and local
  filesystem journeys proving the exact no-alias CLI, no argv value, signed
  DevOps selection, PaaS-only rejection, lifecycle-lock conflict, trust-root
  tamper rejection, protected input enforcement, purpose-separated roots,
  atomic webhook rotation, equal apply, repeated retirement, and closed output;
  the focused suites pass race and 20-run repetition
- the same credential suites pass in a disposable disconnected Debian Linux
  container with the source and module cache mounted read-only, exercising
  owner/mode and no-follow checks; Linux/amd64 CGO-disabled `go build ./...`
  also passes
- five-second native fuzz runs for draft/event digest framing and activation
  with untrusted repository-binding identifiers; the manual-replay identity
  run completed 512,956 executions
- Linux/amd64 CGO-disabled cross-build of the new contract and domain packages
- deterministic OpenAPI generation-drift tests and `git diff --check`
- fixed Gitea `1.27.3` observer tests proving three purpose-separated
  credential reads, exact unauthenticated version and authenticated user/repo
  probes, verified TLS transport with redirects disabled, bounded strict JSON,
  exact repository identity/origin/default-branch checks, separate pull/push
  permission, cancellation, and closed unavailable reasons; the observer,
  resolver, command loop, use case, Audit contract, and topology suites pass
  race and 20-run repetition
- the opt-in provider protocol gate passes against the exact pinned rootless
  Gitea `1.27.3` image digest through an HTTPS test boundary: it provisions a
  private repository and separate fetch/report tokens, then proves the real
  version, current-user, repository identity/origin/default-branch, and
  pull/push permission responses without making the fixture a release input
- source-acquisition use-case, archive-codec, private-filesystem, and Gitea
  adapter tests proving five-way immutable command binding, execute-versus-
  observe fencing, lease renewal, shutdown recovery, closed failure mapping,
  atomic idempotent publication, canonical receipt replay, full rehash/parse,
  bounded protocol responses, exact HTTPS smart-Git request shapes, no
  redirect credential forwarding, SHA-1-only admission, safe path/mode
  handling, and tamper/partial/symlink rejection; the four focused packages
  pass the race detector and 20-run repetition
- versioned BuildExecutor adapter-contract and fenced execution-use-case tests
  proving closed request authority, canonical strict submission/receipt
  documents, deterministic execution and terminal-receipt digests, exact
  archive framing/length/hash, short/changed/trailing archive rejection, exact
  run/revision/archive/deadline binding before effects, execute-versus-observe
  recovery, cancellation and expired-build cancellation, lease renewal and
  lease-loss uncertainty, source-archive failure, definitive executor absence,
  invalid receipt rejection, native-error sanitization, and passed/failed
  handoff to the reporter
- executor-gateway spool tests proving atomic create, equal and changed replay,
  restart recovery, strict temporary cleanup and private file shape, oldest-
  eligible assignment, archive-only first delivery, different-runner takeover
  denial, same-runner `OBSERVE`/`CANCEL` recovery, lease renewal, deadline cap,
  cancellation propagation, stale-fence rejection, terminal equal replay,
  changed-receipt conflict, consecutive digest-bound state history, and
  submission/archive/state tamper rejection; the public runner documents and
  spool suites pass race detection and 20-run repetition
- executor-gateway transport tests over real TLS sockets proving TLS 1.3-only
  negotiation, separate admin and runner client roots, exact build-worker
  identity, runner-namespace authorization, certificate-derived opaque runner
  identity, authority-free canonical requests, bounded headers and bodies,
  admin create/observe/cancel recovery, archive-only first assignment,
  different-runner denial, current-fence renewal and cancellation propagation,
  archive-free same-runner recovery, terminal acknowledgement replay, changed
  completion conflict, and empty sanitized failures; the transport, spool, and
  public-contract suites pass race detection and 20-run repetition
- executor-gateway process-composition tests proving canonical protected
  server key/certificate and self-signed client-root loading, disjoint role
  signing keys, explicit distinct IP listeners, OS-exclusive spool ownership
  with release recovery, coupled shutdown, and a complete admin-submit through
  runner-claim/completion receipt round trip over both real mTLS sockets; an
  architecture gate excludes database, source-provider, IAM, Audit, PaaS,
  Docker, process-exec, and Prow/Kubernetes authority from the gateway source,
  while the fixed disconnected Go 1.26.8 Linux/amd64 suite proves the Linux
  lock and gateway composition twenty times without module lookup
- outbound runner-client and independent private-journal tests proving
  certificate-derived identity, no proxy/redirect/compression authority,
  canonical metadata binding before archive consumption, complete-request
  digests distinct from retry-stable execution identity, structural archive
  reinspection, fsynced atomic publication, OS-exclusive directory ownership,
  abandoned-claim cleanup, strict effect/step/terminal/acknowledged transitions,
  lease renewal, durable cancellation before or during an effect, enforced
  step order, idempotent step replay, atomic monotonic log-cursor persistence,
  archive-free increasing-fence recovery that preserves completed step and log
  progress, locally terminal completion recovery after lease expiry,
  same-runner restart, and rejection of
  changed conclusions, out-of-order steps, changed request, stale fence,
  duplicate execution, foreign identity/entry, unsafe mode, symlink, archive,
  assignment, state, invalid/changed/backwards log cursors, and recomputed
  request-digest, step-chain, or log-chain tampering. A
  real TLS 1.3 mTLS journeys claim through the production client directly into
  the journal, persist the pre-effect marker, renewal, and ordered step
  conclusions, submit and acknowledge the normalized receipt, recover the same
  terminal truth after restart, and replay a locally terminal receipt through
  a new same-runner fence after the original lease expires. The contract, spool, gateway,
  runner client, journal, and gateway-command suites pass race detection and
  twenty-run repetition on Windows, plus twenty runs in the fixed disconnected
  Go 1.26.8 Linux/amd64 image with read-only source and no module lookup
- physical build-worker command and shared process-mTLS tests proving a closed
  environment, protected canonical private key and certificate chain, exact
  SPIFFE client identity, self-signed server-root validation, rejection of
  mismatched keys, ambiguous SANs, duplicate roots, noncanonical PEM, expired
  material, and unsafe key permissions. The process composes only the
  table-blind build repository, read-only source archive, executor admin client,
  heartbeat-gated readiness, and one drain-while-claimed loop whose heartbeat
  continues during a long build and whose dependency or coordination failure
  stops the process. An architecture gate excludes provider, reporter, runner
  journal, executor spool, Docker/process-exec, Kubernetes, IAM, Audit, and PaaS
  authority. The process-mTLS, command, build-execution, and admin-client suites
  pass race detection and twenty-run repetition on Windows and twenty runs in
  the fixed disconnected Go 1.26.8 Linux/amd64 image using read-only source and
  module cache with module lookup disabled. The real process gate below now
  proves cross-process PostgreSQL VERIFY execution; the complete source-to-
  provider journey remains a Gate B item
- closed runner-sandbox adapter tests proving deterministic exact `go test`
  and `go vet` requests, fixed image/API/runtime/user/environment, no network,
  read-only root and source, dropped capabilities, `no-new-privileges`, no
  device/socket/secret mounts, fixed CPU/memory/no-extra-swap/PID/tmpfs limits,
  exact blocking local-log rotation, sensitive-path and mutation rejection,
  bounded sanitized Engine responses,
  pre-claim Docker/API/platform/runtime/resource/storage/image gates, and a
  trusted negative probe whose command and host-side inspection must agree and
  whose container is deleted under a fixed cleanup deadline after failure. The
  lifecycle tests prove exact create/inspect/start/log/wait/delete ordering,
  container-ID continuity, terminal and deletion replay, ordinary and OOM
  failure, pre-start and running cancellation, same-name replacement rejection,
  non-running-only deletion, mutating-outcome ambiguity, sanitized errors, and
  poisoned partial-log reuse. The run-shared output tests prove
  strict Docker multiplex framing, split/interleaved stream reconstruction,
  monotonic bounded chunks, independent native/normalized whole-run limits,
  validated restart restoration without budget or sequence reset,
  complete closed-marker replacement for unsafe lines, poisoned reuse after
  malformed or oversized input, safe UTF-8 preservation, and fuzzed arbitrary
  native bytes. The package passes race detection and twenty-run repetition on
  Windows and twenty runs in the fixed disconnected Go 1.26.8 Linux/amd64
  image. A real read-only Engine journey against Docker `29.6.2` verifies the
  production Unix-socket transport and pinned image inspection, and proves the
  current Docker Desktop host fails closed at `RUNSC_RUNTIME`; it is not
  evidence of container execution, log persistence, or gVisor isolation
- runner-workspace and shared archive-codec tests proving callback content is
  member-bounded without duplicating gzip/tar validation, independent raw
  archive length/hash checks, atomic private staging, OS-exclusive ownership,
  runner/request/execution-bound canonical manifests, globally ordered
  content-and-mode tree digests, exact read-only file and directory modes,
  directory-count bounding, full equal-replay and restart revalidation, and
  rejection of foreign runner identity, changed request/archive/content/mode,
  links, extra directories, file/directory collisions, partial publication,
  unsafe roots, cancellation, and close ambiguity. The workspace, archive,
  and sandbox packages pass race detection and twenty-run repetition on
  Windows plus twenty runs in the fixed disconnected Go 1.26.8 Linux/amd64
  image; a Linux integration also proves the returned source root is the sole
  bind mount accepted by both immutable step plans. This is filesystem and
  request-shape evidence, not repository-code or gVisor execution evidence
- port-driven runner-workflow tests using the real private journal and workspace
  prove archive commit before sandbox effects, synchronous initial and periodic
  lease renewal, two ordered steps, observation before recovery creation,
  `OBSERVE` deferral before a first effect, cancellation before and during an
  effect, fixed-deadline failure, run-leading validated log handoff, cleanup,
  local-terminal replay, completion acknowledgement, and lease-loss containment
  without an invented conclusion. A strict architecture test keeps every
  concrete filesystem, HTTP, Docker, process, database, provider, PaaS, and
  Kubernetes dependency behind a port. The workflow and affected journal,
  workspace, sandbox, runner-client, log, port, and architecture packages pass
  race detection and twenty-run repetition on Windows and twenty runs in the
  fixed disconnected Go 1.26.8 Linux/amd64 image with read-only source and
  module cache; this is orchestration evidence, not repository-execution or
  gVisor evidence
- physical runner-command tests proving complete closed environment
  configuration, canonical loopback-only readiness, disjoint private durable
  roots under one storage boundary, credential/socket separation, one serial
  certificate-bound slot, first-cycle readiness, immediate post-claim drain,
  dependency-failure shutdown, closed error output, and preflight-before-claim
  enforcement. An architecture gate permits only the runner transport,
  journal, workspace, sandbox, orchestration, mTLS, and readiness boundaries
  and excludes database, provider, reporter, IAM, Audit, PaaS, process-exec,
  third-party Docker SDK, Prow, and Kubernetes authority. Command, workflow,
  sandbox, and architecture packages pass race detection and twenty-run
  repetition on Windows and in the fixed disconnected Go 1.26.8 Linux/amd64
  image with read-only source and module cache; that earlier gate is
  process-composition evidence only, not standalone runner release, real
  repository execution, or gVisor isolation evidence
- signed runner-release and CSR-enrollment tests proving the DevOps product
  requires the exact runner-only payload while PaaS-only releases reject it;
  the transferable subset retains the outer release signature and rejects
  missing, extra, tampered, non-regular, unpinned gVisor, or changed-checksum
  content. Production staging copies and hashes the official
  `release-20260831.0` `.tar.zstd` artifact in one pass, and a real Docker image
  save authenticates the pinned repository/OCI digest through the separately
  pinned archive configuration digest. A network-none Docker `29.6.2` DinD gate
  then loads that untagged archive and assigns the sole fixed Matrix-local tag
  against both the default containerd and explicitly selected classic image
  stores: the former proves the exact source-ID/local-RepoDigest profile and the
  latter the exact config-ID/no-RepoDigest profile. Four-slot enrollment proves
  distinct node-local P-256 keys,
  canonical CSRs and SPIFFE identities, disjoint journal/workspace roots,
  operator-pinned server/runner CA fingerprints, certificate-to-CSR public-key
  binding, no platform-held runner private key, entropy-free equal replay, and
  rejection of a self-consistent response carrying an unpinned authority,
  changed node input, foreign installation, or fifth slot. A release assembly
  integration re-verifies the authentic gVisor and toolchain artifacts through
  the independently transferable signed subset. All affected release,
  enrollment, operator-command, local-machine, release-build, and sandbox
  packages pass race detection and twenty-run repetition on Windows and twenty
  runs in the fixed disconnected Linux/amd64 image with read-only source and
  module cache; this is distribution and enrollment evidence, not
  dedicated-node installation or gVisor execution
- dedicated runner-node installation tests proving the closed CLI request and
  non-secret result, release/enrollment/request rebinding, Linux/amd64 root
  preflight before material publication, exact root-owned installed inventory,
  fixed-entry single-threaded bounded zstd extraction, equal replay, and
  rejection of DNS gateway authority, changed payload/PKI, links, foreign host
  profiles, shared Docker configuration, account reuse, path drift, and
  unowned material. Root Linux filesystem integration behind a closed fake
  command boundary proves one account per slot, disjoint ownership, exact
  systemd and nftables rendering and validation, firewall-before-Docker-before-
  toolchain-before-runner activation, exact Docker `29.x` API and `runsc`
  inspection, toolchain cleanup, readiness-gated success, global locking, and
  stop-plus-disable containment on failure. All repository tests and vet pass
  on Windows; the affected installer, runner-command, and CLI packages pass
  race detection and twenty-run repetition on Windows plus twenty runs in the
  fixed disconnected Go 1.26.8 Linux/amd64 image with read-only source and
  module cache. A separate disconnected Linux integration installs the actual
  current runner binary, pinned official gVisor archive, and real Docker-save
  toolchain archive, then re-verifies the complete material inventory and
  extracted binaries. This is installer and filesystem evidence; it is not by
  itself a real systemd/nftables/Docker/runsc host or repository-code execution
  gate
- an opt-in real execution integration on a disposable WSL2 systemd
  Linux/amd64 node with Docker `29.6.2`, the authenticated offline toolchain
  image, and pinned `runsc`. It sends a canonical executable source archive
  through separate TLS 1.3 mTLS admin and runner listeners using the production
  clients, handlers, durable spool, journal, workspace, and runner workflow;
  runs the fixed `go test` and `go vet` steps; proves normalized logs, the exact
  terminal receipt, journal acknowledgement, and zero residual containers; and
  rejects sensitive environment exposure, writable source/root filesystems,
  Docker/control-plane sockets, credential files, privileged-device access,
  non-loopback networking, and reserved/private/metadata egress. A malicious
  repository starts child processes until the fixed 256-PID profile returns the
  runsc `ENOMEM` resource denial, then emits secret-shaped, absolute-path, ANSI,
  control-byte, invalid-UTF-8, and overlong lines whose raw values are absent and
  exact closed markers are present in the authenticated log read. A separate
  real production-sandbox step emits 129 64-KiB blocks, proves the fixed whole-
  run log limit returns no partial chunks or progress, and is cancelled, deleted,
  and observed absent. Before that attack, the same runner store publishes a
  different tenant's immutable decoy workspace and gives its exact host path to
  the repository. Direct read/list, parent traversal read/write, and a writable-
  cache symlink escape all fail; a control symlink to the attacker's own source
  succeeds, the trusted side re-proves the decoy content, and both tenants have
  zero residual step containers. The real Docker response also proves the exact
  non-TTY multiplexed log media type, and the private cache tmpfs proves its
  explicit UID/GID ownership. The expanded journey passes in 48.04 seconds;
  affected Linux vet plus full Windows repository tests and vet pass on the same
  worktree. Combined with the existing real PostgreSQL tenant-concealed public
  run/log reads, this completes Gate B's malicious-repository containment item.
  The joined source journey below now supplies the physical source, authority,
  Audit, executor, and provider-report boundaries that this adversarial gate
  deliberately isolates
- a reusable standalone-process recovery journey on a clean PostgreSQL 18
  database and the same disposable Docker `29.6.2`/pinned-`runsc` node. It
  applies and verifies the DevOps migration twice, seeds one canonical source
  archive and VERIFY intent through isolated runtime roles, then starts the
  actual executor-gateway, build-worker, and outbound runner binaries with
  distinct TLS 1.3 mTLS authorities and role-specific environments. The gate
  kills the first build worker after durable gateway submission, expires its
  database lease, proves the replacement worker's increased fence, kills the
  first runner while its exact labeled step container is running, and proves
  the replacement runner observes that effect under an increased gateway fence
  rather than creating a duplicate. Both immutable Go steps complete, exactly
  one build receipt persists, the VERIFY task is completed, the run reaches
  `REPORTING` without prematurely materializing a REPORT task, the spool is
  terminal, the runner journal is acknowledged, normalized logs persist, and
  no business container or isolation probe remains. Process output contains no
  database password or private key. The same physical recovery function is now
  reused by the provider-originated journey below rather than retaining an
  in-test executor. Its current independent run passes in 43.35 seconds;
  affected Linux package tests and vet plus full Windows repository tests and
  vet pass on the same worktree
- an opt-in joined source-to-Audit recovery journey on one clean PostgreSQL
  `18.6` database, the fixed Gitea `1.27.3` image, Docker `29.6.2`, the pinned
  `runsc release-20260831.0`, and the authenticated Go `1.26.8` toolchain image.
  It applies and verifies IAM, Audit, and DevOps migrations twice, enrolls and
  re-verifies the installation-bound `DEVOPS` service identity, provisions one
  private repository and purpose-separated fetch/report tokens, and writes only
  canonical private credential material. It then starts the actual IAM, Audit,
  DevOps API, source-observer, source-fetcher, check-reporter,
  executor-gateway, build-worker, outbound runner, and DevOps Audit-dispatcher
  binaries. IAM returns the exact tenant, principal, and `DEVOPS` purpose to the
  physical callers, while Audit persists through its runtime-only PostgreSQL
  role; neither authority is represented by an in-memory substitute.

  The observer makes the connection and binding `READY`; the physical webhook
  rejects a forged signature, one valid signed pull-request event creates one
  immutable run and correlated Audit facts, equal replay retains that run, and
  changed-byte replay conflicts. The gate locks only the source-receipt
  relation, lets the first fetcher perform exactly one Gitea `upload-pack` and
  atomically publish the archive, then kills it before PostgreSQL can
  acknowledge the effect. The database retains an open fence-one FETCH and no
  receipt; after bounded test-only lease expiry, a replacement claims fence two,
  validates the existing archive without recontacting Gitea, stores one
  receipt, completes FETCH, and advances the unchanged run to `VERIFYING`.

  The same run then crosses the physical TLS 1.3 mTLS executor boundary. The
  first build worker is killed after its durable gateway submission and a
  replacement claims the increased database fence. The first runner is killed
  while the exact `runsc` step container is running; a replacement with the
  same certificate-bound identity observes the existing effect under the next
  gateway fence, completes the fixed offline `go test` and `go vet` steps,
  persists normalized logs and exactly one runner-bound build receipt, and
  advances the run to `REPORTING`. The VERIFY task ends at fence two, the spool
  is terminal, the journal is acknowledged, and no business or isolation-probe
  container remains.

  A first recovery reporter resolves only the report credential, claims fence
  one, and creates exactly one real Gitea `success` status with context
  `matrix/{pipelineId}/{runId}`. A test-only relation lock withholds only the
  PostgreSQL acknowledgement; after the provider commits, the reporter is
  killed and the run remains `REPORTING` with no check receipt. A replacement
  claims fence two in observe mode, performs one status read and no second
  create, persists the sole provider receipt, and records the run as
  `SUCCEEDED / COMPLETED`.

  Finally, a narrow fault-injection proxy forwards the first dispatcher request
  to the physical Audit service, lets Audit commit it, and withholds only the
  response. The first dispatcher is killed while its outbox row remains leased
  at attempt/fence one; after bounded lease expiry, a replacement replays the
  same immutable event, receives Audit's duplicate outcome, and drains every
  remaining fact. Audit contains exactly the expected DevOps records, the
  crashed outbox row is delivered at attempt/fence two, and the proxy observes
  exactly one accepted request per event plus one duplicate rather than acting
  as an Audit sink.

  The fetched archive is the exact five-file head tree without Git metadata.
  Its content, selected database documents, physical process output, build/check
  receipts, logs, and Audit records contain no webhook secret, provider token,
  service/database credential, private key, or private path. The joined journey
  passes in 45.78 seconds; affected Linux package tests and vet plus full
  Windows repository tests and vet pass. All disposable WSL, Docker, image,
  cache, download, database, repository, token, and proxy resources are removed
  after the gate. Combined with the adversarial repository execution evidence
  and the unit/security recovery matrices above, this completes all four Gate B
  acceptance items; Gate C product UI and offline-release completion remain
  outstanding
- the first Gate C command slice adds bodyless, idempotent, strong-ETag-guarded
  SourceConnection and RepositoryBinding Recheck endpoints with distinct
  administrator-only IAM actions and normalized Audit facts. PostgreSQL keeps
  the resource document and version unchanged, advances only the matching
  observation task, and preserves an already-held observer lease. Unit and HTTP
  tests reject caller health bodies, stale versions, and missing guards; a
  clean PostgreSQL `18.6` journey applies the schema twice, proves exact replay,
  scheduling, active-lease preservation, observer-only state transition, and
  three correlated scheduling facts. The shared IAM/Audit PostgreSQL `18.6`
  authority journey also passes with both new closed actions
- the Gate C browser-client slice replaces the unsupported DevOps placeholder
  in the existing platform shell with product-owned `/devops/code`,
  `/devops/pipelines`, and `/devops/runs` routes. The ID-driven journey creates
  projects, exact-origin Gitea connections, repository bindings, fixed-profile
  drafts, and immutable revisions; reads closed source health, marks a
  two-minute `READY` observation stale from the server observation clock plus
  monotonic elapsed time, and schedules bodyless strong-ETag-guarded Rechecks.
  It also reads exact PipelineRuns and cursor-paged normalized logs, presents
  `RECEIVE -> FETCH -> VERIFY -> REPORT`, and guards cancellation and manual
  replay with the current run version. Session and journey state remain only in
  page memory; source inputs accept three opaque references but no secret value
  or file, and copyable installation-operator commands contain only safe
  identities and explicit private-file placeholders. The shell keeps
  diagnostic reads available while signed product state disables every DevOps
  mutation. Content-addressed embedded JavaScript/CSS and Go contract tests
  prove the exact local information architecture, public route inventory,
  bodyless command boundary, absence of browser persistence/internal authority
  routes/raw problem reflection, and asset-digest integrity. A disposable
  same-origin browser fixture exercised the create/connect/bind/activate and
  run/log journeys with no console warning or error; full-page desktop
  inspection and exact `360px` responsive checks proved no document overflow,
  long evidence wrapping, and an intentionally self-scrolling stage rail. The
  fixture was not retained. Full Windows repository tests, architecture tests,
  vet, JavaScript syntax, DOM-ID, duplicate-ID, and whitespace gates pass. This
  establishes the browser baseline only: real APISIX authorized/viewer/foreign-
  tenant journeys, the complete designed state/accessibility matrix, and the
  signed offline release remain Gate C work
- the Gate C offline-lifecycle harness now rejects either release in its signed
  A/B pair unless DevOps is selected. After a fresh install, the administrator
  first uses the release-carried `mx devops source-credential` surface to apply
  the purpose-separated webhook, fetch, and report credentials from private
  regular input files. Every invocation creates its input in a fresh private
  sibling directory, scans closed JSON output for all source values and private
  paths, then removes the exact file and empty directory and proves both are
  absent before continuing. The administrator uses public IAM and DevOps routes
  through APISIX to create the project, exact-origin connection, repository
  binding, fixed-profile Pipeline, guarded source and binding Rechecks, and
  immutable revision. The physical observer must advance that connection to
  `UNAVAILABLE / PROVIDER_UNAVAILABLE`, rather than `SECRET_UNAVAILABLE`, and
  its binding to `PENDING / CONNECTION_NOT_READY`. The operator then atomically
  rotates the referenced webhook value, proves equal apply and repeated previous
  retirement are idempotent, schedules a distinct guarded Recheck, and observes
  another later `PROVIDER_UNAVAILABLE` version through APISIX. This proves the
  signed topology resolves all three installation-owned credential roots while
  the deliberately unresolvable provider origin fails closed; it is not a
  substitute for the pending trusted local-provider journey. A public-IAM-created
  `DEVOPS_VIEWER` reads that exact graph but receives closed `403` Problems for
  create and bodyless Recheck mutations. Because IAM deliberately has no
  tenant-creation API, the gate uses the already-owned PostgreSQL observation
  boundary to install a second-organization Viewer fixture by copying the
  live administrator password hash, exercises its real IAM session and APISIX
  read to a closed tenant-scoped `404`, and invokes a non-cancelled bounded
  cleanup for every fixture authority and outbox row even when the assertion
  fails; no plaintext credential enters SQL or is retained for restart. The
  same graph is read back
  after failed automatic upgrade rollback, successful B upgrade, explicit A
  rollback, and protected-backup recovery. The post-host-restart phase checks
  the persisted project/connection/binding/Pipeline/revision reference chain
  directly without retaining a user password. DevOps mutation, source-health
  transition, and IAM authorization Audit facts join the existing protected
  backup baseline. Source values remain only in bounded gate memory for command,
  HTTP, and support-evidence leakage checks and are cleared when the pre-restart
  phase returns; the Application PaaS journey remains unchanged. Full Windows
  repository tests and vet plus the affected race and twenty-run suites pass
  against the harness. This is executable acceptance-gate implementation, not
  signed offline runtime evidence; the gate still must run with exact signed
  DevOps A/B bundles before these Gate C items are accepted
- selected-product installation and topology tests proving journal-stable PKI
  issuance time, three disjoint P-256 authorities, exact gateway and
  build-worker identities, canonical write-once authority storage,
  entropy-free replay and derived-file recovery, tamper rejection, private
  spool ownership, read-only runtime certificate mounts, control-network admin
  authority, control-plus-edge gateway membership, one fixed published mTLS
  runner port, no Docker authority in the gateway/build worker, no authority-
  private-key mount, and complete absence from PaaS-only staging and topology.
  The topology gate rejects every host-published service without a non-internal
  network. The gateway process suite also proves its loopback readiness server
  is coupled to both mutually authenticated TLS listeners. A signed release
  assembled from `4b63c1d` completed a clean install on disposable systemd
  Linux/amd64 with Docker Engine `29.6.2` and its default containerd image
  store: all migrations and the 16-service startup completed; install, verify,
  status, and protected support-evidence commands returned `READY`; and strict
  provider observation proved both the requested and active `0.0.0.0:8444`
  binding on the healthy control-plus-edge gateway. Full unit, topology,
  release-build, architecture, vet, race, and twenty-run gates pass on Windows,
  with the affected repeated suites also passing in the fixed disconnected Go
  1.26.8 Linux/amd64 image using read-only source and module cache. This is real
  control-plane installation evidence, not dedicated-runner or repository-code
  execution evidence
- versioned normalized-log contract, gateway spool, and build-worker drain
  tests prove complete labeled-line grammar, 64 KiB chunks, run-leading byte and
  sequence cursors, exact two-step ordering, atomic spool publication and
  restart validation, mTLS role/fence binding, foreign-runner denial, exact
  replay across a recovered runner fence, changed and mid-batch conflict, and
  terminal reads. The build use case retains the VERIFY intent when log
  evidence cannot be drained and persists every proved batch before its
  receipt. A real fixed PostgreSQL 18.6 migration journey proves a
  tenant-leading forced-RLS table, table-blind current-fence writes, independent
  execution/chunk/batch digest verification, five malformed/tampered document
  rejections, idempotent equality, ordered two-batch storage, exact 14-day
  expiry, stale-fence rejection, and append closure after task completion. All
  affected packages pass race detection and twenty-run repetition on Windows
  plus twenty runs in the fixed disconnected Go 1.26.8 Linux/amd64 image with
  read-only source and module cache
- strict public `PipelineRunLogPage` OpenAPI, validation, use-case, and HTTP
  tests proving exact `PipelineRun` IAM authority, canonical optional cursors,
  four-chunk lookahead pagination, bounded `no-store` responses, empty and
  retention-truncated pages, and exclusion of executor IDs, native counters,
  commands, environment, paths, and digests. A real fixed PostgreSQL 18.6
  journey proves table-blind API-only reads, forced tenant concealment,
  database-time expiry, transactional sanitized Audit facts, and independent
  rejection of a `PIPELINE_LOG` resource, changed Audit action, or injected log
  payload; the shared IAM/Audit authority journey accepts the new action while
  keeping the Go and database action catalogs equal
- the shared source-archive reader proves the portable receipt independently,
  matches it to the private deterministic store, structurally inspects and
  hashes the archive before handoff, and verifies its length and digest again
  across complete stream consumption; changed receipts, partial reads, and
  mutation after opening fail closed without exposing a host path
- real PostgreSQL 18 execution/report persistence journey proving heartbeat-
  gated readiness, separate table-blind build-worker and check-reporter roles,
  `VERIFY`-only build claims, `REPORT`-only reporter claims, exactly six
  reporter functions, one open task under concurrent claims, database-created
  and takeover-stable execution windows, monotonic fencing and current-only
  lease renewal, strict build/check receipt shape and digest binding, atomic
  `VERIFYING -> REPORTING -> SUCCEEDED|FAILED`, missing-receipt bypass
  rejection, double apply, and compatibility with the four-product migration
  boundary
- the same pinned real Gitea gate atomically creates a branch commit from the
  trusted default branch and opens a pull request; the production pure-Go
  adapter fetches only the default-branch and pull-head refs, verifies both
  immutable commits, reproduces the exact head tree as a deterministic archive
  without `.git`, creates one exact terminal commit status, and reads it back
  for reconciliation without another create; the disposable container,
  repository, token, and pulled fixture image are removed after the gate
- full repository tests pass with the release-baseline Go `1.26.8` toolchain;
  `govulncheck v1.7.0` reports zero reachable symbol or imported-package
  vulnerabilities after `x/crypto v0.56.0`, with only its unused, unimported
  `openpgp` package reported at module level
- installation and topology tests proving selected-only source-observer,
  source-fetcher, and check-reporter logins, exact dedicated DSN mounts, four
  read-only observer mounts, the fetcher's two read-only inputs and private
  writable archive root, the reporter's single read-only credential root,
  exact process environments, provider-egress confinement, scratch-image CA
  roots, offline binary inclusion, heartbeat-gated API readiness, and absence
  from PaaS-only installations
- real PostgreSQL 18 double-apply and catalog integration tests for the IAM and
  Audit extensions, release-selected Platform/DevOps credential enrollment,
  equal replay, changed-credential rejection, and exact Audit facts
- full in-memory configuration journeys proving action-bound authorization,
  equal/changed replay, transaction retry, result snapshots, and binding-safe
  reactivation
- strict DevOps HTTP, IAM HTTP, Audit HTTP, outbox-dispatch, product discovery,
  signed topology-selection, and release-assembly tests
- real PostgreSQL 18 authority-process journey across IAM, Audit, PaaS,
  DevOps, their Audit dispatchers, and the source-fetcher, source-observer, and
  check-reporter processes, including isolated runtime logins, real heartbeat-
  gated readiness, authorization denial, idempotency conflict, immutable
  revision reads, readiness failure/recovery, five user-authorized DevOps facts,
  and two exact observer-owned source-health facts
- real PostgreSQL 18 configuration journeys proving double apply, exact
  runtime identities, forced cross-tenant isolation, function-only API writes,
  a table-blind worker, immutable binding/revision history, sanitized Audit
  outbox correlation, and the four-schema platform migration boundary
- real PostgreSQL 18 source-observer journey proving a table-blind role with
  exactly four callable functions, heartbeat fail-closed readiness, immediate
  scheduling, database-time claims, cross-tenant fairness over an older task,
  monotonic fencing recovery, stale-fence and stale-resource-version rejection,
  observer-only health writes, equal refresh without Audit, five deterministic
  sanitized transition facts, double apply, and IAM/Audit/PaaS schema denial
- real PostgreSQL 18 source-acquisition journey proving the table-blind fetcher
  has exactly five callable functions, heartbeat-gated fetcher/API readiness,
  exclusive `FETCH` claims, exact immutable source/binding/revision/event
  documents, database-time renewal and fencing recovery, strict receipt
  validation, atomic archive/command/run advancement, missing-receipt bypass
  rejection, receipt-free source failure/cancellation, double apply, and
  IAM/Audit/PaaS schema denial; the four-product migration journey passes on a
  separate fresh database
- real PostgreSQL 18 source-contract upgrade proving deterministic replacement
  of legacy single-origin documents and command snapshots, health-reason
  backfill across current and immutable resources, removal of temporary owner
  policies, repeatability with durable run/Audit data, and rejection of an
  ambiguous multi-origin legacy connection
- real PostgreSQL 18 admission journeys proving deterministic two-Pipeline
  fan-out, equal replay after mutable configuration becomes unavailable,
  changed-replay conflict, atomic queue rejection, cross-tenant concealment,
  and exactly one success when two two-run events concurrently contend at 30
  queued runs; the same scenario passed on five additional fresh instances
- fixed Gitea adapter tests, five-second authenticated-payload fuzzing, and
  HTTP tests proving current/previous HMAC keys,
  authentication-before-decoding, duplicate/case-folded key rejection,
  provider-field minimization, endpoint-origin and object-format binding,
  exact closed HTTP outcomes, 1 MiB enforcement, and IAM-header isolation
- real PostgreSQL 18 ingress journey from a private file key through signed
  Gitea normalization and tenant-scoped SourceConnection read to atomic
  two-Pipeline fan-out, equal replay after mutable configuration becomes
  pending, and signed changed-payload conflict
- pure lifecycle, run-control, and queue tests covering every legal stage,
  stage-specific failure rejection, immediate versus pending cancellation,
  future-stage prevention, direct-source manual replay, equal/changed command
  replay, stale versions, mismatched IAM authority, terminal truth and
  immutability, intent identity, repository drift, and reconciliation bounds;
  the transition fuzz run completed 48,645 executions without producing an
  invalid accepted status
- strict OpenAPI and HTTP tests proving exact run-read/cancel/replay/log IAM
  resources, bodyless commands, required `If-Match` and `Idempotency-Key`
  guards, replay `Location`/ETag, canonical log cursor and `no-store` response,
  closed error mappings, and validation before authorization
- real PostgreSQL 18 run-lifecycle journey proving data-bearing digest
  backfill, tenant-concealed public reads, immediate queued cancellation,
  pending active cancellation, deterministic `EXECUTE` claims, same-intent
  `OBSERVE` recovery, cancellation-invalidated leases and stale fences,
  successful and cancelled terminals, uncertain report retention,
  current-fence lease renewal, ten deferred observations,
  manual-intervention gating, migration reapply, the concurrent two-active-run
  tenant ceiling, and API/worker table and function confinement
- closed Audit/OpenAPI validation and a real PostgreSQL 18 authority journey
  accepting only valid PipelineRun completion outcome/reason pairs; the
  delivery journey proves eight terminal transitions create exactly eight
  atomic deterministic completion facts, five public cancellation requests
  create exactly five IAM-bound accepted facts, two manual replays create
  exactly two IAM-bound accepted facts, and nonterminal worker transitions
  create no completion fact; both replay generations have no task before a
  worker claim. The fresh journey contains 26 mutations, 16 SourceEvents, 34
  PipelineRuns, ten task intents, two BuildExecutor receipts, and 91 Audit
  operations/outbox facts, including three source-recheck scheduling facts,
  five source-health transitions, and four authorized public log-read facts
- fixed `10fea16` data-bearing upgrade preserving all 17 mutations, 16
  SourceEvents, 32 PipelineRuns, nine task intents, and 71 Audit
  operations/outbox facts while backfilling each original run's creation
  operation. A replay through the upgraded API then preserves the selected
  input exactly, and a further migration reapply/verify preserves the resulting
  18 mutations, 33 PipelineRuns, and 72 operations/outbox facts
- fixed `3139ecf` data-bearing upgrade preserving all 13 configuration
  mutations, 16 SourceEvents, 32 PipelineRuns, nine task intents, and 66 Audit
  operations/outbox facts; all three historical cancelled runs gain a
  canonical cancellation request time equal to their completion time, and the
  new API-only cancellation functions pass catalog verification
- fixed `7363b29` data-bearing upgrade preserving all 13 mutations, 16
  SourceEvents, 32 PipelineRuns, nine task intents, and 61 pre-existing Audit
  facts while replacing the legacy transition function with the audited
  signature
- fixed `0d387dd` data-bearing upgrade preserving all 11 legacy mutations and
  outbox facts, backfilling current/revision external repository identities and
  generalized Audit operations, and removing every temporary upgrade policy

## Incremental acceptance

### Gate A: contract, domain, and persistence

1. Strict Go/OpenAPI contracts cover every resource, command, page/cursor,
   problem, enum, and example; unknown fields, duplicates, oversize bodies,
   tenant selectors, provider-native data, and unsafe text fail closed.
2. Immutable revision activation, event equality/conflict, deterministic run
   identity, state transitions, cancellation, replay, source-health freshness,
   lease/fence, reconciliation, quota, and sanitized failure/log behavior pass
   unit, race, fuzz, and repeated tests.
3. Clean PostgreSQL applies the delivery schema twice and proves separate
   migration/API/worker/source-fetcher/source-observer/check-reporter roles,
   forced tenant isolation, database-time leases, stale-fence and stale-resource
   rejection, API-only configuration writes, observer-only health writes,
   reporter-only provider-result writes, and no cross-schema access.
4. Architecture tests prove the delivery context owns its ports, depends only
   on public contracts, does not import Prow/provider implementations into the
   domain, and does not share the PaaS DeploymentExecutor.

### Gate B: real CI vertical slice

1. Operator CLI provisioning plus the source observer make one real pinned
   source-provider connection and repository binding ready, using an exact
   endpoint-scoped custom CA when system roots do not trust the provider,
   without a secret or CA bundle crossing browser/API, argv, environment,
   logs, Audit, or support output. A
   signed change event then creates one run; equal delivery replay is one run,
   while missing/unsafe credentials, unsupported version, permission loss,
   stale health, changed replay, forged/retired signatures, wrong event,
   oversize body, endpoint redirect, and commit mismatch fail closed.
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
   a DevOps project, exact-origin connection, repository binding, draft, and
   immutable revision, sees pending/ready/unavailable/stale source states, and
   can schedule but not forge a recheck; a viewer cannot mutate them and
   another tenant cannot observe them. An installation operator provisions and
   rotates the referenced credentials and, when required, applies or removes
   the exact tenant-and-origin CA trust with the release-carried `mx` CLI.
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
