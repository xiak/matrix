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
  publication, bounded native output normalization, and closed sandbox
  container lifecycle complete; physical runner composition, reporter effects,
  and normalized-log persistence pending
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

The connection and each repository binding show a closed health state, closed
reason, last observation time, and a **Recheck** affordance that only schedules
reconciliation. `PENDING` means configuration has not yet been proved,
`READY` means every required bounded observation succeeded recently, and
`UNAVAILABLE` means a safe actionable category failed. Provider response text,
user identity, token scope names, filesystem paths, and credential material are
never rendered. A stale `READY` observation is not admission authority: the UI
marks it stale and webhook admission fails closed until a fresh observation is
committed.

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
read-only access to the three credential roots, and provider egress only. It
cannot call IAM or Audit, claim PipelineRun tasks, mutate configuration specs,
or read another Matrix schema. A delivery-owned reconciliation table provides
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

The DevOps API receives only the webhook root. The source observer receives all
three roots because proving readiness is its sole side effect; later fetch and
report workers receive only their own purpose root. The source adapter fetches
only the binding's immutable head and trusted base
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
credential root, one installation-owned archive root, and the internal control
plus source-egress networks. It receives no webhook/report credential, IAM or
Audit service credential, executor authority, container socket, PaaS state, or
direct table access. A ten-second database heartbeat with a thirty-second
freshness limit gates both its own readiness and DevOps API readiness.

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
uses verified system roots with TLS 1.2 or newer, disables proxies and every
redirect, and never places a credential in a URL. No system/global repository
configuration, subprocess, hook, submodule, LFS client, SSH/file/git protocol,
tag, or caller-selected refspec is consulted.

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
tenant-leading bounded normalized-log persistence remains a separate pending
delivery boundary.

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
supports the three `BuildExecutor` operations: create-or-observe one
deterministic execution with its bounded source stream, observe it, and request
cancellation. The runner listener trusts a separate runner-client root and
supports only oldest-eligible assignment claim, current-fence renewal with a
cancellation flag, and current-fence terminal completion. It exposes no admin
operation. Both listeners require TLS 1.3, an exact configured server identity,
bounded headers and bodies, no proxy or redirect, and strict canonical
versioned documents from `api/adapter/devopsbuild/v1`; bearer tokens, cookies,
caller-selected URLs, native Docker data, paths, argv, and environment fields
are absent.

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

The runner's closed Engine adapter pins API `v1.46` over one configured,
root-owned, non-world-accessible Unix socket; it has no TCP, proxy, redirect,
CLI, or Docker SDK path. Before any task may be claimed it checks Docker
`29.x`, the daemon API range, Linux/amd64, `runsc`, kernel resource-limit
support, the CPU/memory floors, the installation-owned storage floor, and the
exact local image ID plus repository digest. It then runs only a randomized,
trusted probe from that pinned image and re-inspects the resulting container
through the Engine: the probe checks UID/GID, empty capabilities,
`no-new-privileges`, no non-loopback interface or route, a read-only root,
absence of the Docker socket and sensitive devices, and empty proxy and common
credential variables. The host-side inspection independently checks the
image, command, environment, `runsc`, network/IPC modes, read-only root,
capability/security flags, resources, mounts, logging mode, terminal state,
and network attachment before declaring the node eligible. Failure still
forces bounded container deletion.

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

Cross-step runner orchestration, tenant-leading normalized-log persistence,
and physical runner composition remain subsequent slices, so no process yet
invokes this boundary against repository code.

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
runner orchestration. A cancellation before any sandbox effect durably cancels
the next step and can produce the closed terminal receipt without inventing an
effect. The physical build-worker command now composes only its table-blind
PostgreSQL repository, read-only source archive, exact mTLS admin identity,
executor-gateway client, independent heartbeat, and readiness endpoint. The
dedicated runner process that composes its journal, workspace, tested sandbox
lifecycle, and outbound client, selected release topology, normalized-log
persistence, and a real PostgreSQL-to-runner process journey remain pending.
The closed Docker Engine adapter, pre-claim eligibility probe, and content-bound
read-only workspace are present, but no repository code executes yet.

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

These slices do not complete Gate A. Source readiness, credential lifecycle,
observation, acquisition through an installed isolated process, and the pure
fenced BuildExecutor boundary plus its table-blind PostgreSQL persistence are
complete. Physical execution, reporting, normalized logs, remaining runtime
quotas, check-receipt Audit facts, and pagination remain pending.

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
  progress, same-runner restart, and rejection of
  changed conclusions, out-of-order steps, changed request, stale fence,
  duplicate execution, foreign identity/entry, unsafe mode, symlink, archive,
  assignment, state, invalid/changed/backwards log cursors, and recomputed
  request-digest, step-chain, or log-chain tampering. A
  real TLS 1.3 mTLS journey claims through the production client directly into
  the journal, persists the pre-effect marker, renewal, and both ordered step
  conclusions, submits the normalized receipt, acknowledges it locally, and
  recovers the same terminal truth after restart. The contract, spool, gateway,
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
  module cache with module lookup disabled; real cross-process PostgreSQL
  execution remains a Gate B item
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
- the shared source-archive reader proves the portable receipt independently,
  matches it to the private deterministic store, structurally inspects and
  hashes the archive before handoff, and verifies its length and digest again
  across complete stream consumption; changed receipts, partial reads, and
  mutation after opening fail closed without exposing a host path
- real PostgreSQL 18 BuildExecutor persistence journey proving heartbeat-
  gated readiness, a table-blind worker, `VERIFY`-only build claims,
  `REPORT`-only generic claims, database-created and takeover-stable 20-minute
  execution windows, monotonic fencing and current-only lease renewal, strict
  receipt shape/binding/digest validation, passed and failed receipts, atomic
  `VERIFYING -> REPORTING`, missing-receipt bypass rejection, double apply,
  and compatibility with the four-product migration boundary
- the same pinned real Gitea gate creates a branch, commit, and pull request,
  fetches only its trusted default-branch and pull-head refs through the
  production pure-Go adapter, verifies both immutable commits, and reproduces
  the exact head tree as a deterministic archive without `.git`; the
  disposable container, repository, and token are removed after the gate
- full repository tests pass with the release-baseline Go `1.26.8` toolchain;
  `govulncheck v1.7.0` reports zero reachable symbol or imported-package
  vulnerabilities after `x/crypto v0.56.0`, with only its unused, unimported
  `openpgp` package reported at module level
- installation and topology tests proving selected-only source-observer and
  source-fetcher logins, four read-only observer mounts, the fetcher's two
  read-only inputs and private writable archive root, exact process
  environments, provider-egress confinement, offline binary inclusion,
  heartbeat-gated API readiness, and absence from PaaS-only installations
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
- strict OpenAPI and HTTP tests proving exact run-read/cancel/replay IAM
  resources, bodyless commands, required `If-Match` and `Idempotency-Key`
  guards, replay `Location`/ETag, closed error mappings, and validation before
  authorization
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
  worker claim. The fresh journey contains 23 mutations, 16 SourceEvents, 34
  PipelineRuns, ten task intents, two BuildExecutor receipts, and 84 Audit
  operations/outbox facts, including five source-health transitions
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
   migration/API/worker/source-fetcher/source-observer roles, forced tenant
   isolation, database-time leases, stale-fence and stale-resource rejection, API-only
   configuration writes, observer-only health writes, and no cross-schema
   access.
4. Architecture tests prove the delivery context owns its ports, depends only
   on public contracts, does not import Prow/provider implementations into the
   domain, and does not share the PaaS DeploymentExecutor.

### Gate B: real CI vertical slice

1. Operator CLI provisioning plus the source observer make one real pinned
   source-provider connection and repository binding ready without a secret
   crossing browser/API, argv, environment, logs, Audit, or support output. A
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
   rotates the referenced credentials with the release-carried `mx` CLI.
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
