# FEAT-007: Repository change validation

- Status: Proposed; UX, architecture, and donor analysis complete;
  implementation not started
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

## Implementation prerequisites

Before the first code slice is admitted:

1. Pin one self-hostable source provider and exact tested API/webhook version.
   The initial recommendation is Gitea because it supports a small private test
   fixture; it is an external connected service, not a bundled Matrix product.
2. Select one separately schedulable Matrix Native BuildExecutor profile and
   prove that malicious source cannot reach the Matrix control plane, runtime
   hosts, container socket, other tenants, or adapter credentials. The current
   Application PaaS Compose `WORKLOAD` guarantee is insufficient.
3. Fix one dependency-egress policy, resolver/cache ownership, log store,
   retention duration, maximum run shape, and installation capacity profile.
4. Extend IAM's closed action/role catalog and Audit's closed event union
   without arbitrary attributes or generic service impersonation.

These choices refine adapters and release inventory; they cannot weaken the
provider-neutral public resource model.

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
