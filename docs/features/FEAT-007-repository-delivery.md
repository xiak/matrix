# FEAT-007: Repository-triggered CI/CD delivery

- Status: Proposed; Prow adoption and Tencent CODING product benchmark complete,
  implementation not started
- Target release: Unscheduled post-v0.1
- Proposed contract: `delivery.matrix.xiak.com/v1`
- Target design date: 2026-09-07

## Outcome

Deliver the smallest enterprise CI/CD loop for the private Matrix Application
PaaS: a verified source event selects an immutable pipeline revision and exact
commit, an isolated runner verifies and builds that source into an OCI
artifact, and a successful mainline run hands the verified digest to the
existing application-hosting API for deployment. A change-request run reports
its check result but cannot deploy.

This target is deliberately fixed before inspecting either the Prow donor or
the Tencent CODING product reference. It is not a general workflow engine,
hosted source-control product, arbitrary remote shell service, or
Kubernetes-native CI platform.

## Boundary and ownership

`delivery` is a new logical bounded context inside the PaaS modular monolith.
It does not justify a new deployable service in the first slice.

| Concern | Owner |
| --- | --- |
| Source connection, repository binding, normalized source event, pipeline and immutable revision, delivery run and task attempts | `delivery` |
| Application, ApplicationRevision, Deployment generation, placement, application rollback, and runtime observation | `apphosting` |
| Organization, principal, delivery service account, authorization decision, and credential revocation | `iam` |
| Unified immutable security and delivery facts | `audit` |
| OCI storage and digest verification | An artifact-publisher adapter behind a `delivery`-owned port |
| Source-provider webhooks, commit status, and source archive acquisition | Source-provider adapters behind `delivery`-owned ports |
| Isolated source verification and image construction | A build-executor adapter behind a `delivery`-owned port |

The first implementation remains under the existing PaaS process and schema,
with tenant-leading keys, forced row-level security, and role-separated API
and worker database access. The context owns its tables and never reads or
writes IAM, Audit, or application-hosting tables directly. Cross-context work
uses explicit versioned contracts even when the initial composition is in one
process.

Accepting this context changes the shared product map in
[`ADR-0002`](../architecture/ADR-0002-product-boundary.md). That ADR must be
updated in the implementation slice, after this proposal is accepted; this
analysis does not silently make that cross-FEAT decision.

## Minimal resource model

| Resource | Mutability | Purpose |
| --- | --- | --- |
| `SourceConnection` | Metadata/status versioned | Tenant-bound provider identity plus references to webhook and fetch credentials; never secret plaintext. |
| `RepositoryBinding` | Spec/status versioned | Stable provider repository identity, default branch, source connection, and target Matrix Application/Deployment. |
| `Pipeline` | Metadata versioned | Stable identity and active immutable revision. |
| `PipelineRevision` | Immutable | Trusted trigger policy, fixed build profile, approved dependency egress, artifact destination, and deployment policy. |
| `SourceEvent` | Immutable | Provider, delivery identity, repository, event kind, exact commit, trusted base commit where applicable, and verified payload digest. |
| `DeliveryRun` | Immutable input/status versioned | Exact source event, commit, pipeline revision, mode, task results, output digest/provenance, and terminal result. |

Names, branches, tags, and labels are selectors or display data. Only provider
repository identity, immutable commit ID, pipeline revision ID, canonical
digests, and IAM-derived tenant/subject are authorities.

A UI may eventually edit a pipeline draft, but activation always creates a
new immutable PipelineRevision. A repository-owned YAML/Jenkinsfile, mutable
UI document, restored configuration revision, or caller parameter cannot
silently change the revision already selected by a SourceEvent.

## First vertical slice

The first slice supports one source-provider adapter and two trigger modes:

- `CHANGE`: a verified change-request event runs fetch, verify, and build. It
  reports one provider check and has no deployment authority.
- `MAINLINE`: a verified push to the configured default branch runs fetch,
  verify, build, publish, provenance verification, and deployment through the
  ordinary application-hosting API.

A manual replay selects only the exact SourceEvent and PipelineRevision pair
from an existing DeliveryRun. It creates a new run linked to the earlier run;
it cannot substitute a branch head, mutable tag, build definition, artifact,
or deployment target.

Artifact matching is fail-closed. If the selected run does not produce and
verify its expected digest, delivery cannot fall back to the previous run's
artifact, a configured default, a mutable tag, or a regex-selected latest
version.

The accepted workflow is fixed rather than a DAG or general YAML DSL:

```text
RECEIVED -> FETCHING -> VERIFYING -> BUILDING
                                   |        \
                                   |         -> FAILED
                                   v
                              PUBLISHING -> DEPLOYING -> CONFIRMING -> SUCCEEDED
                                   |              |           |
                                   +--------------+-----------+-> FAILED

CHANGE runs terminate successfully after BUILDING and check reporting.
Uncertain external outcomes enter RECONCILING before any effect is retried.
```

Cancellation stops future work and requests cancellation of a current build;
it never assumes that an unconfirmed provider, artifact, or deployment effect
did not happen. A bounded deadline or exhausted reconciliation ends in
`MANUAL_INTERVENTION` rather than blind replay. `SUCCEEDED`, `FAILED`,
`CANCELLED`, and `MANUAL_INTERVENTION` are terminal; `FAILED` carries a closed
failure class that distinguishes source verification, build, publication,
deployment, policy, and platform failures without native error text.

## Trust and execution profile

1. A webhook is admitted only after size, media type, provider identity, and
   current secret signature validation. A signed timestamp and replay window
   are required when the selected provider protocol supplies one. Provider
   delivery identity plus canonical payload digest always gives equal-replay
   success and changed-replay conflict; only normalized bounded fields are
   retained, never the raw provider payload.
2. Trigger policy and build configuration come from the already trusted
   PipelineRevision. A change-request head cannot replace its own pipeline,
   runner policy, secret grants, artifact destination, or deployment target.
3. Source acquisition resolves the advertised commit from the bound repository
   and produces a content-addressed source bundle. Redirects, submodules,
   large-file objects, and commit mismatch fail closed unless explicitly
   admitted by the immutable profile.
4. Source fetch credentials terminate in the acquisition adapter. Build code
   never receives source-provider, artifact-publisher, IAM, Audit, PaaS, host,
   or runner-control credentials.
5. Build code is untrusted. It runs ephemerally under a separately schedulable
   build isolation guarantee, with bounded CPU, memory, disk, time, processes,
   output, and approved dependency egress. It receives no Docker socket, host
   path, privileged mode, or control-plane network path.
6. The runner accepts a closed build request, not caller-provided host shell,
   Kubernetes PodSpec, Compose document, privileged flags, or provider-native
   object. A source-owned Dockerfile may be an input only inside the isolated
   builder; it is never executed by the control-plane host shell.
7. The build executor returns an OCI layout plus normalized evidence. A
   separate publisher attaches registry credentials, publishes by digest, and
   returns the immutable locator, manifest digest, source digest, pipeline
   revision, builder identity, and bounded provenance.
8. Deployment uses a narrowly authorized delivery service identity and the
   public application-hosting contract. IAM must authorize one narrowly typed
   service-as-subject delivery action bound to the exact tenant,
   PipelineRevision, target Application, and Deployment. `delivery` cannot
   write an ApplicationRevision, Deployment, Operation, receipt, or
   observation table.
9. Logs and evidence are bounded and sanitized at ingestion. Secrets, tokens,
   environment dumps, source-provider payloads, native runner errors, absolute
   host paths, and arbitrary credential-bearing command lines are forbidden
   from API responses, Audit, status, and support output.
10. Tenant concurrency, queue depth, running time, stored log bytes, and
    artifact production are quota-bound. Admission and scheduling are fair
    across tenants; provider retries cannot bypass quota.

The application `DeploymentExecutor` is not a build runner. It continues to
accept only the bounded Matrix application profile and verified, already
available artifacts. Build execution and deployment execution have different
credentials, networks, capabilities, evidence, and conformance suites.

## Prerequisites and cross-FEAT changes

Implementation cannot begin as a Prow port. The first adapter choices and
authority extensions must be accepted explicitly:

1. Select one real source provider and its self-hosted/offline support profile.
   The public delivery contract stays provider-neutral, while webhook headers,
   signatures, API credentials, commit statuses, and rate limits stay in that
   adapter.
2. Provide a separately schedulable untrusted build boundary. The existing
   single-engine Compose `WORKLOAD` guarantee is an application boundary, not
   evidence that hostile build code cannot escape, reach control services, or
   steal host credentials.
3. Select one OCI registry or content-addressed artifact store and an isolated
   publisher. Build code emits an OCI layout without receiving publisher
   credentials.
4. Extend the apphosting-owned artifact availability path so the exact verified
   digest can reach the selected ExecutionTarget before apply. FEAT-004 only
   resolves images already present on its Docker Engine and deliberately
   deferred automatic image distribution. Delivery cannot bypass that owner by
   pulling or loading images directly on a runtime host.
5. Extend IAM's closed action/role catalog and service-as-subject boundary for
   the exact delivery action, and extend Audit's closed event union for
   delivery facts. No generic service impersonation or arbitrary Audit
   attributes are introduced.
6. Define bounded log/artifact retention and its installation-owned storage;
   deleting ephemeral runner state cannot delete retained DeliveryRun metadata
   or immutable Audit records.

## Transactions and external effects

1. Webhook admission validates authority, stores/replays SourceEvent, creates
   the exact DeliveryRun, and writes a sanitized Audit outbox fact in one
   tenant transaction.
2. A worker claims a due task with a lease and monotonic fencing token, stores
   deterministic command intent, commits, then invokes an adapter outside the
   database transaction.
3. Results commit only under the current fence. A timeout or connection loss
   is observed/reconciled before replay. Deterministic command identity excludes
   attempt number.
4. Commit-status reporting is an idempotent external effect derived from the
   DeliveryRun and terminal check result. Provider failure cannot rewrite the
   run result and remains durably retryable.
5. Publication and apphosting-owned artifact availability must finish, and the
   digest/provenance must verify, before the deployment command is admitted. A
   failed or cancelled build cannot mutate application desired state.
6. The application-hosting Operation ID and target Deployment generation are
   recorded as external receipts. Delivery success requires the ordinary PaaS
   operation to reach its verified successful state; delivery does not invent
   a second deployment truth.

## Required ports

- `SourceEventVerifier`: authenticate and normalize one supported provider's
  bounded event envelope.
- `SourceSnapshotter`: acquire one exact commit and produce a verified source
  bundle without exposing fetch credentials.
- `CheckReporter`: publish one idempotent normalized check state.
- `BuildExecutor`: apply, observe, and cancel an isolated closed build request.
- `ArtifactPublisher`: publish and verify one OCI result by digest without
  exposing credentials to build code.
- IAM `Authorizer`, Audit ingestion, and the public application-hosting client
  remain existing authority boundaries rather than delivery-owned substitutes.

Concrete ports are admitted only with the first real adapter and its
conformance tests. The names above describe required boundaries; they do not
authorize empty interfaces or speculative packages during analysis.

## Incremental acceptance

### Gate A: contract, domain, and security policy

1. Strict Go/OpenAPI contracts prove immutable commit and PipelineRevision
   selection, event equal replay/changed conflict, closed enums, tenant scope,
   optimistic concurrency, manual replay identity, and sanitized problems.
2. Unit and property tests prove valid DeliveryRun transitions, deterministic
   command identities, quota admission, cancellation, deadline, fence, and
   observe-before-retry behavior.
3. Adversarial tests reject forged/stale/oversized webhooks, branch-to-commit
   substitution, untrusted pipeline replacement, unauthorized deploy mode,
   secret serialization, provider payload leakage, and cross-tenant access.
4. Architecture tests prove `delivery` does not import provider SDK models into
   domain contracts and cannot use the application executor or another
   context's persistence as its control path.
5. IAM and Audit contract tests prove the delivery service identity cannot use
   generic user authority, target another PipelineRevision or Deployment, or
   emit an open-ended event; revocation and authority outage fail closed.

### Gate B: durable control plane and adapters

1. A clean supported PostgreSQL database applies migrations twice and proves
   forced tenant isolation, API/worker privilege separation, immutable inputs,
   outbox atomicity, lease recovery, stale-fence rejection, and bounded quota
   concurrency.
2. A real supported source provider proves signature rotation, delivery
   deduplication, exact-commit fetch, force-push immunity after admission,
   check reporting, outage retry, and revocation without restart.
3. A real isolated builder proves hard resource/deadline limits, approved-only
   egress, no host or control-plane reachability, no credential exposure, and
   deterministic association of source, builder, output digest, and
   provenance.
4. A real registry proves publish reconciliation, immutable digest retrieval,
   changed-content conflict, and credentials inaccessible to build steps.

### Gate C: real CI-to-CD vertical slice

1. In a disposable network-controlled environment, a signed change event for
   an exact commit triggers one CHANGE run, reports its final check, and cannot
   create or update a Deployment.
2. A mainline event for the accepted commit triggers one MAINLINE run, builds
   and publishes one OCI digest, makes that exact digest available through the
   apphosting-owned path, creates an immutable ApplicationRevision, and
   advances exactly one Deployment generation through the real PaaS API.
3. Duplicate/out-of-order events, worker and provider restarts, timeouts at
   every external-effect boundary, and stale workers neither duplicate effects
   nor deploy a different commit. Unknown effects reconcile before retry.
4. A failing or cancelled verification/build never publishes or deploys. An
   application rollout failure remains an apphosting failure linked from the
   DeliveryRun and does not falsify artifact provenance.
5. Malicious source attempts to read credentials, mount host paths, reach the
   control plane, escape resource limits, spoof logs, or replace trusted policy
   fail without cross-tenant effects or sensitive evidence leakage.

The common generation-drift, unit, architecture, vet, race, repeated,
cross-platform build, Markdown-link, donor-dependency, tenant-authority,
secret-leakage, and `git diff --check` gates must pass on one worktree.

## Explicitly deferred

General DAG/workflow syntax, repository-owned CIFile/Jenkinsfile execution,
visual pipeline design, arbitrary host commands, caller-provided PodSpecs or
Compose files, source-code hosting, merge queues, branch protection
administration, approval plugins, chat-ops commands, release forms, release
trains, multi-environment promotion, production approval, canary/blue-green
rollout, deployment rollback policy, scheduled jobs, test result analytics,
elastic runner autoscaling, shared cache, matrix builds, nested
virtualization, customer-defined executor plugins, and multiple source
providers are outside the first slice.

Prow inspection, the Tencent CODING product benchmark, and the resulting
`REUSE`/`ADAPT`/`REFERENCE`/`REJECT` decisions are owned by the
[`FEAT-007 adoption review`](../adoption/FEAT-007-repository-delivery.md), not
this target.
