# FEAT-010: Application PaaS continuous delivery

- Status: Proposed; UX and architecture complete; implementation not started
- Target products: Matrix DevOps v0.1 and Matrix Application PaaS
- Contracts: `devops.matrix.xiak.com/v1` and
  `paas.matrix.xiak.com/v1`
- Target design date: 2026-09-07
- Depends on: [FEAT-009 mainline OCI publication](FEAT-009-mainline-oci-publication.md)

## Outcome

Complete the smallest source-to-deployment journey: an activated mainline
pipeline takes its exact verified ArtifactVersion, creates one deterministic
handoff through the public Application PaaS API, and follows the resulting PaaS
Operation and Deployment generation to a verified terminal outcome.

DevOps owns the delivery intent and correlation. Application PaaS remains the
only authority for application revisions, deployment generations, artifact
availability on a selected target, placement, rollout, observation, and
rollback. This slice does not introduce environments, approval forms,
promotion, strategies, or direct provider deployment.

## Cross-product contract

The dependency direction is always:

```text
PipelineRun -> ArtifactVersion -> DeliveryAttempt
                                      |
                                      v
                              PaaS public release command
                                      |
                                      v
                    Operation -> Deployment generation -> observation
```

Application PaaS adds one narrowly typed command that atomically:

1. authenticates the DevOps service and authorizes an exact
   `paas.deployment.release-artifact` action for the IAM-derived tenant,
   Application, and Deployment;
2. checks the expected current Deployment resource version/generation;
3. verifies the submitted immutable OCI locator/digest and bounded provenance
   correlation;
4. creates a new immutable ApplicationRevision by replacing one named
   component artifact in the currently accepted revision;
5. creates a new immutable Deployment generation and durable Operation using
   the current exact configuration, secret bindings, replicas, placement
   policy, and desired state;
6. returns the PaaS-owned identities used for later observation.

The request cannot submit a tenant, target, executor, manifest, command,
configuration value, secret, replica count, placement selector, provider
credential, rollout strategy, or mutable image tag. Every call requires an
Idempotency-Key derived from the DeliveryAttempt and exact canonical request.
Equal replay returns the same PaaS Operation/generation; changed replay
conflicts.

## Ownership and resource extension

| Concern | Owner |
| --- | --- |
| Pipeline delivery policy, immutable DeliveryAttempt, handoff command/receipt, and normalized cross-product status | DevOps `delivery` context |
| ApplicationRevision, Deployment generation, Operation, placement, artifact availability, execution, observation, and rollback | PaaS `apphosting` context |
| Exact service identity and cross-product action | `iam` |
| DevOps intent and PaaS mutation facts | `audit`, emitted by each owning context |

`DeliveryTarget` is a versioned DevOps binding to one PaaS installation
identity, Application, Deployment, and component name. Activation resolves and
records the exact PaaS API compatibility and target resource versions inside
the immutable PipelineRevision. It stores no PaaS credential, configuration,
secret, execution target, or provider data.

`DeliveryAttempt` has immutable input—ArtifactVersion, PipelineRun,
PipelineRevision, DeliveryTarget, expected PaaS version/generation, and command
digest—and versioned observed state. It records only the PaaS Operation,
ApplicationRevision, Deployment, generation, normalized state/reason, and
observation time returned by the public API.

## Artifact availability

FEAT-004's Compose ArtifactResolver accepts only an already-present image.
Application PaaS therefore gains an apphosting-owned artifact-availability
port before execution. Given an accepted Deployment generation, placement,
immutable OCI locator/digest, deadline, and deterministic command identity, it
ensures the exact artifact is available to that selected ExecutionTarget and
returns digest-bound evidence.

The availability adapter owns registry read credentials and target transfer.
DevOps and build code never receive those credentials and never pull/load an
image on a runtime host. The DeploymentExecutor still receives only the
bounded application profile and continues to apply with pull/build disabled.
A digest mismatch, mutable-only locator, unsupported platform, missing content,
unverified transfer, or unknown outcome prevents apply and enters the ordinary
PaaS Operation reconciliation path.

## Workflow and failure behavior

1. A successful ArtifactVersion is eligible only when the immutable
   PipelineRevision contains one automatic PaaS delivery policy and its
   DeliveryTarget still matches the expected PaaS resource version.
2. Delivery stores its deterministic handoff intent, commits, then calls PaaS
   outside the database transaction. Response loss is reconciled by the same
   idempotency key before another mutation is attempted.
3. After a receipt, DevOps polls the public PaaS Operation using bounded
   backoff. It never infers success from HTTP acceptance, registry presence,
   provider state, or elapsed time.
4. PaaS performs artifact availability, placement, apply, and observation under
   its existing lease/fence and generation invariants. Only PaaS can report the
   Deployment generation ready.
5. DevOps marks DeliveryAttempt succeeded only when the exact PaaS Operation
   succeeds and its observed Deployment generation equals the receipt.
   Contradictory identity/status enters reconciliation; bounded exhaustion
   becomes `MANUAL_INTERVENTION`.
6. Cancelling before handoff prevents it. After PaaS accepts the command,
   cancellation requests the typed PaaS Operation cancellation if supported
   and then observes it; it never rolls back or stops an application by
   assumption.

Failure of delivery does not rewrite a successful ArtifactVersion or prior
ready Deployment. Automatic application rollback is not hidden inside DevOps;
an authorized user uses the PaaS rollback contract and the UI links that
separate Operation.

## Unified UX

**Delivery** appears in DevOps navigation only when this FEAT is installed. A
pipeline page can bind exactly one automatic target for its MAINLINE revision.
The UI resolves the target through the PaaS public API and clearly labels PaaS
as deployment authority.

The run timeline adds:

```text
... -> PUBLISH -> HANDOFF -> PLACE/AVAILABLE/APPLY/CONFIRM
```

PaaS sub-stages are read-only projections linked to the authoritative
Application PaaS Operation and Deployment pages. The detail view keeps exact
source commit, PipelineRevision, ArtifactVersion digest, DeliveryAttempt, IAM
decision, PaaS ApplicationRevision, Operation, Deployment generation, and
Audit correlations visible together.

The Delivery list shows target application/component, immutable digest,
handoff time, current PaaS observation, and terminal outcome. It does not show
or edit execution targets, credentials, manifests, secret values, Compose
projects, or provider-native state. Stale PaaS observations are timestamped
and never rendered as current success.

## Incremental acceptance

### Gate A: contracts and authority

1. Strict Go/OpenAPI contracts cover DeliveryTarget, DeliveryAttempt, the
   typed PaaS release command/receipt, observation, cursors, and safe problems;
   tenant fields, mutable tags, provider data, configuration, secrets,
   placement, commands, and unknown input fail closed.
2. IAM/Audit closed catalogs prove only the DevOps service may request the
   exact action and only for its tenant/target binding. Revocation, wrong
   service purpose, user-token substitution, cross-tenant ID, and unavailable
   IAM fail closed.
3. Domain/database tests prove immutable artifact-to-target binding,
   optimistic target conflict, deterministic handoff equality/conflict,
   lease/fence, observe-before-retry, exact terminal correlation, cancellation,
   and no cross-schema access.
4. Architecture tests prove DevOps imports only the PaaS public client
   contract; PaaS imports no DevOps package and neither product constructs the
   other's adapters or repositories.

### Gate B: real cross-product delivery

1. Real IAM, Audit, DevOps, PaaS API/worker, PostgreSQL roles, OCI registry,
   artifact-availability adapter, and Compose executor complete one exact
   ArtifactVersion-to-ready-Deployment journey over HTTP.
2. The PaaS adapter transfers/verifies the exact digest to the selected runtime
   without giving registry credentials to DevOps/build code, then Compose
   applies only the PaaS-owned generation with pull/build disabled.
3. Lost handoff response, duplicate/changing request, stale target version,
   registry outage, digest/platform mismatch, transfer uncertainty, PaaS
   restart, worker death, stale fence, failed readiness, cancellation, and
   service-credential revocation satisfy fail-closed reconciliation.
4. Database and network attacks prove no cross-product table access, direct
   runtime mutation, credential reuse, cross-tenant artifact, or competing
   DevOps/PaaS deployment authority.

### Gate C: UI and offline lifecycle

1. Through APISIX and the platform UI, an authorized user binds a target,
   activates the revision, triggers mainline, and follows source, run, artifact,
   handoff, PaaS Operation, and Deployment generation to readiness. Viewer,
   tenant, stale, failure, retry, cancellation, mobile, keyboard, and
   accessibility cases pass.
2. A clean network-disabled signed release uses local source and OCI fixtures
   to execute the entire flow without pull, online build, package manager, or
   hidden provider access. The existing standalone PaaS deployment path also
   remains accepted.
3. Restart, backup, upgrade, failed-candidate rollback, explicit rollback,
   recovery, and support evidence preserve cross-product identity and never
   claim delivery success for mismatched release, digest, Operation, or
   generation.

Common generation-drift, schema, architecture, unit, vet, race, repeated,
real-runtime, cross-platform build, Markdown-link, donor-dependency,
tenant-authority, vulnerability, license, and `git diff --check` gates pass
on the same committed worktree.

## Deferred

Manual promotion, environments, approval/release forms, deployment windows,
canary/blue-green strategies, multi-target fan-out, automatic rollback,
externally managed deployments, direct Kubernetes/host/cloud actions, and
provider-owned deployment truth remain outside this FEAT.

Product authority is owned by
[ADR-0002](../architecture/ADR-0002-product-boundary.md); product-reference
evidence remains in the
[FEAT-007 adoption review](../adoption/FEAT-007-repository-delivery.md).
