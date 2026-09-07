# FEAT-011: CODING connected execution provider

- Status: Proposed; product UX and boundary complete; implementation requires
  a customer-authorized CODING contract fixture
- Target product: Matrix DevOps post-v0.1 provider
- Contract: `devops.matrix.xiak.com/v1`
- Target design date: 2026-09-07
- Depends on: [FEAT-009 mainline OCI publication](FEAT-009-mainline-oci-publication.md)

## Outcome

Allow an organization with an existing, separately licensed CODING SaaS or
private installation to select **CODING Connected** for an immutable pipeline
revision while retaining the same Matrix repository, trigger, run, artifact,
IAM, Audit, and optional PaaS delivery experience.

Matrix triggers one pre-bound CODING build plan for an exact commit, observes
and cancels it by stable external identity, verifies the expected immutable OCI
artifact and bounded provenance, and normalizes the result into the existing
PipelineRun. Matrix Native remains available and is the default.

This FEAT is a connector, not a CODING redistribution, reseller entitlement,
managed CODING service, Jenkins compatibility promise, remote administration
console, or permission for CODING to mutate Matrix PaaS state.

## Qualification gate

No implementation is accepted from public documentation alone. Before Gate A
code, one exact customer-authorized CODING edition and version must prove a
supported contract for:

- connection authentication, least-privilege credential rotation, revocation,
  and rate limits;
- triggering one allowlisted plan for an exact repository and commit without
  arbitrary launch parameters;
- stable run identity, get/status/log, terminal result, cancel, retry/replay,
  webhook/callback authenticity, and outage behavior;
- immutable OCI artifact identity, digest/provenance retrieval, and retention;
- documented lifecycle/support dates for the selected SaaS or private edition.

The probe records only contract behavior and safe schemas. It does not copy
CODING UI, proprietary implementation, Jenkins plugins, CIFile/Jenkinsfile
syntax, binaries, agents, images, or internal APIs. If any required behavior
cannot be supported, activation fails and the provider remains unavailable;
Matrix does not weaken its public contract to fit it.

## Boundary and resource extension

`ExecutionConnection` is a tenant-bound, versioned connection with closed
kind `CODING`, exact endpoint identity, edition/version observation, health,
lifecycle state, capabilities, and secret references. It stores no plaintext
credential, provider project payload, Jenkins credential, agent secret, or
native error.

`ExecutionBinding` binds one Matrix Pipeline to one stable CODING organization/
project and allowlisted build-plan identity. Activation resolves the binding,
capabilities, expected repository, artifact output, and connection version into
the immutable PipelineRevision. Provider project/plan names are display values
only.

The revision's execution profile is exactly one of:

| Profile | Authority |
| --- | --- |
| `MATRIX_NATIVE` | Matrix coordinates its isolated BuildExecutor and separate ArtifactPublisher. |
| `CODING_CONNECTED` | Matrix coordinates a qualified CODING adapter and verifies its output under the same run/artifact invariants. |

Changing profile, connection, plan, capability version, expected output, or
credential policy requires a new PipelineRevision. A run never falls back from
CODING to native execution or from native to CODING after admission.

## Coordination semantics

1. Matrix independently admits the normalized source event, freezes the exact
   commit and PipelineRevision, stores PipelineRun plus Audit intent, and only
   then invokes CODING.
2. The adapter accepts a closed request containing deterministic Matrix command
   identity, exact qualified connection/binding, exact commit, deadline, and
   trace correlation. It cannot accept caller-supplied parameters, script,
   credential, environment, worker label, Kubernetes object, deploy action, or
   target.
3. The bound CODING plan is configured so Matrix is the only trigger for this
   profile. A provider-native automatic trigger that could race or produce an
   uncorrelated run makes the binding unhealthy.
4. Response loss is reconciled by deterministic correlation before another
   trigger. A provider run is accepted only when repository, commit, plan,
   connection, and command identity all match.
5. Matrix maps provider state into the existing closed PipelineRun stages and
   failure classes. Native payloads/errors remain inside the adapter. Bounded
   sanitized log chunks may be projected; detailed native views use an
   authorized link.
6. Success requires the exact expected OCI digest and provenance correlation.
   Missing/mismatched output, mutable tags, prior/default artifacts, ambiguous
   runs, or unverifiable evidence fail closed.
7. Cancellation requests provider cancellation and observes the stable run.
   Timeout never proves cancellation or absence. Bounded uncertainty becomes
   `MANUAL_INTERVENTION`.
8. A later FEAT-010 handoff uses the verified Matrix ArtifactVersion and public
   PaaS API. CODING never receives a PaaS credential or deploys a
   Matrix-authoritative application.

## Product experience

**Connections** appears in DevOps navigation when a connected-provider feature
is installed. The connection flow collects endpoint and secret references,
then performs server-side qualification. It displays normalized provider kind,
edition/version, health, capabilities, credential state, last successful
probe, rate-limit state, and lifecycle/support warning.

Pipeline draft offers **Matrix Native** and **CODING Connected** only when each
profile is ready and compatible. Activation presents the selected immutable
provider, plan display identity, artifact contract, and revision change.

Run lists and details retain the same Matrix layout, status, source identities,
timeline, ArtifactVersion, Audit, and PaaS correlations. A provider badge and
safe external-run link explain where execution occurred. Switching provider
does not create a second resource vocabulary or hide Matrix evidence.

Unavailable, unauthorized, revoked, rate-limited, incompatible, lifecycle
warning, callback stale, ambiguous run, artifact mismatch, and external-link
denied states have explicit UI treatments. Public CODING service retirement or
lost customer entitlement is visible on connection and activation screens;
existing Matrix artifacts and Audit history remain readable.

## Security and lifecycle

- Connection and callback credentials are distinct, least-privilege,
  tenant-bound references resolved only inside the adapter. Rotation and
  revocation affect the next call.
- Endpoint admission uses an installation allowlist, TLS trust policy, DNS/IP
  revalidation, redirect rejection, request/response bounds, deadlines, and
  SSRF protection.
- Callbacks require provider-supported authenticity plus stable external and
  Matrix correlation. They cannot select tenant, pipeline, revision, commit,
  artifact, outcome, or PaaS target.
- Matrix quotas bound concurrent external runs, trigger/cancel/status/log
  calls, callback rate, stored logs, and reconciliation duration. Provider
  retries cannot bypass them.
- Native credentials, parameters, logs, errors, URLs with tokens, Jenkins
  objects, agents, and infrastructure never enter public API, Audit, UI cache,
  or support evidence.
- Disabling/removing a connection prevents new activation/runs but preserves
  immutable historical Matrix metadata. In-flight runs reconcile under an
  explicit drain or manual-intervention policy; they are not silently moved to
  native execution.

## Incremental acceptance

### Gate A: qualified contract and adapter conformance

1. The exact supported CODING edition/version and commercial authority are
   recorded with an executed safe contract probe. Unsupported or undocumented
   endpoints are absent from implementation.
2. Strict Go/OpenAPI provider-neutral contracts cover connection, binding,
   capability/lifecycle state, immutable profile selection, normalized
   execution/artifact results, cursors, and safe problems. No native schema is
   exported.
3. A strict adapter conformance suite proves deterministic trigger,
   get/observe, cancel, callback verification, log bounds, artifact
   verification, rotation/revocation, rate limit, timeout, equality/conflict,
   and normalized failures.
4. Architecture, dependency, license, and artifact scans prove no CODING or
   Jenkins binary/package/image/plugin/source is copied or added as a
   build/runtime dependency.

### Gate B: real connected execution

1. Against the exact authorized CODING fixture, Matrix triggers one bound plan
   for an exact change and mainline commit, observes one stable external run,
   reports normalized state, and records the exact verified ArtifactVersion.
2. Lost responses, duplicate trigger/callback, changed correlation, automatic-
   trigger race, stale callback, cancel uncertainty, provider restart/outage,
   rate limit, credential rotation/revocation, artifact mismatch, prior/default
   artifact, and retention expiry pass fail-closed reconciliation tests.
3. Tenant, network, and credential attacks prove another organization cannot
   select the connection/plan/run/artifact, arbitrary parameters cannot be
   launched, and CODING cannot reach PaaS or Matrix authority credentials.
4. The same pipeline recreated with Matrix Native proves equivalent normalized
   identities and evidence without claiming byte-identical logs or
   provider-specific stages.

### Gate C: UI and release lifecycle

1. Through APISIX and the platform UI, an authorized user creates, qualifies,
   rotates, disables, and inspects a connection; activates a connected
   revision; and follows its run/artifact/Audit evidence. Role, tenant, empty,
   failure, lifecycle, mobile, keyboard, and accessibility cases pass.
2. Installation declares the connector independently from Matrix Native.
   Upgrade, failed-candidate rollback, explicit rollback, backup, recovery,
   restart, and support evidence preserve exact provider configuration/state
   without leaking credentials or falsely reporting readiness.
3. Loss or retirement of the CODING service prevents new connected activation
   and runs, keeps Matrix Native selectable, and preserves historical Matrix
   evidence and PaaS independence.

Common generation-drift, schema, architecture, unit, vet, race, repeated,
real-provider, cross-platform build, Markdown-link, dependency, vulnerability,
license, tenant-authority, secret-leakage, and `git diff --check` gates pass
on the same committed worktree.

## Deferred

Bundled/private CODING distribution, automated purchase/entitlement, generic
Jenkins connection, CODING project/repository mirroring, native pipeline
editing, plugin administration, agent/node-pool administration, arbitrary
launch parameters, non-OCI artifacts, direct CODING deployment, and automatic
cross-provider failover remain outside this FEAT.

Commercial and product-reference evidence is owned by the
[FEAT-007 adoption review](../adoption/FEAT-007-repository-delivery.md).
