# FEAT-009: Mainline OCI publication

- Status: Proposed; UX and architecture complete; implementation not started
- Target product: Matrix DevOps v0.1
- Contract: `devops.matrix.xiak.com/v1`
- Target design date: 2026-09-07
- Depends on: [FEAT-007 repository change validation](FEAT-007-repository-delivery.md)

## Outcome

Extend the proven DevOps control plane with one mainline path: a verified push
to the bound default branch selects an immutable pipeline revision, verifies
and builds the exact source into an OCI layout, publishes it through a
credential-isolated adapter, verifies the remote immutable digest, and exposes
one traceable ArtifactVersion in the Matrix UI.

This slice ends at a verified registry artifact. It does not deploy an
application, approve a release, promote between environments, scan arbitrary
package ecosystems, host a generic artifact repository, or expose registry
credentials to build code.

## Boundary and ownership

| Concern | Owner |
| --- | --- |
| MAINLINE event/run policy, artifact destination binding, immutable ArtifactVersion, provenance correlation, and UI projection | `delivery` |
| OCI image construction without publisher credentials | `BuildExecutor` adapter |
| Registry authentication, push, digest observation, and receipt | `ArtifactPublisher` adapter |
| OCI blob/manifest storage and retention | Connected OCI registry |
| Authorization decisions and immutable facts | `iam` and `audit` |
| Runtime artifact availability and deployment | `apphosting`; unused by this slice |

Delivery stores metadata and evidence, not OCI layers. It cannot read registry
storage directly, issue a pull credential to untrusted build code, or mutate
Application PaaS state.

## Resource and pipeline extension

| Resource | Mutability | Purpose |
| --- | --- | --- |
| `ArtifactDestination` | Spec/status versioned | Tenant-bound OCI registry/repository identity, health, retention class, and publisher secret reference. |
| `ArtifactVersion` | Immutable | Exact repository locator, OCI manifest/index digest, source snapshot digest, commit, PipelineRevision, PipelineRun, builder identity, build-profile digest, bounded provenance digest, publish receipt, and creation time. |

Artifact tags are display/search aliases only. They are never accepted as
ArtifactVersion identity or as a later deployment input. Equal publication of
the same expected canonical content returns the existing version; a different
digest or evidence under the same deterministic command conflicts.

An activated MAINLINE revision contains a trusted, closed workflow:

```text
RECEIVE -> FETCH -> VERIFY -> BUILD -> PUBLISH -> CONFIRM
```

The build stage receives an exact content-addressed source snapshot, a
digest-pinned builder profile, bounded non-secret build arguments, resource
limits, and an output contract for one OCI layout. It cannot push, load an
image into an application runtime, select a mutable base-image tag, request a
host socket, or return a provider-native object.

The publisher alone resolves a narrowly scoped write credential. It validates
the OCI layout, layer and configuration digests, media types, repository
boundary, maximum size/count, and expected command identity before upload.
After publication it reads the remote manifest by digest and proves byte/digest
equality before committing ArtifactVersion.

## Product experience

**Artifacts** appears in DevOps navigation only when this FEAT is installed.
The pipeline detail adds MAINLINE trigger and artifact destination without
changing CHANGE run behavior. A mainline run keeps exact commit, pipeline
revision, builder, destination, and digest visible across its stage timeline.

The artifact list is organized by DevOps project and repository, with safe
filters for pipeline, branch display value, commit, digest, and time. The
ArtifactVersion detail shows:

- immutable digest and copy action;
- exact source event/commit, source snapshot, PipelineRevision, and PipelineRun;
- builder and build-profile identities;
- normalized OCI platform/media metadata and bounded provenance verification;
- publisher receipt, Audit correlation, and registry observation time;
- an explicit **Not deployed** state until FEAT-010 creates a PaaS handoff.

Mutable registry tags, native registry errors, credentials, internal endpoints,
raw provenance documents, and arbitrary annotations are not rendered. Missing,
changed, or inaccessible remote content is a visible failed verification, not
silently replaced by a prior artifact or latest tag.

## Workflow and failure behavior

1. MAINLINE admission verifies the provider push and proves its branch is the
   RepositoryBinding's current trusted default branch before selecting the
   exact commit and active revision.
2. Each external effect uses deterministic intent, lease/fence, bounded
   deadline, receipt, and observe-before-retry behavior. Build retry starts a
   fresh isolated environment; publish retry first observes the expected
   remote digest.
3. ArtifactVersion commits in the same tenant transaction as the successful
   confirmation transition and sanitized Audit outbox fact. A run cannot reach
   `SUCCEEDED` without a verified remote digest.
4. Cancellation stops future stages and requests executor cancellation. A
   partially uploaded artifact remains unaccepted until confirmation; cleanup
   is registry policy, not proof of rollback.
5. Missing output, mutable base resolution, unexpected layer/media type,
   digest mismatch, changed receipt, unavailable registry, quota exhaustion,
   or unverifiable remote state fails closed or enters bounded reconciliation.
   No prior/default/latest artifact fallback exists.

## Security, quota, and retention

- Build and publisher identities, credentials, networks, and processes are
  separated. Registry credentials can write only the bound tenant repository
  and cannot list or mutate another destination.
- Egress permits only the activated dependency profile during build and the
  exact registry during publication. Redirects and DNS/endpoint changes are
  revalidated against installation policy.
- Per-tenant concurrent builds, CPU/memory/disk/time, input/output bytes,
  layer count, registry requests, stored metadata, and publication rate are
  bounded and observable.
- ArtifactVersion metadata is retained under one declared policy independent
  from registry garbage collection and ephemeral executor cleanup. Remote
  absence never deletes historical Audit or run evidence.
- UI/API/Audit/support surfaces redact credentials, build environment,
  native errors, raw manifests/provenance, internal endpoints, and absolute
  paths while retaining canonical digests and safe reason codes.

## Incremental acceptance

### Gate A: contract and domain

1. Strict Go/OpenAPI contracts and examples cover destinations, MAINLINE
   policy, build/publish results, ArtifactVersion, pages/cursors, and safe
   failures; unknown fields, mutable-only identity, unsafe media, oversize
   data, and provider-native payloads fail closed.
2. Domain tests prove default-branch admission, immutable binding, exact
   source/profile/output correlation, artifact equality/conflict, no fallback,
   state transitions, cancellation, reconciliation, quota, and retention.
3. PostgreSQL tests prove tenant-leading keys, forced isolation, separate
   API/worker roles, deterministic publication commands, current fencing,
   immutable ArtifactVersion rows, and no registry/PaaS cross-write.
4. Architecture and secret-flow tests prove build code cannot construct or
   receive an ArtifactPublisher, registry credential, PaaS client, host socket,
   or provider-native configuration.

### Gate B: real source-to-registry slice

1. A real local source-provider fixture emits a signed default-branch push;
   exact source is fetched and an isolated real builder produces one OCI layout
   from digest-pinned inputs.
2. A real pinned OCI registry accepts publication through the separate adapter.
   Matrix re-fetches by digest, records one immutable ArtifactVersion, and
   correlates source, run, builder, publication, and Audit evidence.
3. Registry outage, lost response, duplicate request, changed remote content,
   wrong repository, oversize/layer attack, mutable base, cancellation, worker
   death, stale fence, and credential revocation pass fail-closed and
   observe-before-retry tests.
4. Malicious build code cannot obtain the publisher credential, reach the
   registry write endpoint directly, load an application runtime, escape the
   executor, or forge accepted artifact evidence.

### Gate C: UI and offline lifecycle

1. Through APISIX and the real platform UI, an authorized user activates a
   MAINLINE revision, observes all six stages, opens the exact
   ArtifactVersion, and follows source/run/Audit correlations. Tenant, role,
   empty/loading/error, mobile, keyboard, and accessibility cases pass.
2. A clean network-disabled release starts the declared builder integration
   and local pinned registry fixture from included artifacts, completes
   source-to-registry publication, and performs no pull, online build, or
   package-manager fetch.
3. Restart, backup, upgrade, failed-candidate rollback, explicit rollback,
   recovery, and support evidence preserve the correct immutable metadata and
   never relabel an unavailable or mismatched registry artifact as verified.

Common generation-drift, schema, architecture, unit, vet, race, repeated,
real-runtime, cross-platform build, Markdown-link, donor-dependency,
tenant-authority, vulnerability, license, and `git diff --check` gates pass
on the same committed worktree.

## Deferred

Application deployment, release approvals, environments, promotion, canary or
blue/green strategy, arbitrary package formats, registry administration,
artifact mutation/deletion UI, vulnerability-policy engine, keyless signing,
SBOM policy, persistent caches, multiple outputs, and CODING artifacts remain
outside this FEAT.

Product boundaries are owned by
[ADR-0002](../architecture/ADR-0002-product-boundary.md); donor and CODING
product-reference evidence remains in the
[FEAT-007 adoption review](../adoption/FEAT-007-repository-delivery.md).
