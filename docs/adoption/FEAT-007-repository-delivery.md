# FEAT-007 adoption review: Kubernetes Prow

- Status: Complete for architecture analysis; no implementation accepted
- Target: [`FEAT-007 Repository-triggered CI/CD delivery`](../features/FEAT-007-repository-delivery.md)
- Review date: 2026-09-07
- Direct donor dependency allowed: No

## Verdict

Use Prow as a strong `REFERENCE` for an event-driven CI control plane and
`ADAPT` a small set of behaviors. Do not install Prow as Matrix's DevOps
subsystem, import `sigs.k8s.io/prow`, copy its component topology, or expose
ProwJob, Kubernetes PodSpec, Tekton, GitHub, GCS, or cluster credentials in a
Matrix contract.

Prow is primarily a Kubernetes-native job and source-review automation system.
Its core creates jobs from source events, runs arbitrary Kubernetes/Tekton job
specifications, reports results, automates merges, and removes old resources.
It can perform delivery only because a trusted postsubmit job may carry
deployment credentials and run provider-native commands. It does not own the
immutable OCI publication, provenance, promotion, Matrix Deployment, or
application-runtime verification required by the FEAT-007 target.

The decision is therefore:

- `GO`: borrow the event-to-run control-loop decomposition, exact source-ref
  identity, reconcile-before-create behavior, separated status reporting,
  bounded concurrency concepts, trust-boundary tests, and cleanup concerns.
- `NO-GO`: reuse Prow binaries/packages, make Kubernetes a FEAT-007 prerequisite,
  accept arbitrary PodSpecs/pipelines, mount publisher or deployment
  credentials into build code, or treat a successful job exit as CD truth.

## Fixed baseline

| Donor | Commit | License | Inspection policy |
| --- | --- | --- | --- |
| `kubernetes-sigs/prow` | `1a000594c40919068dd43a5704f279f273135d18` | Apache-2.0 | Read-only Git object inspection at the fixed commit; no Matrix build/runtime dependency and no worktree edits. |

The donor worktree was clean on `main` and the fixed commit was authored on
2026-09-04. Prow's own overview states that its Go packages are intended for
Prow and provide no backward-compatibility promise. That reinforces the
architectural rejection of a direct package dependency even though the source
license permits reuse subject to its terms.

## Adoption decisions

Sizes below describe the inspected text/source slice at the fixed commit, not
a proposed Matrix implementation size.

| Slice at fixed commit | Size | Decision | Rationale |
| --- | ---: | --- | --- |
| `site/content/en/docs/overview/architecture.md`, `jobs.md`, and `life-of-a-prow-job.md` | 3 documents | `REFERENCE` | Preserve the explicit event → job → scheduling → execution → reporting → cleanup flow and the separation of service and build execution concerns. Prow's microservice count, Kubernetes CRDs, clusters, and component names are deployment choices, not Matrix domain boundaries. |
| `pkg/github/webhooks.go`, `hmac.go`, `pkg/hook/server.go`, and tests | 5 files / 1,188 lines | `ADAPT` | Preserve SHA-256 HMAC validation, multiple repository-scoped secrets, required event and delivery identities, strict media type, and provider-event normalization. Replace payload-selected global/org fallback, unbounded `io.ReadAll`, absent durable replay admission, and acknowledge-before-durable-processing with an endpoint-bound connection, bounded body, provider-supported signed time checks, canonical digest, and one transaction before returning success. |
| `pkg/plugins/trigger`, `pkg/pjutil/{pjutil,trigger,filter,abort}.go` | 12 files / 6,326 lines | `ADAPT` | Preserve CHANGE versus MAINLINE trigger classes, exact base/head commit identities, deleted-branch and draft filtering, changed-path/branch policy, superseded-run cancellation, and trust-oriented negative tests. Replace GitHub membership/labels, regex chat-ops, random job identity, provider object models, and config-load fallback with IAM authorization, immutable PipelineRevision, deterministic event/run identity, and fail-closed policy. |
| `pkg/apis/prowjobs/v1/types.go`, `pkg/config/jobs.go`, in-repo configuration, and their tests | 6 files / 5,588 lines | `REFERENCE` for resource shape; `REJECT` as a contract | Desired run input separated from observed status, exact base/pull SHAs, explicit job type/state, deadlines, cluster choice, reporting, and concurrency fields are useful design evidence. ProwJob directly embeds Kubernetes `PodSpec`, Tekton `PipelineRunSpec`, namespace/cluster, secret names, service accounts, arbitrary annotations, provider URLs, and mutable configuration defaults. FEAT-007 instead uses provider-neutral immutable input and a closed build profile. |
| `pkg/config/inrepoconfig.go` and `.prow.yaml` behavior | Included above | `REFERENCE` for config verification; `REJECT` for the first slice | Versioning job policy with source is convenient and its validation/duplicate checks are useful test categories. Prow builds an in-repo configuration after combining base and head commits; allowing a change under test to alter runner, secret, cluster, or deployment policy violates the first Matrix trust boundary. A trusted immutable PipelineRevision remains authoritative. |
| `cmd/prow-controller-manager`, `pkg/plank`, and `pkg/scheduler` | 16 files / 5,832 lines | `ADAPT` for reconciliation; `REJECT` as an implementation | Preserve event-driven reconciliation, observe an existing deterministic execution object before creation, state-specific deadlines, cancellation, bounded revival, oldest-first concurrency, and separate scheduling. Reimplement with PostgreSQL intent/lease/fencing and a BuildExecutor receipt. Prow's safety relies on Kubernetes object identity/cache semantics; its external scheduler falls back to the requested cluster and its failover maps only cluster names, which cannot enforce Matrix capacity, tenant fairness, or isolation guarantees. |
| `cmd/crier`, `pkg/crier`, and `pkg/github/report` | 30 files / 11,058 lines | `ADAPT` | Preserve a reporter port, `ShouldReport`, state-sensitive delivery, independent workers, provider rate-limit handling, and recorded last-reported state. Matrix requires durable command intent and receipt, equal replay/changed conflict, bounded retry/dead letter, and IAM/Audit correlation; a map of prior states patched after the external call is not its idempotency authority. Only the first source-provider adapter enters the slice. |
| `clonerefs`, `entrypoint`, `initupload`, `sidecar`, and `pkg/pod-utils` | 118 files / 15,016 text lines | `REFERENCE` | Stage separation, exact base/head checkout, process deadlines/grace, captured exit status, bounded metadata, and log/artifact finalization are valuable runner test categories. The implementations decorate Kubernetes Pods, rewrite entrypoints, pass broad job JSON/environment data, mount source/storage secrets, and rely on GCS/S3 conventions. Secret censoring after build code received a secret is defense in depth, not Matrix's primary boundary; fetch, publisher, IAM, and deployment credentials must never enter build code. |
| Separate service/build/trusted-cluster guidance in `scaling.md`, `getting-started-deploy.md`, and `more-prow.md` | 3 documents | `ADAPT` as a mandatory isolation gate | Prow explicitly warns that malicious change code may escape a container, steal cluster secrets, or attack control services, and recommends separating untrusted tests from trusted publish/deploy jobs and the service cluster. Matrix adopts the threat model, but not Kubernetes clusters as the public guarantee. FEAT-007 cannot run arbitrary build code on the current production Compose host under only `WORKLOAD` isolation. |
| `cmd/gangway` and `pkg/gangway` | 10 files / 3,273 text lines | `REFERENCE` | Create/get/list run operations and server-side job allowlists confirm a small northbound surface. Generated gRPC, Google auth, ProwJob fields, and job-name authorization are rejected; Matrix uses strict versioned HTTP contracts and IAM-derived tenant/action authority. |
| `cmd/deck` and `pkg/spyglass` | 172 files / 32,149 text lines | `REFERENCE` for UX; `REJECT` as code | Run history, status, log/artifact inspection, rerun, abort, and source-review links inform a later Matrix UI slice. The implementation is coupled to ProwJob, Kubernetes, GitHub membership/OAuth, GCS/TestGrid, and its own frontend. Matrix extends its existing PaaS UI and IAM boundary instead. |
| `cmd/sinker` and `cmd/horologium` | 6 files / 2,823 lines | `REFERENCE`; scheduled runs `REJECT` for the first slice | Explicit retention, resource cleanup, metrics, and preserving scheduling anchors are useful operational concerns. Deleting aged ProwJobs/Pods cannot define Matrix record retention, Audit integrity, or artifact policy. Periodic pipelines are explicitly deferred. |
| `cmd/tide` and `pkg/tide` | 20 files / 16,605 text lines | `REJECT` for FEAT-007 first slice | Batch retesting against a current base and merge eligibility are mature source-review capabilities, but merge queues and branch administration are separate business policy and greatly expand provider permissions. Matrix first reports checks and never merges source. |
| `pkg/plugins` suite | 154 files / 65,096 text lines | `REJECT` | Approval, labels, ownership, issue management, chat-ops, and third-party automation are a contributor-governance product. Importing them would turn the delivery slice into a GitHub bot platform and duplicate IAM policy. Selected threat cases may be cited by later FEATs without retaining the suite. |
| `cmd/pipeline`, `pkg/pipeline`, and Prow's Tekton agent | 39 files / 5,141 lines | `REJECT` | This is a Kubernetes/Tekton execution adapter and generated client closure, not a provider-neutral Matrix pipeline domain. FEAT-007's first workflow is fixed and its BuildExecutor cannot accept a caller-provided PipelineRun. |
| `test/integration` | 91 files / 65,699 text lines | `REFERENCE` | Fake GitHub/Gerrit/Git/PubSub services plus Kind-based component tests show useful deterministic integration techniques. Matrix must add its own strict fake contracts and real source-provider, registry, PostgreSQL, isolated-builder, and PaaS vertical gates; Prow's integration suite is neither copied nor accepted as Matrix evidence. |
| Entire Prow repository and dependency closure | Large Kubernetes/cloud/provider closure | `REJECT` | The module directly depends on Kubernetes API machinery/client/controller-runtime, Tekton, several cloud SDKs, GitHub/Gerrit/Jira/Slack integrations, GCS/S3, generated clients, and Go packages with no compatibility promise. It conflicts with the small offline Matrix release, current dependency rules, and donor-independence requirement. |

There is no package-level `REUSE` decision. The useful slices all require
Matrix authority, state, security, error, storage, and runtime semantics, so
copying them unchanged would be misleading even where the Apache-2.0 license
would allow it.

## Material gaps exposed by the comparison

1. **Durable admission and replay.** In the inspected Hook path, a valid event
   is acknowledged before handler completion. The delivery GUID becomes a
   label, while each ProwJob receives a newly generated UUID; no durable
   `(connection, delivery, payload digest)` equality/conflict boundary is
   present in this path. Matrix must commit SourceEvent, DeliveryRun, and Audit
   outbox before returning success.
2. **Execution isolation.** Prow gains its isolation from separately operated
   Kubernetes build clusters. Matrix v0.1 currently proves only application
   `WORKLOAD` isolation on one Docker Engine. A separately schedulable runner
   that cannot reach the host, control plane, or credentials is an acceptance
   prerequisite, not a later hardening task.
3. **Artifact and supply-chain authority.** ProwJobs can upload arbitrary
   artifacts, but ProwJob status contains no accepted OCI digest/provenance or
   publication-to-deployment invariant. Matrix needs a credential-isolated
   publisher and a verifiable source → pipeline → builder → OCI digest chain.
   FEAT-004 additionally resolves only images already present on the target;
   apphosting must own a new digest-preserving availability/import path before
   FEAT-007 can complete CD.
4. **CD truth.** Prow documents deployment as a trusted postsubmit job running
   `kubectl apply` with credentials. Matrix must instead call the existing
   apphosting API, record its Operation and Deployment generation, and wait for
   that authority's verified outcome. Delivery cannot load or pull images on a
   runtime host as an undocumented shortcut.
5. **Tenant and security authority.** GitHub organizations/memberships, labels,
   Kubernetes namespaces/service accounts, and arbitrary secret names cannot
   substitute for Matrix IAM decisions, forced PostgreSQL tenant isolation,
   exact secret references, or unified Audit facts.
6. **Failure semantics.** Prow's compact job states and Kubernetes object
   reconciliation are suitable for its substrate. External source, build,
   registry, reporting, and PaaS effects require deterministic commands,
   receipts, leases/fences, explicit `RECONCILING`, and bounded
   `MANUAL_INTERVENTION` in Matrix.
7. **Offline footprint.** Prow can be self-hosted, but its normal topology and
   documented paths assume Kubernetes plus provider/cloud integrations. That
   is not evidence that the accepted Matrix offline Compose release can carry
   it or safely execute builds.

## Concept mapping

| Prow concept | Matrix target owner | Treatment |
| --- | --- | --- |
| Hook plus trigger plugin | `delivery` webhook use case + source-provider adapter | Normalize one closed provider event, authenticate it, persist before acknowledgement, select exact PipelineRevision. |
| Presubmit / postsubmit | `CHANGE` / `MAINLINE` run mode | Keep the trust distinction; only MAINLINE may request delivery. |
| ProwJob spec/status | `DeliveryRun` immutable input and versioned status | Preserve exact source/run identity; remove all Kubernetes/provider-native fields. |
| Scheduler + Plank/controller-manager | `delivery` worker + build placement + `BuildExecutor` | Use durable intent, lease/fence, receipt, observation, quota, and exact isolation rather than Kubernetes cache semantics. |
| Pod utilities | Source snapshotter, isolated process wrapper, log collector, artifact handoff | Reimplement at the runner boundary with least privilege and no publisher/deployer credentials in build code. |
| Crier | `CheckReporter` outbox worker | One supported provider, deterministic report command, retry/reconcile, and recorded receipt. |
| Deck / Spyglass | Existing Matrix PaaS UI | Later views over Matrix APIs and log authorization; no Prow frontend reuse. |
| Sinker | Delivery retention/cleanup policy | Clean ephemeral runner state independently from immutable Audit and retained run metadata. |
| Tide / plugins / periodic jobs | Deferred FEATs | Do not enter the first CI-to-CD vertical slice. |

## Admission recommendation

FEAT-007 is technically viable and Prow is a valuable donor, but implementation
should not begin by porting Prow. Before Gate A implementation is accepted, the
product must select one real source provider and prove an implementation plan
for a separate untrusted build boundary, an OCI registry/publisher, approved
dependency egress, apphosting-owned digest distribution, IAM/Audit contract
extensions, and log retention. Those choices determine the first real adapters;
they do not change the provider-neutral delivery/apphosting boundary.

No Prow source, generated file, API type, configuration, binary, image,
manifest, or dependency is copied or referenced by Matrix build/runtime code.
