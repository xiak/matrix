# FEAT-007 adoption review: Prow and Tencent CODING DevOps

- Status: Complete for donor and product-reference analysis; no implementation
  accepted
- Target: [`FEAT-007 Repository-triggered CI/CD delivery`](../features/FEAT-007-repository-delivery.md)
- Review date: 2026-09-07
- Direct donor dependency allowed: No

## Verdict

Use the two references for different purposes:

- Prow is a strong `REFERENCE` for an event-driven CI control plane and a
  source of selected `ADAPT` behaviors.
- Tencent CODING DevOps is a `REFERENCE` for the end-to-end product journey
  across source triggers, CI runs, an artifact repository, application-centric
  CD, release visibility, permissions, and operations. Its public product
  documentation is not a source-code donor or a compatibility contract.

Do not install Prow as Matrix's DevOps subsystem, import
`sigs.k8s.io/prow`, copy its component topology, or expose ProwJob, Kubernetes
PodSpec, Tekton, GitHub, GCS, or cluster credentials in a Matrix contract. Do
not clone CODING's Jenkins/CIFile DSL, Spinnaker-derived deployment model,
provider-native cloud accounts, generic credential injection, or breadth of
products into the first Matrix slice.

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
  bounded concurrency concepts, trust-boundary tests, cleanup concerns, and
  CODING's explicit source → build → artifact → application delivery journey.
- `NO-GO`: reuse Prow binaries/packages, make Kubernetes a FEAT-007 prerequisite,
  accept arbitrary PodSpecs/pipelines, mount publisher or deployment
  credentials into build code, treat a successful job exit as CD truth, use a
  previous/default artifact after a match failure, or build a general DevOps
  suite before the first vertical slice is proven.

## Fixed baseline

| Donor | Commit | License | Inspection policy |
| --- | --- | --- | --- |
| `kubernetes-sigs/prow` | `1a000594c40919068dd43a5704f279f273135d18` | Apache-2.0 | Read-only Git object inspection at the fixed commit; no Matrix build/runtime dependency and no worktree edits. |

The donor worktree was clean on `main` and the fixed commit was authored on
2026-09-04. Prow's own overview states that its Go packages are intended for
Prow and provide no backward-compatibility promise. That reinforces the
architectural rejection of a direct package dependency even though the source
license permits reuse subject to its terms.

## Product-reference baseline

Tencent CODING is reviewed only through its official public documentation as
observed on 2026-09-07. The pages are mutable, span multiple generations of
CODING's CI engines, and provide neither a fixed source commit nor a stable API
promise. They support product and threat-model decisions only; every material
behavior must be reverified before a future implementation slice depends on
it.

| Official CODING documentation | Evidence used |
| --- | --- |
| [Classic CI overview](https://coding.net/help/docs/ci/intro.html), [classic CI quick start](https://coding.net/help/docs/devops/ci/start.html), and [custom QCI nodes](https://coding.net/help/docs/qci/infra/customize-node.html) | Classic CODING CI explicitly builds on Jenkins, declares Jenkins 2.293 compatibility, authors Jenkinsfile, and distributes a `2.293-cci` Jenkins WAR for custom nodes. |
| [Cloud-Native Build overview](https://coding.net/help/docs/cnb/intro.html) and [trusted built-in tasks](https://coding.net/help/docs/cnb/pipelines/internal-steps.html) | A later product line presents a Docker-native `.coding-ci.yml` runner model and separates trusted master-side tasks from user runner space. |
| [CI pipeline creation](https://coding.net/help/docs/qci/intro/quick-start.html) | A pipeline may be UI-hosted or repository YAML; the UI-hosted form is described as fixed against third-party changes. |
| [CI trigger rules](https://coding.net/help/docs/ci/configuration/trigger.html) | Push/MR/path/actor filters, API and scheduled triggers, and cancellation of superseded builds. |
| [Build node pools](https://coding.net/help/docs/ci/node/pool.html) | Schedulable node pools, per-plan authorization, node state, and self-hosted execution concerns. |
| [Credential management](https://coding.net/help/docs/admin/credential.html) | Configuration refers to credential IDs while selected execution environments resolve actual values. |
| [CD product model](https://coding.net/help/docs/cd/intro.html) and [application center](https://coding.net/help/docs/cd/console.html) | CI, artifact repositories, applications, deployment processes, cloud accounts, strategies, and operational views form a product chain. |
| [Deployment process configuration](https://coding.net/help/docs/cd/pipe/overview.html) | Triggered/manual execution, configuration revision history and locking, serial/parallel stages, cancellation, and rollback-oriented workflow. |
| [Artifact configuration](https://coding.net/help/docs/cd/pipe/artifacts.html) and [artifacts in processes](https://coding.net/help/docs/cd/pipe/artifacts/in-pipelines.html) | Expected-artifact matching and cross-stage/process propagation, including digest-shaped Docker references and fallback behavior. |
| [Manual confirmation](https://coding.net/help/docs/cd/pipe/stages/manual.html) | Named approvers, separate notification and approval roles, bounded waiting, and a future promotion gate. |
| [Security logs](https://coding.net/help/docs/admin/security-log.html) | Operator, repository, and artifact activity are visible as distinct audit categories. |

### CODING engine assessment

Calling classic CODING CI a productized or vendor-wrapped Jenkins is accurate,
but calling the whole CODING DevOps product a Jenkins skin is not:

1. The classic CI documentation says the service was optimized on top of
   Jenkins, declares compatibility with Jenkins 2.293, uses Groovy
   Jenkinsfile as its pipeline definition, and requires CODING's
   `jenkins.war` plus Jenkins home bundle on manually installed QCI nodes.
   The visual editor is therefore a product layer over a Jenkins execution
   model, while CODING adds hosted control-plane behavior such as project
   integration, triggers, credentials, node pools, logs, reports, and
   artifacts.
2. CODING CD is a different subsystem. Its public documentation describes an
   application-centric deployment product with Spinnaker-derived triggers,
   artifacts, and CloudDriver integration. Jenkins is not its deployment
   authority.
3. CODING Cloud-Native Build is documented as a separate Docker-native
   `.coding-ci.yml` pipeline/runner model with trusted master-side built-in
   tasks and isolated user runner space. The public pages do not establish its
   private implementation, so Matrix must not assume either Jenkins reuse or
   complete independence internally; its published contract is nevertheless
   materially different from classic Jenkins CI.

Matrix adopts the product lessons, not the engine. Jenkins is not admitted as
FEAT-007's control plane, domain model, pipeline language, credential system,
or default runner. A future Jenkins integration could only be evaluated as an
optional BuildExecutor adapter for an existing enterprise installation, with
the same closed request, isolation, receipt, provenance, and secret-boundary
conformance gates as any other executor.

## Prow adoption decisions

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

## Tencent CODING product-reference decisions

`REUSE` does not apply because no CODING source or distributable was inspected
or accepted. `ADAPT` below means re-express a product behavior under Matrix's
own contracts and implementation, not copy a proprietary API, UI, or schema.

| CODING product slice | Decision | Matrix treatment |
| --- | --- | --- |
| Code trigger → CI → artifact repository → application CD journey | `REFERENCE` | Keep one traceable journey and shared correlation from SourceEvent through DeliveryRun, OCI digest, apphosting Operation, and Deployment generation. Do not make source hosting, test management, project planning, or a full DevOps suite part of FEAT-007. |
| UI-hosted or repository-hosted pipeline definitions, configuration lock, and revision history | `ADAPT` selectively | Preserve a trusted draft/activate flow whose activation creates an immutable PipelineRevision. Repository-owned pipeline execution, arbitrary Jenkins/CIFile syntax, restoration that mutates an active revision, and a visual DAG editor remain outside the first slice. |
| Push/MR/path/actor trigger filters and superseded-run cancellation | `ADAPT` | The provider adapter normalizes one provider's event while trusted PipelineRevision policy selects CHANGE or MAINLINE. A branch or tag is resolved and frozen to an exact commit before admission; cancellation stops future work without assuming an external effect was absent. |
| Artifact repository and expected-artifact binding | `ADAPT` with a stricter invariant | Make the registry/publisher a first-class boundary and carry immutable digest plus provenance into apphosting. Reject CODING's documented previous/default-artifact fallback for Matrix: mismatch, missing digest, or unverifiable provenance fails closed. |
| Application-centric deployment, release form, manual confirmation, and promotion between environments | `REFERENCE`; promotion deferred | Preserve the separation between build completion and an application release decision. AppHosting remains owner of Application, Deployment, rollout and rollback. Production approval, release forms, environments, and promotion become later FEATs only after one automatic MAINLINE path is proven. |
| Flexible deployment stages, strategies, provider cloud accounts, Kubernetes/host actions, and Spinnaker-derived infrastructure | `REJECT` for FEAT-007 | These are mature product capabilities but cross the Matrix product boundary. Delivery submits a typed request to apphosting and cannot accept provider manifests, host scripts, kubeconfig, service-account credentials, or direct infrastructure mutations. |
| Managed and self-hosted build node pools | `REFERENCE` for scheduling and operations | Preserve explicit capacity, eligibility, health, drain, and run history concepts. Do not accept persistent workspace/cache, default access by all pipelines, root execution, or a registered agent as proof of hostile-build isolation; the Matrix BuildExecutor must pass its own security gates. |
| Credential IDs, project tokens, and runtime credential resolution | `ADAPT` only at adapter boundaries | Store references rather than plaintext and authorize every use. Source fetch, publisher, reporter, and deploy identities stay separate; generic credentials and secret-valued launch parameters are never made available to untrusted build steps. |
| Operation, repository, and artifact logs | `ADAPT` | Emit normalized, immutable Matrix Audit facts with tenant, subject, action, resource, command identity, and outcome. Search/export views are not the authority, and native payloads, command lines, credentials, or mutable provider text are not copied into Audit. |
| Jenkins-based classic CI/QCI, Cloud-Native Build, plugins, UI, APIs, schemas, and deployment implementation | `REJECT` | Public documentation spans multiple product generations and cannot establish a stable reusable contract. Matrix gains no CODING or Jenkins build/runtime dependency and copies no proprietary implementation or product vocabulary into its public API. |

## Material gaps exposed by both comparisons

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
   artifacts, while CODING demonstrates why an artifact repository and
   expected-artifact binding are first-class product concepts. Neither is the
   Matrix invariant: ProwJob status contains no accepted OCI
   digest/provenance chain, and CODING documents fallback to a prior/default
   artifact when matching fails. Matrix needs a credential-isolated publisher,
   a verifiable source → pipeline → builder → OCI digest chain, and fail-closed
   binding. FEAT-004 additionally resolves only images already present on the
   target; apphosting must own a new digest-preserving availability/import path
   before FEAT-007 can complete CD.
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
   it or safely execute builds. CODING's managed service and provider-native
   integrations likewise provide product evidence, not an offline Matrix
   runtime design.
8. **Product breadth.** CODING shows the value of a coherent user journey,
   revision history, approvals, environments, deployment strategies, logs,
   and operational views. Implementing that breadth at once would violate the
   first-slice target. Matrix first proves one source provider, two trigger
   modes, one isolated builder, one OCI publisher, and one apphosting-owned
   deployment path; later FEATs may grow the product without weakening those
   identities.

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

## CODING concept mapping

| CODING concept | Matrix target owner | Treatment |
| --- | --- | --- |
| Project/code repository | External provider plus `delivery` RepositoryBinding | Matrix binds one provider repository; source hosting and project planning are not in scope. |
| CI pipeline/build plan | `delivery` Pipeline, immutable PipelineRevision, and DeliveryRun | Retain stable identity, immutable activated policy, history, and run visibility; keep the first execution graph closed. |
| Build node pool | BuildExecutor adapter and installation-owned capacity | Schedule only eligible isolated capacity with tenant quota, health, drain, and hard security guarantees. |
| Artifact repository / expected artifact | ArtifactPublisher plus apphosting-owned artifact availability | Publish and bind by exact digest and provenance; never select previous/default/latest on failure. |
| CD application | `apphosting` Application | Reuse the product-level application perspective without creating a second application model in `delivery`. |
| Deployment process / release form | DeliveryRun handoff to apphosting Operation | The first MAINLINE policy is automatic and fixed; approval, promotion, and release forms are later policies. |
| Cloud account / infrastructure | `apphosting` ExecutionTarget and its adapters | Delivery cannot see or use provider credentials or mutate infrastructure directly. |
| Credential manager | IAM authorization plus adapter-owned secret references | Resolve minimum credentials only in the adapter that needs them; build code receives none of these authorities. |
| Operation/security logs | `audit` facts plus delivery read models | Audit is immutable authority; UI history and exported reports are projections. |

## Admission recommendation

FEAT-007 is technically viable. Prow is the more useful control-plane donor;
Tencent CODING is the more useful end-to-end product reference. Together they
reinforce rather than replace the target boundary: `delivery` owns verified
source-to-artifact workflow, while `apphosting` owns deployment truth.

Implementation should not begin by porting either system. Before Gate A
implementation is accepted, the product must select one real source provider
and prove an implementation plan for a separate untrusted build boundary, an
OCI registry/publisher, approved dependency egress, apphosting-owned digest
distribution, IAM/Audit contract extensions, and log retention. Those choices
determine the first real adapters; they do not change the provider-neutral
delivery/apphosting boundary.

No Prow source, generated file, API type, configuration, binary, image,
manifest, or dependency is copied or referenced by Matrix build/runtime code.
No CODING API, CIFile/Jenkinsfile syntax, product schema, implementation,
binary, agent, plugin, or credential model is copied or accepted as a Matrix
build/runtime dependency.
