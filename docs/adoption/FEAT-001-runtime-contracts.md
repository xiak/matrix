# FEAT-001 adoption review: Runtime contracts

- Status: Complete
- Target: [`FEAT-001 Runtime domain and versioned contracts`](../features/FEAT-001-runtime-contracts.md)
- Review date: 2026-08-25
- Direct donor dependency allowed: No

## Fixed baselines

| Donor | Commit | Worktree policy |
| --- | --- | --- |
| `D:\XiaK\project\2026\matrix` | `69336e51f94fa98f6aa278fa4c62382e224dbeaf` | Read with Git object commands only; approximately 187 current worktree changes are excluded. |
| `D:\XiaK\project\2026\senatria\matrix` | `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d` | Read with Git object commands only; current worktree state is excluded. |

The target design was fixed before these slices were opened. Decisions below
compare each slice to that target instead of treating donor code as the
default architecture.

## Legacy PaaS comparison

| Slice at fixed commit | Size | Decision | Rationale |
| --- | ---: | --- | --- |
| `internal/runtime/domain` and repository-neutral records | Included in 73-file Runtime slice | `ADAPT` | Preserve immutable workload specifications, explicit authority, desired/observed separation, capability facts, digest-backed artifacts, secret references, and fail-closed validation. Redesign names and scope around Tenant/ResourcePool/WorkloadRelease; do not copy old Project/Environment/Application/Service topology. |
| `internal/runtime/applyworkload/commandcontract` | 17 files / 16 Go / 4 tests | `ADAPT` | Preserve strict machine-readable schema, immutable references, bounded payloads, canonical request digest, and duplicate-conflict behavior. Replace the internal owner-contract framework and legacy hierarchy with public `api/paas/v1` resources. |
| `internal/runtime/createplacement` | 6 files / 6 Go / 3 tests | `REFERENCE` | The operation-backed planning pattern is useful for FEAT-003, but it does not define ResourcePool, exact v0.1 isolation classes, or an `UNSCHEDULABLE` public decision. No code enters FEAT-001. |
| `internal/kernel/operation` | 703 files / 683 Go / 184 tests | `REFERENCE` | Its idempotency scopes, immutable request digests, transition-table tests, evidence lineage, and recovery semantics are strong. The general 25-state governance kernel and large transitive closure are disproportionate for Runtime v0.1 and would reintroduce the old product architecture. |
| `internal/kernel/providerregistry` | 54 files / 54 Go / 14 tests | `ADAPT` | Preserve normalized error classes, versioned capability identity, idempotency declarations, invocation receipts, unknown outcomes, and explicit adapter modes. Replace vendor/provider registries with the three target adapter ports and smaller stable vocabulary. |
| `internal/worker/runtimeprovider` | 19 files / 19 Go / 7 tests | `ADAPT` | Preserve durable pre-dispatch, lease fencing, caller-owned evidence identity, replay, and unknown-outcome reconciliation. Reimplement against the new Operation and adapter command envelope without importing the legacy kernels. |
| `internal/provider/mock` | 22 files / 19 Go / 6 tests | `REFERENCE` | Its durable fake proves replay, conflicting digests, transient/terminal/unknown outcomes, and credential references. FEAT-001 builds a smaller fake from the new interfaces; direct code would pull ProviderRegistry internals. |
| Entire `app/service/paas` tree | Thousands of files | `REJECT` | Wholesale reuse violates the independent-product boundary, brings legacy IAM/Audit authorities and business hierarchy, and prevents a minimal dependency closure. |

## IAM and Audit comparison

| Slice at fixed commit | Decision | Rationale |
| --- | --- | --- |
| `app/service/iam/api/protos/matrix/iam/v1/common.proto` and `permission.proto` | `ADAPT` | Reuse the authority semantics: PaaS tenant identity maps to IAM `organization_id`, authorization is a server-side permission decision, and decision IDs are auditable. Generated IAM code is not copied into FEAT-001. |
| `platform/go/sdk/audit/model.go` and `contract.go` | `REFERENCE` | Evidence sanitation follows the Audit contract's bounded attributes, sensitive-key rejection, stable actor/target/action/result vocabulary, and microsecond UTC time. The unified Audit event remains owned by Audit and is integrated in FEAT-005. |
| `platform/go/sdk/audit/outbox.go` | `REFERENCE` | Preserve atomic business-write/outbox insertion, fencing, immutable event key/fingerprint, replay acceptance, retry, rejection, and dead-letter behavior for FEAT-005. It is not moved into a new top-level `platform/`. |
| Whole `platform/go/foundation` or `platform/go/sdk` directories | `REJECT` | A generic shared layer has not earned multiple consumers in the new repository. Future adoption is capability-by-capability into its owner or a specifically approved SDK. |

## Result

The new design is smaller and better aligned with the first releasable slice:
it exposes exact tenant/isolation behavior, separates adapters by capability,
and omits the legacy business hierarchy. The donors remain more mature in
durable operations, idempotency, evidence, and crash recovery, so those
semantics are adapted deliberately.

FEAT-001 copies no donor source file. Semantic reuse is substantial, but direct
code reuse is zero for this feature. Every implementation file is authored in
the independent repository and has no donor build or runtime dependency.
