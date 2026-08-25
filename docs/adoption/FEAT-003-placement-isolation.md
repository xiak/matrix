# FEAT-003 adoption review: tenant placement and isolation

- Status: Complete
- Target: [`FEAT-003 tenant placement and isolation policy`](../features/FEAT-003-placement-isolation.md)
- Review date: 2026-08-25
- Direct donor dependency allowed: No

## Fixed baselines

| Donor | Commit | Worktree policy |
| --- | --- | --- |
| `D:\XiaK\project\2026\matrix` | `69336e51f94fa98f6aa278fa4c62382e224dbeaf` | Read only with Git object commands. The current dirty worktree is excluded. |
| `D:\XiaK\project\2026\senatria\matrix` | `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d` | Read only with Git object commands. The current worktree is excluded. |

The FEAT-003 target algorithm, isolation seam, transaction boundary, and
acceptance gates were fixed before these source slices were opened.

## Legacy PaaS comparison

| Slice at fixed commit | Size | Decision | Rationale |
| --- | ---: | --- | --- |
| `runtime/createplacement/contract.go` | 564 lines | `ADAPT` | Preserve strict JSON decoding, exact tenant authority/scope closure, canonical sets, and bounded identifiers. Reject its caller-selected `RuntimeTargetRef`, `ProviderBindingID`, isolation attributes, policy references, and quota references: those bypass a scheduler and expose provider topology to the request. |
| `runtime/createplacement/plan.go` | 183 lines | `REJECT` as an implementation | Its durable approval boundary is explicit and honest, but `ResolveProtectedOwnerInlinePlanSpec` returns `ErrDurableApprovalGatePlannerRequired`; it is not an implemented placement planner. The target keeps a pure deterministic planner followed by a transactional persistence gate. |
| `runtime/createplacement/service.go` | 154 lines | `ADAPT` | Preserve closing the proposal and tenant scope before starting a generic operation. The new use case uses a smaller tenant/release/policy scope and does not import ResourceKernel ownership. |
| `runtime/data/repo/postgres/createplacement_owner_mutation.go` | 891 lines | `ADAPT` | Preserve authoritative database transaction time, in-transaction revalidation, exact authorized-operation checks, immutable-scope checks, and atomic mutation. Replace the caller-selected target flow with capacity-row locking, planner execution, immutable decision insertion, and reservation insertion. |
| `createplacement_owner_mutation_integration_test.go` | 1,200 lines | `REFERENCE` | Reuse rollback, commit, exact replay, and retry test categories. It does not test candidate selection, capacity, concurrent overcommit, reservation expiry, or row-level security, so it cannot serve as FEAT-003 acceptance evidence. |
| Runtime `domain/records.go` and `domain/values.go` | 1,506 lines | `REFERENCE` | Canonical collections, cloning, provider-neutral isolation/topology, and explicit lifecycle modeling are useful. The donor intentionally hydrates an already chosen target and binding; its Project/Environment/Application graph and tenant-authority-owned targets conflict with the target's platform-owned inventory model. |
| Runtime use-case and PostgreSQL write paths | 1,168 lines | `ADAPT` | Preserve `INSERT ... ON CONFLICT DO NOTHING`, then load the authority-scoped row and require semantic equality for replay. FEAT-003 narrows this to `(tenant_id, operation_id)` plus the canonical request digest and returns `IDEMPOTENCY_CONFLICT` for unequal reuse. |
| `MIG-P1-008` runtime registry migration and verifier | 1,853 lines | `ADAPT` | Preserve composite authority keys, authority-bearing foreign keys, check constraints, and post-migration verification. Add placement capacity rows, decisions, reservations, forced row-level security, transaction-local tenant context, and a non-bypass runtime role; none exists in this donor slice. |
| `REQ-006-tenant-isolation-and-data-partitioning.md` | 146 lines | `ADAPT` | Preserve that PaaS tenant identity is not a provider account/namespace, tenant predicates are mandatory, provider mapping is explicit, standalone mode keeps the same logical boundary, and later physical partitioning must not change service contracts. |
| `RT-001-service-runtime-boundary-and-placement-model.md` | 569 lines | `REFERENCE` | Its target model calls for deterministic, policy-filtered, evidenced placement and provider-neutral isolation. The fixed implementation does not perform scheduler selection, capacity reservation, or concurrent overcommit protection. |
| ResourceKernel, Project, Environment, ProviderRegistry, quota, and approval graph closure | Thousands of lines | `REJECT` | It is a mature but materially different product graph. Importing it would recreate the legacy PaaS authority model before the Local Compose runtime needs it and would make physical/provider concerns part of tenant placement. |

## Senatria comparison

| Slice at fixed commit | Size | Decision | Rationale |
| --- | ---: | --- | --- |
| `devops/application/catalog/component_target_config_service.py` | 175 lines | `REJECT` for FEAT-003 | It renders deployment configuration after a target is selected from environment naming. Its path, value, and secret-metadata safeguards are useful later for FEAT-004, but it has no tenant, isolation, capacity, or scheduler boundary. |
| `devops/cd/deploy/prepare-compose-target-config.sh` | 216 lines | `REJECT` for FEAT-003 | It is release tooling driven by an environment-selected deploy target, not a policy or capacity planner. It remains possible FEAT-004 behavior evidence and is not copied. |
| `api/auditcontract/placement.go`, generated contract vectors, and Audit placement deriver | 280+ lines | `REFERENCE` | Here “placement” is deterministic Audit virtual-slot/shard derivation, not workload runtime placement. Reuse only the version-qualified digest contract, canonical golden vectors, and fail-closed conformance-test pattern; reject the shard algorithm and Audit vocabulary. |
| Senatria business release and environment model | Large DevOps closure | `REJECT` | The independent PaaS must not absorb Senatria business services, environment authority, or deployment naming. FEAT-004 will consume an already authorized placement decision through its own runtime contract. |

## Design comparison result

The legacy PaaS is mature in transaction-bound authorization, immutable scope,
authority-bearing relational keys, exact replay, rollback, and migration
verification. It is not an automatic scheduler: the request selects the
runtime target and provider binding, while the durable planner path explicitly
reports that a planner is still required. It also has no capacity reservation,
candidate-set digest, concurrent overcommit protection, or PostgreSQL row-level
security.

The fixed FEAT-003 design is therefore retained. It is deliberately smaller
and stronger for this release:

- callers provide tenant, release, and policy identities but never a target or
  provider binding;
- the pure planner owns deterministic filtering and strategy selection;
- the PostgreSQL transaction owns authoritative time, capacity locking,
  decision/reservation atomicity, and exact replay;
- composite tenant keys and explicit predicates are reinforced with forced
  row-level security;
- platform inventory remains outside tenant ownership, while placement and
  reservations remain tenant scoped;
- future host, Kubernetes, cloud, or physical isolation is added through the
  isolation-policy and infrastructure-provider seams, not a new request shape.

No donor source file is copied and neither donor is a build or runtime
dependency.

## Donor-informed amendments

The review changes implementation tactics without changing the fixed public
resource boundary:

1. PostgreSQL transaction time is authoritative for `DecidedAt`, pending-lease
   evaluation, and persisted transaction facts. Caller time is used only by
   Gate A deterministic tests.
2. Replay returns a prior decision only after exact semantic request-digest
   equality. Every target, policy, release, reservation, and tenant assumption
   is revalidated inside the placement transaction before a new decision is
   committed.
3. Composite tenant keys and explicit tenant predicates from the donor are
   retained, while forced row-level security and a non-bypass runtime role are
   intentional defense-in-depth improvements.
4. Caller-selected targets, provider bindings, ResourceKernel ownership,
   Project/Environment closure, and inline durable-plan placeholders are not
   admitted.
5. Senatria Audit's versioned digest and golden-vector conformance pattern is
   referenced for candidate-digest tests. Its audit shard calculation is not a
   runtime placement algorithm.
