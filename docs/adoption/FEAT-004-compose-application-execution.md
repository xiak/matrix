# FEAT-004 adoption review: Compose application execution

- Status: Complete
- Target: [`FEAT-004 Compose application execution`](../features/FEAT-004-compose-application-execution.md)
- Review date: 2026-08-25
- Direct donor dependency allowed: No

## Fixed baselines

| Donor | Commit | Worktree policy |
| --- | --- | --- |
| `D:\XiaK\project\2026\matrix` | `69336e51f94fa98f6aa278fa4c62382e224dbeaf` | Read only through Git object commands; exclude its worktree. |
| `D:\XiaK\project\2026\senatria\matrix` | `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d` | Read only through Git object commands; exclude its worktree. |
| `D:\XiaK\project\2026\senatria\matrix` design | `338d9b5fcb820120c32265e380c55e5f171cdb75` | Read only through Git object commands; use as rationale, not executable evidence. |

The FEAT-004 resource boundary, generation model, minimal Operation protocol,
ports, Compose profile, and real-runtime gates were committed before these
slices were opened.

## Legacy PaaS comparison

| Slice at fixed commit | Size | Decision | Rationale |
| --- | ---: | --- | --- |
| `runtime/applyworkload/commandcontract/contract.go` and `contract.go` | 981 lines | `ADAPT` | Preserve bounded canonical input, immutable artifact/config references, opaque secret references, desired generation, digest drift, and fail-closed decoding. Replace ServiceRuntime, Project/Environment/Service lineage, ResourceKernel contracts, caller-selected placement, health-policy references, and the donor shared-kernel closure with the accepted public resources. |
| `runtime/applyworkload/service.go`, PostgreSQL owner mutation, and integration test | 1,492 lines | `ADAPT` | Preserve atomic owner mutation plus Operation submission, authoritative in-transaction revalidation, exact replay, commit/rollback fault categories, and immutable execution identity. FEAT-004 uses a smaller tenant-RLS generation transaction and the existing automatic placement path. |
| Operation `state.go`, `idempotency.go`, and `operation_step_attempt.go` | 1,398 lines | `REFERENCE` | Stable command identity, request-hash equality, explicit legal transitions, bounded attempts, reconciliation, and manual intervention are useful. The 25-state approval/compensation lifecycle and generalized subject/scope/resource idempotency graph exceed this vertical slice. |
| Event-lease domain and PostgreSQL statements | 563 lines | `REFERENCE` | Database time, lease ownership, CAS/fencing, bounded acquisition, and stale-writer rejection inform the worker protocol. FEAT-004 does not import event publication, projector, topology, or the generalized lease framework. |
| Complete Operation, EventLease, AuditEvidence, ResourceKernel, policy, approval, and contract-schema closure | Thousands of files/lines | `REJECT` | It is a different governance platform and would recreate the code, test, and documentation explosion this new repository avoids. One explicit Operation table and apphosting workflow satisfy the current release. |

## Senatria comparison

| Slice at fixed commit | Size | Decision | Rationale |
| --- | ---: | --- | --- |
| `component_target_config_service.py` and its tests | 175 implementation lines | `ADAPT` | Preserve deterministic iteration, path confinement, regular-file/no-symlink checks, a 1 MiB secret bound, restrictive permissions, and value/key collision rejection. Replace environment-variable authority, property patch files, business component metadata, and best-effort permission failure with exact ConfigurationRevision/SecretVersionReference bindings and fail-closed writes. |
| Compose package config/image/port/network contract services | 272 implementation lines | `ADAPT` | Preserve digest-required images, service-owned configuration, no application host ports, bounded network attachment, and loopback-only debug intent. Generate typed Compose JSON and validate behavior; reject regex parsing of YAML, hard-coded services, debug overrides, and file-presence snapshots. |
| `compose_release_state.py` | 1,302 lines | `REFERENCE` | Regular-file and symlink defenses, bounded canonical state, digest seals, atomic/fsynced writes, current/last-successful identity, and pre-transition verification are strong receipt patterns. It controls platform release packages rather than tenant Deployment generations, so no code is copied. |
| `run-compose-deployment.sh` and `rollback-compose-release.sh` | 3,527 lines | `REJECT` as implementations | Cross-process locking, readiness observation, source-state restoration, and explicit rollback-compensation failure are useful behavior categories. The scripts execute a Senatria-wide release graph, source shell environments, mutate shared directories, and depend on Python and business-specific recovery steps. |
| `prepare-deployment-env.py` | 141 lines | `REJECT` | Collision checks and digest references are covered by the target compiler. Shell-quoted environment files, tags, CI variables, and affected-component selection are not PaaS authority. |
| `compose_runtime_source.py` | 276 lines | `ADAPT` | Preserve a fixed observation command, shared locking, declaration validation, bounded output, normalized workload/health/image facts, and rejection of unknown records. Implement local Go process execution over generated project state; reject arbitrary SSH script transport and Audit-specific operational probes. |
| Checked-in product Compose files and DevOps release/catalog closure | Large | `REJECT` | They describe Senatria platform and business delivery, not a tenant-neutral executor. They are neither templates nor runtime dependencies for Matrix PaaS. |

## PaaS design comparison

The design donor's 311-line adoption manifest explicitly recommends extracting
narrow Operation identity/idempotency/lease semantics instead of importing the
complete legacy Operation closure. Its GitLab-first projection and staged
release roadmap target a different product. The dependency warning is
`REFERENCE`; its runtime sequence and scope are `REJECT` for FEAT-004.

## Resulting implementation constraints

1. Keep the target's public ApplicationRevision/Deployment model and move only
   executor method data needed by external adapters into internal-visible v1
   schemas; no universal runtime contract returns.
2. Use one small Operation state machine with database-time leases, fencing,
   exact request/command replay, and observe-before-retry for uncertain effects.
3. Compile typed deterministic Compose JSON. Do not parse or patch user YAML and
   do not retain the donor's service catalog, shell environment, or scripts.
4. Confine state below an installation-owned root, reject symlink traversal,
   use atomic durable writes and a cross-process project lock, and fail if
   secret permissions cannot be enforced.
5. Resolve verified images and exact secrets through injected ports. Apply with
   pulls/build disabled; keep secrets out of Compose JSON and receipts.
6. Publish no application host ports. Observe normalized project-network
   endpoints for the later GatewayAdapter and verify Gate C through a
   network-scoped probe.
7. Test semantic plans, state transitions, security boundaries, and real
   effects. Do not adopt donor tests tied to YAML text, specific services,
   script layout, line counts, or call sequences.

No donor source is copied and no donor repository is a build or runtime
dependency.
