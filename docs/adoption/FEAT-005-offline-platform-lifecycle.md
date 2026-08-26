# FEAT-005 adoption review: Offline platform distribution and lifecycle

- Status: Complete
- Target: [`FEAT-005 Offline platform distribution and lifecycle`](../features/FEAT-005-offline-platform-lifecycle.md)
- Review date: 2026-08-25
- Direct donor dependency allowed: No

## Fixed baselines

| Donor | Commit | Worktree policy |
| --- | --- | --- |
| Legacy PaaS | `69336e51f94fa98f6aa278fa4c62382e224dbeaf` | Read only through Git object commands; exclude its worktree. |
| IAM/Audit foundation and delivery donor | `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d` | Read only through Git object commands; exclude its worktree. |
| PaaS design | `338d9b5fcb820120c32265e380c55e5f171cdb75` | Read only through Git object commands; use as rationale, not executable evidence. |

The FEAT-005 supported host, signed bundle, fixed inventory, lifecycle,
upgrade/rollback semantics, CLI surface, and real offline gates were committed
before these slices were opened.

## Legacy PaaS comparison

| Slice at fixed commit | Size | Decision | Rationale |
| --- | ---: | --- | --- |
| `kernel/bootstrap/installation` contracts, aggregate, transition graph, history validation, and readiness digest | 47 files / 4,753 lines | `REFERENCE` | Explicit state transitions, optimistic versioning, immutable history, proof-bound transitions, sealed readiness, and distinct recovery states are useful failure categories. FEAT-005 uses one much smaller local installation journal and does not inherit ResourceKernel, UUIDv7 reference algebra, handoff, credential, BreakGlassCase, ledger, or AuditEvidence graphs. |
| Complete bootstrap installation/readiness/recovery/authorization closure and its independent-audit documents | More than 127 related source files | `REJECT` | It models a governance bootstrap program with thirteen states, eighteen edges, typed child authorities, and several prerequisite owner contracts. Importing it would create the code, test, and documentation explosion that the replacement-first repository rules prohibit. |
| `paas-release-root-audit-export` canonical artifact exporter | 6 files / 519 lines | `REFERENCE` | Exact canonical bytes, length, and SHA-256 bindings reinforce the target manifest checks. Base64 embedding of internal catalogs, vectors, schemas, profiles, and release-root governance is unrelated to an operator bundle and is not adopted. |

## Foundation and delivery donor comparison

| Slice at fixed commit | Size | Decision | Rationale |
| --- | ---: | --- | --- |
| Release manifest helper, generator, and JSON Schema | 757 lines | `ADAPT` | Preserve a closed schema, exact release identity, explicit component/image inventory, semantic versions, digest references, architecture, and rejection of unknown records. Replace GitLab pipeline metadata, tags as runtime authority, affected-project projection, and the mutable component catalog with the canonical signed FEAT-005 manifest. |
| Offline packager, signed verified-local image installer, and offline tests | 3,763 lines | `ADAPT` | Preserve build-time image closure, one archive per image, archive length/digest, signer identity, no-follow single-regular-file reads, duplicate-key rejection, load-then-inspect image identity, restrictive atomic state, and verified previous-release history. Implement the target in Go with Ed25519 and canonical relative paths; reject runtime ENV rewriting, tag restoration as authority, SSH tooling, Harbor upload, Python, shell runbooks as execution, and tests that snapshot filenames or command order. |
| `compose_release_state.py` | 1,420 lines | `ADAPT` | Preserve path confinement, link rejection, bounded strict state, fsynced atomic replacement, content seals, explicit current/last-successful identity, transition inventory, and verify-before-publish. Replace legacy receipt-upgrade catalogs, checked-in Compose package hashing, environment parsing, compatibility aliases, and Python CLI modes with the smaller installation state machine. |
| `run-compose-deployment.sh`, `rollback-compose-release.sh`, `deploy.sh`, `preflight.sh`, and `verify.sh` | 6,928 lines | `REJECT` as implementations; `REFERENCE` for failure categories | Locking, uncertain-effect observation, preflight, verify-before-cutover, quiesce, compatibility floors, prior-release restoration, and failure diagnostics inform tests. Thousands of lines of shell mutate a donor-wide business graph, source ENV, contain component-specific rollback branches, and cannot become Matrix PaaS lifecycle authority. |
| Audit recovery commitment/signature/verifier slice | 5 files / 659 lines | `ADAPT` | Preserve bounded immutable bytes, digest and length commitment, signer key identity/fingerprint, exact Ed25519 signature size, independent verification, and context-bounded reads. Reject the Audit archive repository, assurance, retention, checkpoint, and materialization domain from the installation bundle. |
| Checked-in APISIX, backup, IAM bootstrap, and product Compose topology | Thousands of lines; APISIX/backup sample is 14 files / 4,365 lines | `REJECT` | These files describe donor routes, Lua policies, certificates, Neo4j/Audit recovery, business components, and secret ENV. FEAT-005 generates a closed Matrix topology and consumes separately accepted component contracts; donor configuration is neither a template nor a runtime dependency. |
| Harbor offline package and registry configuration scripts | 9 delivery files plus surrounding tests | `REJECT` | A private registry is unnecessary for the one-engine Phase 1 profile and adds daemon mutation, certificate, upload, restart, and rollback authority. The target loads exact signed archives directly and never edits Docker daemon configuration. |

## PaaS design comparison

The design donor's adoption manifest is `REFERENCE` for N-minus-one reader
compatibility, expand/contract migrations, independent IAM/Audit/UI releases,
exclusive online versus offline delivery, and explicit rollback drills. Its
GitLab/current-DevOps execution authority, projection roadmap, staged
integration provider, and legacy UI plan are `REJECT`: FEAT-005 installs the
new Docker/Compose-first product and cannot subprocess or depend on the old
DevOps closure.

## Resulting implementation constraints

1. Own the compact lifecycle in an `installation` context and keep one
   user-facing `mx` command tree. Do not import the legacy bootstrap aggregate
   or recreate its child authority graph.
2. Canonicalize, hash, and Ed25519-verify the complete regular-file manifest
   before an effect. Pin the out-of-band signer identity; neither a filename,
   tag, archive listing, nor Docker output is authority.
3. Build may acquire approved images, but install, verify, upgrade, rollback,
   and recovery form no registry/pull/build/network command. Verify archive
   bytes before load and exact image identity after load.
4. Confine files below one protected installation root, reject links and
   volume roots, use bounded no-follow reads, same-directory atomic durable
   writes, and one OS installation lock.
5. Generate one closed Matrix platform Compose document from the accepted
   release inventory. Do not parse donor YAML, source ENV files, accept bundle
   hooks, or retain business-specific rollback branches.
6. Persist intent before effects, observe uncertain effects before retry, and
   publish the current release only after full verification. Retain exactly
   one verified previous release for N-minus-one rollback.
7. Require expand/contract database compatibility across current and previous
   binaries. Keep binary rollback data-preserving; treat backup recovery as a
   separate explicit destructive operation.
8. IAM, Audit, APISIX, UI, PostgreSQL, and PaaS images must satisfy their own
   real contracts. A donor service, mock, in-process authority, or health-only
   image cannot fill the bundle inventory.
9. Test manifest tampering, ownership, interruptions, real load/inspect,
   install, upgrade failure, rollback, recovery, and leakage behavior. Do not
   adopt tests tied to script layout, exact Compose text, ENV files, SQL text,
   line counts, or incidental command order.

No donor source is copied and no donor repository is a build or runtime
dependency.
