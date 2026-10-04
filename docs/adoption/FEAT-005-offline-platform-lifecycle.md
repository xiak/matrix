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
| Matrix authority-profile increment | `c29f9e3f065af4a6dcfc06596ee9a49a5c671774` | Same-repository fixed patch; adapt only release/lifecycle mechanisms, excluding Phase 3 host implementation, checkpoint and acceptance state. |
| Matrix security-mail installation slice | `7d002ea2ff7afafc961974123fb4e16f23945a23` | Same-repository fixed patch; adapt the private configuration and installed notification-consumer boundary only, excluding donor profile values, host/node work and acceptance state. |
| Matrix authentication-recovery installation sequence | `9d8ff34fdc2e1c45a278357d45e2803b799eaa29`, `4b3920fb4e714a7cfac6ff37da157f79c10f0079`, `5bb7836039165d88f3b0b88e48c533eaab902203`, `25e28b40f951554664ae2356713e054a2d8bb659` (all ancestors of fixed cumulative object `487fcfe13e8b2a687997b103ad3aad2c35a2b96e`) | Read only through fixed Git objects. Adapt only the installation-side authentication closure, replay anchor, backup custody and pre-effect inspection; exclude donor profile values, PaaS/node work, credentials, checkpoints and acceptance state. |

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

The multi-tenant release target in FEAT-006/005 additionally adopts the fixed
Matrix authority-profile increment as follows:

| Fixed slice | Decision | Rationale |
| --- | --- | --- |
| `c29f9e3` manifest v2, exact profile comparison, sealed backup/recovery binding and support output | `ADAPT` | Keep independent authority versions plus the code-owned contract revision. Retain this branch's own service composition and coordinated revision, owned by FEAT-005, rather than importing the donor's host composition. Also close unproved cross-profile recovery before journal or provider changes, while preserving same-profile recovery. |
| `c29f9e3` published v1 canonical/signature/backup preservation and pre-effect rejection gates | `REUSE` | Preserve evidence for real published formats without inventing cross-profile N-1 support. Run the gates on this branch and extend its existing process owner, never inherit the donor's acceptance result. |
| `c29f9e3` PaaS2/host expectations and FEAT-008 status | `REJECT` for this slice | IAM release verification does not authorize importing host admission, changing another Phase or asserting its release acceptance. |
| `7d002ea2` canonical `SecurityMailConfiguration` private-file contract | `ADAPT` | Keep the strict, redacted operator input and bind it later to this installation's sealed IAM bootstrap before writing the purpose-only channel. It is not an HTTP API, journal payload, support artifact or caller-selected authority scope. |
| `7d002ea2` notification executable, purpose-only login, keyring/channel mounts and fixed Alpine base | `ADAPT` | Package the accepted IAM notification executable and generate this branch's protected DSN/keyring/channel from the sealed installation. Keep the runtime image on `scratch`, copying only the CA bundle from the fixed Alpine image so public and private SMTP certificates can be verified without adding a shell. Use a new mail-only egress network rather than the donor's shared management network. |
| `7d002ea2` shared non-internal management network for the notification worker | `REJECT` | A mail credential should not share a general provider network with PaaS or other control-plane services. This branch gives only the notification dispatcher a separate `mail-egress` membership and preserves `control` as internal. |
| `7d002ea2` donor release profile, host/node topology and foreign gate status | `REJECT` | This branch owns its exact authority profile and must prove its own notification consumer, SMTP custody and signed runtime; importing another branch's numbers or evidence would not validate the combined IAM source. |
| `9d8ff34f` purpose-only authentication-recovery executable packaging and protected file mounts | `ADAPT` | Add the already-owned IAM recovery executable to the signed IAM image and invoke it only through the installation adapter. Preserve a read-only root, exact single-file mounts, no network, bounded resources, stable exit classes and redacted provider failures; do not create a northbound recovery API or grant the normal IAM service/worker these files. |
| `4b3920fb` replay snapshot and completion anchor | `ADAPT` | Bind one recovery command to its immutable intent and exact response-loss replay. Persist the monotonic recovery epoch only on the exact successful terminal recovery transition; ordinary journal writes, failed recovery and changed replays cannot advance it. |
| `5bb78360` backup custody and authentication-state reconciliation | `ADAPT` | Export the IAM backup lease, TOTP custody commitment and complete authentication-state digest from one purpose-only snapshot; close authentication before destructive restore and reconcile/reopen the exact sealed snapshot before normal services start. Earlier backup wire versions remain readable only as historical formats and are not recoverable by the current profile. |
| `25e28b40` pre-effect recovery inspection | `ADAPT` | Inspect the exact recovery intent before journal advancement, database restore, service stop or another provider effect. An invalid, forbidden, conflicting or unavailable result fails closed; a lost success response is resolved only through the original bounded completion identity. |
| `487fcfe1` Phase 3 profile numbers, node/PaaS topology, credentials and runtime evidence | `REJECT` | The current branch owns IAM/Audit/PaaS `64/34/3` and its coordinated revision. Fixed donor behavior informs this installation slice, but another branch's signed releases, node gates and acceptance statements cannot validate this composition. |

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

No legacy repository is a build or runtime dependency.
