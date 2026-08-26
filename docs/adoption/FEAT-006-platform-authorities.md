# FEAT-006 adoption review: Platform IAM and Audit authorities

- Status: Complete
- Target: [`FEAT-006 Platform IAM and Audit authorities`](../features/FEAT-006-platform-authorities.md)
- Review date: 2026-08-25
- Direct donor dependency allowed: No

## Fixed baselines

| Donor | Commit | Worktree policy |
| --- | --- | --- |
| Legacy PaaS | `69336e51f94fa98f6aa278fa4c62382e224dbeaf` | Read only through Git object commands; exclude its worktree. |
| IAM/Audit foundation donor | `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d` | Read only through Git object commands; exclude its worktree. |
| PaaS design | `338d9b5fcb820120c32265e380c55e5f171cdb75` | Read only through Git object commands; use as rationale, not executable evidence. |

The independent authority target, closed Phase 1 roles and actions, bootstrap
contract, opaque credentials, Audit event union, indefinite retention, and
acceptance gates were committed before any of these slices was opened.

## Legacy PaaS comparison

| Slice at fixed commit | Size | Decision | Rationale |
| --- | ---: | --- | --- |
| Embedded `internal/iam` identity, access-grant, session, service-identity, and CheckAccess closure | 350 files | `REJECT` as an implementation; `REFERENCE` for trust-boundary attacks | The static mTLS client map rejects caller identity headers and binds one verified credential to tenant and subject, which reinforces fail-closed tests. It is not an independently runnable IAM authority, has no user login/bootstrap lifecycle suitable for this product, and would duplicate the new service boundary. |
| Embedded `kernel/auditevidence` evidence graph, storage, query, and access recording | 299 files | `REJECT` as an implementation; `REFERENCE` for access-audit behavior | Recording an authorized evidence read and keeping actor/target authority aligned are useful security cases. The graph contains operation snapshots, policy evidence, publication lineage, retention references, and many product-specific identities; it is neither the compact unified Audit service nor a compatible wire contract. |
| Bootstrap authorization and break-glass graph | 41 files plus its document/test closure | `REJECT` | Multi-party break-glass cases, handoff, recovery authorities, UUIDv7 reference algebra, and proof graphs are outside the Phase 1 organization/role/session slice. |
| PaaS documentation and independent-audit fixtures | 982 files under `app/service/paas/docs` | `REJECT` | They are historical verification artifacts and design snapshots for superseded embedded authorities. Importing them would recreate the test and documentation explosion prohibited by repository policy. |
| `app/ui/src/ui/xiak` | 158 files | `REJECT` for this FEAT | It contains presentation primitives and social/group UI, but no PaaS login flow, IAM API client, Audit client, or authority contract. FEAT-006 has no UI compatibility obligation to this slice. |

No legacy user, session, role, audit record, header protocol, or database is a
migration source or fallback authority.

## IAM foundation donor comparison

The fixed IAM tree contains 658 files, including generated Ent persistence,
protobuf/gRPC surfaces, JWT/JWKS, Redis-backed identity state, Wire
composition, scripts, and BMS-specific policy.

| Slice at fixed commit | Decision | Rationale |
| --- | --- | --- |
| Organization/user/session domain and pure authorization evaluator | `ADAPT` | Preserve one organization-bound subject, active/expired/revoked session facts, fixed role-to-action evaluation, deterministic denial reasons, and audit-required decisions. Use database time and the smaller Matrix role catalog; do not retain instance/project scopes, projection rebuilds, caller-selected organizations, or local-clock defaults. |
| Argon2id foundation and password policy | `ADAPT` | Preserve versioned PHC-style Argon2id hashes, random salts, constant-time verification, bounded parameters, rehash detection, and a fixed bounded password policy. Reject silent configuration clamping, hard-coded policy dates, arbitrary violation metadata, phone/email/history/keyboard rule machinery not required by the target, and secret-bearing errors. |
| Service-account and client-secret aggregates | `ADAPT` | Preserve high-entropy opaque credentials stored only as digests, organization binding, expiry, disable/revoke terminal behavior, and constant-time verification. Reject business/technical owners, environment, review intervals, rotation groups, prefixes, multiple auth methods, and token-signing machinery. |
| MVP bootstrap use case and startup runner | `ADAPT` for convergence and exact replay; `REJECT` as code | Preserve an atomic first-run transaction, equal replay, changed-input conflict, built-in role seeding, and same-transaction Audit outbox facts. Replace environment-variable bootstrap, BMS roles, default instance, JWT signing keys, mutable searches, generic HTTP idempotency snapshots, and plaintext-bearing logging with the exact restrictive installer file and content digest. |
| IAM Audit recorder, outbox, dispatcher, and health classification | `ADAPT` | Preserve transactional append, stable event identity, at-least-once delivery, lease recovery, fencing-protected completion, bounded retry/dead letter, and unhealthy backlog visibility. Map only the closed FEAT-006 event union; reject SDK `attributes`, display-name/localization maps, native error text, framework metrics closure, and the donor SDK dependency. |
| Runtime privilege reconciliation and legacy Audit-table removal | `REFERENCE` | Distinct migration/runtime roles, no role membership/ownership, revoked public defaults, and removal rather than compatibility storage inform schema attacks. The target uses separate named schemas and narrower API-only functions instead of donor-wide public-schema CRUD grants or donor table names. |
| IAM protobuf/OpenAPI surface and auth SDK | `REFERENCE` for endpoint and failure categories; `REJECT` as an implementation | Login/logout, session revocation, explicit action decisions, strict enum handling, and normalized unavailable/denied outcomes inform tests. Protobuf, gRPC, Kratos, JWT, refresh tokens, organization hints, custom roles/conditions, ABAC maps, caller-supplied subject/tenant, Redis revocation, and local authorization fallback are outside or contradict the target. |
| Ent-generated data layer, remaining use cases, commands, scripts, configs, and deployment closure | `REJECT` | The generated and framework closure is substantially larger than the accepted vertical slice and would create duplicate models, APIs, tests, and operational paths. |

## Audit foundation donor comparison

The fixed Audit implementation contains 1,258 files below `internal`, thirteen
Audit proto contracts, fifty-one migrations, and large projection, retention,
integrity, archive, recovery, and export subsystems.

| Slice at fixed commit | Decision | Rationale |
| --- | --- | --- |
| Ingestion proto, intake domain, PostgreSQL identity-first append, and conflict classification | `ADAPT` | Preserve producer identity derived from authenticated workload credentials, bounded batches, canonical fingerprints, database acceptance time, atomic identity registration, equal duplicate success, and changed-content conflict. Replace event-key placement, shard/lane policy, partial per-item rejection, protobuf validation, and async normalization with one strict HTTP event per Phase 1 request and `(source,eventId)` identity. |
| Canonical fact and immutable intake/canonical tables | `ADAPT` | Preserve deterministic canonical bytes, domain-separated SHA-256, immutable fact rows, mutable delivery state kept separate, and update/delete/truncate attacks. Use the target's closed event fields and immediate per-tenant sequence/hash append; reject arbitrary `attributes`, localization/display snapshots, taxonomy, residency, sensitivity, placement, and policy version graphs. |
| HMAC-SHA256 cursor codec and bounded query filters | `ADAPT` | Preserve an opaque size-bounded base64url envelope, domain separation, constant-time MAC verification, version rejection, no trailing bytes, expiry, exact query binding, and deterministic page anchors. Bind the smaller cursor directly to IAM-derived tenant and accepted time/action/actor filters; reject projection generations, query sessions, consistency modes, keyword search, keyring lifecycle, and the donor query projection. |
| Integrity stream, segment, checkpoint, witness, archive, and recovery domains | `REFERENCE` for canonical hashing; `REJECT` for Phase 1 implementation | Canonical domain-separated hashing reinforces the record-chain contract. Virtual slots, lanes, epochs, segment leases, materialization, signing, witness delivery, external checkpoints, envelope keys, and recovery manifests are a separate assurance platform, not the minimal per-tenant chain. Their own lease/fencing is operational concurrency, not ownership of producer Operations. |
| Retention, deletion, archive, S3/AWS/KMS/Tink/Zstd, edge WAL, replay, projection rebuild, snapshot export, and fifty-one-migration closure | `REJECT` | Phase 1 retention is indefinite and exposes no delete or archive path. These subsystems introduce configuration, credentials, workers, data copies, rollback branches, and failure modes that the accepted target explicitly defers. |
| Audit SDK client/outbox/auth helpers | `REFERENCE` for retry classification; `REJECT` as a dependency | Bounded responses, terminal versus retryable HTTP classification, duplicate-as-delivered behavior, fencing validation, and redacted failure classes inform adapters. The SDK brings protobuf/runtime-profile/TLS/token-provider abstractions and a generic event model that are not the target contract. |

## PaaS design comparison

The design donor is `REFERENCE` for keeping IAM and Audit as independent
authorities, rejecting local authorization fallback, deriving organization
scope from authenticated identity, committing business facts with a local
Audit outbox, and allowing asynchronous delivery after commit. Its existing
DevOps/GitLab execution authority, web-session/signed-assertion protocol,
projection release roadmap, embedded legacy evidence graph, and expectation
that already-existing IAM/Audit services can be reused are `REJECT`: this
repository must deliver the two real authorities inside its own offline
release.

## Resulting implementation constraints

1. Implement compact independent `iam` and `audit` services in this repository;
   do not import a donor module, generated tree, SDK, schema, or runtime.
2. Derive tenant and subject only from current credential bindings. Reject
   tenant/subject headers, organization selectors, caller-supplied permission
   subjects, ABAC maps, and all failure-time local fallback.
3. Use fixed code-owned roles/actions, opaque hashed sessions and service
   credentials, database time, exact bootstrap replay, and transactionally
   coupled IAM Audit outbox facts.
4. Admit a closed sanitized Audit event union authenticated by service
   identity derived by IAM from the producer's own current credential; do not
   accept a source selector or shared producer credential. Canonicalize once,
   classify exact replay, and append the immutable per-tenant sequence/hash
   chain in one database transaction.
5. Keep Audit delivery lease/fencing inside each producer's outbox mechanism.
   Audit owns ingested records, integrity, retention, and query—not PaaS or IAM
   worker lifecycle.
6. Keep IAM, Audit, and PaaS schemas, owners, migrations, runtime roles,
   credentials, pools, and processes separate, with no cross-schema reads.
7. Implement only bounded tenant-derived Audit query and verification with an
   opaque tenant/query-bound cursor and local read-access record. Defer the
   donor projection, archive, export, retention-deletion, checkpoint, and
   cryptographic key-governance closures.
8. Test behavior and security invariants rather than donor SQL text, generated
   files, path inventories, framework call order, or historical documents.

No donor source is copied and no donor repository is a build or runtime
dependency.
