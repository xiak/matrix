# FEAT-006 adoption review: Platform IAM and Audit authorities

- Status: Complete for the accepted foundation and the reviewed IAM replacement slices; later slices require their own fixed-source review
- Target: [`FEAT-006 Platform IAM and Audit authorities`](../features/FEAT-006-platform-authorities.md)
- Review date: 2026-08-25
- Refactor review date: 2026-09-11
- Direct donor dependency allowed: No

## Fixed baselines

| Donor | Commit | Worktree policy |
| --- | --- | --- |
| Legacy PaaS | `69336e51f94fa98f6aa278fa4c62382e224dbeaf` | Read only through Git object commands; exclude its worktree. |
| IAM/Audit foundation donor | `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d` | Read only through Git object commands; exclude its worktree. |
| PaaS design | `338d9b5fcb820120c32265e380c55e5f171cdb75` | Read only through Git object commands; use as rationale, not executable evidence. |
| Matrix platform-authority baseline | `9fd45b03ea398828fa3e74bf99961d2348c68299` | Existing target implementation; preserve its accepted installation/tenant authority separation. |
| Matrix Phase 2 tenant/account slice | `6a0f417743948a5303d3a3342cb1e8902c9d17f2` | Same-repository fixed functional patch; selective adaptation only, excluding its task checkpoint and other branch state. |
| Matrix installation Audit slice | `6401e9602d2a5313cdc31f38363b86f404505894` | Confirmed fixed public contract and storage patch; selective adaptation only, preserving this branch's accounts and FEAT evidence. |
| Access-management product reference | `1ad6884ff1f844429b477d5578a039ec809211d7` | Same-repository Markdown-only fixed source synthesized from the public Tencent Cloud CAM navigation on 2026-09-10; use for product vocabulary and source traceability, never as executable evidence or a runtime dependency. |

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

## Multi-tenant fixed-slice comparison

The multi-tenant target in FEAT-006 precedes the following focused recheck.
The new Matrix source is not a legacy dependency and is not adopted as an
entire moving branch.

| Fixed slice | Decision | Rationale |
| --- | --- | --- |
| Matrix `9fd45b0` IAM decisions, current-credential checks, platform-role guards, outboxes, and existing authority-process gate | `REUSE` | They own the current security boundaries and behavioral test harness. Tenant work must preserve platform actions and their restart/revocation regression. |
| Matrix `a36cf9817f522549b995ea9c1f0d873499b4fe62` verified multi-tenant IAM executable and original schema | `REFERENCE` for retained-session upgrade | Run the fixed schema-2 executable to produce actual accounts, changed credentials, revoked roles/sessions and unversioned active sessions before schema-3 migration. Do not retain its unsafe password-session behavior or treat this SQL test as permission for a cross-profile release transition. |
| Matrix `6a0f417` qualified login, alias reservation, tenant opening, member/query/password-reset workflows, and account-access console | `ADAPT` | Reuse tenant-local credentials, member paths, and primary-account protection. Replace exact-bootstrap-only platform permission with explicit platform roles. Daily administrator handoff must not transfer primary ownership; add credential protection for platform users without creating a second realm/member UI or tenant resource identity. |
| Matrix `6a0f417` producer-resolution endpoint | `ADAPT` | Keep one append-only endpoint and its authenticated producer identity. Registered-tenant membership alone is insufficient: add immutable IAM fact or historical decision evidence without reevaluating the original user's current authority. |
| Matrix `6a0f417` changes to `000002_managedservice_actions` | `REJECT` | The target's existing `000001` already owns these actions plus the accepted platform actions. Restoring a second overriding catalog would remove platform authority; the distinct `000003_tenant_accounts` storage slice can be adapted independently. |
| Matrix `6401e96` sealed ServiceIdentity installation, canonical encoding, namespaced Audit storage, platform query and populated-upgrade gates | `ADAPT` | Preserve its public function/column order and old tenant bytes, combine with existing dual-tenant accounts, and replace producer-home equality only with event-bound historical authority proof. Public Audit encoding remains the single owner. Its Phase 3 feature status is not imported or accepted by this branch. |
| Legacy `69336e51` `checkaccess/trustedsession/resolver.go` and `checkaccess/domain/evaluation_source_validation.go` | `REFERENCE` for lineage attacks; `REJECT` as code | The trusted actor/service lineage and exact applicable-source checks inform substituted-tenant/decision tests. Embedded context injection, policy/evidence graphs, grant snapshots, and delegation modes are not the target HTTP authority proof. |
| Legacy `69336e51` `authsession/contract/authorization_basis.go` | `REFERENCE` for explicit recovery authority; `REJECT` as code | Recovery cannot be an implicit ordinary session privilege. Its delegated-support/break-glass ownership graph is not required for the target's auditable tenant-administrator recovery and must not enter this implementation. |

## Resulting implementation constraints

The subsequent local installation-primary recovery target in FEAT-006 was
fixed before this focused recheck. It does not adopt a legacy recovery graph
or add any legacy build/runtime dependency.

| Fixed local-recovery slice | Decision | Rationale |
| --- | --- | --- |
| Matrix `5721b7b1a985f25c9730ddb9229a51f7f6c3b63a` sealed bootstrap, Argon2id, monotonic credential generation, SERIALIZABLE transactions and immutable IAM outbox proof | `REUSE` / `ADAPT` | Keep the existing receipt bytes, hash profile, session revocation, retry and exact historical-fact evidence; add a distinct purpose-limited local entry and atomic completion under the same IAM owner. Ordinary bootstrap or tenant-primary recovery must not become offline platform authorization. |
| Matrix `91af8482aa218f64f90a7151bca388918367dc7a` local capability/private-file contract and public BootstrapDigest | `REUSE` | Keep the frozen purpose, MAC input, original expected state, command/commitment receipt query, sanitized result and unique bootstrap digest owner. Installation consumes the same contract; no private codec copy or online recovery permission is introduced. |
| Legacy `69336e51` `authsession/contract/authorization_basis.go` and `bootstrapidentity/contract/recovery_basis.go` | `REFERENCE` for explicit same-installation authority; `REJECT` as code | Fixed-object inspection confirms that recovery is separate from ordinary sessions and binds installation authority. Its break-glass/recovery-mode reference graph, UUIDv7 closure and delegated-support model do not implement this bounded original-primary password transaction. |
| Matrix `5721b7b` public Audit encoder, closed action catalog and seven-column IAM claim | `REUSE` / `ADAPT` | Reuse the single canonical encoder and unchanged delivery contract. Add only the exact installation-primary SYSTEM fact; no generic SYSTEM/platform exception, fake user decision, or duplicate encoder. |

1. Implement compact independent `iam` and `audit` services in this repository;
   do not import a donor module, generated tree, SDK, schema, or runtime.
2. Derive tenant and subject only from current credential bindings. The
   Phase 2 qualified child-login suffix is only a credential lookup namespace;
   it does not select the tenant of an authenticated operation. Reject
   tenant/subject headers, post-login organization selectors, caller-supplied permission
   subjects, ABAC maps, and all failure-time local fallback.
3. The accepted foundation uses fixed code-owned roles/actions, opaque hashed
   sessions and service credentials, database time, exact bootstrap replay,
   and transactionally coupled IAM Audit outbox facts. The refactor reviewed
   below replaces only the role/action authorization representation through
   independently accepted, profile-bound slices; it does not weaken the
   credential, bootstrap or outbox invariants.
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

No legacy repository is a build or runtime dependency. The fixed Matrix
account slice is adapted in-tree under the existing IAM and console owners.

The tenant/subaccount extension rechecks the legacy
`authsession/contract/actor_identity.go` slice at `69336e51...`: `REFERENCE`
for typed session-to-authority reference binding and `REJECT` as an implementation.
Its UUIDv7 value-object closure, social identity models, and absent qualified
password login do not implement Matrix account aliases, tenant onboarding, or
subaccount management. Those workflows extend the existing target IAM owner;
no additional donor implementation or dependency is adopted.

## Public CAM architecture comparison

The fixed product reference is a supplier-neutral synthesis. The following
decisions were independently checked against Tencent Cloud's public CAM
documentation on 2026-09-11. These sources describe product objects and
observable authorization behavior; they do not disclose or constrain Matrix's
internal process topology.

| Publicly documented slice | Decision | Matrix rationale |
| --- | --- | --- |
| A main account owns its resources while users belong to one account; routine work uses separately authorized subusers or roles | `ADAPT` | Keep `Organization.ID == TenantID`, qualified tenant-local login and independent user credentials. Model the existing primary as a non-transferable tenant root identity, not a child tenant or a platform operator. The root and a revocable administrator user are different authorities. Sources: [CAM overview](https://cloud.tencent.com/document/product/598/10583), [user types](https://cloud.tencent.com/document/product/598/13665), [main account tasks](https://cloud.tencent.com/document/product/598/41656). |
| Users can inherit policies through groups for bulk authorization | `ADAPT` | Add tenant-confined user membership and group policy attachments after system-policy parity. Groups cannot authenticate, own resources or contain service principals. Source: [user groups](https://cloud.tencent.com/document/product/598/14985). |
| Identity policies, resource policies and ACLs use action/resource semantics; policy statements support effect, action, resource and typed conditions | `ADAPT` for the common policy core; `REFERENCE` for deferred resource policies/ACLs | Replace hard-coded role checks with one compiled policy evaluator. Start with system-managed identity policies and current resources; add customer versions and a bounded condition catalog in a later slice. Do not copy QCS/UIN identifiers or COS-specific ACL behavior. Sources: [policy overview](https://cloud.tencent.com/document/product/598/38503), [policy syntax](https://cloud.tencent.com/document/product/598/10604). |
| Requests default to deny; a matching explicit deny takes precedence over matching allows | `ADAPT` | This becomes the single evaluator invariant. Unknown vocabulary, revisions and authority failures remain deny. Source: [evaluation logic](https://cloud.tencent.com/document/product/598/10605). |
| Custom policy edits create versions and a selected default version controls effective permission | `ADAPT` | Use immutable policy versions, content digests and an atomic effective-version pointer. Tencent's exact five-version quota is `REFERENCE`, not a Matrix invariant. Source: [policy version control](https://cloud.tencent.com/document/product/598/37301). |
| A user/role permission boundary limits the intersection of otherwise granted permissions and grants nothing by itself | `ADAPT` in the customer-policy slice | Preserve the maximum-permission invariant and explicit-deny precedence. Do not add a boundary API before the common evaluator and a real delegated-administration gate exist. Source: [permission boundaries](https://cloud.tencent.com/document/product/598/48770). |
| A role is a virtual identity with a separate trust policy and permission policies, no persistent password/access key, and STS issues bounded temporary credentials | `ADAPT` in a later vertical slice | Introduce `Role` and `RoleSession` only after policies exist. Require both caller permission and target trust, preserve the original principal, and keep long-lived user/service credentials distinct. Sources: [role concepts](https://cloud.tencent.com/document/product/598/19421), [AssumeRole](https://cloud.tencent.com/document/product/1312/48197). |
| Role operations retain the assumer/session identity in operation audit | `ADAPT` | Extend the existing immutable decision and Audit correlation with direct and original principals; Audit remains evidence, never an online authorization source. Source: [role audit](https://cloud.tencent.com/document/product/598/115890). |
| Each product documents whether it supports service-, action- or resource-level authorization and which resources each API accepts | `ADAPT` | Matrix products publish a versioned `AuthorizationProfile` used by both static analysis and runtime validation. This machine-readable signed profile is a Matrix design, not a claim about Tencent's internal implementation. Sources: [supported products](https://cloud.tencent.com/document/product/598/67350), [product API example](https://cloud.tencent.com/document/product/598/70005). |
| SAML/OIDC user and role SSO, cross-account roles and regionally replicated policy state | `REFERENCE` and defer | Retain external-source and deployment prerequisites under IAM/012. Sources: [SSO overview](https://cloud.tencent.com/document/product/598/96014), [product consistency](https://cloud.tencent.com/document/product/598/10586). |
| ABAC/tag authorization | `ADAPT` | Implement typed, product-attested attributes in IAM/008; do not accept arbitrary caller maps. Source: [ABAC overview](https://cloud.tencent.com/document/product/598/74876). |
| Main-account keys, provider-specific user categories, account numbers, resource strings, console routes, quotas and API names | `REJECT` as Matrix contracts | Preserve the security lessons—secrets returned once, disable/rotate/delete lifecycle and least privilege—but do not clone Tencent identifiers, product-specific exceptions or UI wording. Source: [access-key lifecycle](https://cloud.tencent.com/document/product/598/40488). |

## Refactor decisions against the current Matrix implementation

| Current owner at `4c9cf650530be04e401bb6a76ce3a4946b8c6251` | Decision | Replacement boundary |
| --- | --- | --- |
| `Organization`, tenant lifecycle and resource ownership | `REUSE` | The organization remains the tenant account; no parallel `Account` aggregate or service is added. |
| `tenant_accounts.primary_principal_id`, primary login and original-primary recovery | `ADAPT` | Preserve the stable identity and credential lineage while making root ownership explicit and distinct from ordinary administrator permissions. Tenant root can never imply installation/platform authority. |
| `Principal` types `USER` and `SERVICE_ACCOUNT`, credential generation and current-state session checks | `ADAPT` | Keep long-lived human/workload separation and fail-closed reload. Add role-session/original-principal context only with the STS slice. |
| `BuiltinRole`, `RoleBinding` and role-management endpoints | `ADAPT` for data migration; `REJECT` as the final authorization model | Seed equivalent system-managed policies and migrate each binding to a policy attachment in one release-profile transaction. Do not preserve the old table/API as a second authority. |
| `authority.RoleAllows` | `REJECT` after parity replacement | One policy evaluator must reproduce the complete old role/action matrix before the switch, then own system and customer policies alike. |
| `ServiceCanRequest` and the IAM-global action enum | `ADAPT` | Preserve authenticated producer confinement but move product action/resource ownership into registered product profiles; do not infer ownership only from string prefixes. |
| credential-derived `POST /v1/authorize` | `ADAPT` | Keep caller and subject authentication; extend the request/decision with exact product profile, resource set, policy versions, original identity and condition digest. Caller-supplied tenant/subject remains forbidden. |
| immutable tenant/installation Audit, event-bound producer proof and local platform recovery | `REUSE` | Preserve canonical bytes, chain identity, seven-column claim and closed recovery facts. Policy refactoring cannot reclassify old events, revive credentials or grant platform roles. |
| The paused global `allowedActions`/action-availability proposal | `REJECT` as an authorization contract; `REFERENCE` for a future UI hint | Resource- and condition-sensitive permission cannot be represented as a globally authoritative action list. A later UI capability endpoint must be context-bound, revision-bound and conservative; the server still authorizes every request. |

The implementation requirements, slice order and acceptance now belong to
[`IAM/`](../../IAM/README.md), not a duplicate design in this adoption record.

## IAM/001 fixed action-catalog adoption

The smallest target is the existing action/resource/calling-service/scope
contract with one immutable owner; no new permission or dynamic profile is
implied. The target was recorded before this focused source inspection.

| Fixed source and slice | Decision | Reason |
| --- | --- | --- |
| Matrix `b0e8627b7e8303136875bda074f2e382c23dfc0b`: `api/iam/v1/enums.go`, `validation.go`, `authority/authorization.go` and owning tests | `ADAPT` | Retain exact accepted action literals, resource bindings, caller confinement, scope and verifier semantics. Replace the repeated inventory/switch/prefix definitions with one value-only catalog consumed by all three owners. |
| Legacy PaaS `69336e51f94fa98f6aa278fa4c62382e224dbeaf`: `accessgrant/usecase/action_validation.go` | `REFERENCE` | A referenced action must exist and explicitly support its authorization resource kind; unavailable or mismatched definitions fail closed. No legacy repository/reader/domain type is imported. |
| Same legacy commit: `accessgrant/seed/catalog.go`, `platformaccess/profile/domain/bootstrap_profile.go` | `REJECT` as implementation | Its multi-level grant graph, deterministic UUID framework, obligations and required platform-admin bootstrap profile do not implement this release's single sealed service purpose and bounded verifier probe. No bootstrap entitlement is inferred from a catalog entry. |
| Matrix fixed snapshot `66f772ea1363886669c4a0a5a8a729bf0407324c` | `REFERENCE` for subsequent consumer alignment | The installation owner identifies this as a host-enrollment consumer snapshot. It is not imported into the catalog slice, and its Phase 3 acceptance is not inherited. The complete integration must preserve its host actions and exact proof mappings; the eventual fixed donor review belongs to that slice. |

The foundation donor object `f51d5ed...` is not available in this checkout's
object database. Its prior foundation review is not new inspection evidence;
IAM/001 imports no code from it. The actual legacy review above uses read-only
Git objects, never the donor's working files.

## IAM/002 policy authority adoption

The smallest target is system-policy parity with immutable documents/versions,
one deny-first evaluator and transactional attachments preserving real revoked
history; the feature target precedes this review.

| Fixed source and slice | Decision | Reason |
| --- | --- | --- |
| Matrix `3b11eb9dbabd70211e665c00e4e665658b461bd1`: action definitions, actual decision tests and current `authority.RoleAllows` | `ADAPT` | Preserve the accepted action/resource/service/scope matrix, then remove the role-specific evaluator rather than keeping a fallback. |
| Legacy `69336e51f94fa98f6aa278fa4c62382e224dbeaf`: `accessgrant/domain/accessprofile/profile.go`, `statement.go`, `version.go` | `REFERENCE` for invariant separation; `REJECT` as code | The donor separates stable profile identity, version content, statements and defensive copies. Its multiple active versions, scope inheritance, obligation/operation/reference graph and external condition references do not implement this product's one effective immutable policy version or bounded typed language. No donor type, module or runtime is imported. |
| Matrix `aa345eca5f1ed3921000aa5380d5bfd2aa6d0a50`: current role-binding and local credential-recovery SQL/receipt contracts | `ADAPT` for storage; `REUSE` sealed history | Migrate exact binding IDs, versions and revoked history into attachments. Preserve historical receipt/capability bytes and one-shot recovery; a new policy model cannot supply an offline grant or revive a revoked link. |
