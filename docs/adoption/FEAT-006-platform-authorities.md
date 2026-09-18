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

The independent-chain target and invariant gates in FEAT-006 precede this
focused current-owner replacement; it introduces no additional donor runtime.

| Fixed current Audit slice | Decision | Rationale |
| --- | --- | --- |
| Matrix `b4bf4110efae1f3604d86587feb867579a8cfe50` repository transaction and error mapping | `ADAPT` | Replace only Audit SERIALIZABLE with REPEATABLE READ: exact event/head locks, immutable records and unique replay identity already own the invariant. Preserve stable snapshots, whole-transaction 40001/40P01 retry, five attempts and unknown-outcome refusal; do not apply this isolation choice to IAM. |
| The same fixed ingestion/query owner and `000001_authority` event/head/append functions | `REUSE` | Retain event-before-head ordering, early locking for audited reads, exact proof, SQL/ACL/RLS, atomic registry/record/head writes, canonical bytes and hash chains. Cross-chain interference does not justify a global lock, larger retry budget or weakened replay conflict. |

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
| Matrix `273196d2442fd70b6824ec10fcd4ef8ba0f95a38`: IAM migration Source and Audit transaction coordinator | `ADAPT` | Replace separately committed IAM fragments with one context-owned transaction including final verification, proved against actual retained old-binary data. Pace only known rolled-back Audit conflicts; retain attempt bounds and reject unknown outcomes. No shared migration framework, client retry workaround or second canonical encoder is introduced. |

## IAM/004 fixed group-adoption review

The Group target was frozen in `IAM/FEAT-IAM-004` before implementation. No
moving branch or another worktree is a donor, and no legacy group package is a
build or runtime dependency.

| Fixed source and slice | Decision | Reason |
| --- | --- | --- |
| Matrix `384d6d76b65498ed6b428ba9a2905ef67831b919`: ActionDefinition catalog, deny-first evaluator, policy/version/attachment store, SERIALIZABLE transaction owner and Account/User lifecycle | `ADAPT` | Keep one evaluator, credential-derived Account, immutable versions, outbox facts and exact evidence. Generalize the internal attachment target from principal-only storage to typed USER/GROUP without a group evaluator or second attachment table; inherited decisions add membership evidence. |
| Matrix `384d6d76b65498ed6b428ba9a2905ef67831b919`: direct User attachment/session snapshot and CurrentIdentity `policyAttachments` | `ADAPT` then replace | Direct attachments remain valid sources, but the effective permission snapshot must distinguish DIRECT from GROUP and bind the live membership. Do not retain the direct-only projection as a parallel effective-authority model. |
| Access-management product reference `1ad6884ff1f844429b477d5578a039ec809211d7`: Group, many-to-many membership and inherited policy behavior | `REFERENCE` for product behavior | Use Group as a non-login, non-owner User collection and preserve direct versus inherited provenance. External route names, quotas and unobservable internal topology are not Matrix contracts. |
| Tencent CAM public Group material analyzed at fixed `b0e8627b7e8303136875bda074f2e382c23dfc0b` | `REFERENCE` | It corroborates bulk authorization and multi-group membership. It does not prove database tables, transaction order, caching, consistency or Audit internals; those remain Matrix-owned and require real gates. |
| Legacy PaaS `69336e51f94fa98f6aa278fa4c62382e224dbeaf`: `app/ui/src/ui/xiak` social/group presentation | `REJECT` | It has no current IAM Action/Resource, membership authority, inherited evidence, Account isolation or fail-closed revocation contract. |
| Matrix account donor `6a0f417743948a5303d3a3342cb1e8902c9d17f2` | `REJECT` for Group implementation; `REUSE` only through already-adapted Account/User invariants | The fixed slice has no Group or inherited-policy authority. Qualified login, Account ownership and root/User protection already exist in the target and are preserved, not copied again. |
| Matrix `0bd6dd9dd8166fe31c67edb8cd49cd523606a401`: Audit `authority/cursor.go` and IAM credential/Group/account transaction owners | `REFERENCE` for cursor cryptography; `ADAPT` the IAM directories | Keep bounded strict base64url, purpose separation and constant-time MAC comparison. IAM owns a distinct persisted key and current-subject/query/complete-policy-source binding; it cannot import Audit internals, share the Audit key or treat its existing query binding as IAM authority revision evidence. Bearer-derived lookup/verification digests are `REJECT` as signing keys because a credential holder can derive them. Raw ID continuation is replaced, not retained as a fallback. |

The concrete API, lock order, capacity limits and acceptance matrix belong only
to `IAM/FEAT-IAM-004`; this adoption record does not duplicate them.

## IAM/005 policy publication and diagnostics adoption

The current-language diagnostic target was recorded in IAM/005 before this
focused fixed-object review. It does not reduce the feature's custom-policy,
condition, boundary or real-runtime requirements.

| Fixed source and slice | Decision | Reason |
| --- | --- | --- |
| Matrix `8117c54c112c842106d82fe934e460a280862549`: `api/iam/v1/policy.go`, current policy contract tests and `api/contractjson/decode.go` | `ADAPT` | Add deterministic safe field diagnostics to the existing strict validator; keep one bounded decoder and canonical/digest owner. Preserve rejection of duplicate/unknown fields and invalid scope/action/resource coverage. Do not duplicate grammar or include input values in errors. |
| Same fixed Matrix source: the current attached-policy evaluator | `REUSE` | Syntax validity does not publish a policy or authorize an attachment; the current owner-resolved snapshot and explicit-Deny evaluation remain mandatory. |
| Matrix `8117c54c112c842106d82fe934e460a280862549`: existing `identityaccess/accounts.go` serializable account authorization and `postgres/accounts.go` policy directory projection | `ADAPT` | Extend the existing current-credential/PDP/transaction owner with customer policy creation and exact content read. Reuse typed attachments, immutable versions and source outbox; no parallel publisher, evaluator or caller-selected account. Publication remains root-only until the feature's explicit safe delegation contract is implemented. |
| Matrix `7104b1de8f16ae82645e149b2c5376f983eae5cd`: `api/iam/v1/policy.go` immutable content/digest, PostgreSQL `guard_policy_metadata_change`, policy history and publisher transaction owners | `ADAPT` | Add customer-owned nondefault version reads, bounded version creation and explicit default selection under the existing current publisher/Policy locks. Keep content immutable, mutate only the Policy revision/default pointer, and retain the actual old version in historical decision evidence. No second compiler, policy store or automatic default publication. |
| Matrix `aa28c39ca25ad0136b4a7042f1f1ae358d4f1429`: current publisher/Policy lock, optimistic metadata revision, immutable outbox intent and exact default projection | `ADAPT` | Add display-name mutation through the same current PDP/root boundary and Policy revision. Preserve stable identity/content/attachments, current-authority replay checks and atomic outbox. Do not introduce another publisher, generic receipt framework or a name-derived policy identity. |
| Matrix `02fed1296d0f425e610812a870c85ed524295447`: policy metadata transitions, publisher locks, immutable content/default relation and outbox intent | `ADAPT` | Retire an unreferenced customer policy atomically without physically deleting content or permission history. Split shared publisher eligibility from active-policy lookup so only exact deletion replay can inspect its terminal result; do not weaken other active-only mutations. Replace retired-inclusive management inventory with current ACTIVE inventory to avoid lifetime capacity exhaustion. |
| Matrix `0ac6445a33fb2e592fe94d2787a87cd7460ec4ae`: policy version storage/guards, current publisher locks, exact content reads and retained lifecycle proof | `ADAPT` | Add irreversible nondefault version retirement to the existing content owner and release management capacity without deleting history. Distinguish a new publication from equal content by its monotonic Policy revision; retain old version IDs and canonical bytes. Do not revive retired IDs or relax the shared decision/attachment history guard. |
| Matrix `b99e082fa9ba8a6412eeb766387f4fbeb5df0aa3`: strict PolicyDocument codec/canonical, sole attached-policy evaluator, database-time decision and cursor authority | `ADAPT` | Add declared IAM-sourced time conditions to the same statement owner and pass the existing database clock through evaluation and cursor reauthorization. Preserve absent-condition bytes and retained decision proof; reject caller clocks, unknown condition sources and undeclared platform/probe support. No second evaluator or generic attributes interface. |
| Matrix `581ce7584527470e1fe377040eb98ffe161e83de`: typed time conditions, immutable content/canonical and owner-validated attached-policy snapshot | `ADAPT` | Extend the same condition structure with bounded exact string sets sourced only from IAM's authenticated Account/Subject. Distinguish duplicate key/operator from the same operator on different keys; normalize copied value sets without changing old single-value time or absent-condition bytes. Reuse current transaction, Group provenance and historical version proof, not a caller-supplied attributes map or a second evaluator. This is a fixed-source design choice, not acceptance of the planned string slice. |

Legacy `69336e51f94fa98f6aa278fa4c62382e224dbeaf` is not present in this
checkout's object database. The earlier IAM/002 review remains historical
context, not evidence of a new inspection. This foundation imports no legacy
code or runtime and makes no new claim about a donor diagnostic implementation.

For the resource-prefix target recorded in IAM/005, fixed Matrix
`4f22e223398fbe4523bc09d6a369677cb23767db` is `ADAPT`: its existing
PolicyResourceSelector, strict validator/canonical and sole attached-policy
evaluator gain a bounded literal prefix under an explicit ActionDefinition
capability. Its PaaS `getApplication`/`authorizePath` is `REFERENCE` for the
exact instance ID boundary; no PaaS production code is imported or changed.
Implicit action-name wildcards, arbitrary glob/regex execution and inferring
collection support from resource kind are `REJECT`. No legacy implementation
or runtime dependency is introduced; acceptance remains with IAM/005.

For the User permission-boundary target in IAM/005, fixed Matrix
`b342e9da08515f9172b29d1ac237a088171c9e53` is `ADAPT`: reuse its sole typed
statement evaluator, current session authority, User/Policy revisions,
restricted publisher transactions, cursor owner and immutable decision/outbox
evidence. A boundary must be resolved and recorded separately from positive
attachment provenance, then intersected with grants. Reusing the statement
language does not justify synthesizing an attachment or a second evaluator.
The fixed public analysis at `b0e8627b7e8303136875bda074f2e382c23dfc0b`
is `REFERENCE` for the User/Role maximum-permission and set/get/remove concepts;
it is not evidence of a vendor's database, locks, cache or historical proof.
Implicit removal on policy deletion, an absent snapshot treated as no boundary,
and a boundary that grants rights by itself are `REJECT`. No legacy code or
runtime is introduced. API, lock order and implementation acceptance belong
only to IAM/005; RoleSession integration remains with IAM/006.

For the current-identity console consumer in IAM/010, fixed Matrix
`119f232ea7cf7ba7d91a1ef6433e132e0127f03f` is `ADAPT`: extend its existing
strict HTTP decoder, AccountIdentity, scene and account-access renderer to
consume the mandatory UserPermissionBoundary projection. Its public
PolicyVersionReference is `REUSE` as the wire contract, not a policy body or
positive grant. Inferring rights from boundary names, defaulting missing
authority to null, and retaining a second old identity decoder are `REJECT`.
No external UI workspace or legacy runtime is imported; UI acceptance and
remaining boundary management belong to IAM/010, not this adoption record.

For User boundary management in IAM/010, fixed Matrix
`ef51b1d509e7e38dfb2146416c7e057a97638765` is `ADAPT`: extend the existing
UserAccess capability projection and account-access provider/detail form.
The fixed119f232e set/get/remove transaction is `REUSE`; it is not rewritten
in the UI. Root eligibility comes from the current transaction's Account
relation plus PDP, not a browser role-name check. Automatic new request IDs
after uncertain results and a failed read presented as no boundary are
`REJECT`. No new navigation framework, policy evaluator or legacy dependency.

For the next CAT-05 product-profile slice, fixed Matrix
`6292fa09ad286960a1098ad3383a896c9374bffe` is `ADAPT`: retain its single action
catalog, IAM-owned condition sources and actual apphosting/managedservice PEPs.
Its application-create collection, exact application-read and shared
offering-read collection/detail entry points are `REFERENCE` for explicit
target modes, not evidence of already implemented Profile admission.
Inferring instance/list behavior from an Action name, runtime wildcard growth
from the latest catalog, and a tenant-editable product registry are `REJECT`.
Registration and runtime acceptance belong to IAM/001 and008; no UI or legacy
runtime is imported by this slice.

For source-registered Profile projection, fixed Matrix
`c6bd0788c8978d34537c28020115352d23722ede` is `ADAPT`: keep bounded canonical
encoding and exact references, replace shape-local result kind with action-local
successful resource kind to preserve actual Account-to-User/Group/Policy and
Group-to-Membership authorization. Fixed
`be3c4a96b4381426c01cd6315eaa3713c2855982` is `REFERENCE` for exact pool-create /
target-register IDs and mixed pool/target list/detail shapes. Its host runtime
is not imported. Its full twelve platform actions define the final ABI difference
gate; the unpublished five-action draft is not represented as the final product.
Deriving collection semantics from action spelling or substituting a successful
child ID for the authorized parent is `REJECT`.

For the full platform-catalog target recorded in IAM/001, fixed Matrix
`be3c4a96b4381426c01cd6315eaa3713c2855982` is `ADAPT` for its twelve platform
Action/resource/scope definitions and closed drain/activate/remove Audit facts;
its PaaS HTTP handlers are `REFERENCE` for target modes, not an imported host
implementation. Its file history identifies
`ca7f6940159e53fbae183b7b6d5f379705a0cba1`, also contained in be3, as `ADAPT`
for the explicit node-enrollment.create collection-to-ExecutionTarget proof
and negative tests. Unrelated terminal/session actions in be3 are not part of
this slice. Fixed `8afc1f94c47671c9b4d01081099572ed6183953b` is `REUSE` for
the sole Profile encoding/projection and `ADAPT` for its PaaS declaration and
explicit SYSTEM policy document. Same-revision content replacement, automatic
existing-default advancement during seed replay, and treating collection
authority as exact final payload evidence are `REJECT`. This source decision
does not claim that the new actions, storage or runtime gates are implemented.

For immutable policy-compilation content in IAM/005, fixed Matrix
`2bcbe50afaa025380c76c9cd232cd204d87b67a3` is `REUSE` for its strict
policy grammar, document canonical bytes, Profile encoder and complete product
declarations, and `ADAPT` for the validator's capability lookup. Explicit frozen
Profile inputs replace a dependency on the current global catalog when validating
compiled content; current publication continues to use the same validator with
current capabilities. The complete author document plus exact product references
and SID-bound resolved actions form one new domain-separated commitment.
Caller-selected profile heads, runtime pattern growth, and a second policy
grammar or copied canonical implementation are `REJECT`. This contract-only
adoption does not change the current PolicyVersion wire or prove registered
history, SQL publication, real Profile-bound decisions or product PEP behavior.
The same fixed source's Audit query/verify sentinels are `REFERENCE` for
authority-wide collection semantics, not caller-selectable chain instances.
Its unpublished PaaS revision2 and Audit instance-verification declaration are
`REJECT` as release contracts: replace the drafts with complete first-revision
declarations before runtime registration. There is no published Profile consumer
to justify preserving either draft. Immutable revisions after actual registration
remain mandatory; this is not permission to rewrite registered content.

For IAM/001 immutable registration and current-source admission, fixed
`d3a08bfa7c248793ffb51499186486efa2ebb377` is `REUSE` for the only Profile
canonical encoder, exact-reference validation and complete first declarations.
Its existing authority migration transaction, owner/runtime separation and
immutable policy history protection are `ADAPT` for the archive/current-head
boundary. Current selection is explicit, not the last or maximum archived
revision. Exact historical lookup never substitutes the current head.
Runtime registration, current-head fallback, same-tuple replacement and a
copied JSON canonicalizer are `REJECT`. No legacy dependency, host runtime,
new product HTTP API or published installation profile is imported.

For IAM/001 current request/decision binding, fixed
`fdb880345e4e46d296330f25f7072dbfef408c87` is `REUSE` for exact immutable
Profile lookup, source-head admission and the existing request digest owner;
its recorder/evidence and product PEPs are `ADAPT` for explicit target modes
and protected decision contract metadata. Reconstructing an original request
in a production adapter, accepting absent fields as legacy eligibility, and
retaining the old recorder/private assertion overloads are `REJECT`.
Fixed `384d6d76b65498ed6b428ba9a2905ef67831b919` remains `REFERENCE` for
the earlier decision-contract cutover, but is `REJECT` as a positive source
for the compiled-policy cutover: it does not satisfy this slice's explicitly
proved Root management/interpretation baseline. The existing retained-policy
gate now uses fixed1dc rather than expanding unpublished schema1..N support.

For IAM/005 compiled-version cutover, fixed
`1dc1079c4e7bec80f5345d06929875b492ba9a86` is `REUSE` for the sole
policy compiler/canonical encoder, immutable Profile archive and explicit
request target contract; existing publication, version retirement, defaults,
attachments and history are `ADAPT` owners. Its document-only policy rows are
`REFERENCE` for retained bytes, not proof of each row's originating executable
or permission to infer a missing compilation. A supported legacy interpretation
requires fixed-source and actual predecessor/PEP non-expansion evidence.
Automatic recompilation/default movement, current-head historical fallback,
and treating an old row or an existing r1 archive as provenance are `REJECT`.
No host implementation, published release profile or other worktree state is
adopted by this slice.

Fixed `f272d06f84d8a753f0a7ec2cf3dc4276f637d660` is `REUSE` for the pure
frozen/current compatibility check before any selector, condition or Effect.
The selected1dc source's exact SYSTEM seed IDs/digests and immutable r1
declarations are `ADAPT` as a closed interpretation ceiling, never an author
compilation or a mutable name allowlist. CUSTOMER document-only content is
`REFERENCE` for management/history only until Root explicitly publishes a
compiled version and selects it. Root CUSTOMER attachments require old-API
removal before cutover; privileged corrupt Root/group fixtures are negative
tests, not old-version provenance or supported user workflows.

For IAM/005 bounded action-family patterns, fixed
`32dc1a4aab4a69d1c6cb4d04437dd7f8fd739cb0` is `REUSE` for the sole
author/compilation canonical owner, exact Profile references and pre-match
compatibility validation, and `ADAPT` for statement capability validation over
the frozen resolved action set. Its exact-only SQL publication and PDP are
`REFERENCE` for the subsequent atomic runtime cutover, not pattern support.
Runtime glob evaluation, current-head expansion of old versions, silently
filtering incompatible declarations, global/product-only wildcard authority,
and a second policy grammar or encoder are `REJECT`. The pure compiler slice
does not enable HTTP publication, change schemas, or import other worktrees.

For the IAM/005 runtime family cutover, fixed
`9febf76690e96f98abbf265b3ce840b8bf3dbc2c` is `REUSE` for the frozen
three-segment compiler, unchanged exact commitments and pre-deduplication work
budget. Existing32dc publication transactions, immutable archive loader,
private SQL assertion, recorder and sole PDP are `ADAPT`: validate full
resolution, then match only exact resolved SID actions. Transport integrity
alone, author-action fallback, SQL LIKE/caller regex, scope-filtered expansion,
automatic default advancement and rewriting registered r1 are `REJECT`.
No new permission, runtime product-registration API or release profile is adopted.
The same fixed32dc private SQL action CASE projections are `REJECT` as a second
current catalog; their owner-only signatures are `ADAPT` to registered current
Profile content. Historical exact-archive proof and closed event-to-decision
mapping are `REUSE`, not replaced by current-head lookup. Source-commitment
equality remains complete; reflective traversal is `ADAPT` to typed field
comparison, never a reference-only trust shortcut or cached permission.
Full supplied Profile validation is `REUSE`; building temporary indexes for
unreferenced actions is `ADAPT` to exact author dependencies and all matching
family members. Skipping malformed unrelated declarations or filtering a
requested family's scope/condition conflicts is `REJECT`.

For IAM/001 readonly editor discovery, fixed
`f15cc983a69092528a66eb49b0509b760392187c` is `REUSE` for the single
AuthorizationProfile declaration/canonical owner and locked registry/source
consistency. Its existing Account management transaction, iam.policy.list
decision, strict HTTP boundary and contract generator are `ADAPT` for a bounded
metadata response. A copied UI action catalog, caller-selected current/history,
filtered declarations retaining an original digest, directory-as-permit,
registration/write APIs and a new audit event are `REJECT`. No legacy runtime,
other worktree or product implementation is imported; acceptance belongs to001.

For IAM/006, the smallest first runtime target is current Account Root management
of custom Role metadata, immutable same-account USER trust and tenant policy
attachments. Role credentials and product authorization remain mandatory later
gates, not implied by CRUD. Fixed `40407e2710a45ee1000552146cd362740074369a`
Group/Policy transactions, restricted PostgreSQL functions, current PDP,
credential-generation ownership, strict JSON and ordinary IAM fact/outbox are
`REUSE`/`ADAPT`; never model a Role as a password-bearing USER or GROUP.
The same fixed source's User-boundary private session reference and sorted
principal locking are `ADAPT` for attachment writes. Its older attachment
mutation carries no session reference; treating an authorization decision as
proof of the calling session, or retaining its session-less SQL overload as a
fallback, is `REJECT`. Credential/current-session checks stay with the existing
transaction owner, not a new interchangeable cache authority.
Fixed `1ad6884ff1f844429b477d5578a039ec809211d7` roles-and-trust.md and
temporary-credentials-and-sts.md were inspected as `REFERENCE` for product
separation, double-sided admission, bounded sessions and lineage. Their generic
signed-token/cache descriptions are `REJECT` as Matrix implementation: use the
existing opaque, purpose-separated credentials and authoritative current reads.
No legacy Role/Trust runtime implementation is imported or claimed reverified;
the earlier fixed legacy rejection remains in force.
Fixed `1bcaa62bf6b11c20a7b34458408a221ed0aa633c` is `REUSE` for the sole
strict trust contract/canonical encoder. Fixed `f9ca482df5bde3c8689e9d105f382e178a6abdab`
is `REUSE` for current authenticated attachment sessions and audited-read head
locking; the existing closed IAM event/Audit catalog is `ADAPT` for Role facts.
Its directory cursor codec is `ADAPT` only to add the exact Role directory and
same-Role trust-history queries. Permissive unknown-directory handling,
rewriting registered IAM Profile r1 or advancing retained SYSTEM defaults is
`REJECT`; R1 appends the source-owned r2 and requires explicit current grants.

On2026-09-16, the primary [AssumeRole API](https://cloud.tencent.com/document/product/1312/48197)
was rechecked: caller permission and target carrier trust are separate, and
session policy/duration are distinct inputs. These are `ADAPT` semantics, not
permission to copy caller SourceIdentity, provider ARNs, provider-specific token
triples, quotas or unimplemented MFA/IdP/service selectors. The primary
[role-audit guide](https://cloud.tencent.com/document/product/598/115890) is
`REFERENCE` for retaining the actual assumer, not authority to infer a stable
identity from a caller-chosen session label. The role-concepts page timed out;
its fresh contents were not used as new evidence. Exact Matrix fields, lock
invariants, actions, budgets and acceptance remain owned by006.

For R2, fixed `bf7e8fbbdffe96b8af5b250edd1ed746c5b99265` is `REUSE` for
the complete Role/trust owner, source-qualified current sessions, opaque
credential issuer and immutable IAM facts. Its cursor's full attachment,
membership, Policy/default and boundary revision projection is `ADAPT` for
source-authority change detection, not a cursor or digest that grants access.
Current-Allow-only checks that revive a session after revoke/regrant, a Role
stored as a USER, and a second policy/canonical or credential implementation
are `REJECT`. Existing USER-only Subject/Audit/Operation handling is `ADAPT`
only with a complete typed ROLE lineage and actual consumer/storage gates;
enum-only acceptance or platform/probe widening is `REJECT`. The existing
once-only secret response owner is `ADAPT` for issuance, while permanent
plaintext replay, silent reissuance after unknown outcome and a generic
receipt/cache service are `REJECT`. R2 does not adopt a new deployment or
release profile from another task.

For001/005 subject capabilities, fixed
`6ae975d9a65569d5215fca26ef65a16722d2cd13` is `ADAPT` for the existing
Profile encoder/deep copy, strict JSON/schema and sole compiled-policy request
compatibility check. Its immutable registered declarations and digests are
`REUSE`; absent subject types retain only their original USER/probe ceiling.
Adding ROLE to PrincipalType, rewriting old declarations, automatically
recompiling defaults, dropping an incompatible old Deny, and a second
product/scope-based ROLE allowlist are `REJECT`. Subject capability does not
prove an authenticated RoleSession or a working PaaS/Audit consumer. The actual
R2 source revisions and SQL/actor cutover remain owned by006.

For R2 retained subject-capability acceptance, fixed
`d45402d91c89a5bb23f52fcfde65491435cd0f55` is `REFERENCE` as the actual R1
executable that issues USER-only compiled policy content and real Role
attachments. Its source is built only inside the existing authority-process
fixture, never imported as a runtime dependency. The existing fixed IAM21
`1dc1079c4e7bec80f5345d06929875b492ba9a86` gate remains `REFERENCE` for the
distinct document-to-compilation interpretation boundary. Both use their
actual registered declaration and preserve original bytes/defaults; inventing
legacy state by deleting current fields, granting ROLE by replacing an old
Profile, and replaying every unpublished schema revision are `REJECT`.
Implementation status and runtime evidence belong only to IAM/006.

For R3 self-service discovery and current-role display, fixed
`0752c602ab4ce6d73a21094c8e9f75a1c8750183` is `REUSE` for the separate
USER/ROLE credentials, current-role lookup, sole policy/trust evaluator,
purpose-bound cursor owner and strict API codec. Its RoleAccess projection
and bounded read adapters are `ADAPT` for minimal same-account self views.
Reusing the issuance-only `read_role_assumption` as a directory reader is
`REJECT`: it takes issuance locks and interprets an issuance request ID.
Requiring management list/read permission to discover an otherwise assumable
role, revealing every account role with a forbidden flag, frontend Trust
evaluation, cached identity as a permit and an old/new current-identity wire
alias are `REJECT`. This is a target adoption decision, not R3 implementation
or browser acceptance; those remain in IAM/006 and the UI owner.

For irreversible RoleSession source authority, fixed
`960416dd85adab225bd97ee89509df04173f978b` is `ADAPT` for the existing
source/role snapshot, concrete transactional mutation triggers and current
credential lookup. Its account directory row is `REUSE` only as an explicit
writer lock barrier, never its numeric revision as session authority. The
once-only issuer, recorder8/evidence5/claim7 and single Audit canonical owner
are `REUSE`. Fixed `0752c602ab4ce6d73a21094c8e9f75a1c8750183` is `REFERENCE`
for actual old IAM/PaaS executables producing retained RoleSessions,
Operation, outbox and private evidence. Old proof bytes remain unchanged;
only fully qualified old issuance receives a protected interpretation marker.
Active-source-only ABA checks, fabricated old generations, a default legacy
marker, account-wide session invalidation, event-history scans per request,
counter reset during replay, and deadlocks hidden by retry are `REJECT`.
The retained actor foreign keys are `REUSE`; Role/Policy publisher, User
boundary and attachment actor/USER locks are `ADAPT` to preserve non-key
identity-state exclusion without conflicting with the preceding decision's
KEY SHARE, including self-target rereads. Removing referential integrity,
dropping current actor/session or platform credential protection checks,
or accepting conversion deadlocks is `REJECT`.
This does not create a runtime donor dependency or a release upgrade promise.

For administrator RoleSession management, fixed
`1ebab37aef4bce12b963f52d3919748a9d50d4c6` is `REUSE` for the immutable
issuance record, separate USER/ROLE credentials, sole PDP/cursor/Audit
encoding, source generations and non-key actor locks. Existing role
directory and terminal revocation adapters are `ADAPT` for bounded
role-nested management, exact receipt observation and a decision-backed
administrator fact. Self discovery, possession-only exit and source-user
revocation remain distinct contracts. Reusing their permission-free fact as
administrator authority, treating ACTIVE as business eligibility, exposing
private lineage, unbounded history scans, fake resource versions and
cursor watermarks as permits are `REJECT`. No UI preview shape or donor
runtime becomes a dependency; implementation and evidence belong IAM/006.

## Programmatic credentials target review

The smallest enterprise target is owned by IAM/007: non-root USER key
lifecycle, one-time secret disclosure, installation-separated encrypted
material, request-bound signatures, durable replay rejection and current
policy enforcement. The following review does not claim an implemented
AccessKey or a published signed protocol.

| Fixed source / slice | Decision | Rationale |
| --- | --- | --- |
| Matrix `1ebab37aef4bce12b963f52d3919748a9d50d4c6`, credential/secret encoding, current USER/PDP, transaction/outbox and real PEP owners | `REUSE` for secret redaction, current authority and tests; `ADAPT` for distinct credential carrier | Actual `SubjectContext` requires a Session and product adapters parse bearer only. A fake Session, another PDP, or exchanging a signed request for a reusable USER permit is rejected. Opaque digest verification cannot verify HMAC. |
| Matrix `be4974e68fc167b418c9eee00c96aaf1b844693f`, record-bound HKDF/AES-GCM and explicit info/AAD encoder | `REUSE` material format/vectors; `ADAPT` the unique binding owner into `api/iam/v1` | Installation and IAM need one purpose-limited private-file/commitment contract. Preserve exact format1 info/AAD bytes, delete the old authority encoder and reuse a single private length-prefix primitive. A second encoder, generic caller-defined canonicalizer, whole-document commitment or wrapping-ID rebind is `REJECT`. This does not adopt any installation WIP or prove runtime custody. |
| Matrix `bc7d059571b55ee84c58b62adf1d794cf63ff9a6`, private keyring codec, process file reader, SERIALIZABLE transaction and USER/GROUP authority generation owners | `REUSE` codecs, protected reads and authority barriers; `ADAPT` network custody and key lifecycle | Keep one exact private encoder, immutable process-owned material and existing authorization generations. Key management needs a separate permanent registry/once-only creation intent, not a fake Session or a second PDP. A principal row lock alone does not refresh a stale snapshot; stabilize current identity/boundary policies before generation locks, matching existing publishers and attachment writers, without giving keys RoleSession revocation semantics. Missing files never generate replacements, and source readiness never grants release compatibility. |
| Same fixed `bc7d0595`, purpose-separated length-prefix encoding, redacted Secret and raw32-byte material format; product-reference `1ad6884f` signing document re-read at its fixed object | `REUSE` the private byte primitive and material decoding; `ADAPT` one bounded request-signature transport | Preserve encrypted format1 bytes. Explicitly bind external scheme/authority/raw target and behavior-changing headers; strict UTF-8/percent validation preserves duplicate-query value order. Use independently generated Node vectors, not only a shared Go encoder round-trip. Reject vendor region/date derivation, fake login Sessions, caller-provided body digests, bearer exchange and a second PDP. Pure HMAC/codec does not adopt any gateway rewrite or prove nonce consumption. |
| Same fixed `bc7d0595`, `authorization_profile.go` subject capability, canonical sets, deep copy and immutable-source equality | `REUSE` the single Profile encoding and exact-reference check; `ADAPT` explicit USER authentication methods | USER support does not imply AccessKey support. Preserve absent-field historical bytes with LOGIN_SESSION-only meaning; bind the new bounded set to the original digest and compare/copy every field. A new SubjectType, product-name whitelist, changed current source head or registration inferred from syntax is `REJECT`. Pure admission metadata does not prove current credentials, nonce consumption or policy compatibility. |
| Same fixed `bc7d0595`, `policy.go` complete frozen compilation/current-request check | `REUSE` complete commitment and exact target validation; `ADAPT` an AccessKey-only stricter semantic check | The only permitted extension is adding the key carrier while retaining LOGIN_SESSION; an already-declared key carrier may remain unchanged. Compare every other action field through the existing canonical owner, including unused shapes/conditions and subject capabilities, before Allow/Deny selector matching. Reject rewriting stored compilations, dropping an incompatible Deny, extending frozen action families or loosening the existing login/ROLE path. |
| Matrix `d2b1db475c5c60fd6f7f680f0149935fbb903129`, K1 actor/target locks, USER/GROUP source generations, key tombstones and original service credential tables | `REUSE` current projections, generation barriers and real immutable identities; `ADAPT` credential-bound cross-account lookup | The installed service home is not the target account. Lock sorted physical Accounts/principals before credential, policies, generations and key; keep known disabled states for later MAC-verified Deny. An owner-only key locator must refer to the real retained key, and the service locator must bind the original lookup digest as well as principal. Inferring platform protection from filtered ACTIVE policy snapshots, inventing service credential versions, fabricating login Sessions, and accepting material as permission are `REJECT`. This adoption does not prove atomic nonce/decision recording or consumer integration. |
| Same fixed `d2b1db47`, `decideAndRecord`, record8, original outbox/proof and Audit actor/canonical owners | `REUSE` the single PDP and atomic decision/outbox; `ADAPT` record9 and typed one-to-one signature evidence | A valid MAC's Deny must commit its permanent nonce, while malformed or unauthenticated requests allocate none. Preserve USER login, ROLE and SERVICE separation; extend only the closed USER key attribution and keep absent-field historical bytes. Replaying an old permit, cache/local-map nonce authority, a second recorder/canonical encoder, current reauthorization of committed facts, and claiming SQL independently verifies the MAC or final business payload are `REJECT`. Product PEP and installation adoption remain separate gates. |
| Product reference `1ad6884ff1f844429b477d5578a039ec809211d7`, `access-key-lifecycle.md` and `request-authentication-and-signing.md` | `REFERENCE` | The fixed files were read for one-time disclosure, overlapping rotation, actual request coverage, current revocation and source-network restrictions. They do not provide executable or independently verified cryptographic code. |
| Same fixed product reference: generic four-state key model, vendor-derived signature scope, unavailable MFA/SSO and regional/VPC vocabulary | `REJECT` as a mandatory first implementation | Concrete Matrix lifecycle, protocol and supported integration boundaries belong007. Do not import a second revocation state without a distinct accepted operation, foreign headers or unsupported network/provider selectors. |
| Foundation `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d`, previous service-account/client-secret review in this record | `REFERENCE` only to the prior recorded review; `REJECT` as new code adoption | Its Git object is unavailable in this task and sources.yaml contains no physical URL/path. This review does not claim a fresh inspection. No guessed repository, moving branch, plaintext store, donor JWT/Redis framework or runtime dependency is admitted. |

Public-reference cross-checks are requirements input, not source-code donors:
[Tencent key lifecycle](https://cloud.tencent.com/document/product/598/37140)
confirms creation-only Secret disclosure and overlapping keys;
[RFC9421](https://www.rfc-editor.org/rfc/rfc9421.html) is `REFERENCE` for
explicit covered components, application requirements and replay/HTTP
ambiguity attacks. This is not a claim that Matrix implements the whole RFC
or the vendor's protocol. Runtime and acceptance facts remain solely in007.

## Login session self-management target review

The smallest target is owned by IAM/009 S1: the authenticated USER lists its
own actual login Sessions and irreversibly ends another, preserving current
credential-generation checks, exact intent and immutable tenant facts. It is
not administrator discovery, RoleSession/AccessKey management or a new store.

| Fixed source / slice | Decision | Rationale |
| --- | --- | --- |
| Matrix `644fff09446fc8ffb003cc53cf2fb55d4f58828a`, `authentication.go`, `management.go` and original session SQL | `REUSE` real Session/generation and transaction/outbox; `ADAPT` owner-bound discovery and atomic self-revocation | Existing logout proves its current bearer, while the five-argument SQL function only relates supplied principal and target in its self branch. Adapt that same owner with the actual caller Session and replace its weaker shape; do not create a second revoker. The original terminal row/outbox lacks a unique caller-Session/request binding, so a narrowly typed immutable self-revocation completion is required for exact replay. Neither caller IDs nor `applied=false` prove that intent. No blanket self permission is added to the administrator action. |
| Same fixed source, original opaque `CursorCodec`, Role self-exit and immutable outbox/terminal receipt checks | `REUSE` bounded encoding and original fact ownership; `ADAPT` the closed login-session purpose and exact completion binding | A cursor is not a permit or a frozen directory snapshot. Keep a single codec and database authority; do not copy Role issuance/source-authority vectors into a login Session, fabricate a Session or add Redis/generic SessionStore. A revoked target or historical event alone does not prove this request completed. |
| Matrix `c2fbd9e38d424e68c0466618ee74613aced3c3fb`, fixed Phase3 K2 integration | `REFERENCE` shared-owner integration boundary; `REUSE` the identical S1 session owners already present here; `REJECT` importing PaaS, release profile or acceptance state | The fixed diff has no changes to S1's IAM types/validation/generator, PostgreSQL, authentication/management or cursor relative to `644fff09`. Its other changes belong to product action catalogs, proof mappings and actual consumers. Shared S1 edits use this confirmed boundary without merging another branch or inheriting its acceptance. |
| Product reference `1ad6884ff1f844429b477d5578a039ec809211d7`, `04-user-guide/users/login-and-operation-protection.md` | `REFERENCE` session expiry/revocation and authentication-strength boundaries; `REJECT` unproven device/online metadata or runtime adoption | A physical device is not a Session. Client/IP/activity/MFA labels require real trustworthy inputs. Source prose is not an implementation, database authority or reason to introduce unsupported providers, cookies or risk scores into S1. |

The source review is not an acceptance claim or a release migration promise;
routes, qualification, shared edit windows and actual gates belong IAM/009.

## Local MFA governance target review

IAM/009 owns the target: a real USER binds a local TOTP authenticator,
completes the required factors before receiving a login Session, and uses
purpose-limited one-time recovery without acquiring another identity or
platform permission. This is design review, not an implementation window.

| Fixed source / slice | Decision | Rationale |
| --- | --- | --- |
| Matrix `644fff09446fc8ffb003cc53cf2fb55d4f58828a`, `authentication.go`, `credential.go`, password and transaction/outbox owners | `REUSE` password verification, redacted secrets, purpose-separated random credentials and transactions; `ADAPT` an explicit incomplete-authentication boundary | Password success currently issues a Session, and no TOTP/challenge authority exists. Do not put a pre-authentication challenge in the Session table, treat a factor-bound flag as completed MFA, or add a second IAM/STS service or generic store. |
| Same fixed source, AccessKey material/keyring contract and ADR-0004 | `REFERENCE` custody and failure-closed requirements; `REJECT` direct use for MFA seeds | Its wrapping purpose, subject/material binding and installation consumer are specifically AccessKey. MFA needs an explicitly agreed independent material boundary, not an AccessKey row, password hash, cursor key or local-recovery secret repurposed as seed custody. No installation WIP or MFA custody implementation is adopted. |
| Same fixed source, `local_recovery.go`, `000003_tenant_accounts` and `000004_local_credential_recovery` | `REUSE` original root/platform protection and exact immutable intent principles; `REJECT` implicit authenticator recovery authority | Existing capabilities only change passwords under their sealed purpose; neither online reset nor offline password recovery authorizes removal of a future factor. A DB-only epoch/consumption record also cannot prove non-revival across a restored backup. New purpose/backup boundaries require their actual owners and gates. |
| Product reference `1ad6884ff1f844429b477d5578a039ec809211d7`, `04-user-guide/users/login-and-operation-protection.md` | `REFERENCE` binding, step-up, login protection and recovery requirements; `REJECT` executable or current-policy inference | It is requirements prose, not code or proof of MFA, cookie sessions, risk scoring or automatically enforced administrator rules. Its encrypted recovery-code recommendation is not adopted: one-way verification suffices for offline high-entropy saved codes and avoids later recovery of plaintext. |

[RFC6238](https://www.rfc-editor.org/rfc/rfc6238.html) and
[RFC4226](https://www.rfc-editor.org/rfc/rfc4226.html) are `REFERENCE` for
the OTP construction and independent fixed vectors, not source-code donors.
[NIST SP800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) is
`REFERENCE` for one-time verification, throttling, hashed saved recovery
codes and the absence of OTP phishing resistance; this is not a compliance
claim. No library/version is selected or added by this review. Runtime,
material protection, recovery eligibility and acceptance belong solely009.

## Password and authentication-budget target review

IAM/009 owns account-governed password changes and bounded multi-instance
authentication; configuration is not an authorization Policy. This review
does not open the shared implementation window or alter installed defaults.

| Fixed source / slice | Decision | Rationale |
| --- | --- | --- |
| Matrix `644fff09446fc8ffb003cc53cf2fb55d4f58828a`, `authority/password.go` and its current tests | `REUSE` the strict versioned Argon2id verifier, salts and redacted secret handling; `ADAPT` new-password rules separately | Account rules must not change hashing cost or reinterpret old password bytes. Existing byte-count/category rules are current behavior, not evidence that account settings, history or a blocklist exist. |
| Same fixed source, `authentication.go`, `management.go`, `service.go`, `lookup_login`, `user_credentials` and existing password mutation functions | `REUSE` canonical realm resolution, real credential generations and transaction/outbox ownership; `ADAPT` durable authentication outcomes and bounded admission | Current authentication errors roll back the workflow transaction. Failure counts need committed outcomes, while cross-replica in-flight attempts must not bypass a post-hash counter. Existing changed_at is real password history metadata, not a collection of prior password verifiers. |
| Same fixed source, `issue_session`, `lookup_session`, IAM process/HTTP entry and `processhttp/server.go` | `REUSE` database time, absolute expiry and current qualification; `REFERENCE` process limits only | HTTP connection timeouts and a default eight-hour Session do not provide per-account settings, idle expiry, crypto-work admission or cluster-wide abuse protection. Product/edge source addresses require their actual consumer authority, not arbitrary forwarded headers. |
| Product reference `1ad6884ff1f844429b477d5578a039ec809211d7`, `04-user-guide/users/login-and-operation-protection.md` | `REFERENCE` configurable password, expiry, history and login restrictions; `REJECT` unsupported implementation/default inference | Product prose supplies requirements, not proof of persisted counters, current MFA or a trusted network source. Do not infer root/platform credential control from tenant administrator status. |

The official [password-rules reference](https://cloud.tencent.com/document/product/598/36249)
is `REFERENCE` for the distinction between configurable subuser rules and
credential operations. Vendor-specific minima, composition defaults,
lockout durations and the public hashing description are not adopted as a
Matrix cryptographic implementation or production default.
[NIST password-verifier requirements](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver)
are `REFERENCE` for length, blocklists, full-secret verification and bounded
attempts, not a Matrix compliance claim. Rules, actual budgets, history
retention, permissions and acceptance remain with009; no blocklist dataset,
new dependency or configurable production API is adopted by this review.

## Security-report and idle-governance target review

IAM/009 owns scoped credential reports, accurate activity coverage and
current-authority remediation. Reports are observations, not authorization
or proof that an object has never been used.

| Fixed source / slice | Decision | Rationale |
| --- | --- | --- |
| Matrix `644fff09446fc8ffb003cc53cf2fb55d4f58828a`, `CurrentIdentity`, `PolicyGrantSource`, `ActionCapability` and the single authority evaluator | `REUSE` actual direct/group/boundary lineage and evaluation rules; `ADAPT` an explicitly authorized diagnostic projection | The current public decision only distinguishes ALLOWED/DENIED. A capability hint, flattened action list or today's reevaluation is not a historical explanation or an executable permit. |
| Same fixed source, `AuthorizeAccessKey`, `decideAndRecord`, immutable decision/key/Role evidence and IAM outbox | `REUSE` committed attribution and exact event identities; `REFERENCE` as activity sources | Valid-MAC Deny is distinct from bad MAC, replay, business acceptance and business success. No last-used/report authority exists; maximum event time or outbox pending=0 cannot prove cross-product completeness. Preserve older records without invented lineage. |
| Same fixed source, AccessKey metadata/mutations and existing User lifecycle | `REUSE` versioned, protected target mutations and permanent deletion history; `ADAPT` explicit idle preconditions only when supported | An old report cannot authorize a new mutation, and updated_at is not last use. Automatic idle decisions need current qualification and complete activity evidence under the real target lock; existing verifier or service purpose cannot acquire generic tenant write rights. |
| Product reference `1ad6884ff1f844429b477d5578a039ec809211d7`, `04-user-guide/security-analysis-report.md` and `07-practices/operation-audit-and-accountability.md` | `REFERENCE` reporting/diagnosis/remediation needs and evidence distinctions; `REJECT` runtime, risk-data or wire-format inference | The prose does not prove current MFA/IP signals, exported artifacts or cross-account analysis. Its example event is not adopted over the actual closed Audit/canonical contract; missing source data stays unknown. |

The official [credential-report reference](https://cloud.tencent.com/document/product/598/65676)
is `REFERENCE` for a downloadable, scoped credential-status view; the vendor's
four-hour reuse window and numbered key columns are not Matrix contracts.
[OWASP CSV Injection](https://community.owasp.org/attacks/CSV_Injection)
is `REFERENCE` for export tests, including the limits of quoting across
spreadsheet clients and save/reopen. No universal safe-CSV claim, report
framework, data warehouse, background principal or new permission is adopted
by this design review. Cross-product queries and actual acceptance belong
to009 and the respective source owner.

## Bounded capacity observation target review

IAM/011 owns the real-runtime measurement and its acceptance limits. This
slice does not change a production permission or reuse another task's fixture.

| Fixed source / slice | Decision | Rationale |
| --- | --- | --- |
| Matrix `3080922f6ae1871f1c351d5ee30f03551fc3c605`, `test/authorityprocess/process_e2e_test.go` | `REUSE` current bootstrap, restricted runtime DSNs, real binaries, HTTP setup and outbox/chain checks; `ADAPT` a closed bounded measurement mode | Preserve actual two-instance identities and original deadlines/costs. Each measured request must verify its response and account/subject; health checks, mock PDPs and aggregate process durations cannot stand in for capacity. No second test framework or published profile is introduced. |
| Same fixed source, group/custom-policy/boundary HTTP fixtures and current request-bound authorization | `REUSE` supported data/authority construction; `REFERENCE` its workload scale | Current fixtures provide real input contracts, not a claimed saturation load, tenant fairness budget or HA deployment. Fixed closed-loop samples and sampled PostgreSQL waits must state what they cannot measure. |

The legacy framework metrics and Redis authority closure remain rejected by
the foundation review. No legacy telemetry implementation, external load
service or production debug endpoint is adopted.
