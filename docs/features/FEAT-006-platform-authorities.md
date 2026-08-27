# FEAT-006: Platform IAM and Audit authorities

- Status: Phase 1 foundation accepted; Phase 3 multi-tenant extension not accepted
- Target release: Private Application PaaS v0.1
- Target design date: 2026-08-25
- IAM API contract: `iam.matrix.xiak.com/v1`
- Audit API contract: `audit.matrix.xiak.com/v1`
- Phase 3 extension: installation authority and fixed account/historical-proof integration implemented; host and offline release acceptance remain in FEAT-008

## Outcome

Deliver independently runnable, PostgreSQL-backed IAM and Audit authorities
that replace the test ports currently used by the PaaS. A credential entering
through APISIX must yield an IAM-owned tenant, subject, and authorization
decision; every accepted PaaS mutation must arrive at an append-only,
queryable, integrity-verifiable Audit record through the existing durable
outbox path.

This is the smallest real authority slice required by
[`FEAT-005`](FEAT-005-offline-platform-lifecycle.md). It deliberately combines
the two authorities in one vertical FEAT so their cross-service proof is owned
once, while their code, schemas, credentials, processes, and source-of-truth
boundaries remain separate. The target is fixed before donor inspection.

## Ownership and non-ownership

| Concern | Owner |
| --- | --- |
| Organization/Tenant, principal, role binding, credentials, session, authorization decision | `iam` |
| Unified audit record, exact replay, integrity chain, retention, and query | `audit` |
| Application resources, Operations, PaaS Audit outbox | `apphosting` |
| IAM Audit outbox and delivery | `iam` |
| Generic attempts, lease, fencing, and unknown-outcome handling | The producing context's Operation mechanism |
| Gateway routing and browser boundary | APISIX and the consuming release topology |

Lease and fencing tokens are concurrency controls, not Audit authority. The
PaaS Operation worker, PaaS Audit dispatcher, and IAM Audit dispatcher may each
use the mechanism with independent state; Audit never owns their lifecycle.

IAM and Audit may share the released PostgreSQL server, but use different
schemas, owners, migration roles, runtime roles, credentials, and connection
pools. They receive no cross-schema table grants and never read another
context's database. Integration is through the versioned HTTP contracts.

## IAM authority

### Model and bootstrap

IAM owns these Phase 1 resources:

- `Organization`, whose immutable ID is the exact PaaS `TenantID`;
- organization-owned `Principal` of type `USER` or `SERVICE_ACCOUNT`;
- fixed `RoleBinding` from one principal to a built-in role in that same
  organization;
- `UserCredential`, opaque `ServiceCredential`, revocable `Session`, and
  immutable `AuthorizationDecision`.

The installer generates one restrictive, non-manifest bootstrap file with an
installation identity, initial organization, initial administrator, random
administrator password, and exact service-account credentials for IAM itself,
the PaaS, Audit, and installation verifier. IAM persists only password
hashes, credential hashes, and the bootstrap content digest. Equal bootstrap
replay is success; changed content for the same installation identity
conflicts. A bootstrap secret, password, service credential, or bearer token
is never returned by health, status, Audit, support evidence, or native errors.

The initial administrator is marked to change its password. Installation and
recurring verification use the narrowly authorized verifier service account,
not the administrator password. The protected bootstrap file remains an
operator recovery input until password change succeeds, then `mx` can retire
only that installation-owned file.

### Authentication and authorization

User passwords are bounded and hashed with a versioned Argon2id profile and a
unique random salt. A user principal belongs to exactly one organization.
The primary/root identity has a globally unique unqualified login; subaccounts
use `username@organization-id` or `username@account-alias` and can share names
across tenants. The suffix is only a credential lookup namespace. Primary
ownership is separate from revocable administrator roles: ordinary member
status/password and role commands cannot disable, reset or demote the primary.
Daily administrator handoff does not transfer that identity. Account responses
are projections of Organization and its primary USER, not another tenant model.
Login returns a cryptographically random opaque bearer session plus the
non-secret current password-change requirement.
The database stores only its digest, absolute
database-time expiry, revocation, principal, and exact organization. Phase 1
has no JWT, external IdP, LDAP, SAML, OIDC, social login, API-key query
parameter, or tenant-selection header.

Long-lived internal service credentials are random opaque values stored only
in exact read-only files and as digests in IAM. The IAM authorization endpoint
requires both the calling service identity and the transient subject
credential. It accepts a closed action, typed resource reference, and request
correlation ID; tenant and subject come only from the current session or
service binding. It returns one immutable decision ID and either an exact
authorized tenant/subject or a normalized denial. Authentication, policy, or
database uncertainty fails closed.

APISIX preserves the user's opaque Bearer credential on public IAM, Audit, and
PaaS routes and removes any caller-supplied internal subject header. Each
business service authenticates itself to IAM with its own file credential when
requesting an authorization decision; the gateway is routing authority, not an
identity or product-authorization principal.

`POST /v1/installation:verify` is the one fixed service-as-subject boundary.
It accepts only the verifier service Bearer, `installation.verify`, and the
bootstrap installation resource; a subject credential or another action is
rejected. IAM reloads the verifier's current service credential, role binding,
organization, and bootstrap receipt for every decision, so revocation and an
installation mismatch fail closed without granting the verifier any generic
PaaS, Audit, or IAM authority.

An authenticated service can read only the identity bound to its current
Bearer through `GET /v1/service-identity`. That endpoint accepts no request
body, tenant, principal, purpose, source, or other selector. Audit append uses
`POST /v1/audit-producer:resolve` with only the full closed event. Current
producer purpose determines the source; caller-supplied producer/source
overrides and shared credentials are forbidden. This is append evidence, not
a reusable user permit or permission to read another tenant.

Built-in organization roles are:

| Role | Authority |
| --- | --- |
| `ORGANIZATION_ADMIN` | Manage organization principals/bindings and all organization PaaS and Audit actions. |
| `PAAS_DEVELOPER` | Create/read application resources and create/update/rollback/stop Deployments. |
| `PAAS_VIEWER` | Read application resources, Deployments, and Operations. |
| `AUDIT_READER` | Read and verify the organization's Audit records. |
| `INSTALLATION_VERIFIER` | Run only the fixed no-secret installation verification actions in the bootstrap organization. |

The action catalog includes the accepted PaaS `Authorizer` actions plus the
minimal IAM administration, Audit read/verify, and installation-probe actions.
Roles and actions are code-owned closed values in Phase 1; customers cannot
upload policy languages, expressions, scripts, or provider-native documents.

### Installation-scoped platform authorization

FEAT-008's host admission uses the separate `PLATFORM_OPERATOR` role for
execution-pool create/read, execution-target register/read, platform Operation
read, platform Audit read/verify, and platform-role grant/revoke. Organization
administration never grants these actions; the platform role does not implicitly
grant tenant application or organization administration. Platform bindings admit
user principals only.
The existing role-binding commands select their IAM action from the actual
role, including retained revoked bindings, so replay cannot change authority.
An unrevoked platform binding also protects a disabled USER from ordinary
tenant password-reset/status commands. Grant and credential changes serialize
on that principal; initial/reset-password users must change their password
before receiving a platform binding. Tenant administration cannot take over
platform credentials or use tenant recovery to grant platform authority.

Allowed platform decisions contain the exact `installationId` from IAM's
sealed bootstrap receipt and no `tenantId`. Allowed tenant decisions contain
only `tenantId`; denials expose neither authority nor subject. The calling
service must still own the action. IAM reloads the current session, roles and
receipt on every request and rejects incomplete identity or password-change
state. SQL guards enforce the same installation/user/active-role boundary.
IAM authorization Audit facts remain in the actor's organization because their
target is the IAM decision, not the platform resource.

A fresh bootstrap grants the initial administrator two independent bindings:
organization administrator and platform operator. Neither equal bootstrap
replay nor schema reapplication repairs or regrants a revoked platform role.
Older installations without a platform binding require an explicit authorized
upgrade/recovery path; that offline lifecycle remains unaccepted. No migration
silently promotes organization administrators.

### IAM transactions and Audit

Credential changes, session issue/revoke, organization/principal/binding
mutations, and authorization decisions are bounded transactions using
database time. Security mutations and accepted/denied authorization decisions
atomically write a fixed sanitized IAM Audit outbox event. Delivery is
at-least-once through the same behavior class as the PaaS dispatcher: stable
event ID, database lease, monotonic fence, bounded retry, dead letter, and
equal-replay success at Audit. Delivery failure never erases the committed IAM
fact; a saturated or dead-lettered outbox is unhealthy and visible without
payload leakage.

## Audit authority

### Ingestion and integrity

Phase 3 platform host facts use `installationId` instead of `tenantId`.
The closed action selects the authority class; mixed or missing authority is
invalid. IAM binds each producer service to the sealed installation as well as
its organization. Installation and tenant chains, cursors, RLS and Operation
uniqueness are disjoint even if their textual IDs are equal. Existing tenant
canonical bytes and record hashes remain unchanged. The same ingestion,
replay, integrity and retention implementation serves both partitions; no
synthetic tenant or parallel Audit service is introduced. Platform query and
verification require distinct installation-scoped IAM actions and record their
own access facts. `api/audit/v1.CanonicalizeEvent` owns the pure canonical event
encoding and content digest; Audit's chain implementation reuses that function.

IAM and Audit readiness require schema version 2. The existing Audit migration upgrades retained tenant storage
atomically without rewriting event documents, canonical bytes or hashes. Its
exclusive table locks cover foreign-key validation and restore forced RLS
before commit. No old SQL aliases or second Audit implementation remain.
Retained-data migration is not proof of compatibility with an older executable
or of the offline release's upgrade/rollback policy.

Installation binding alone is not permission to publish another tenant's facts.
Producer resolution binds the current service identity, one tenant or
installation, and the canonical digest of the exact event. IAM-source events
must match IAM's own committed outbox. PaaS/Audit events require an immutable
allowed decision plus its original IAM fact, matching actor, request,
correlation, authority and closed action/resource mapping. Host create/register
binds the actual target ID. Ordinary application/service create decisions name
a collection: they do not prove the final target, Operation ID or business
payload. Those facts remain the source transaction/outbox's responsibility;
there is no claim of a separate source receipt or payload attestation.

Historical proof does not reevaluate the original user's current session,
roles, status or target tenant activation. Current producer revocation, wrong
purpose/installation, an unknown tenant or missing evidence fails closed;
temporary IAM failure leaves delivery retryable. The fixed verifier remains a
closed probe exception, not a general service-account mutation capability.
One public canonical encoder remains authoritative; no old target-selector
endpoint or parallel authorization path is retained.

Audit admits only authenticated service identities and a closed versioned
event union for IAM and PaaS facts. Every event has source, event ID, authority,
actor, IAM decision correlation where applicable, fixed action, typed target,
result, request/content digest, safe correlation IDs, and UTC occurrence time.
There is no arbitrary attributes map, request body, configuration value,
secret, credential, native provider payload, stack trace, or absolute path.

The Phase 2 control-plane slice extends the closed PaaS-source union with only
`managedservice.quota-entitlement.activated`,
`managedservice.service-installation.created`, and
`managedservice.service-installation.ready`. The activation fact targets the
entitlement, the accepted creation fact joins the installation to its durable
Operation, and the ready fact targets the installation after the worker's
fenced completion. The source outbox retains the ready fact's Operation foreign
key, while its public Audit event deliberately omits `operationId`: one
Operation has one accepted mutation fact rather than a second synthetic
acceptance identity. All three retain the original IAM decision, actor,
request digest, and request correlation without endpoint, credential
reference, machine binding, provider payload, or native error.

`(source, eventId)` is the idempotency identity. Equal canonical replay returns
the stored result; different canonical content conflicts. A successful ingest
serializes one per-authority sequence and stores canonical event bytes,
content SHA-256, previous record hash, and a domain-separated record hash. The
database runtime role cannot update a record, rewrite a sequence, or delete a
record. Verification recomputes the selected authority chain from an accepted
checkpoint and fails on a gap, changed content, or changed predecessor.

Phase 1 retention is `INDEFINITE`: there is no purge, overwrite, truncate, or
tenant deletion path. Configurable expiry, archive tiers, legal hold, and
cryptographic checkpoint export require a later accepted contract. Indefinite
retention is intentionally stronger than silently implementing an incomplete
purge path, and backup/recovery remains owned by installation.

### Query

Audit query requires a user bearer credential and calls IAM for
`audit.record.read` or `audit.integrity.verify`. The returned tenant is IAM
authority; a tenant header, query filter, cursor, actor, or record body cannot
change it. Queries use bounded page sizes, deterministic descending sequence,
an opaque tenant-bound cursor, and optional bounded time/action/actor filters.
The separate `/v1/platform/records:query` and `/v1/platform/integrity:verify`
routes require `audit.platform-record.read` and `audit.platform-integrity.verify`;
their scope and cursors are bound to the IAM-derived installation instead.
Responses expose the sanitized event, sequence, hashes, ingestion time, and
retention policy only. Reading or verifying Audit writes a local sanitized
access record without recursively calling the ingestion API.

### Fixed installation verification

`POST /v1/installation:verify` on the PaaS is the only platform mutation path
available to the installation verifier. The request selects only the exact
installation and release already bound into the running PaaS process. The
PaaS calls IAM's fixed verifier endpoint on every request, then composes the
ordinary application lifecycle to converge one deterministic private probe
Deployment. Artifact locator and signed digest, workload shape, resource
limits, fixed local PlacementPolicy, and the two non-secret environment values
are process-owned; the caller cannot submit an image, command, configuration,
Secret, provider control, placement selector, or generic PaaS action. The
response exposes only the exact Deployment generation and Operation state
needed for bounded polling.

`POST /v1/installation:verify` on Audit uses the same verifier credential and
accepts only that PaaS Operation and Deployment identity. It returns `PENDING`
until the durable PaaS Audit dispatcher has delivered the accepted mutation
fact. A verified result requires the exact verifier service actor, original IAM
decision, accepted Deployment create/update action, tenant, Operation, and
Deployment target, then recomputes the bounded hash-chain segment ending at
that immutable record. It appends one sanitized local integrity-access fact;
it neither acquires a producer lease nor owns a fencing token.

## Cross-process contracts and service behavior

Versioned Go contracts and generated OpenAPI own:

- IAM bootstrap status, current service identity, login/logout/password change,
  organization/principal and binding commands, authorization request/decision,
  and readiness;
- Audit ingest/replay result, bounded query page/cursor, chain verification,
  fixed installation verification, health, and normalized RFC 9457-style
  problems;
- PaaS fixed installation verification request/result in addition to the
  existing generic application lifecycle contracts.

Decoders reject unknown fields, duplicate/non-canonical identity, trailing
JSON, oversized input, unsafe external text, and unsupported enum values.
Credential material is transient request data and is excluded from ordinary
JSON marshaling, logging, errors, decisions, and Audit events. HTTP servers use
the Go standard library with explicit timeouts, body bounds, injected clocks
only in unit tests, graceful context cancellation, and no debug endpoint.

The PaaS implements its existing `Authorizer` and `AuditIngestor` ports with
real HTTP clients. It never falls back to a caller header, local allow-list,
in-process Audit sink, or cached permit when IAM/Audit is unavailable. Equal
Audit delivery is success; changed replay and authentication failure are
terminal normalized failures.

IAM and Audit are separate executable modes or binaries and independently
runnable services in the fixed release topology. Readiness proves database
schema compatibility and the service's own invariants. It is not a health-only
placeholder and does not claim downstream PaaS success.

## Incremental acceptance

The account/proof integration must repeat the existing authority gates with
two independently created tenants, repeated child names and realm login,
primary/platform credential protection, delayed delivery after user revocation,
current producer rejection, and the real PaaS host Operation/outbox path.
Retained single-tenant credentials, revocations and immutable Audit data must
survive schema replay and process restart. This does not accept the remaining
platform tenant lifecycle, original-primary recovery, task-local browser or
signed populated offline upgrade/rollback gates.

### Gate A: contracts, domain, and database authority

1. Strict Go/OpenAPI examples cover every request/response and reject unknown,
   duplicate, tenant-header, credential-serialization, oversize, and enum
   drift. Generation, schema, architecture, unit, race, and repeated gates
   pass.
2. Argon2id password verification, opaque session/service credential hashing,
   expiry/revocation, fixed role/action decisions, exact replay/conflict, and
   fail-closed behavior pass without secret-bearing errors or Audit data.
3. Audit canonical event validation, equal replay/changed conflict, per-tenant
   sequencing and hash-chain verification, immutable retention, bounded query,
   and cursor tenant confinement pass.
4. Clean PostgreSQL 18 applies both schemas twice and proves migration/runtime
   role separation, forced tenant isolation, API-only writes, immutable Audit
   rows, database-time session/lease behavior, and stale-fence rejection.

### Gate B: real authority vertical slice

1. Real independently running IAM and Audit bootstrap twice from exact files;
   changed bootstrap, weak login, expired/revoked session, wrong service
   credential, denied role/action, cross-tenant resource, and unavailable IAM
   all fail closed.
2. Through real HTTP, an administrator creates a user/binding, that user logs
   into one organization, PaaS receives the exact tenant/subject/decision, and
   role or session revocation affects the next request without a process
   restart.
3. Accepted and denied IAM facts plus accepted PaaS mutations reach Audit
   through real PostgreSQL outboxes. Audit outage/restart proves backlog retry;
   duplicate delivery is one record, changed replay conflicts, dead letter is
   observable, and no source transaction loses its outbox fact.
4. A real authorized Audit query returns only its IAM-derived tenant, validates
   the hash chain, records the access, and rejects cross-tenant filters/cursors.
   Database and HTTP attacks prove no cross-schema read/write or secret/native
   leakage.

### Gate C: offline release consumption

[`FEAT-005`](FEAT-005-offline-platform-lifecycle.md) Gate B/C must package the
accepted IAM and Audit binaries/images, wire their exact file credentials and
clients, and repeat bootstrap, authorization, delivery, query, restart,
upgrade, rollback, backup, and recovery through APISIX with external network
disabled. FEAT-006 is not accepted merely because port fakes or direct service
tests pass.

## Implementation evidence

The fixed `26f3569` account/proof slice is integrated and locally verified with
this branch's existing host admission. Fresh PostgreSQL 18 race gates passed
IAM/Audit HTTP, dual-schema privilege and immutable-storage attacks, retained
Audit/PaaS upgrades, and an actual `9fd45b0` IAM executable's populated upgrade
and restart. The five-process gate passed HTTP tenant opening, qualified
subaccount login, dual outboxes, cross-tenant binding/cursor denial, historical
replay and revoked-producer rejection while retaining real PaaS host
registration and its Operation/Audit correlation. Full-repository race/vet,
ten repeated focused runs, stable generation, module verification and Linux
builds passed; the existing console's 52 tests and two bounded static builds
passed with matching embedded assets. Independent CI for this consuming
commit is pending.

Exact-bootstrap-only tenant opening remains until the separately verified IAM
platform-lifecycle replacement. New tenants do not inherit platform roles;
ordinary tenant administration cannot grant them. These integration checks do
not accept the complete multi-tenant or offline release extension.

- Gate A was accepted on 2026-08-26. Strict generated Go/OpenAPI contracts,
  current-credential-only service identity, fixed Argon2id and
  opaque-credential behavior, closed RBAC decisions, bootstrap and Audit replay
  classification, canonical facts, independent tenant hash chains, indefinite
  retention, and tenant/filter-bound cursors pass generation, schema,
  architecture, unit, race, and repeated gates.
- A clean PostgreSQL 18 database applies both role bootstraps and both schemas
  twice through separate non-superuser migration identities. The behavioral
  integration gate uses only the granted API/worker/runtime functions and
  attacks direct tables, owner escalation, cross-schema access, forced RLS,
  canonical/event disagreement, arbitrary payloads, record hashes, immutable
  update/delete/truncate paths, database session/event/lease time, lease
  recovery, and stale fencing tokens.
- Gate B was accepted on 2026-08-26 after implementation commit `255b790`.
  IAM, Audit, the IAM Audit dispatcher, PaaS, and the PaaS Audit dispatcher run
  as five independent processes with exact file credentials, least-privilege
  database logins, and HTTP-only authority integration. PaaS readiness binds
  its schema and outbox invariants to the live IAM identity of its configured
  PaaS service credential; there is no header, local allow-list, cached permit,
  or in-process Audit fallback.
- A fresh PostgreSQL 18 race gate starts and restarts all five binaries. It
  proves equal and changed bootstrap, weak login, database-time session expiry,
  immediate role/session revocation, wrong-role and wrong-service denial,
  cross-tenant resource rejection, and IAM-unavailable fail-closed behavior.
  The accepted PaaS Operation carries the exact IAM tenant and subject, and its
  durable outbox fact joins one immutable IAM decision to one PaaS-source Audit
  record.
- The same process gate proves accepted and denied IAM facts, accepted PaaS
  mutations, Audit outage backlog and restart, equal duplicate delivery,
  changed replay conflict, terminal bad-credential dead letters, unhealthy
  readiness, authorized tenant-only Audit query and chain verification, local
  access facts, strict tenant-selector/cursor filtering, cross-schema denial,
  and absence of credential or native-error leakage. Independent clean PG18
  race gates repeat the PaaS, IAM HTTP, Audit HTTP, and dual-schema database
  attack matrices.
- Gate C was accepted from exact source commit `c88a84f`. Compatible signed
  releases ran the complete lifecycle in a fresh Docker-in-Docker engine whose
  outer network was disabled and whose inner engine initially contained no
  containers, images, or volumes. Through APISIX, real IAM authenticated the
  user and authorized application mutations; the IAM and PaaS dispatchers
  delivered immutable facts to Audit; tenant-bound Audit query and integrity
  verification passed across configuration changes, failed and successful
  upgrade, explicit rollback, protected-backup recovery, application rollback,
  stop, support collection, and a full engine restart. The same source passed
  clean PostgreSQL 18 race gates for migration, IAM HTTP, Audit persistence and
  HTTP, the PaaS worker, and the independent authority-process flow, plus the
  common generation, unit, architecture, vet, race, repeated, build,
  dependency, documentation, stale-term, path-leakage, and diff gates.
- FEAT-007 extends the accepted Audit authority without changing its source,
  replay, integrity, or retention boundaries. A shared PaaS dispatcher drains
  independently owned apphosting and managed-service outboxes with bounded
  leases and fencing; clean PostgreSQL 18 gates prove the three new actions,
  their public contracts, source-bound ingestion, transactional correlation,
  and delivery through the existing immutable Audit chain.
- The Phase 3 IAM extension passes the existing strict contract, role matrix,
  real PostgreSQL HTTP and database attack gates. The existing independent
  IAM/Audit/PaaS process gate proves explicit platform grants, next-request
  revocation, rejected organization-admin self-grant, and no authority
  resurrection after IAM restart with equal bootstrap. Each tested allowed
  or denied platform decision joins exactly one delivered immutable IAM Audit
  fact. These checks do not accept platform-resource mutations or the offline
  upgrade/recovery path.
  Source `a757a27` also passes full-repository race/architecture, vet, module
  verification, stable generation, ten repeated IAM runs, Linux builds and
  [independent CI](https://github.com/xiak/matrix/actions/runs/33046535740),
  including the existing real node/collector process regression.
- The Phase 3 Audit extension passes clean PostgreSQL 18 apply-twice, immutable
  storage and privilege attacks, and an upgrade from the actual `9fd45b0` SQL
  with retained tenant records. Equal tenant/installation IDs and Operation IDs
  remain separate; old canonical bytes, record hashes and replay survive.
  IAM/Audit HTTP and the five-process race gate prove platform-only access,
  next-request revocation, no restart regrant, wrong producer installation and
  purpose rejection, and unchanged platform replay after Audit restart. The
  platform fixture tests producer/Audit authority, not a completed host mutation
  or PaaS Operation. PaaS database regressions, full-repository race/architecture,
  vet, module verification, stable generation, ten repeated focused runs, Linux
  builds, modified documentation links and diff checks also pass locally.
  Source `6401e96` passes [independent CI](https://github.com/xiak/matrix/actions/runs/33050553233):
  the existing Go/race and real node/collector gates plus the real PostgreSQL,
  retained-data upgrade and authority-process gates in the same workflow.

## Deferred

External identity providers, LDAP, SAML, OIDC, MFA/WebAuthn, SCIM, customer
policy languages, custom roles, multi-organization principals, token signing
and key rotation, high availability, remote policy decision points,
configurable Audit deletion/archival/legal hold, cryptographic external
checkpoints, SIEM export, and Audit full-text search remain outside Phase 1.

The shared product and dependency boundaries remain owned by
[`ADR-0002`](../architecture/ADR-0002-product-boundary.md) and
[`DEPENDENCY-RULES`](../architecture/DEPENDENCY-RULES.md). Fixed donor decisions
are owned by the
[`FEAT-006 adoption review`](../adoption/FEAT-006-platform-authorities.md).
