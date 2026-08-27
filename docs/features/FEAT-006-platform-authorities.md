# FEAT-006: Platform IAM and Audit authorities

- Status: In progress
- Target release: Matrix PaaS Phase 2 tenant accounts
- Target design date: 2026-08-25
- IAM API contract: `iam.matrix.xiak.com/v1`
- Audit API contract: `audit.matrix.xiak.com/v1`

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
Primary-account login accepts the globally unique primary login name;
subaccount login accepts `username@account-alias` or `username@organization-id`
in the same `loginName` field. The suffix is a credential lookup namespace,
not an email address, DNS dependency, tenant-selection header, or permission.
The authenticated credential, never a later request selector, determines the
organization. Login returns a cryptographically random opaque bearer session
plus the non-secret current password-change requirement.
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
Bearer through `GET /v1/service-identity`. The endpoint accepts no request
body, tenant, principal, purpose, source, or other selector.

Audit resolves each producer through `POST /v1/audit-producer:resolve`. IAM
authenticates the current service credential, checks its exact bootstrap
installation binding and IAM/PaaS/Audit purpose, and verifies that the proposed
event organization is an existing account in that installation. The response
binds that organization to the authenticated producer without changing the
producer's own organization. Only this append-only producer boundary may span
the installation's tenants; it grants no user, query, or resource access.
Unknown organizations, user credentials, verifier credentials, and caller
purpose/subject selectors fail closed. Existing disabled organizations may
still receive their committed historical outbox facts. Audit derives the closed
event source from the verified producer purpose and checks the returned target
against the event. Shared producer credentials and source headers are forbidden.

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

### Tenant accounts and subaccounts

The IAM organization is the cloud-account-shaped resource owner, not an AWS
Organizations-style parent of accounts. A primary principal is its protected
owner login; a subaccount is a tenant-bound user, not another resource owner.
Resources and quota remain organization-owned regardless of which user creates
them. Organization boundaries isolate tenants; fixed role authorization
controls access among users of the same tenant. The current roles apply to the
whole tenant, not only to resources created by a particular user. User groups,
resource groups, per-project/per-instance policies, cross-account role trust,
SSO, and MFA are outside this password-only slice. IAM isolation is not a claim
of dedicated host, storage, or network isolation.

This product mapping follows the distinction between
[AWS accounts and IAM users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html),
[Tencent CAM user types](https://cloud.tencent.com/document/product/598/13665),
and [Alibaba RAM users](https://help.aliyun.com/zh/ram/user-guide/overview-of-ram-users).
[AWS account isolation](https://docs.aws.amazon.com/accounts/latest/reference/welcome-multiple-accounts.html)
is a boundary reference, not a claim that Matrix implements AWS Organizations.

Each organization has one immutable primary account and organization ID.
Its optional login alias is a separately managed, globally unique lowercase
identifier, not the primary user's login name or an email/DNS ownership claim.
An organization administrator sets it through access-management user settings.
Alias changes use optimistic concurrency, affect subsequent login lookup only,
and never change resource ownership, organization ID, or a session's tenant.
The former alias stops authenticating and remains reserved to its organization
against reassignment; the stable organization-ID form continues to work.
Child login names are unique inside an
organization and may repeat across organizations. The two login forms share
the password/session mechanism, but an unqualified child login is rejected.
Malformed, ambiguous, unknown, disabled, and wrong-password identities do not
reveal whether a tenant or user exists. There is no public identity-discovery
or username-only "next step" endpoint.

The exact installer-created administrator may open another tenant account
with its own primary account and initial password. This capability is bound
to the bootstrap identity, not to the general `ORGANIZATION_ADMIN` role; it
cannot be granted through tenant role bindings and grants no read or mutation
authority over another tenant's PaaS resources. Tenant creation is atomic and
audited. Public self-registration, payment, organization deletion, impersonation,
cross-tenant session switching, and host administration are outside this slice.

An organization administrator can list its users and active role bindings,
create a subaccount with no business permissions by default or an explicitly
selected initial fixed role, grant/revoke tenant roles,
disable/re-enable a subaccount, and reset its password. Initial-role creation
is one transaction. Disable and password reset revoke all of that user's
sessions; re-enable cannot revive an old session. Password reset requires
replacement at the next login. Primary accounts, internal service identities,
and the acting administrator cannot be disabled or reset through subaccount
management. Primary administrator bindings cannot be removed. The installation
verifier role is never assignable to a user.

Directory reads are bounded and scoped by the current session; pagination
cannot select another tenant. Current-identity reads expose only the current
organization, principal, fixed roles, and the bootstrap-bound tenant-opening
capability. No password, hash, session credential, service credential, or host
binding enters those responses or Audit facts.

Acceptance requires two real tenants with the same child login name, correct
qualified login, wrong-suffix and unqualified-login denial, tenant-confined
directory and role operations, viewer mutation denial, primary-account
protection, immediate role/session revocation, and no resurrection after
re-enable. Real PostgreSQL and HTTP gates must exercise these paths without
direct-table writes as a substitute for tenant onboarding. Existing bootstrap
accounts, credentials, resources, and audit records must survive migration;
only the global child-login namespace is replaced.

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

Audit admits only authenticated service identities and a closed versioned
event union for IAM and PaaS facts. Every event has source, event ID, tenant,
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
serializes one per-tenant sequence and stores canonical event bytes,
content SHA-256, previous record hash, and a domain-separated record hash. The
database runtime role cannot update a record, rewrite a sequence, or delete a
record. Verification recomputes the selected tenant chain from an accepted
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

- IAM bootstrap status, current service identity, audit-producer resolution, login/logout/password change,
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

The Phase 2 tenant-account extension is implemented but not release-accepted.
On 2026-08-27 its generated contracts, full repository unit/architecture tests,
vet, and IAM/Audit race suites passed. The IAM HTTP gate on real PostgreSQL 18
proves two accounts with repeated child names, ID/alias login, old-alias
reservation, concurrent alias acquisition, bounded directories, explicit
initial grants, protected primary identities, tenant confinement, role
revocation, disable/re-enable, all-session password reset, and populated-schema
replay. A fresh database repeat passed with the race detector enabled.

The Audit HTTP and dual-schema PostgreSQL gates passed, including all four new
account actions, tenant-bound filters and cursors, chain integrity, runtime
privileges, and immutable records. The independent IAM/PaaS/Audit process gate
now creates the second tenant through HTTP rather than direct-table fixtures:
its child creates a PaaS resource, both outboxes deliver to that tenant, the
bootstrap owner cannot read the resource or its audit, and the second tenant's
chain verifies. User and verifier credentials cannot become audit producers;
the producer contract verifies registered target organizations through IAM.

These results do not replace Gate C. The account extension has not yet run the
signed, network-disabled install/upgrade/rollback/backup/recovery journey or
been applied to the user's existing installation. The prior accepted
foundation evidence below covers only its named source revisions.

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

## Deferred

Permission-request approval workflows and time-limited grants are not part of
the current direct-administrator-grant contract. Database engine/data access
also remains separate from PaaS control-plane authorization.

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
