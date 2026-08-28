# FEAT-006: Platform IAM and Audit authorities

- Status: Accepted foundation; minimal multi-tenant slice accepted on `feat/iam-xxx`
- Target release: Private Application PaaS v0.1 multi-tenant extension
- Target design date: 2026-08-25
- IAM API contract: `iam.matrix.xiak.com/v1`
- Audit API contract: `audit.matrix.xiak.com/v1`
- Phase 3 extension: installation-scoped IAM authority implemented; host-resource consumption and offline upgrade acceptance remain in FEAT-008
- Multi-tenant extension: accounts, primary/platform credential protection, historical producer proof, tenant lifecycle, original-primary recovery and password-session policy pass backend, signed lifecycle and installed-browser gates; keyboard-only usability verification is deferred by the user in FEAT-007

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
body, tenant, principal, purpose, source, or other selector. The required
`installationId` comes from its current credential's sealed installation;
`organizationId` still identifies its service-home tenant, not every tenant
that it may serve.

Audit resolves each producer through `POST /v1/audit-producer:resolve`. IAM
authenticates the current service credential, checks its sealed installation
and IAM/PaaS/Audit purpose, and proves the exact submitted event against its
committed IAM fact or original authorization evidence. The closed mapping and
its source-payload limitation are specified in the multi-tenant target below.
The response binds the event's scope and canonical digest without changing
the producer's identity. This one-append result grants no reusable permit,
user, query, or resource access. Unknown scopes, substituted evidence, user
or verifier producer credentials, and caller source/purpose selectors fail
closed. Current user/session/role state does not invalidate a committed fact;
current producer credential validity remains required. Audit derives source
from purpose and verifies scope/digest before touching its record registry.

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
read, and platform-role grant/revoke. Organization administration never grants
these actions; the platform role does not implicitly grant tenant application
or organization administration. Platform bindings admit user principals only.
The existing role-binding commands select their IAM action from the actual
role, including retained revoked bindings, so replay cannot change authority.

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

A password change preserves only the submitting session derived from the
effective bearer and revalidated inside the transaction. First-login,
administrator-reset and original-primary-recovery password changes always
revoke other sessions: a second temporary-password session must never gain
normal permissions when another session completes password replacement.
Ordinary password changes accept `revokeOtherSessions`, defaulting to true;
explicit false may retain only already valid sessions of that same USER.
It cannot revive a revoked or old temporary session. The password, effective
session policy and sanitized Audit fact commit together. Each password change,
reset or primary recovery advances a per-USER credential generation under the
same principal lock; login binds the session to the credential generation it
verified. This generation is a monotonic counter, not a timestamp. Legacy sessions
without credential-version evidence always fail closed and require a new
login; transaction timestamps cannot establish which password issued them.
No migration backfills or retention option may bless these legacy rows.
Wrong-password and failed transactions leave the password,
sessions and success facts unchanged. The console calls these login sessions,
not devices; it does not add device fingerprinting or a device inventory.
This hardening increments IAM's schema to 3 and the release contract revision
to 3. Retained-session process gates, the populated signed lifecycle in
FEAT-005 and the installed-browser journey in FEAT-007 pass for this contract.
Audit remains 2 and this branch's PaaS remains 1. The complete `3/2/1`
revision 3 profile is verified independently; the previous signed `2/2/1`
revision 2 evidence is not reused to certify the new password/session contract.

An explicitly bound `PLATFORM_OPERATOR` may open another tenant account with
its own primary account and initial password, list/read tenant metadata,
suspend/restore access, and recover that tenant's original primary credentials.
These are installation-scoped actions, not `ORGANIZATION_ADMIN` privileges or
an exception for the bootstrap person. Tenant creation is atomic and grants
only the new primary's protected tenant-administrator binding; it neither
reruns bootstrap nor grants platform or cross-tenant resource permissions.
Public self-registration, payment, organization deletion, impersonation and
cross-tenant session switching are outside this slice.

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
organization, principal, fixed roles, and the platform-role tenant-opening
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
event union for IAM, PaaS and Audit facts. Every event has source, event ID,
exactly one tenant or installation chain scope,
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

`(source, eventId)` is the idempotency identity. After producer proof, equal
canonical replay returns the stored result; different canonical content
conflicts. Unproved or changed historical authority is denied before registry
lookup. A successful ingest serializes one chain sequence and stores canonical event bytes,
content SHA-256, previous record hash, and a domain-separated record hash. The
database runtime role cannot update a record, rewrite a sequence, or delete a
record. Verification recomputes the selected tenant chain from an accepted
checkpoint and fails on a gap, changed content, or changed predecessor.
Internal `tenant:` and `installation:` chain keys keep equal raw IDs separate.
Existing tenant canonical bytes, hashes and cursors remain unchanged. The one
public `auditv1.CanonicalizeEvent` encoder serves ingestion, replay and proof.

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

Platform records use `/v1/platform/records:query` and
`/v1/platform/integrity:verify`, backed by the separate
`audit.platform-record.read` / `audit.platform-integrity.verify` IAM actions.
Their installation comes from the current IAM decision, not a query selector;
platform access does not authorize a tenant chain. Tenant and installation
page/verification responses expose exactly their authorized scope.
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

### Multi-tenant extension target

The accepted Phase 1 evidence below does not accept tenant lifecycle or a
multi-tenant installation. This extension keeps `iam` as the existing owner;
it does not introduce an Account service, a second tenant aggregate, or a
public-cloud IAM platform. Its smallest enterprise outcome is an operator
opening a tenant, that tenant's administrator managing independently
credentialed members, and those members using only their authorized tenant
resources through real IAM, PaaS, Audit, and the existing console.

The application workflows and transactions remain in `identityaccess`, pure
credential/role rules in `authority`, database enforcement in the existing
IAM PostgreSQL adapter, and HTTP contracts in `api/iam/v1`. Cross-service
authorization and Audit ingestion use the existing service-owned HTTP ports;
no service reads another context's tables. Each security mutation and its
sanitized fact commit together through the existing IAM outbox.

| Boundary | Required invariant |
| --- | --- |
| Resource ownership | `Organization.ID` is `TenantID`. Applications, service installations, quota entitlements, Operations, and tenant Audit records belong to that tenant, not their creator. Disabling a member cannot transfer or delete them. |
| Membership | A member is a `USER` principal with independent credentials and tenant-local built-in role bindings, not a child tenant. A service identity cannot log in as a user or receive user/platform roles through member management. |
| Login realm | The pre-authentication realm resolves exactly one immutable organization. `(tenant, loginName)` is unique; the same login name in two tenants is supported. There is no ambiguous cross-tenant fallback, public realm/member discovery, or realm switch inside an existing session. Reuse the console owner's qualified `loginName` namespace rather than add a second realm protocol; any retained unqualified installation login is a lookup rule, not privileged authority. |
| Business authority | Every protected request reloads current IAM identity and role state. Headers, resource IDs, URLs, bodies, and cursors never replace IAM-derived tenant authority. A platform tenant ID is a management target, never an impersonation selector. |
| Platform separation | `PLATFORM_OPERATOR` manages tenant lifecycle through explicit platform actions, without generic tenant application, Secret, Audit-read, or terminal access. `ORGANIZATION_ADMIN` manages only its tenant's members and tenant roles and cannot grant a platform role. New-tenant initialization grants only its initial organization administrator; it never calls installation bootstrap. |
| Service production | A service's installation binding, producer purpose, and permission to target a tenant are separate facts. Multi-tenant ingestion requires a positive IAM-owned target-tenant/installation check as well as the existing closed source/action checks; removing the producer-tenant equality check alone is forbidden. |
| Suspension | Member or tenant suspension freezes subsequent protected access and new changes, not data or running workloads. Restoration does not regrant revoked roles or resurrect revoked sessions. Accepted durable Operations and outbox deliveries may finish; the extension does not claim cancellation of already accepted work or instantaneous termination of open streams. New requests fail closed during IAM uncertainty. |

Unauthenticated unknown realm, unknown member, disabled tenant/member, and
wrong-password cases must have the same normalized authentication failure and
bounded password-verification work. Passwords, temporary credentials, realm
existence hints, and native errors cannot enter responses, logs, Audit facts,
or ordinary JSON marshaling. Strict contract validation remains separate from
authentication failure. The installer, console login, password-change, logout,
and protected bootstrap-file retirement must use the same realm semantics.

Tenant administrators can create/list/read members, suspend/restore them, and
grant/revoke the closed tenant roles. Member reads and binding lists are
bounded and tenant-confined; no admin API exposes credential digests or
plaintext. Each tenant retains its one primary user's protected administrator
binding, including during concurrent member and role changes. Delegated
administrator roles remain revocable; ordinary handoff grants a child user
daily administration without transferring primary ownership. Credential
recovery is an explicit, auditable workflow with fresh temporary credentials,
required password change, and revocation of prior sessions; it is not bootstrap
replay, a direct SQL repair, or a hidden generic impersonation capability.
The installation's service-home organization cannot be suspended through
tenant management, and online tenant recovery cannot recover platform
credentials or grant platform roles.

Daily administrator handoff is not primary/root ownership transfer. The
primary user's tenant-administrator binding remains protected; another
tenant administrator cannot disable or reset that identity through member
commands. A successor's password change can prove readiness for daily
administration, but cannot authorize removing primary-account protection.
Primary credential recovery is an explicit separate workflow, not promotion
of a child user to account owner. This distinction follows the separate
root and delegated-administrator boundaries in the
[AWS root-user documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html)
and [Alibaba RAM administrator documentation](https://www.alibabacloud.com/help/en/ram/create-admin-user).
Resources remain owned by the existing organization, not the primary person.
Matrix implements this primary/delegated-administrator boundary without
including billing, identity-provider, account-ownership transfer or custom
policy products in the slice.

An unrevoked `PLATFORM_OPERATOR` binding also protects its user's credentials
from ordinary tenant member status/password commands, even if that user is
already disabled. Platform grants and credential changes serialize on the
same principal; a platform grantee must have completed initial/reset password
change. Tenant administration cannot become platform credential takeover.
Platform recovery remains the installation owner's separate lifecycle.

The platform lifecycle slice extends the existing account command owner:

| HTTP route | IAM action | Target |
| --- | --- | --- |
| `POST /v1/organizations` | `iam.organization.create` | New organization ID |
| `GET /v1/organizations` | `iam.organization.read` | Organization collection `organizations` |
| `GET /v1/organizations/{organizationId}` | `iam.organization.read` | Exact organization ID |
| `POST /v1/organizations/{organizationId}:set-status` | `iam.organization.set-status` | Exact organization ID |
| `POST /v1/organizations/{organizationId}:recover-administrator` | `iam.organization-administrator.recover` | Original primary USER ID, checked inside the named tenant |

The URL is a platform command's target, never the caller's tenant. Status and
recovery requests require the current organization's `resourceVersion`;
recovery additionally names its exact `principalId` and a new temporary
password. The response is the existing non-secret `OrganizationAccount`.
Stale versions and redundant status transitions conflict without changing data;
concurrent status/recovery commands cannot both consume the same version.
Recovery preserves primary ID/login and tenant ownership, enables that USER,
restores only its protected `ORGANIZATION_ADMIN` binding if absent, forces a
password change and revokes all of its old sessions. It does not enable a
suspended tenant. A child, service identity, other tenant's primary, or any
primary with an unrevoked platform binding is refused under the same principal
lock used for platform grants. This online workflow cannot recover the
installation operator; that remains the offline lifecycle boundary.

Suspension revokes every active tenant session and freezes subsequent access
and command admission. Restoration does not revive any session or revoked
binding. The sealed service-home organization cannot be suspended, preserving
normal current-credential checks for its producers and operators. Neither
command mutates PaaS resources, quota, accepted Operations or existing
workloads. Work admitted before suspension may finish through its existing
worker/outbox; in-flight requests are not retrospectively canceled. This is
next-request revocation, not an implemented real-time long-connection kill.

New lifecycle events are `iam.tenant.created`, `iam.tenant.disabled`,
`iam.tenant.enabled` and `iam.tenant-administrator.recovered` in the installation
chain. The first three target the real organization ID; recovery targets the
original primary USER and requires `target.tenantId`. That target field is
only a resource namespace and is forbidden on every other action. It cannot
change chain, query or role scope. Existing `iam.organization.created` facts
remain tenant-scoped with unchanged canonical bytes and hashes; neither
migration nor replay reclassifies them. Each successful lifecycle mutation
and its sanitized fact commit atomically with the current platform decision.

IAM outbox storage remains owned by the producing organization. The worker's
claim keeps its original six columns and appends `installation_id` from that
physical owner's sealed bootstrap receipt, never from the event. Tenant facts
must still match their storage owner; installation facts must match that seal.
Completion and fencing use the claimed row identity, not a chain selector.
Readiness and migration verification check the exact result-column contract;
malformed scope is retained as a dead letter before delivery. Sharing schema
version numbers is not an N-1 dispatcher or release
compatibility claim. The release owner's `contractRevision` must also bind
this result shape before a populated upgrade or rollback can be accepted.

Installation-scoped Audit partitioning remains the FEAT-008 owner's shared
implementation. Tenant lifecycle facts use that agreed platform scope;
tenant member/role/session facts stay in the tenant chain. The extension must
preserve existing canonical bytes, `(source,eventId)` replay classification,
immutable records, sequence/hash chains, and delayed outbox delivery after a
tenant is suspended. Historical accepted facts are not reauthorized as new
tenant mutations when replayed. Installation identity alone must not permit
forging another installation's tenant or inventing a tenant.

The producer proof extends the one existing `/v1/audit-producer:resolve`
endpoint. Its input is the exact closed Audit event, not an independently
selected tenant/source/purpose. Its output binds the current producer,
validated tenant-or-installation scope, and the existing canonical event
content digest to this append only. It is never cached as a permit or exposed
as user resource/read authority. IAM-source facts must exactly match IAM's
own committed outbox document, including denied decisions, bootstrap,
session, and password facts that have no allowed business decision.

The existing IAM `identityaccess` use-case boundary owns `audit_producer.go`:
historical cross-context evidence is separate from current identity-domain
evaluation. Its PostgreSQL adapter reads only IAM's own committed records.
`api/iam/v1` references the public Audit event and its generated schema in
one direction; it does not copy the event schema or import Audit internals.
The IAM schema/readiness contract requires this proof boundary; Audit's independent
partition schema remains version 2, while PaaS remains at its own version.
These numbers do not constitute a release compatibility or downgrade claim.

For PaaS/Audit sources, an immutable original decision proves historical
authority, actor, action, request, and scope. The event and decision must have
the same actor and request correlation; the current producer purpose and
installation must match the source and original authority. The mapping is
closed, with no action-prefix fallback:

| Audit event | Original IAM decision | Resource constraint |
| --- | --- | --- |
| `paas.application.created` | `paas.application.create` | `APPLICATION`, `collection` |
| `paas.configuration.created` | `paas.configuration.create` | `CONFIGURATION`, `collection` |
| `paas.configuration-revision.created` | `paas.configuration-revision.create` | `CONFIGURATION_REVISION`, `collection` |
| `paas.application-revision.created` | `paas.application-revision.create` | `APPLICATION_REVISION`, `collection` |
| `paas.deployment.created` | `paas.deployment.create` | `DEPLOYMENT`, `collection` |
| `paas.deployment.updated` | `paas.deployment.update` | `DEPLOYMENT`, exact event target ID |
| `paas.deployment.stopped` | `paas.deployment.stop` | `DEPLOYMENT`, exact event target ID |
| `paas.deployment.rolled-back` | `paas.deployment.rollback` | `DEPLOYMENT`, exact event target ID |
| `paas.execution-pool.created` | `paas.execution-pool.create` | `EXECUTION_POOL`, actual requested target ID; installation scope |
| `paas.execution-target.registered` | `paas.execution-target.register` | `EXECUTION_TARGET`, actual requested target ID; installation scope |
| `managedservice.quota-entitlement.activated` | `managedservice.quota-entitlement.activate` | `QUOTA_ENTITLEMENT`, `collection` |
| `managedservice.service-installation.created` | `managedservice.service-installation.create` | `SERVICE_INSTALLATION`, `collection` |
| `managedservice.service-installation.ready` | Original `managedservice.service-installation.create` | Retained create decision; the producing worker/outbox owns final target/Operation correlation |
| `audit.records.read` | `audit.record.read` | `AUDIT_RECORD`, `records` |
| `audit.integrity.verified` | `audit.integrity.verify` | `AUDIT_CHAIN`, `chain` |
| `audit.platform-records.read` | `audit.platform-record.read` | `AUDIT_RECORD`, `records`; installation scope |
| `audit.platform-integrity.verified` | `audit.platform-integrity.verify` | `AUDIT_CHAIN`, `chain`; installation scope |

The existing fixed installation verifier is a separate closed exception:
`installation.verify` must name the sealed installation and its original
verifier service actor, not any service principal. Its PaaS facts are limited
to fixed-probe application/configuration/revision creation and Deployment
create/update; its Audit integrity fact targets `installation-verification`.
It cannot authorize managed-service quota/purchase, arbitrary user resource
mutations, another tenant, or another installation. The fixed-probe owner
continues to enforce its exact process-owned resources and payloads. IAM proves
the sealed verifier, original installation decision, closed action and fixed
24-hex probe namespace, not the release/artifact-derived exact probe payload.

An original collection-create decision does not contain the final resource
ID, Operation ID, or business request digest. This proof therefore does not
claim independent proof of a specific committed business payload: the source
context's existing transaction/outbox still owns that fact. No generic
receipt framework or cross-service payload lookup is added. Negative gates
must substitute tenant/installation, actor, decision, request, action, exact
resource target, event digest, and producer purpose independently; absent or
uncertain evidence fails closed. Historical user/session/role revocation or
tenant suspension cannot invalidate a previously committed fact, while the
producer credential itself must still be current and effective. Canonical
encoding/hash computation has one public Audit contract owner, never a copy
inside IAM or an import of Audit's internal implementation.

Tenant deletion/data destruction, billing, organization trees, custom roles or
policy DSL, SSO/multiple identity providers, and cross-organization people are
excluded. Host observation, execution-pool/target implementation, platform
Operations, terminals, and general installation Audit are not reimplemented
here. No real-time stream revocation or public-cloud isolation claim is made.

### Multi-tenant vertical gates

Existing owners are extended rather than adding a parallel test framework.
Contract/unit/architecture/security checks precede each focused PostgreSQL
gate; the existing independent authority-process gate proves cross-service
behavior at each backend milestone, followed by the console and offline
lifecycle gates where their contracts change.

1. **Tenant opening and authentication.** A real platform operator creates two
   independent tenants and their initial administrators without rerunning
   bootstrap or gaining tenant roles. Platform list/detail and suspend/restore
   work; tenant administrators and ordinary members cannot invoke them.
   Both tenants contain an administrator and ordinary member with matching
   login names. Correct realm/password login, initial password change, logout,
   bad/unknown/disabled realm/member failures, and unavailable IAM are proven
   through real HTTP. Tenant suspension affects the next protected request
   across IAM, PaaS, and Audit. The installation authority/service credentials
   cannot be accidentally disabled by suspending an ordinary tenant.
2. **Member and administrator lifecycle.** In each tenant, the administrator
   lists/reads/creates/suspends/restores members and grants/revokes permitted
   built-in roles. Next-request member, role, session, password-reset, and
   tenant revocation behavior is tested. Cross-tenant member/binding/session
   IDs, cursor reuse, service-principal substitution, platform self-grant,
   revoked-binding replay, and concurrent attempts to remove the primary
   administrator fail safely. Daily child-administrator handoff and explicit
   primary credential recovery preserve primary identity, never promote a
   child to root, and produce correlated sanitized facts. An unrevoked platform
   binding protects even a disabled user's credentials; concurrent platform
   grant versus tenant password reset/status changes cannot permit takeover.
   Two initial/reset-password sessions cannot both become privileged after one
   changes the password. Ordinary password changes retain the verified current
   session and default to revoking others; explicit false retains only valid
   same-user sessions, never revoked or old temporary ones. A later platform
   grant and schema replay/restart cannot promote an invalid old session.
   Concurrent change/reset/recover/logout must not preserve a revoked session;
   a concurrent old-password login cannot evade required other-session
   revocation. Omitted, explicit true/false and forced-change options require
   separate gates, including current-session substitution denial.
3. **Resource and Audit isolation.** Both tenants create/read their own
   applications, database/service installations, quota entitlements, and
   Operations. Cross-tenant resource IDs, filters, headers, bodies, cursors,
   and roles never expose or mutate the other tenant. Disabling a creator or
   tenant preserves tenant ownership and existing workloads. Separately
   running IAM, Audit, PaaS, and dispatchers deliver each accepted mutation's
   tenant/actor/decision correlation through real PG18. Delayed delivery,
   exact replay, changed replay, unknown/wrong-installation tenant, wrong
   producer purpose, and IAM outage are covered without weakening immutable
   Audit chains or allowing platform operators to read tenant data.
   Shared application/configuration IDs and idempotency keys remain
   tenant-local. A configuration or revision cannot reference another tenant's
   application or configuration; rejected references leave no resource,
   Operation or accepted outbox fact. Distinct configuration values and their
   Operations are read only through the corresponding tenant session.
4. **Restart, single-tenant upgrade, and rollback.** The existing offline
   lifecycle owner upgrades an actual populated single-tenant installation,
   not only a fresh schema. Credentials, resources, Audit chains, and revoked
   identities/roles/sessions survive equal bootstrap and migration replay plus
   process restart. A verified rollback either preserves the supported
   contract or explicitly refuses an unsafe downgrade before modifying data;
   it must never revive credentials, discard a second tenant, or rewrite Audit
   history. The release topology's realm-aware clients must work through
   APISIX after upgrade and protected-backup recovery.
5. **Operable console.** Reuse the accepted control-plane components and
   navigation. In this task's isolated environment, a real browser opens a
   tenant as platform operator, manages members as tenant administrator,
   logs in as members in both realms, and sees only permitted resources.
   Reload/logout and forbidden/stale-session responses are exercised; a mock,
   empty screen, health response, or component test does not accept this gate.

At baseline `9fd45b0`, login accepts no realm and `iam.login_index` is globally
keyed by login name; there are no tenant opening/status or member-query/status
HTTP workflows. Audit ingestion confines a producer to its home organization.
The existing process gate proves a single bootstrap tenant plus isolation
attacks, not two independently provisioned tenants. These are gaps, not
accepted multi-tenant behavior. The existing console owner's overlapping
tenant/account work and the installation Audit owner's shared contracts must
have explicit implementation ownership and verified fixed commits before
integration; uncommitted work is not a donor or acceptance evidence.

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

The isolated `feat/iam-xxx` integration adapts fixed source `6a0f417` onto
`9fd45b0`, retaining the accepted platform-role boundary. It does not import
another Phase's checkpoint, moving branch, or acceptance status. The existing
action catalog remains in `000001`; the distinct account storage slice is
`000003`. User creation cannot attach `PLATFORM_OPERATOR`; explicit platform
binding commands keep their separate authority. The console can read that
role without presenting it as an assignable tenant role.

On 2026-08-27 this integrated branch passed fresh PostgreSQL 18 IAM HTTP and
Audit HTTP race gates, the dual-schema privilege/immutable-record gate, and
the independent IAM/Audit/PaaS plus two dispatcher process gate. These use a
task-owned database server, random loopback ports, and bounded concurrency;
no shared installation was changed. The IAM gate exercises repeated child
names, qualified login, alias competition/reservation, bounded directories,
explicit tenant grants, immediate role/session revocation, password reset,
and populated-schema replay. The process gate opens a second tenant through
HTTP, creates its PaaS resource, delivers both outboxes, verifies its chain,
and rejects cross-tenant resource, binding, and cursor access. The platform
grant/revoke/self-grant-denial and equal-bootstrap restart regression remains
in the same gate. Frontend type/lint/architecture/style checks, 52 tests, a
two-worker production build, and all 59 embedded files' export equality pass.
Full-repository tests and vet, IAM/Audit contract and service race tests,
stable contract generation, and Linux amd64 IAM/Audit/PaaS/UI builds also pass.

The primary/platform credential-protection increment also passed the fresh
PG18 IAM HTTP race gate, including a plain tenant administrator racing a
platform grant against password reset or member suspension, and rejecting
reset/enable of a pre-existing disabled platform user. Initial/reset-password
users cannot receive a platform binding until they change that password.
The independent five-process regression, focused IAM/contracts/architecture
tests, and vet pass. Primary-member and primary-role protection remain intact;
no online platform recovery or primary-ownership transfer was introduced.

The historical-proof increment adapts the public installation contract from fixed source
`6401e9602d2a5313cdc31f38363b86f404505894`, retaining the account integration
and the `686efca` credential-protection rollback point. This branch's own
fresh PG18 gates pass for IAM/Audit HTTP, separated database privileges,
immutable records, and all five independent authority/dispatcher processes.
The resolve endpoint now accepts only the event-bound request and verifies
the historical evidence specified above. Real HTTP tests reject independent
tenant selectors, substituted actor/decision/request/correlation/scope and
wrong producer purpose; exact IAM facts reject any content change. Historical
facts still resolve after the original user logs out and is disabled. The
process gate verifies both real tenant outboxes, the fixed verifier, Audit
outage/restart, equal replay, changed-authority denial, changed-business-payload
replay conflict, and current producer credential revocation. Unit gates cover
every closed action mapping and the explicitly unproved create payload.
It also passed [independent CI](https://github.com/xiak/matrix/actions/runs/33054487149)
at `26f3569269ba6e8bf3ac55b3c596c55590e1144a`.

The existing process-test owner builds and runs the actual IAM executables
from fixed `9fd45b0` and `a36cf9817f522549b995ea9c1f0d873499b4fe62` against
their original single-tenant and multi-tenant schemas. HTTP creates and changes
credentials, revokes a role/session and the platform binding, then the current
schema is applied twice and the new executable starts and restarts. Primary
identity, changed passwords, qualified child login, revocations and original
IAM facts are retained; the new binary rejects the unmigrated old schema
before bootstrap. The independent Audit upgrade gate retains original tenant
documents, canonical bytes and hashes from `9fd45b0`, keeps identical raw tenant
and installation IDs in separate chains, and rejects immutable-record writes.
Every old active session lacks credential-generation evidence and must log in
again; neither its issuance time nor explicit retention blesses it. New
generation-bound sessions survive explicit false, migration replay and process
restart without reviving revoked sessions. IAM readiness is 3 and Audit is 2;
these SQL migration checks do not authorize a cross-profile signed release
transition or historical-binary rollback.

The platform lifecycle increment passes this branch's real PG18 IAM HTTP,
Audit HTTP, separated-schema and retained-record upgrade gates. A non-primary
user with only an explicit platform role opens a tenant; tenant administrators
and ordinary members cannot use platform metadata or lifecycle commands.
Wrong versions, non-primary users, foreign-tenant targets and even a disabled
platform-bound primary leave credentials, sessions, bindings and success facts
unchanged. Same-version status/recovery races commit exactly one transition.
Recovery can repair a legacy disabled primary's missing active tenant-admin
binding without reviving its old revoked binding or transferring ownership.
The worker gate completes both tenant and installation claims and rejects
forged scopes into owner-bound dead letters; every Audit action is exercised
through both append and filtered query.
Full-repository unit/architecture tests and vet, IAM/Audit contract and service
race tests, stable generation and Linux amd64 builds also pass.

The independent five-process gate opens the second tenant over HTTP, admits a
real PaaS mutation during an Audit outage, then suspends the tenant. Both
outboxes deliver after Audit returns while old IAM/PaaS/Audit sessions remain
denied. Original-primary recovery, equal-bootstrap IAM restart and explicit
tenant restoration preserve forced password change and old-session revocation.
Disabling the resource creator changes neither the application document nor
the accepted Operation's tenant and original actor. All four lifecycle facts
arrive in the installation chain; tenant audit bytes, replay and verification
remain separate. This gate does not run a workload executor and therefore does
not by itself prove continued execution of a live container.

Process database identity must be proved independently of successful HTTP
flows. The original test DSN helper changed a parsed pgx config and then used
`ConnString()`, which returned the original migration-admin URL. Those runs
do not establish least-privilege executable logins or database tenant
isolation. This does not invalidate the separate adapter attack gates that
connect directly with the modified configuration. The corrected helper
constructs an explicit runtime URL, removes query credential overrides and
bounds each process pool to two connections. Its default, database-free gate
checks the user/password/address round trip. The real process gate checks
`session_user` and `current_user` with that DSN and separately inspects every
running binary's `pg_stat_activity` login, connection bound, and absence of
superuser/RLS-bypass privileges; the identity probe cannot satisfy the running
process check. No production diagnostic endpoint is introduced.
On 2026-08-27, this branch passed the corrected PG18 race gate for all five
processes and for the actual fixed `9fd45b0` IAM executable's populated
upgrade/restart. Other Phase branches must adapt and rerun their own gates;
these results do not certify their binaries.
The `cf003e4` correction is retained in the console/runtime milestone
`b66d77db0499b227f42b3b14d1869329aabcca30`, which passes all three
[independent CI jobs](https://github.com/xiak/matrix/actions/runs/33065779664).

The resource-isolation increment in the same gate uses two actual tenant
sessions with matching child login names, idempotency keys and database
resource IDs. Each tenant independently activates quota and admits two
database services; equal replay keeps its own quota/Operation, changed replay
conflicts, and over-quota admission leaves no reservation. Foreign quota,
service and Operation IDs, caller tenant headers/body fields and unsupported
selectors/cursors cannot select another tenant. A platform-only user has no
tenant-resource access, a viewer cannot mutate, and role revocation affects
the next request. Suspension rejects quota/service/Operation reads; recovery,
restoration and creator disable preserve their ownership, original actor and
accepted content. Real outboxes deliver one quota fact and two creation facts
per tenant with the original IAM authority. These are pending service records,
not claims that a PostgreSQL workload has been provisioned.

The same real-process gate also creates applications, configurations and
configuration revisions with matching IDs and idempotency keys in both
tenants. Equal replay preserves the local Operation; changed replay conflicts.
Distinct configuration values survive spoofed tenant/subject headers and URL
selectors without crossing tenants. Foreign application/configuration
references leave no resource, Operation or accepted outbox fact. Each
Operation remains readable only in its tenant; platform-only and revoked
roles cannot read or mutate these resources. Every delivered creation fact
joins its original tenant, actor, IAM decision, target and Operation exactly
once, without configuration values entering Audit. The bounded PG18
five-process race gate passes with these checks on 2026-08-27.

The task-local real-runtime gate on 2026-08-27 additionally runs the production
PaaS executor with the independent IAM/Audit/PaaS/UI processes, both dispatchers
and APISIX. Separate runtime database logins have one or two actual connections
and neither superuser nor RLS-bypass privileges. Browser-created PostgreSQL 18
workloads use the fixed image, at most two running instances, and verified
limits of 0.5 CPU and 1 GiB each. An initial infrastructure failure remains a
real `FAILED` Operation and releases its reserved quota; it is not rewritten
as a successful installation. Docker's exhausted default address pools are
worked around only with a task-owned explicit /28 network for the actual
generated Compose project, without changing global configuration or removing
another task's network.

Before starting the executor for the replacement request, the gate checks
that the tenant and original creator are both disabled and the accepted
Operation is still pending. The normal worker then provisions the database
and delivers its `managedservice.service-installation.ready` fact with the
original actor and IAM decision, while the tenant remains paused. Pausing the
other tenant preserves its already-running database and inserted row. Both
database rows, container identities and start times survive the tenant pauses
and an equal-bootstrap IAM process restart; disabled access is not revived.
Explicit restoration does not change resource ownership or resurrect old
sessions. Fresh public HTTP sessions reject foreign resource, Operation,
quota and audit-cursor access, keep platform and tenant audit reads separate,
verify both tenant chains and the installation chain completely, and replay
the historical ready fact as an exact duplicate. These live-engine observations
are task-local evidence, not an assertion that the pending-record CI gate runs
a workload executor.

The password-session increment passes this branch's fresh PostgreSQL 18 race
gates on 2026-08-28: forced initial/reset/recovery changes, ordinary omitted,
true and false choices, invalid selectors, atomic failure, later platform
grant, and concurrent change/change, reset, recovery, logout and old-password
login. Credential generation advances exactly once per successful change;
legacy NULL sessions remain denied after both actual old-binary upgrades.
The independent five-process regression retains actual restricted database
logins, dual-tenant resource/Operation isolation, lifecycle and historical
outbox proofs. The Audit HTTP, separated-schema and retained canonical/hash
gates also pass. Full-repository unit/architecture/race and vet, strict contract
generation, dependency verification and Linux amd64 builds pass. The native
Linux release boundary preserves published v1 authentication and rejects
different complete profiles before effects, including the prior `2/2/1`
revision 2. Fixed implementation
`5721b7b1a985f25c9730ddb9229a51f7f6c3b63a` passes all three
[independent Verification jobs](https://github.com/xiak/matrix/actions/runs/33138242923).

On 2026-08-28 the same fixed source passes the populated signed revision-3
install, A/B upgrade, failed-candidate rollback, data-preserving rollback,
selected-backup recovery and owned local-engine restart gates in
[FEAT-005](FEAT-005-offline-platform-lifecycle.md). The installed browser then
passes the dual-tenant password/session and real database journey in
[FEAT-007](FEAT-007-control-plane-console.md), including measured 360-pixel
controls. Together with the earlier lifecycle/resource checks retained by the
current regressions, these accept this branch's minimum multi-tenant slice.
The user's deferred keyboard-only usability gate is not counted as passed.
This does not accept another Phase, main, complete public-cloud IAM, an
arbitrary historical N-1 binary, or a cross-profile runtime transition.
The FEAT-005 owner retains the exact signed profile and compatibility limits;
retained-data SQL migration tests are not a substitute for signed lifecycle
acceptance, nor permission to upgrade an incompatible published installation.
Prior foundation evidence below covers only its named source revisions.

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
- Gate B's initial HTTP-flow evidence dates from implementation `255b790` on
  2026-08-26. It is not evidence of actual executable database-login isolation;
  that boundary requires the corrected process gate described above.
  IAM, Audit, the IAM Audit dispatcher, PaaS, and the PaaS Audit dispatcher run
  as five independent processes with exact file service credentials and
  HTTP-only authority integration. PaaS readiness binds
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
