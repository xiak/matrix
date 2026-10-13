# FEAT-007: Control-plane console and managed-service activation

- Status: In progress
- Target release: Matrix PaaS Phase 2
- Target design date: 2026-08-26
- Console API contract: `ui.matrix.xiak.com/v1`
- Managed-service API contract: `managedservice.matrix.xiak.com/v1`

## Outcome

Deliver an authenticated browser control plane in which an Account user can
inspect a release-owned service catalog, explicitly activate one service for
that Account, obtain a bounded offering quota, and install a real managed
service into an operator-configured local region. The same accepted release
must carry the UI, managed-service authority, provider artifacts and real
runtime evidence; a visual mock, catalog-only entry, or browser-only order is
not acceptance.

The current real providers are PostgreSQL 18, MySQL 8.4 LTS, Elasticsearch
8.19 and RabbitMQ 4.1. They are consumers of one generic service-definition,
activation, offering and installation protocol rather than four hard-coded IAM
products. Payment, invoices, tax and marketplace settlement remain outside
the private-deployment target.

## Product journey

1. The browser loads the independent Matrix control console through APISIX.
2. A user logs in with only `loginName` and `password`. IAM derives the
   organization and returns one opaque session plus the non-secret
   password-change requirement. A first-login user must replace the initial
   password in the same memory-only session before entering the console;
   there is no organization selector, JWT, external identity provider, or
   social-login branch.
3. The authenticated console shows an overview, service catalog, Account
   activations, quota, service installations, and local-region configuration
   allowed by the user's current IAM permissions.
4. The catalog exposes only release-owned service definitions whose offerings
   have registered real providers. A new service is registered by the product
   owner in the trusted release; an Account cannot publish or alter catalog
   definitions.
5. A separately authorized user explicitly activates one exact service
   definition for the current Account. Activation does not grant resource
   permissions, allocate quota, create a service role, or create a workload.
6. A user activates one allowed quota shape for an offering of an already
   activated service. This is a durable entitlement, not simulated monetary
   payment. The request accepts no caller price, currency, discount, invoice,
   payment result, Account selector, or product-native option.
7. A user selects an active quota and an eligible local region, names the
   service, reviews the exact resources, and submits an idempotent installation
   command.
8. The managed-service authority reserves quota atomically, provisions the
   selected release-owned offering asynchronously, and exposes normalized progress.
   A failed installation cannot silently consume or duplicate quota.
9. The ready result exposes a stable service endpoint and an opaque
   platform-owned credential reference. Passwords, machine credentials,
   Docker details, host paths, and provider-native errors never enter the UI
   response, Audit event, or support evidence.
10. Logout revokes the IAM session before the browser forgets it. The bearer
   credential otherwise exists only in page memory and is never placed in a
   URL, cookie, local storage, session storage, log, or rendered DOM.

## Ownership and boundaries

| Concern | Owner |
| --- | --- |
| User, password credential, session, organization, role, authorization decision | `iam` |
| Service definition, Account activation, offering, quota entitlement, quota consumption, service installation, provisioning state | `managedservice` |
| Local region registration and normalized machine capability | `managedservice` through its local-infrastructure port |
| Product lifecycle effect and credential-file custody | the offering's managed-service provider adapter |
| Application, ApplicationRevision, Deployment, application placement, and application execution | `apphosting` |
| Browser composition, navigation, session memory, order draft, and result rendering | `app/ui/paas` |
| Immutable accepted security and business facts | `audit` |
| Offline artifact inventory, installation, upgrade, rollback, backup, and recovery | `installation` |

`managedservice` is a distinct bounded context and API inside the Phase 2
modular monolith. It does not add database, search, queue, volume, credential,
or arbitrary native specifications to the Application PaaS workload contract.
Its use cases own transactions; the service catalog and activation domain stay
provider-independent, while persistence and each real product effect remain
adapters. A separate service-catalog process is not introduced until a real
non-managed-service consumer creates an ownership, scaling or release boundary.

The UI imports only versioned public contracts. It never imports a service
`internal` package, receives an internal service credential, proxies a user
credential through its Go process, or calls the APISIX Admin API.

### Three-party operating model

The feature has three independent consumers and must remain correct for all of
them:

| Party | Owns | Must not do |
| --- | --- | --- |
| Matrix contract and authority owners | public schemas, catalog validation, activation lifecycle, IAM Profile protocol, provider port, transaction/outbox rules, RLS and release compatibility | encode a service name in the evaluator, fabricate product readiness, or let UI metadata become authority |
| Service/product maintenance team | stable service definition, offerings, immutable artifacts, provider adapter, product-specific authorization declarations where needed, service-role templates where needed, native lifecycle and real-runtime/support gates | write an Account activation directly, mint IAM decisions, accept tenant/provider selectors, publish a catalog item without a real provider, or widen an accepted role template in place |
| Account users and administrators | explicitly activate an available service, obtain delegated permissions/quota, create and operate Account-owned resources, and consent to a separate service role where required | register/modify service definitions, choose artifacts/native commands, switch Account by selector, or turn activation into ownership by the individual actor |

The installation/release owner is the integration boundary between the first
two parties. It accepts only an exact signed release input, validates every
service definition, offering, provider and authorization declaration as one
closed graph, and gives all replicas the same canonical catalog digest. It does
not grant any Account activation during install, migration, bootstrap or
replay.

### Service-team onboarding and maintenance

A service team onboards through the source/release contract, not a customer
northbound registration API. Its smallest accepted contribution contains:

1. one stable `ServiceDefinition` and at least one immutable
   `ServiceOffering` that references it;
2. one provider implementation registered for every published offering, with
   exact artifact digests, bounded resources, readiness, reconciliation,
   deletion/retention semantics and secret custody;
3. use of the existing managed-service IAM actions, or a separately versioned
   product `AuthorizationProfile` only when the service exposes genuinely new
   business actions/resource kinds;
4. versioned service-role templates only when the service must act on other
   Account resources; activation alone never creates or passes the role;
5. API/domain/security tests plus a real create, native protocol use, restart,
   revoke, cross-Account, Audit and terminal-cleanup gate for that provider.

The registry rejects duplicate service/offering IDs, missing or extra
providers, namespace collisions, an unavailable artifact, invalid Profile
references and nondeterministic catalog bytes before readiness. Adding a
normal offering or service does not modify the generic IAM evaluator,
activation use case, activation table or UI routing. A service-specific
operation may extend only its own versioned declaration and PEP.

Product namespaces are centrally allocated release identities, not display
names chosen by a team or an Account. A service ID is lowercase, stable and
never reassigned after publication; its owning team and source owner are
review metadata, while the signed definition digest is the runtime authority.
Changing a team name, UI label or repository location therefore cannot change
an Account's activation. A product team cannot claim an existing namespace or
publish a second definition with the same `{id, revision}` and different
bytes.

The onboarding interface is deliberately small and typed. The existing
managed-service package will provide one definition constructor/validator,
one offering constructor/validator, one provider registration port and one
reusable conformance gate. A new team supplies product-owned values and a real
adapter; it does not copy a handler, migration, authorization evaluator,
activation table or UI page. The conformance gate runs the same registration,
create, native-use, reconcile, revoke, cross-Account, Audit and cleanup
protocol for an arbitrary service ID. A generated OpenAPI client and stable
error codes are the northbound integration surface; internal Go packages,
SQL, provider payloads and release-file layout are not an SDK.

Maintenance is additive and immutable: a new engine or provider release gets a
new offering/version and digest; existing installations continue to reference
their accepted offering until an explicit upgrade or termination workflow
handles them. Display-only corrections do not change activation authority. A
security-, legal- or consent-relevant activation contract change requires a
new definition revision and an explicit future renewal flow before it can
invalidate or expand an existing activation. It cannot silently reinterpret an
old Account consent.

Publication and runtime compatibility use exact capabilities, not optimistic
version comparisons. The release graph binds the catalog digest, managed-
service contract revision, referenced IAM Profiles, service-role templates,
provider registration and artifact digests. Every replica reports the same
accepted graph in readiness; a rolling deployment with mixed graphs keeps the
new definition unavailable until all serving replicas can enforce it. Before
v1, tests retain the current graph plus only one meaningful direct predecessor;
obsolete development schemas and synthetic compatibility paths are deleted.

Service dependencies, commercial eligibility and service retirement are
closed extension points rather than hidden activation side effects:

- activating one service never recursively activates another service;
- a genuine prerequisite must be a trusted, versioned definition rule with a
  stable denial code and no caller-supplied result;
- billing, legal terms, real-name checks and marketplace settlement may later
  implement such a rule, but cannot be inferred from IAM administration;
- `UNAVAILABLE` prevents new activation and installation while preserving
  existing Account activations and workloads;
- deprecation and end-of-sale require an explicit replacement and support
  window, while deletion/data destruction remains a separate audited command.

No dependency or eligibility field is added before a real product consumes
it. The extension point is frozen here so the first consumer extends the
trusted definition and its validator instead of adding a product-name branch
or arbitrary attributes map.

### Product-team and user experience contract

The service integration is split into three planes so one team cannot
accidentally turn publication into customer authority:

| Plane | Product-team operation | Account-user operation | Authority |
| --- | --- | --- | --- |
| Supply | publish a signed definition, offerings, providers, artifacts and optional authorization declarations | discover only definitions admitted by the installed release | release graph and catalog validator |
| Enrollment | declare closed prerequisites and safe lifecycle semantics | explicitly activate one exact definition when current Policy permits | IAM decision plus managed-service serializable transaction |
| Resource | implement provider effects, reconciliation and support evidence | obtain quota, create/use/terminate resources and separately consent to roles | product PEP, Account RLS, quota/Operation/outbox and Audit |

For a product team, the happy path is `allocate namespace -> implement one
provider -> run conformance gate -> include in signed release -> become
discoverable`. Publication fails before readiness if any declaration lacks a
provider, action owner, real artifact or required gate. There is no manual SQL,
bootstrap replay, UI patch or per-Account registration step.

For an Account user, the API projects independent booleans and reasons for
`discoverable`, `canActivate`, `activated`, `canAllocateQuota` and
`canCreateResource`; the console renders those server facts and never derives
them from primary/child/admin labels. A denial returns one bounded remediation
class such as permission missing, prerequisite unmet, definition changed,
service unavailable, quota missing or region ineligible. It never exposes
Policy internals, another Account, provider errors or secret material. A
request/correlation ID links the safe response to Operation and Audit evidence
without making log text part of the contract.

The generic authority remains horizontally scalable: API and worker replicas
are stateless with respect to authorization; the database, IAM decision and
exact release graph are authoritative. Unique keys, serializable transactions,
row locks, leases/fencing, idempotency commitments and transactional outbox
close cross-replica races. Reads may use bounded caches only for immutable
catalog bytes; activation, revocation, quota and resource authorization are
never accepted from a cache. Backpressure and per-Account request limits fail
with stable retry semantics rather than unbounded queues or duplicate effects.

Product observability is part of onboarding. Every accepted product exposes
normalized readiness, bounded Operation progress, stable non-secret failure
codes, Account-safe metrics and correlated Audit facts. Native logs and
provider credentials stay in the product adapter/support boundary. The
platform distinguishes request acceptance, provider progress, terminal
success, terminal failure and unknown outcome; neither an HTTP timeout nor an
Audit enqueue is presented as resource success.

### Real-user ownership and use

Service activation is one Account-level relationship, not one activation per
sub-user. The activating USER/ROLE is retained as the Audit actor, but the
activation, quota, installation, Operation, data and workload remain owned by
the Account. Disabling or deleting that actor therefore does not delete or
reassign the resources. Future requests still require another current identity
with the appropriate resource action; activation is never a bearer permit.

The normal user path is `discover service -> activate once -> allocate quota ->
create resource -> optionally consent to a service role -> operate resource`.
Each arrow is independently authorized and auditable. Account suspension
blocks new protected mutations and access according to IAM, but does not
silently destroy data or stop already running workloads. Product-native
credentials, provider errors and internal topology remain outside catalog and
activation responses.

## Enterprise target model

### Public-cloud precedent and selected boundary

The public APIs demonstrate two useful but distinct patterns:

- Google Cloud exposes a consumer-scoped Service Usage resource and
  `services.enable`, `services.disable`, `get` and `list`; enabling requires a
  separate IAM permission and returns an Operation.
- Azure registers a resource-provider namespace for a subscription; provider
  registration has its own state and authorization-consent projection, and
  resource creation may trigger registration.
- Tencent Cloud and Alibaba Cloud commonly keep first-use activation in each
  product API, such as `ActivateService`, `OpenService` or
  `OpenAckService`; RAM/CAM still authorize that operation independently.
- AWS commonly permits direct product use and creates a service-linked role on
  first use where cross-service authority is required. Its service-linked-role
  create/delete lifecycle is not the product-activation lifecycle.

Matrix adopts a consumer-scoped generic activation resource like Google Cloud
and Azure, while retaining the Tencent Cloud and Alibaba Cloud rule that the
product owner publishes its own trusted service definition and provider. It
also retains the AWS/Tencent Cloud separation between service activation and
service-linked-role consent. The external references are the
[Google Service Usage API](https://cloud.google.com/service-usage/docs/reference/rest),
[Azure provider registration API](https://learn.microsoft.com/en-us/rest/api/resources/providers/register?view=rest-resources-2021-04-01),
[Tencent Cloud ActivateService example](https://cloud.tencent.com/document/api/1729/109752),
[Tencent Cloud service-linked-role API](https://cloud.tencent.com/document/product/598/43711),
[Alibaba Cloud MNS OpenService](https://help.aliyun.com/zh/mns/openservice),
[Alibaba Cloud ACK OpenAckService](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/developer-reference/api-cs-2015-12-15-openackservice)
and [AWS CreateServiceLinkedRole](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateServiceLinkedRole.html).

### Service definition and Account activation

`ServiceDefinition` is a release-owned immutable activation contract with a
stable lowercase ID, display metadata, revision, canonical content digest and
availability state. Its ID identifies a service family such as `postgresql`;
it is not an IAM `ProductID`, provider image, engine version, offering or role.
Only definitions backed by at least one registered and accepted provider may
be `AVAILABLE`. There is no tenant-facing create/update/delete catalog API.

`ServiceActivation` is owned by exactly one Account and one exact
`ServiceDefinitionReference {id, revision, contentDigest}`. Existence means the
service is active; the first slice has no speculative `ACTIVATING` state. It
stores a monotonic resource version and database activation time. The current
credential supplies Account and actor; neither is accepted from a header,
query, path, body, cursor or provider callback.

Activation is only permission to begin using that service family. It does not
grant a USER or ROLE permission to create/read resources, allocate an offering
quota, accept prices, create a service-linked role, or let the provider act on
other Account resources. Those remain separate, independently authorized and
audited relationships. `ProductManagedService` remains the IAM authorization
namespace for this bounded context and must not be cloned into
`managedservice.postgresql`, `managedservice.mysql`, or one ProductID per
catalog entry.

Public clouds consistently give the account/project/subscription owner this
ability while leaving ordinary child identities empty by default. They also
permit delegation: Google Cloud includes `serviceusage.services.enable` in
Owner/Editor and the dedicated Service Usage Admin role; Azure includes
`/register/action` in Owner and Contributor; Tencent Cloud and Alibaba Cloud
document main-account or authorized administrator/CAM/RAM user flows. AWS has
no universal activation action, but ordinary IAM users still start with no
permissions and first-use service-linked-role creation requires an explicit
IAM permission. Matrix therefore adopts this default policy matrix:

| Current identity | Default activation authority |
| --- | --- |
| Original primary USER | Yes, because its protected `system.account-administrator` attachment includes the action; there is no evaluator `isPrimary` bypass |
| Child USER or assumed ROLE with `system.account-administrator` | Yes |
| USER or ROLE with the narrow `system.service-activation-administrator` policy | Yes |
| `system.paas-developer` | No activation by default; it may use already activated services according to its resource actions |
| `system.paas-viewer` or ordinary child USER | Read-only or none according to attached policy; never activate by identity type alone |
| `system.platform-operator` | No; operating the installation does not imply access to an Account's service catalog state |
| service identity | No; service identity cannot grant its customer an activation or act as an Account administrator |
| AccessKey | Deferred until the managed-service programmatic PEP is explicitly admitted; no browser/session fallback |

The narrow system policy is a delegable permission document, not a new account
class or hard-coded role. A custom policy may grant the same closed action when
the policy compiler admits it. Suspension, USER/ROLE disablement, attachment
revocation and session revocation take effect on the next protected request.
The opening action is Account-wide, matching the project/subscription-level
cloud APIs; the first slice does not pretend to support per-service activation
delegation when its create-collection authorization cannot prove that shape.

Permission is necessary but does not override product-owned prerequisites.
Some public-cloud products restrict initial legal, billing or service-role
consent to the main account even when ordinary resource administration is
delegable. The four current Matrix private-deployment services have no billing
or legal prerequisite and therefore use `PERMISSION_ONLY`: either Account
Administrator or the narrow delegated policy may activate them. A future
product that truly requires original-primary consent must introduce a closed,
server-validated activation prerequisite in its trusted definition and prove
that flow before publication. The UI must never infer eligibility from an
"administrator" label, and activation must never auto-create a service-linked
role to satisfy such a prerequisite.

The first slice deliberately has no deactivate endpoint. Product dependencies,
existing resources, retained data, quota and service-role cleanup need an
explicit product contract; a generic delete must not silently stop workloads
or destroy data. A later deactivation protocol must fail closed while dependent
resources or roles exist and must define its own audited terminal behavior.

### Service offering

`ServiceOffering` is a code-owned immutable catalog entry with:

- stable ID and exact service-definition reference;
- display name and bounded description;
- engine family and supported major version;
- allowed quota shapes;
- supported region capability selector;
- server-owned installation profile version;
- availability state.

The current release admits offerings for PostgreSQL 18, MySQL 8.4 LTS,
Elasticsearch 8.19 and RabbitMQ 4.1. A fifth or later service uses the same
definition/activation/offering/provider registry; adding it must not add a
service-name branch to IAM, the generic use case, persistence or UI. The
browser cannot submit an image, artifact digest, command, Compose document,
port, volume, environment value, extension, superuser name, provider-native
option, or arbitrary provider schema.

### Quota entitlement

`QuotaEntitlement` is Account-owned and contains an immutable offering,
quota shape, purchased instance count, resource version, activation time, and
current reserved/consumed counts. Allowed shapes are code-owned and use checked
integer CPU, memory, and storage values. A request chooses a shape and instance
count only; the server resolves all numeric resources.

Quota activation uses `(Account, idempotencyKey)` plus a canonical request
digest and requires an ACTIVE activation for the offering's service in the
same transaction. Equal replay returns the same entitlement. Changed reuse
conflicts. Concurrent reservations lock the entitlement and cannot exceed its
purchased count or any capacity dimension.

### Local region

`Region` is an operator-owned installation target. The first profile is
`LOCAL_MACHINE`, backed by an exact LocalMachine binding and a normalized
capability observation. Tenant users select only a region ID. They cannot see
or set an endpoint, host key, credential reference, Docker socket, host path,
provider payload, or target ID.

Phase 2 exposes a read-only local-machine configuration view to organization
administrators. Region registration, its display name, and capability
inspection remain installer-owned exact configuration. A browser mutation or
inspection trigger is deferred until a real infrastructure authority owns that
workflow; the browser never accepts a private key, plaintext machine
credential, endpoint, socket, or host path.

### Service installation

`ServiceInstallation` is organization-owned and contains:

- immutable ID, name, offering, engine version, quota entitlement, and region;
- exact reserved quota and installation profile version;
- desired state and monotonic resource version;
- normalized phase, current Operation, endpoint reference, credential
  reference, and safe failure code;
- creation and observation times from database time.

Create validates authority and all referenced current facts, reserves quota,
stores the installation and one durable Operation in one serializable
transaction, then returns `202 Accepted`. The worker acquires a bounded lease
and fencing token, reconciles uncertain effects before retry, and records a
sanitized Audit outbox fact in the owning transaction.

The local PostgreSQL provisioner uses only the release-owned digest-pinned
artifact and server-generated restrictive credential material. It performs no
pull or build, never executes caller input, and owns only objects labeled with
the exact installation identity. Persistent storage is installation-owned and
must survive process restart and compatible platform upgrade. The outer
installation-owned directory remains restrictive while its PostgreSQL 18 bind
mount root preserves the fixed image's sticky traversal contract; PGDATA below
that root remains owned and confined by PostgreSQL. A terminal
provisioning failure releases only the reservation proven to belong to that
installation; retry or equal command replay cannot create a second instance.

## Console architecture

The replacement UI is a Matrix-owned Next.js 16 and React 19 App Router
application. It preserves the fixed donor's complete route, provider,
repository, scene, renderer, and public-component architecture rather than
reducing that application to a component library. Next.js performs a static
export at build time and the immutable result is embedded into the existing Go
UI binary. A Next.js server, React tooling, package manager, and donor source
are never production runtime dependencies. Production installation remains
offline and makes no browser-side external asset request.

The first end-to-end component chain is:

```text
Next.js App Router entry
  -> route parser
  -> ControlPlaneProvider
  -> ControlPlaneRepository (real public API adapter)
  -> ConsoleScene
  -> internal ConsoleShellRenderer
  -> @ui/xiak Layout, Sider, Header, Button, Input, Badge, and Typography
```

The donor shell is translated as a whole into PaaS language:

| Donor shell responsibility | Matrix control-plane responsibility |
| --- | --- |
| guild rail | product rail for platform overview and managed-service families |
| channel/context sidebar | active product navigation for catalog, quotas, installations, and regions |
| chat/content page | selected control-plane workflow or resource detail |
| right workspace | order review, installation Operation, or contextual inspector |
| user settings dock | authenticated principal, role summary, and revoking logout action |

The social domain, labels, content, and mocked workbench data do not cross the
boundary. The route and scene vocabulary is rewritten around offerings,
entitlements, regions, installations, and Operations; no guild, channel,
message, friend, or social billing type remains in target source.

Public components use semantic Ant Design-style names and a stable
`@ui/xiak` facade. Parser, wire, scene, and renderer types never leak through
that facade. Business clients do not fetch from leaf components. Server data
stays behind the repository and in the owning provider/application state. Only
transient cross-region shell state may enter a client store. Global CSS owns
reset and the palette-to-functional-to-semantic theme tokens; components use
scoped styles and functional tokens instead of donor hash classes, inline
styles, or raw theme colors.

The initial theme uses neutral light surfaces, one restrained blue accent,
subtle panel borders, and low-elevation shadows. Public controls share sizing,
radii, focus, disabled, and semantic status treatments. Content grids respond
to the available content width so opening the workspace does not compress the
overview into unreadable columns. The style gate checks normal text, status,
input boundary, and focus contrast against the theme's resolved color tokens.

The desktop shell has a product sider, stable header, primary content, and an
optional contextual panel. Compact mode uses one overlay at a time and leaves
the active task reachable. The login route and every authenticated route must
remain keyboard usable, visibly focused, reduced-motion compatible, and
readable at 360 CSS pixels without horizontal page scrolling.

Command failures must be visible inside an open contextual panel, not hidden
behind its compact-mode overlay. Closing the panel preserves the same notice
in the main content; reopening it restores the notice in the panel without
duplicating live alerts. This behavior requires component and real 360-pixel
installed-release checks, not just a successful backend permission denial.
Refreshed installation choices must match the IDs that a submit would send.
When an initially unavailable or previously selected quota/region becomes
available or invalid, the form must explicitly request a selection rather
than displaying an option it has not selected or silently changing the target.
Refreshing these choices preserves the user's instance ID and display name.

## Public API and authority

The managed-service API provides only the bounded routes needed by the journey:

- list/get available service definitions;
- create and list/get Account service activations;
- list/get available offerings for registered providers;
- list/get eligible regions;
- activate and list/get quota entitlements;
- create and list/get service installations;
- get the installation Operation;
- inspect the non-secret local-machine region configuration as an organization
  administrator.

The frozen service-activation surface is:

```text
GET  /managed-services/v1/services
GET  /managed-services/v1/services/{serviceId}
GET  /managed-services/v1/service-activations
GET  /managed-services/v1/service-activations/{serviceId}
POST /managed-services/v1/service-activations
```

Reading definitions, reading activation state and activating are separate IAM
actions. `GET /services` never proves that the Account activated a service;
`GET /service-activations*` returns only after
`managedservice.service-activation.read` succeeds and otherwise returns a
closed authorization response rather than leaking state. Resource list/read or
create permission is neither required for that activation read nor implied by
it. Conversely, a deliberately minimal custom resource Policy may operate an
already active service without receiving activation-directory permission; its
resource request still rechecks the Account activation server-side.

Catalog access projects the existing non-authoritative `ActionCapability` for
the exact `managedservice.service-activation.activate` action and target so the
console can decide whether to render an activation control. `canActivate` is
therefore an actor-relative Policy result, never an identity-class boolean.
There is no generic `canEnterWorkspace`: entering and operating a product
workspace uses that product's exact collection/resource read and mutation
capabilities. Every command authenticates, authorizes and rechecks current
state again; the projection is not a cached permit.

The first slice has no activation-in-progress state. The Account fact and its
Audit outbox either commit together or do not exist. A definite authorization
or prerequisite denial creates no activation; an unknown result is resolved by
repeating the same idempotency key and exact request. `UNAVAILABLE` or retired
definitions reject new activation but do not erase an existing activation or
stop resources. Consent-relevant definition changes use a new exact revision;
the existing activation remains bound to its accepted revision until a future
explicit renewal protocol is delivered. Display-only changes do not require
renewal.

Browser results are scoped to the credential generation that initiated the
request. Login, logout, role-session replacement or Account switch invalidates
pending projections and resource responses in the UI; a late response cannot
restore an earlier identity's controls. This client rule improves presentation
only—the server still treats each request independently and derives Account
and actor from the current credential.

`POST` requires `Idempotency-Key` and accepts only:

```json
{
  "service": {
    "id": "postgresql",
    "revision": 1,
    "contentDigest": "sha256:<canonical-definition-digest>"
  }
}
```

The exact reference prevents a stale console from consenting to a definition
different from the one it displayed. The server resolves the current trusted
catalog and rejects unknown, unavailable or changed references; the body never
accepts Account, actor, ProductID, offering, quota, price, role, provider,
artifact, callback or arbitrary attributes. First commit and exact replay
return the same `ServiceActivation`; reuse of the idempotency key with changed
input conflicts. A unique `(account_id, service_id)` key and one serializable
transaction close concurrent commands from multiple API replicas.

The transaction revalidates the current IAM decision and catalog reference,
inserts the activation and its immutable Audit outbox fact atomically, and
uses database time. PostgreSQL RLS is forced on the Account-owned activation
table. The catalog is release-owned deterministic input: replicas with a
different canonical catalog digest fail readiness instead of serving a mixed
definition. Optional caches may accelerate reads but never authorize or
survive as the activation authority.

Every admitted mutation requires `Idempotency-Key`. Phase 2 has no mutable
region endpoint. Collection queries are bounded and deterministically ordered.
Organization, user, and role come only from IAM. Public resource IDs cannot
select another organization, and PostgreSQL row-level security is forced on
every organization-owned table.

IAM adds the closed `managedservice.service-definition.read`,
`managedservice.service-activation.activate` and
`managedservice.service-activation.read` actions and the
`SERVICE_DEFINITION`/`SERVICE_ACTIVATION` resource kinds to the managed-service
Profile. The Account Administrator and narrow Service Activation Administrator
system policies receive the mutation; PaaS Developer and PaaS Viewer receive
only reads needed for already activated services. This is policy evaluation,
not a UI-only or primary-user shortcut. An expired, revoked, malformed or
unavailable session fails closed on the next request.

### Account access extension

The existing `/console/access` route consumes the account and lifecycle
authority in [FEAT-006](FEAT-006-platform-authorities.md). Platform tenant
management and tenant-member management are independent capabilities: a
platform-only operator must be able to open and manage tenant metadata without
querying that tenant's users or resources. The original primary user is shown
separately from the tenant resource owner and from revocable child
administrators; this route offers no primary transfer or platform-role grant.

The lifecycle controls use the returned organization version and explicit
confirmation. Suspension explains that access freezes without destroying data
or stopping workloads. Recovery fixes its target to the original primary user,
clears the submitted temporary password, and cannot implicitly resume a
suspended tenant. Protected platform credentials remain an offline recovery
boundary. Conflict, revocation, and unavailable responses must not look like
successful changes.

Password/session behavior implements FEAT-006's effective
session policy. Existing user settings expose ordinary password replacement
to the current user, with "exit other login sessions" checked by default.
Explicit false retains only other valid sessions, not revoked credentials.
Required first-login/reset/recovery replacement offers no opt-out and keeps
only the revalidated current bearer. The console names sessions, not devices.
Password inputs clear on submission. Unknown results or invalid credentials
return to login; a definite validation rejection can be corrected in place.
Late password responses cannot restore a session after logout or expiry.
The new behavior passes 90 frontend tests, type/lint/architecture and all 20
contrast checks, with two separate two-worker production exports matching all
59 embedded files. The current-session choice, forced no-opt-out form,
immediate password clearing and late-response/expiry protections are included.
Its real installed browser gate passes from fixed source `5721b7b` as detailed
below; previous release evidence is not used to certify this new contract.

Acceptance on the isolated IAM branch requires adapter/component gates and a
real browser against its own IAM/PaaS/Audit environment: a platform-only user
opens and manages a tenant; tenant administrators create and authorize child
users; matching child names log into separate tenants and see only permitted
resources; status/recovery, forced password replacement, logout/reload,
permission denial and stale-session behavior work. Measured 360-pixel checks
cover these controls. The user has explicitly deferred native keyboard-only
verification; it remains an unpassed usability follow-up, not a prerequisite
for this prioritized IAM slice. Source checks or another Phase's browser
evidence do not replace its installed-release gate.

This branch's adaptation passes type checking, lint, architecture, the 20
contrast checks, 90 frontend tests, Go embed checks and two bounded,
two-worker production exports matching all 59 embedded files. Adapter and
component gates cover platform-only navigation, version-bound lifecycle
requests, original-primary recovery while paused, password clearing on
conflict, disabled platform-credential protection, and removal of protected
content after a failed session. Background reads cannot erase a rejected
command's notice; a failed protected poll or a command discovering an invalid
session removes the old resource snapshot. An account refresh cannot retain
an earlier mutation's success message after session failure. The nine added
behavior regressions fail before these corrections and pass afterward.
The quota and installation denial regressions additionally prove one live
notice in the active context panel, preserving it in the main content when
closed and restoring it when reopened. Both fail with the old main-only notice
and pass with the renderer correction and installed-release check below.
Four further regressions cover quota/region choices appearing or becoming
invalid after refresh: the visible placeholder requires explicit selection,
invalid choices cannot submit, instance inputs survive, and the submitted IDs
match the new choices. These fail before the selection correction and pass
afterward and in the signed-runtime quota refresh check below.

On 2026-08-27 this branch's real APISIX/IAM/Audit/PaaS browser environment
passes the account/lifecycle path: a platform-only child opens two tenants,
each original primary changes its initial password and creates a child with
the same username, and explicit tenant roles permit the corresponding resource
workflow. Qualified tenant-ID and account-alias logins resolve to the correct
tenant. Both children complete their own forced password changes and submit
real quota and database requests; each sees only its tenant's resources.
The live executor and preserved-data evidence belong to FEAT-006.

The same browser sessions prove role revocation, read-only write denial,
member disable/enable and password reset, rejection of a stale member version
after concurrent password change, and old-session denial after restoration.
Platform-only access does not load the tenant user directory or permit tenant
resource reads. Recovery keeps the original primary ID, does not resume a
paused tenant, and still requires password replacement after explicit tenant
restoration. Actual logout and full-page reload do not retain a usable browser
credential. Failed polls remove protected content; write-denial notices remain
visible across successful polls, and a failed account refresh shows no stale
success notice.

Measured 1280-by-900 and 360-by-800 CSS-pixel views cover account/member
controls, tenant status/recovery confirmations and the resource list without
horizontal page overflow. Account card headers wrap complete action buttons
instead of squeezing their labels into vertical text. Keyboard-only end-to-end
verification remains open: pointer-driven browser actions and component
keyboard tests do not certify that gate. The user has deferred this lower-priority
keyboard-only gate; it is not counted as passed. The signed offline profile/lifecycle evidence
belongs to [FEAT-005](FEAT-005-offline-platform-lifecycle.md); neither changes
another Phase's acceptance state.

### Installed-release browser evidence

The current password/session journey passes on 2026-08-28 against signed
Release A `matrix-v0.1.0-5721b7b1a985`, fixed source
`5721b7b1a985f25c9730ddb9229a51f7f6c3b63a`, after FEAT-005's populated
revision-3 lifecycle and owned-engine restart. Its three independent
[Verification jobs](https://github.com/xiak/matrix/actions/runs/33138242923)
pass. No development UI, mocked service, browser data stub or other Phase's
running environment is used.

Both original primaries log in and create a child named `session-member` with
an explicitly selected developer role. Their qualified logins resolve to
separate tenants. Two initial-password sessions exist for the first child:
after one completes forced replacement, only that current session can proceed;
the other cannot change the password or gain ordinary permissions. The second
tenant's child completes its own independent forced replacement. Each child
creates a real PostgreSQL 18 installation with the same public resource ID
`session-database`; its browser lists only its tenant's instance.

An ordinary password change with the default checkbox retains the current
session and rejects the other session's next protected request. All three
password inputs are empty after submission. A fresh additional login then
tests explicit false: both still-valid sessions remain usable after protected
reads, but the earlier revoked session remains denied. The other tenant's
session and resource list are unaffected. These are independent browser
sessions, not a claim about device identification.

The original primary resets the first child's password through member
management. After that transaction reports completion, both of the child's
previously valid sessions lose protected content on their next reads, and the
old password cannot log in. Two fresh reset-password sessions then prove that
forced replacement again retains only the submitting session; the other
temporary session cannot promote itself or change the replacement password.
The accepted new password logs in normally and sees only the original tenant's
database. Passwords and all browser actions are handled by the acceptance
driver, not left as manual work for the user.

Both PostgreSQL 18.4 workloads are bounded to 0.5 CPU and 1 GiB. Their container
IDs, start times and distinct SQL marker rows stay unchanged through explicit
session retention, administrator reset and forced replacement. Separate
authenticated Audit readback verifies four alpha and one beta password-change
facts for these new children, only alpha's reset fact, and each database's created/ready pair joined
to the expected child, tenant, original IAM decision and request correlation.
Both tenant chains verify completely; no password appears in those records.
This readback is an HTTP/data check in addition to, not a replacement for,
the real browser observations.

Desktop interaction and an actual 360-by-800 CSS-pixel view cover the new
password controls. At 360 pixels the full option and explanation are visible,
pointer toggling works in both directions, password inputs remain empty and
the document has no horizontal overflow. The temporary viewport override is
removed after checking. Native keyboard-only end-to-end acceptance remains
explicitly deferred by the user and is not inferred from pointer or component
tests.

The unchanged tenant/lifecycle and resource-control paths also retain their
earlier installed-runtime evidence: signed source `b3a6f81` exercises tenant
opening, primary/child creation, alias login, identical resource IDs and
tenant suspension/recovery with live PostgreSQL data. Source `464910f` proves
visible quota/installation denials in the open 360-pixel context panel and
preserves one notice through close/reopen, plus disabled-member reset/enable
and old-session denial. Source `a36cf98` proves a quota activated in a separate
primary session appears after the child's refresh, requires explicit
selection, preserves entered values and still refuses a viewer's submission.
These checks use real signed, profile-checked UI upgrades and preserved
database markers, not disabled-input checks. Their regressions remain in the
current 90-test suite; their former revision-2 profile does not certify the
new session contract, which is verified separately above.

## Incremental acceptance

### Gate A: control-console foundation

1. The Phase 1 single-page configuration workspace is replaced, not retained
   as a parallel or compatibility route.
2. The locked Next.js static export is deterministic, copied into the Go embed
   boundary, and a drift gate proves generated assets match source without a
   network fetch or a production Next.js server.
3. Real IAM login and logout work through APISIX with credentials only in page
   memory. First-login password replacement is a real IAM workflow, reload
   requires login, and storage and DOM inspection find no bearer or password.
4. The app shell, catalog, quota configurator, region view, and installation
   review render through the semantic scene-to-public-component chain. No UI
   action reports a purchased quota or installed service before a real API
   result exists.
5. Next.js route/export, type, lint, architecture, component behavior,
   accessibility, responsive, security-header, offline-asset, Go embed, and
   visual acceptance gates pass.

### Gate B: managed-service authority

1. Strict Go/OpenAPI contracts validate service definitions, Account
   activations and all existing resources; they reject unknown, duplicate,
   oversize, stale definition references, unsupported offering/shape,
   caller-selected Account, native provider, price/payment, credential,
   artifact and machine fields.
2. Domain tests prove catalog closure, definition canonicalization, activation
   idempotency, checked quota arithmetic, concurrent reservation bounds, equal
   replay, changed conflict and valid installation transitions. A synthetic
   fifth service name passes the same contract/domain path without adding a
   service-name switch; it is not published without a real provider gate.
3. A clean PostgreSQL database applies the managed-service schema twice and
   proves migration/runtime role separation, forced Account isolation, unique
   concurrent activation, activation-before-quota, transactionally coupled
   activation/entitlement/reservation/Operation/Audit facts and database-time
   behavior. Only the current schema and one meaningful direct predecessor are
   retained before v1; obsolete pre-release snapshots are replaced, not
   multiplied into a compatibility matrix.
4. Real IAM permits Account Administrator and the narrow Service Activation
   Administrator to activate, denies PaaS Developer/Viewer, Platform Operator,
   ordinary USER and service identity, and immediately observes session,
   USER/ROLE, Account or attachment revocation. IAM, catalog or database
   uncertainty fails closed.
5. Two Accounts activate the same service independently; same service ID,
   idempotency key, resource ID and cursor cannot cross Account boundaries.
   Concurrent exact commands converge, changed replays conflict, failed
   authorization/Audit leaves no partial activation, restart does not revive a
   revoked identity, and quota or installation creation without a current
   activation is rejected without side effects.
6. The browser completes login, catalog selection, service activation, quota
   activation, region selection, installation submit and bounded Operation
   polling against the real services without a mock or privileged browser
   path. UX/UI implementation remains owned and accepted on its separate
   branch after consuming the fixed public contract.
7. One product-team conformance fixture with an arbitrary service ID registers
   through the same typed constructors and provider port, while duplicate
   namespace, missing/extra provider, changed same-revision bytes, mismatched
   Profile/artifact, nondeterministic catalog and mixed-replica digest all fail
   before publication. The fixture is not exposed as a customer product.
8. User-facing capability projection distinguishes discover, activate, quota
   and resource authority. Stable remediation classes and correlation IDs are
   safe, Account-scoped and consistent across replicas; timeout, retry and
   unknown provider outcome never fabricate activation or installation
   success.

### Gate C: local PostgreSQL and release consumption

1. From an empty owned local region, the worker installs the fixed PostgreSQL
   artifact with no registry, pull, build, arbitrary command, plaintext
   manifest secret, host-path selector, or unrelated Docker mutation.
2. Readiness proves the exact engine/version, durable storage, quota identity,
   endpoint reference, credential reference, and Audit facts. Restart preserves
   data and reconciles an interrupted or uncertain create without duplication.
3. Unsupported offering, exhausted quota, stale region observation, wrong
   organization, revoked session, altered artifact, native failure, and worker
   restart all fail with normalized non-secret behavior.
4. The offline release packages the rebuilt UI and managed-service runtime,
   installs with external network disabled, and repeats the complete browser
   journey through APISIX and real IAM.
5. Upgrade, failed upgrade rollback, explicit platform rollback, backup,
   recovery, status, verify, and support evidence preserve or safely reconcile
   service installations without credential, machine, native-error, or path
   leakage.

Common generation-drift, unit, vet, race, repeated, schema, architecture,
real-PostgreSQL, real-local-runtime, cross-platform build, Markdown-link,
stale-term, donor-dependency, tenant-authority, secret/path-leakage, browser,
and `git diff --check` gates must pass on the same committed worktree.

## Implementation status

- Gate A now implements the complete App Router -> route -> provider ->
  repository -> scene -> renderer -> public-component chain for account IAM,
  the generic catalog, per-product activation, quota and installation routes.
  The browser keeps the IAM bearer only in page memory and every product route
  consumes the same public service-definition contract; no product name is a
  UI authorization switch. Source `602dd53c89b5bd6322b5189044e1a076e58cbbf6`
  passes 67 frontend files and 1,278 tests, type/lint/architecture checks, 228
  contrast pairs, 59 exported pages covering 57 normalized routes, and exact
  rebuilding of 319 embedded files. Keyboard-only and 360-pixel installed-
  release verification remain deferred by the user's current priority; source
  checks do not substitute for that later gate.
- Gate B now uses the generic `ServiceDefinition`/`ServiceActivation` boundary
  and provider registry for PostgreSQL, MySQL, Elasticsearch and RabbitMQ.
  Account activation, quota, resource permission and service-role consent are
  independent current facts. Product onboarding is release-owned and closed
  by typed definitions, immutable offerings, an exact provider registry and
  authorization declarations instead of a mutable service-name whitelist.
  A synthetic fifth service passes the same contract/domain conformance path
  without a new IAM or UI branch, while publication still fails closed unless
  a real provider and its fixed artifact are present.
- On 2026-10-13, the isolated browser-process gate from that fixed source
  passed in 435.583 seconds against a fresh PostgreSQL 18 database and the
  digest-pinned PostgreSQL provider. The browser performed primary login,
  service activation, quota activation, installation and bounded polling; SQL
  proved the real runtime before termination. It also set, replaced and
  removed a USER permission boundary, attached `PaaSViewer`, recorded an exact
  installation-read allow, revoked the attachment in a second primary session,
  and observed an exact read denial from the original member session. The gate
  then proved physical runtime/data/credential deletion, quota return, terminal
  Operation facts and the verified Audit chain. This is a source/process gate,
  not the still-required signed offline-release/APISIX browser acceptance.
- GitHub Actions run
  [38261952694](https://github.com/xiak/matrix/actions/runs/38261952694)
  passed for the exact `602dd53c89b5bd6322b5189044e1a076e58cbbf6`
  source: all 18 jobs completed successfully, including Go, console,
  authority-process, managed-product and installation PostgreSQL HA gates.
  The result belongs only to that fixed commit; this documentation update does
  not inherit or replace the final signed-release gate.

## Deferred

Money movement, invoices, tax, discounts, metering-based billing, marketplace
publishing, additional engines beyond the four accepted providers, arbitrary
Helm/Compose templates, customer images, public-cloud accounts, VM/network provisioning, Kubernetes,
multi-region placement, high availability, read replicas, point-in-time
restore, engine upgrades, deletion, external IdP, LDAP, SAML, OIDC, MFA, and
mobile-native applications remain outside this target.

The product and source dependency boundaries remain owned by
[`ADR-0002`](../architecture/ADR-0002-product-boundary.md) and
[`DEPENDENCY-RULES`](../architecture/DEPENDENCY-RULES.md). Fixed donor
decisions are owned by the
[`FEAT-007 adoption review`](../adoption/FEAT-007-control-plane-console.md).
