# FEAT-007: Control-plane console and PostgreSQL service activation

- Status: In progress
- Target release: Matrix PaaS Phase 2
- Target design date: 2026-08-26
- Console API contract: `ui.matrix.xiak.com/v1`
- Managed-service API contract: `managedservice.matrix.xiak.com/v1`

## Outcome

Deliver an authenticated browser control plane in which an organization user
can enter with a login name and password, inspect the platform, activate a
bounded PostgreSQL quota, and install one PostgreSQL service into an
operator-configured local region. The same accepted release must carry the UI,
managed-service authority, fixed PostgreSQL artifact, local provisioner, and
real-runtime evidence; a visual mock or browser-only order is not acceptance.

This is the smallest enterprise target for the requested public-cloud-style
console. It contains one real offering and one thin infrastructure profile.
It does not invent payment, invoices, public-cloud credentials, MySQL, ELK, or
generic provider schemas before a real second implementation exists.

## Product journey

1. The browser loads the independent Matrix control console through APISIX.
2. A user logs in with only `loginName` and `password`. IAM derives the
   organization and returns one opaque session plus the non-secret
   password-change requirement. A first-login user must replace the initial
   password in the same memory-only session before entering the console;
   there is no organization selector, JWT, external identity provider, or
   social-login branch.
3. The authenticated console shows an overview, service catalog, quota,
   service installations, and local-region configuration allowed by the
   user's fixed IAM role.
4. The catalog exposes one available offering, `POSTGRESQL`, with server-owned
   artifact and installation policy. MySQL and ELK are absent, not disabled
   fake products.
5. A user activates one allowed quota shape. This is a durable product
   entitlement, not a simulated monetary payment. The request accepts no
   caller price, currency, discount, invoice, or payment result.
6. A user selects an active quota and an eligible local region, names the
   service, reviews the exact resources, and submits an idempotent installation
   command.
7. The managed-service authority reserves quota atomically, provisions the
   fixed PostgreSQL service asynchronously, and exposes normalized progress.
   A failed installation cannot silently consume or duplicate quota.
8. The ready result exposes a stable service endpoint and an opaque
   platform-owned credential reference. Passwords, machine credentials,
   Docker details, host paths, and provider-native errors never enter the UI
   response, Audit event, or support evidence.
9. Logout revokes the IAM session before the browser forgets it. The bearer
   credential otherwise exists only in page memory and is never placed in a
   URL, cookie, local storage, session storage, log, or rendered DOM.

## Ownership and boundaries

| Concern | Owner |
| --- | --- |
| User, password credential, session, organization, role, authorization decision | `iam` |
| Offering, quota entitlement, quota consumption, service installation, provisioning state | `managedservice` |
| Local region registration and normalized machine capability | `managedservice` through its local-infrastructure port |
| PostgreSQL lifecycle effect and credential-file custody | managed-service local provisioner adapter |
| Application, ApplicationRevision, Deployment, application placement, and application execution | `apphosting` |
| Browser composition, navigation, session memory, order draft, and result rendering | `app/ui/paas` |
| Immutable accepted security and business facts | `audit` |
| Offline artifact inventory, installation, upgrade, rollback, backup, and recovery | `installation` |

`managedservice` is a distinct bounded context and API inside the Phase 2
modular monolith. It does not add PostgreSQL, MySQL, ELK, volumes, credentials,
or arbitrary native specifications to the Application PaaS workload contract.
Its use cases own transactions; its domain stays provider-independent except
for the one code-owned PostgreSQL offering; persistence and local execution
remain adapters.

The UI imports only versioned public contracts. It never imports a service
`internal` package, receives an internal service credential, proxies a user
credential through its Go process, or calls the APISIX Admin API.

## Enterprise target model

### Service offering

`ServiceOffering` is a code-owned immutable catalog entry with:

- stable ID and kind;
- display name and bounded description;
- engine family and supported major version;
- allowed quota shapes;
- supported region capability selector;
- server-owned installation profile version;
- availability state.

Phase 2 initially admits exactly one available entry: PostgreSQL. The browser
cannot submit an image, digest, command, Compose document, port, volume,
environment value, extension, superuser name, or provider-native option.

### Quota entitlement

`QuotaEntitlement` is organization-owned and contains an immutable offering,
quota shape, purchased instance count, resource version, activation time, and
current reserved/consumed counts. Allowed shapes are code-owned and use checked
integer CPU, memory, and storage values. A request chooses a shape and instance
count only; the server resolves all numeric resources.

Activation uses `(organization, idempotencyKey)` plus a canonical request
digest. Equal replay returns the same entitlement. Changed reuse conflicts.
Concurrent reservations lock the entitlement and cannot exceed its purchased
count or any capacity dimension.

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

## Public API and authority

The managed-service API provides only the bounded routes needed by the journey:

- list/get available offerings;
- list/get eligible regions;
- activate and list/get quota entitlements;
- create and list/get service installations;
- get the installation Operation;
- inspect the non-secret local-machine region configuration as an organization
  administrator.

Every admitted mutation requires `Idempotency-Key`. Phase 2 has no mutable
region endpoint. Collection queries are bounded and deterministically ordered.
Organization, user, and role come only from IAM. Public resource IDs cannot
select another organization, and PostgreSQL row-level security is forced on
every organization-owned table.

IAM adds closed managed-service actions and maps them to the existing
`ORGANIZATION_ADMIN`, `PAAS_DEVELOPER`, and `PAAS_VIEWER` roles. It does not
introduce a customer policy language or a UI-only authorization shortcut. An
expired, revoked, malformed, or unavailable session fails closed on the next
request.

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

Acceptance on the isolated IAM branch requires adapter/component gates and a
real browser against its own IAM/PaaS/Audit environment: a platform-only user
opens and manages a tenant; tenant administrators create and authorize child
users; matching child names log into separate tenants and see only permitted
resources; status/recovery, forced password replacement, logout/reload,
permission denial and stale-session behavior work. Keyboard and 360-pixel
checks cover these controls. Source checks or another Phase's browser evidence
do not accept this extension, and do not replace the installed-release gate.

This branch's adaptation passes type checking, lint, architecture, the 20
contrast checks, 71 frontend tests, Go embed checks and two bounded,
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
and pass with the renderer correction; its installed-release narrow-screen
check remains pending until the corrected signed UI is exercised.

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
keyboard tests do not certify that gate. The complete installed-release
browser gate also remains open. The signed offline profile/lifecycle evidence
belongs to [FEAT-005](FEAT-005-offline-platform-lifecycle.md); neither changes
another Phase's acceptance state.

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

1. Strict Go/OpenAPI contracts validate all resources and reject unknown,
   duplicate, oversize, unsupported offering/shape, caller-selected tenant,
   native provider, price/payment, credential, artifact, and machine fields.
2. Domain tests prove catalog closure, checked quota arithmetic, concurrent
   reservation bounds, equal replay, changed conflict, and valid installation
   transitions.
3. A clean PostgreSQL database applies the managed-service schema twice and
   proves migration/runtime role separation, forced tenant isolation,
   transactionally coupled entitlement/reservation/Operation/Audit facts, and
   database-time behavior.
4. Real IAM permits only the closed role/action matrix and immediately observes
   session or role revocation. IAM or database uncertainty fails closed.
5. The browser completes login, catalog selection, quota activation, region
   selection, installation submit, and bounded Operation polling against the
   real services without a mock or privileged browser path.

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

- Gate A implementation replaces the Phase 1 page with the complete donor-
  shaped App Router -> route -> provider -> repository -> scene -> renderer ->
  public-component chain, seven static routes, memory-only IAM sessions,
  deterministic Go embedding, strict CSP hashes, and a four-region shell.
  The console layout retains its provider across child-route navigation.
  Source gates cover the light theme, 20 semantic contrast pairs, and 31
  frontend tests, including visible failed revocation, logout during failed
  or pending resource loads, keyboard workspace sizing, and native instance-ID
  validation. The installed `8700095` candidate previously proved anonymous
  login, offline assets, and no horizontal overflow. The current source still
  requires final installed-release browser verification of authentication,
  route transitions, keyboard use, and 360-pixel layouts; source and component
  checks do not substitute for that acceptance.
- Gate B authority is complete for the admitted PostgreSQL slice: the closed
  managed-service Go/OpenAPI contract now includes collection and single-
  resource reads for offerings, regions, quota entitlements, service
  installations, and installation Operations. Existing-role IAM actions,
  forced organization RLS, serializable quota reservation, idempotent replay,
  worker leases, fencing transitions, and transactionally coupled Audit facts
  pass unit and real PostgreSQL 18 tests. The installed `8700095` candidate
  completed real IAM-authorized single-resource reads and returned identities
  equal to their collection resources. The UI polls only active installation
  resources and reloads quota truth once an Operation becomes terminal.
- Gate C execution is complete through the fixed PostgreSQL 18 image:
  server-generated file credentials, pull-never/no-build Compose, exact
  ownership labels, persistent bind data, bounded resources, normalized
  endpoint/credential references, retry, terminal quota release, and
  uncertain-create reconciliation. The `a83e271` signed release completed a
  fresh external-network-disabled install, failed-upgrade automatic rollback,
  successful upgrade, explicit N-1 rollback, protected backup/recovery,
  support-evidence sanitization, whole-engine restart, negative API paths, and
  worker-restart reconciliation. The signed `8700095` successor then upgraded
  from it with external network count zero, passed status/verify, retained two
  managed PostgreSQL instances, preserved both durable probe rows, and still
  reported PostgreSQL server version `180004`.

The clean pushed `8700095` source passed `go generate ./api/...`, module
verification, full unit, vet and race suites, repeated critical packages,
clean PostgreSQL 18 migration/tenant/Audit integration, the real fixed-image
PostgreSQL lifecycle, Linux amd64 cross-build, all UI type/lint/architecture/
style/test/embed gates, Markdown links, fixed-donor verification,
donor-dependency and social-term scans, and `git diff --check`. Final
acceptance must repeat the release and browser gates from the documentation-
converged source commit.

## Deferred

Money movement, invoices, tax, discounts, metering-based billing, marketplace
publishing, MySQL, ELK, Redis, arbitrary Helm/Compose templates, customer
images, public-cloud accounts, VM/network provisioning, Kubernetes,
multi-region placement, high availability, read replicas, point-in-time
restore, engine upgrades, deletion, external IdP, LDAP, SAML, OIDC, MFA, and
mobile-native applications remain outside this target.

The product and source dependency boundaries remain owned by
[`ADR-0002`](../architecture/ADR-0002-product-boundary.md) and
[`DEPENDENCY-RULES`](../architecture/DEPENDENCY-RULES.md). Fixed donor
decisions are owned by the
[`FEAT-007 adoption review`](../adoption/FEAT-007-control-plane-console.md).
