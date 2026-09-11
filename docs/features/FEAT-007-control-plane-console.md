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
   password-change requirement. Primary-account and subaccount entries switch
   inside the same login card. Subaccounts use one `username@account-alias`
   (or `username@organization-id`) field plus password; no separate tenant
   selector, email verification, DNS resolution, or preliminary user lookup is
   introduced. A first-login user must replace the initial
   password in the same memory-only session before entering the console;
   there is no post-login organization selector, JWT, external identity provider, or
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
10. The access-control view shows the current tenant and login identity, and
    provides real tenant-scoped subaccount creation, role bindings, status,
    and password reset. Its user-settings section allows an organization
    administrator to set/change the separate primary-account login alias and
    shows the stable account ID and both qualified-login forms. Only the
    bootstrap-bound administrator sees tenant
    account opening. IAM owns the account rules and acceptance in FEAT-006;
    this view preserves the existing provider/repository/scene/renderer chain,
    semantic themes, accessible keyboard controls, and memory-only secret handling.
    Switching the anonymous login mode clears password/error state. The child
    identifier input is text, not HTML email, and accepts the IAM-qualified
    identifier grammar. No test fixture or local state substitutes for an IAM
    result, and unavailable backend capabilities are never shown as success.
    The view separates resource-owning account identity from the current
    operator. The user directory contains IAM subusers, not independent
    tenants; primary-account details belong to user settings. Creation defaults
    to no business authorization. The live platform-role catalog describes
    tenant-wide built-in roles; it does not imply creator-only resource
    visibility or a custom-policy authorization engine.
    The service opens an overview followed by bookmarkable user, group,
    policy, role, role-SSO, user-SSO, federated-account, API-key, user-settings
    and tenant-management workspaces. These use grouped service-local
    navigation, not another global product menu or a long top-level tab bar.
    An optional repository capability supplies the extended MOCK workspace.
    Its account-scoped data is isolated from the live IAM adapter and never
    grants real permissions. The live adapter has no such capability and
    renders an explicit unavailable state instead of inventing success.
    Preview workflows cover group membership and inherited policies; custom
    policy visual/JSON editing, versions and associations; role trust,
    session duration and console access; SAML/OIDC provider configuration,
    role mappings and user SSO; enterprise-directory visibility and member
    import; subuser key creation, status and deletion; password/session
    configuration; and allowlisted credential/security reports. Referenced
    objects cannot be deleted, system policies cannot be changed, and keys
    must be disabled before deletion. A generated key secret is explicitly
    nonfunctional, displayed once, and excluded from stored workspace state
    and reports. Browser reload or sign-out resets preview data.
    Federated-account provisioning models enterprise members separately from
    SSO: importing a visible member creates an ungranted preview subuser,
    without installing an app, scanning a QR code, inviting a person or
    connecting a real corporate directory. Tencent's CAM
    [overview](https://cloud.tencent.com/document/product/598/17848),
    [policy associations](https://cloud.tencent.com/document/product/598/10602),
    [API-key lifecycle](https://cloud.tencent.com/document/product/598/40488),
    [OIDC providers](https://cloud.tencent.com/document/product/598/93430) and
    [enterprise account flow](https://cloud.tencent.com/document/product/598/14482)
    are interaction references; Matrix retains its own theme, components and
    supported account contracts. This is primary-workflow coverage, not a
    claim of complete Tencent CAM feature or authorization compatibility.
    Account settings follow the
    [Tencent alias workflow](https://cloud.tencent.com/document/product/598/118709);
    the qualified-login convention is also documented by
    [Alibaba RAM](https://help.aliyun.com/zh/ram/support/faq-about-ram-users).
    These are product semantics references, not additional UI-framework donors.

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

Platform backup captures an opaque local-provisioner inventory witness before
dumping control-plane state and refuses to publish a snapshot if that inventory
changes during the dump. Recovery checks the witness before changing the
platform, and again after stopping its writers. A service created since the
snapshot makes the old backup ineligible; recovery must not orphan that
service or silently return its quota to the pool. The operator can select a
backup that includes the current inventory. A concurrent inventory change
during recovery fails closed before database restore. Managed PostgreSQL data
is preserved in place, not rewound by the platform snapshot. If the change is
detected only after shutdown, the existing recovery failure contract requires
operator intervention; automatic availability recovery is not claimed.
Backups lacking this required witness are rejected rather than interpreted as
an empty inventory.

## Console architecture

The replacement UI is a Matrix-owned Next.js 16 and React 19 App Router
application. It preserves the fixed donor's complete route, provider,
repository, scene, renderer, and public-component architecture rather than
reducing that application to a component library. Next.js performs a static
export at build time and the immutable result is embedded into the existing Go
UI binary. A Next.js server, React tooling, package manager, and donor source
are never production runtime dependencies. Production installation remains
offline and makes no browser-side external asset request.

Client navigation prefetch is part of that delivery boundary. The pinned
Next.js exporter has a [Windows segment-path encoding defect](https://github.com/vercel/next.js/issues/92339);
the build normalizes only generated segment filenames into the router's flat
URL convention before embedding, without duplicate paths or runtime aliases.
Already-correct exports are unchanged and target collisions fail before moves.
Go embeds underscore-prefixed files throughout this owned generated directory,
as required by [Go's directory embedding rules](https://pkg.go.dev/embed#hdr-Directives).
Source, assets and build scripts participate in the deterministic build ID.

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
| guild rail | favorite-service shortcuts and the Dashboard entry |
| channel/context sidebar | active product navigation for catalog, quotas, installations, and regions |
| chat/content page | selected control-plane workflow or resource detail |
| right workspace | order review, installation Operation, or contextual inspector |
| user settings dock | authenticated principal, role summary, and revoking logout action |

The social domain, labels, content, and mocked workbench data do not cross the
boundary. The route and scene vocabulary is rewritten around offerings,
entitlements, regions, installations, and Operations; no guild, channel,
direct-message, friend, or social billing type remains in target source.

Public components use semantic Ant Design-style names and a stable
`@ui/xiak` facade. Parser, wire, scene, and renderer types never leak through
that facade. Business clients do not fetch from leaf components. Server data
stays behind the repository and in the owning provider/application state. Only
transient cross-region shell state may enter a client store. Global CSS owns
reset and the palette-to-functional-to-semantic theme tokens; components use
scoped styles and functional tokens instead of donor hash classes, inline
styles, or raw theme colors.

The application defaults to a deep-navy, ice-cyan dark theme. `next-themes`
registers three explicit preferences: dark, mixed and light; system follows the
OS light/dark preference and never resolves to mixed. Palette primitives and
semantic tokens remain in `tokens.css`; `data-theme` selects their mappings at
the root. Light covers the whole interface, including the brand header,
favorite rail, global popups, content dialogs and portalled dropdowns. Mixed
keeps a light workspace and content dialogs, while `data-surface="shell"` on
the global header, favorite rail and header popups reuses the complete dark
semantic mapping. Dark applies that mapping to the entire interface. A
portalled Select carries its originating surface identity, not a frozen theme
value, so an already open menu follows theme changes without a remount.
The cascade order is `base` reset, `xiak` public controls, then unlayered
feature composition. Layout overrides do not depend on Next.js chunk order.
Public controls share sizing, radii, focus, disabled, and semantic status treatments.
The style gate resolves all three themes at workspace and shell boundaries,
including brand, normal text, status, input boundaries, focus and notification
badge contrast. It also rejects light surfaces with dark backgrounds (or the
reverse) and mismatched native color schemes. Content grids respond to the
available width so a contextual workspace does not make the overview unreadable.

`AppearanceProvider` composes the theme and locale providers without remounting
IAM state. `next-intl` owns typed message lookup, ICU interpolation and locale
formatting; `src/i18n/messages` owns `zh-CN` and `en` resources with key-parity
and message-format tests. Dates and numbers in migrated views use its locale
formatters rather than string concatenation; the initial formatter time zone
is explicitly UTC. The static console does not introduce locale routes,
middleware, cookies, or a production Next.js server. Only non-secret display
preferences (`matrix.theme`, `matrix.locale`) may enter local storage. Blocked
storage remains usable for the current page; language changes synchronize
between tabs and update the document language. Authentication errors remain
language-neutral codes in application state and are translated at rendering.

Login, IAM, the global shell, Dashboard, managed-service workflows, resources,
Operations, DevOps, monitoring and logs use the same theme and keyed-message
boundaries for interface copy. Source-provided names, descriptions, environment
names and event contents remain data; changing language does not rewrite them.
The existing Next.js 16, React 19 and TypeScript stack is retained; Radix UI
supplies tab and radio-menu keyboard/focus semantics behind `@ui/xiak`, with
CSS Modules owning their appearance. The static host's CSP is unchanged:
`next-themes`'s bootstrap script is covered by the exact embedded script hash,
native color-scheme is set in CSS, and Radix tab wrappers omit generated inline
styles at the public-component boundary.

The desktop shell has a product sider, stable header, primary content, and an
optional contextual panel. Compact mode uses one overlay at a time and leaves
the active task reachable. The login route and every authenticated route must
remain keyboard usable, visibly focused, reduced-motion compatible, and
readable at 360 CSS pixels without horizontal page scrolling.

### Unified cloud UX system and preview

#### UX release and live-adapter continuity

The existing `feat/cloud-console-ux` implementation under `app/ui/paas` is
the UX release baseline. Preserve its approved pages, service navigation,
public components, themes, locales and complete isolated MOCK journeys.
Useful fixes from another branch are reviewed as bounded slices through the
existing adoption record; they do not replace this shell or silently remove
accepted workspaces.

MOCK acceptance is an intermediate UX release, not production authorization
or real-runtime acceptance. Subsequent public-API integration adapts the
existing repository and composition boundaries so the accepted renderers and
interactions are reused. Contract gaps must be explicit; they do not justify
a second implementation of the same UI. Installed-product visibility and
resource authorization still come from the accepted backend authorities,
never from preview state or the presentation registry. Formal login/API
verification remains deferred until the other UX acceptance is reviewed;
the separate one-click MOCK entry remains available meanwhile.

#### CAM UX replication scope and research gate

The current CAM replication goal uses Tencent Cloud as an interaction and
authorization-semantics reference, while preserving Matrix's components,
brand, themes, locale boundary and existing live IAM contract. Performance
tuning is paused at the measured status below; functional regression gates
remain required. External reference knowledge is indexed in the
[CAM research collection](../research/tencent-cam/README.md). This FEAT remains
the owner of the Matrix implementation contract and acceptance evidence; the
contract must be recorded before the corresponding implementation slice starts.

Reference browsing is read-only or stops before submission. Any QR-code,
scan-to-confirm, payment, paid activation or subscription popup must be closed
and the dependent path marked skipped. Do not wait for a scan, pay, accept a
charge, change existing cloud permissions, issue credentials or weaken security
to complete a reference flow. A skipped step is not successful verification;
use official documentation to identify its intended behavior and label what
was not exercised. Existing Tencent users, groups, policies and roles remain
unchanged. Matrix examples use synthetic identities and resources, never
copied account identifiers, credential values or private cloud inventory.

The research must distinguish observed Tencent behavior, the Matrix target,
current implementation gaps and acceptance evidence. Its primary chain is
policy document -> default version -> user/group/role association -> request
evaluation -> permitted resource/action, not merely a list of policy names.
Custom policies, resource-granular decisions, role sessions and conditions
remain explicit MOCK capabilities until the IAM owner separately adopts and
accepts a real contract; the browser cannot become the authorization authority.

#### CAM reference findings and Matrix interaction contract

The reference review on 2026-09-09 covered the signed-in CAM navigation and
unsubmitted group, policy, role and provider forms. No reference policy,
membership, role, credential or security setting was saved. The following
table is the implementation contract, not a claim that the target is already
implemented or that a successful reference submission was exercised.

| Workspace | Verified reference behavior | Matrix target and current gap |
| --- | --- | --- |
| Overview | Identity counts link to directories; high-privilege associations, recent sensitive actions, account identity, login links and security guidance are separate blocks. | Keep the existing overview composition; derive counts and guidance from the same workspace state. Never show simulated protection as real MFA or a real security assessment. |
| Users | The subuser detail distinguishes access method from permission. An ungranted user is guided to join a group, copy another user's permissions or attach policies. Adding permissions is a content-area selection/review flow. | Reuse the existing user wizard and permission selector; add source-aware effective-permission inspection and cross-links to group/policy details. Copying permissions must describe precisely which direct bindings or memberships are copied; it never clones passwords, keys, boundaries or role sessions. |
| Groups | Creation is a three-step content page: basic information, policy selection, review. Empty policy selection is allowed. The selector separates available/selected items and states its per-operation limit. | Replace the combined group dialog with this journey. Group details own separate member and permission operations, with an impact review when removing an inherited grant. A group is not a login identity and cannot be assumed. |
| Policy directory | All/preset views show policy name, product, permission category, description, last modified time and authorization action. Custom-only omits product and permission category. Presets cannot be deleted. | Use these columns with Matrix products. Preset categories are explicit directory metadata (global/product), not read/write classifications or tag conditions. Actual grants remain derived from default policy content. |
| Policy creation | Entry chooser offers generator, policy syntax, tag authorization, and product-feature/project authorization. The fourth entry carries upgrade guidance toward tags and the generator. Name becomes immutable after creation. | Four entry points share one content-area edit/configure/review draft and save contract. The fourth selects registered Matrix product functions; project permissions are explicitly unavailable. Templates copy into custom policies, never mutate presets. Resource-tag conditions remain distinct from policy metadata tags. |
| Policy editor | Select a service, then read/write/list/other actions, their authorization granularity, all/specific resources, and optional key/operator/value conditions. Structured resource input exposes service, region, owner, type and resource ID. The analyzer separates errors, warnings and suggestions. | Add a code-owned preview capability catalog and structured statement editor. Invalid drafts remain editable; errors block progression, warnings explain broad access. Unsupported syntax cannot be silently dropped when switching modes. |
| Policy detail | Syntax has readable service/resource/condition summary and JSON. Versions and usage are separate tabs; permission associations and boundary uses are separate sections. | Readable effect/action/resource summary, full JSON, bounded versions, exact linked subjects and separate boundary references are implemented. Group links lead to affected members and their named inherited grants. Previewing an old version never activates it. |
| Roles | Carrier selection distinguishes account, cloud service and IdP. Account-role creation separates trust, policies, tags and review. Detail separates permissions, carrier summary/trust JSON and sessions. Service-owned roles have different mutation affordances. | Replace the combined role dialog with a content workflow. Keep trust, permission policies and optional boundary separate. Add explicit session simulation/revocation rather than implying that membership in a role works like a group. Do not claim live STS. |
| Role and user SSO | Role SSO uses an IdP and a role without mirroring employees as subusers; user SSO enters as an existing subuser. Provider creation distinguishes OIDC URL/client IDs/public keys from SAML metadata. | Group both routes under Identity providers, not Identity security. Federated accounts belong to Identities; API keys and user settings remain under Identity security. Preserve the current synthetic configuration boundary and separate routes. Provider validation is local shape validation only. No real discovery, key retrieval, enterprise login, enablement or enrollment is part of acceptance. |
| Enterprise accounts | The current entry requires an enterprise administrator to scan and activate it. | Reference activation was skipped without clicking activate. Matrix's existing synthetic member-import demonstration remains explicitly MOCK; it is not evidence of a tested Tencent import or a connected corporate directory. |
| API keys and settings | Key entry warns against primary-account long-lived keys and states that SecretKey is only shown at creation. Settings group password, account, login and security concerns. | Keep subuser-only, one-time nonfunctional MOCK credentials and separate settings sections. Reference key issuance, acknowledgement of saved keys, security mutations and enrollment were not performed. |

The generator and association contracts are supported by Tencent's
[policy generator](https://cloud.tencent.com/document/product/598/37739) and
[authorization management](https://cloud.tencent.com/document/product/598/10602)
guides. The implementation uses Matrix components and product semantics, not
Tencent assets, account inventory, API names or every Tencent preset. The
reference's historical preset-specific version-pinning notice is not adopted:
Matrix preview associations resolve their policy's current default version.

#### Policy workspace refinement contract

The policy-mode slice keeps the existing preview domain and replaces its
directory and review presentation. Acceptance requires:

- A compact policy directory with kind tabs, service/category filters, one
  keyword search, sorting and pagination. The custom-only view hides and clears
  preset-only filters and columns. Global presets have no specific product;
  custom policies have no inferred preset category. Last modified time changes
  with policy content, metadata or versions, not associations or no-op saves.
  Returning from details retains view context within the account session; it
  never persists drafts, bindings or credentials to browser storage.
- A searchable, paginated service summary grouped by Allow/Deny, derived from
  the registered action catalog. Selecting a service opens inline operation
  details with localized descriptions, access classification, resource
  granularity and exact resources/conditions. Each operation row retains its
  source statement. Multiple statements never become a unioned resource or
  condition rule; their independent branches remain inspectable. Returning
  restores the service search, page and keyboard focus. The same viewer works
  in creation review and historical inspection without submitting its parent
  workflow. Original wildcard expressions and complete JSON remain unchanged.
  Preset descriptions are localized without translating user-authored content.
- Generator, JSON, resource-tag and product-feature starting paths share one
  document draft, validation owner and final save. Going back retains the mode
  and draft. Editor projection is separate from authorization validity: empty
  and incomplete representable drafts remain switchable without changing their
  JSON. Unsupported fields and lossy values stay in JSON; saving and diagnostics
  continue to use the strict policy validator. Product-feature selection starts
  empty, uses explicit registered actions and current-account resource scope,
  and cannot erase Deny, conditions,
  specific resources or wildcards when converting an existing draft. Project
  authorization is not simulated by inventing a new project model.
- The tag path requires resource-tag conditions on every submitted statement;
  all configured tags must match. Only supported operations are offered, while
  incompatible prior selections remain visible for correction. Account-level
  actions cannot be narrowed by tags or specific resources. Request-tag
  conditions remain unsupported, and no helper flow adds unscoped permissions.
  Policy metadata tags are organization metadata, not authorization conditions.
- One validation owner for execution and editor diagnostics. Diagnostics have
  severity and a document path; errors block saving, warnings and suggestions
  are review guidance, never proof that a request will be authorized.
- Policy association changes have a selection/review/confirm boundary. Review
  names additions/removals and explains remaining group grants. Batch attachment
  is bounded, additive and atomic; it never replaces unrelated bindings.
- Content edits and rollback show statement additions/removals and named
  affected users, groups, roles and boundary uses. The comparison is structural
  and must not claim that removed text necessarily removes effective access.
- Existing immutable revisions, tenant isolation, unsupported-syntax rejection,
  keyboard/draft protection, theme and locale gates remain intact. Browser
  acceptance covers desktop and a 360 px viewport, search/detail/return,
  create/associate/edit/inspect/rollback and failed validation retaining drafts.

#### Policy, identity and resource semantics

The preview must explain this model rather than presenting policy names as
permissions:

```text
Tenant owns resources; a user creating a resource does not acquire ownership
  User -> directly attached policy IDs ------------------+
       -> group memberships -> group policy IDs ---------+-> current default
  Role -> permission policy IDs -------------------------+   policy documents
       -> trust document: who may assume this identity       |
       -> optional maximum-permission boundary               v
  Request(identity, action, resource, context) -> explain allow / deny
```

A user is an authenticated principal, a group distributes grants, a role is
an assumable identity, and a policy describes actions on resources under
conditions. Console/programmatic access enables an authentication method,
not a grant. Resources remain owned by the tenant even when a subuser creates
them. These distinctions follow the reference's
[policy concepts](https://cloud.tencent.com/document/product/598/38503),
[role concepts](https://cloud.tencent.com/document/product/598/19421) and
[resource descriptions](https://cloud.tencent.com/document/product/598/10606).

Matrix retains its own `version: "1"` preview document dialect; this is not
Tencent CAM JSON import compatibility. Each statement has an effect, nonempty
action list, nonempty resource list and an optional supported condition. The
syntax version is different from a policy's stored revision number. The
preview capability catalog owns service keys, action IDs, read/list/write/
permission-management classification, explicit operation/resource granularity,
applicable resource types and each action's supported condition keys. The
directory's presentation registry does not become an authorization registry.
The existing catalog is the single owner; no parallel vocabulary, persisted
summary model or alternate policy dialect is introduced.

The completed editor contract is:

- One document is the source of truth for visual editing, JSON, summary,
  validation, review and simulation. Never truncate a multi-statement policy
  to make it fit the visual editor. Invalid JSON stays as a local draft.
- Unsupported root/statement/condition fields are blocking diagnostics, not
  silently discarded data. Reject unknown actions or mismatched resource
  types in executable preview rules; never claim a condition is enforced if
  it is not implemented. Draft size and statement counts remain bounded.
- Resource references identify service, tenant, region, resource type and ID.
  The structured editor explains each part and produces the same canonical
  value used by the simulator. `*` means all applicable resources **inside
  the current tenant**, never bypassing tenant isolation. Operation-level
  actions that require `*` must be distinguished from resource-level actions.
- Conditions start with typed resource-tag equality, source IP/CIDR and UTC
  time bounds. A statement matches only when every configured condition
  matches. Missing/invalid context cannot turn a restriction into an allow.
  A missing context needed to establish a deny is reported as indeterminate
  and cannot produce an allow result. Unsupported operators remain explicit.
  Tencent's [condition reference](https://cloud.tencent.com/document/product/598/10608)
  informs the UX; Matrix must publish and test its own smaller supported set.
- Presets have actual, inspectable documents for Matrix services, including
  read/list coverage and explicit high-privilege warnings. Do not generate a
  fake thousand-policy catalog for services the platform does not offer.

Custom-policy names are immutable; description-only edits do not manufacture
a new authorization revision. Content edits create a new immutable revision.
Retain at most five revisions, block removal of the effective revision, and
require an explicit choice of a nondefault revision to delete when full.
Revision identifiers increase monotonically and are not reused after deletion.
Selecting a previous default is a rollback: show the old/new documents and
affected associations before confirmation. Do not silently evict history or
activate a version merely because it was inspected. This lifecycle follows
Tencent's [version-control guide](https://intl.cloud.tencent.com/zh/document/product/598/32669).

Associations are references to policy IDs, not copied JSON. The same binding
must be visible from both the policy and identity side. User-group changes
affect inherited permissions; detaching a direct policy does not remove an
equivalent group grant. Policy deletion is blocked while referenced, including
as a boundary. Selection is bounded and paginated, retains selections across
searches, counts selected items explicitly and distinguishes no data from no
search results. Initial selection grants nothing automatically.

For the supported same-tenant identity-policy subset, evaluation is default
deny, any applicable explicit deny wins, otherwise an applicable allow is
required. A user combines direct and group grants. A role session uses role
permission policies, not an automatic union with the caller's user policies.
Trust checks control whether a role may be assumed; trust alone grants no
resource action. An optional user/role boundary limits the permitted set by
intersection and never grants access by itself. A role must not be assumable
because its name was guessed; caller authority and trust must both pass in
the preview's supported scenario. These rules reference
[evaluation](https://cloud.tencent.com/document/product/598/10605) and
[permission boundaries](https://intl.cloud.tencent.com/zh/document/product/598/39425).
Resource-based policies, ACLs, cross-account delegation and provider-specific
exceptions are outside this preview evaluator and must not be labelled
compatible or inferred from the simple identity-policy rule.

The resource-access preview is a diagnostic, not a login or authorization
switch. The administrator selects a synthetic user/role, action, resource and
request context; the result shows allow/explicit-deny/implicit-deny or an
unsupported/indeterminate reason, matched statement and revision, direct or
group origin, trust/boundary outcome, and what change would alter the result.
It performs no business mutation and never replaces the current session.
Unknown or cross-tenant resources are rejected before wildcard evaluation.
Future live enforcement must occur in IAM and every owning backend's read,
list and mutation path; hiding a button, a route guard or this simulator is
not a security boundary. FEAT-006's closed live role/action contract remains
unchanged by this UX work.

#### CAM implementation slices and acceptance

The scenario-driven preview uses the same pages and repository boundary as
future fixed-contract integration; its one-click DEV entry remains available
for ongoing UX review. Backend candidates without a fixed, accepted revision
are not integration evidence and never cause automatic fallback to MOCK.

The independent access-explanation slice uses a coherent synthetic
set covering an ungranted console user, duplicate direct/group grants,
resource-path versus resource-tag rules, a matching explicit deny, boundary
intersection, immutable policy revisions and a same-account assumable role.
Existing simple examples remain valid; added examples use registered actions
and synthetic resources, not copied cloud inventory or a fake large catalog.
Example requests only fill diagnostic inputs: they neither alter associations
nor supply a canned verdict. Results always resolve current workspace facts.

The simulator keeps a compatible operation when changing resource and clears
the old result when any request input or workspace truth changes. Initial
selection comes from the supplied diagnostic inventory, not a service name
hardcoded in the renderer. It distinguishes policy decision from account,
credential and real-session availability; checks not performed are explicitly
not evaluated. Decisive evidence precedes optional nonmatching details, with
links to the exact policy and group. Local MOCK role expiry/revocation must
remain explicit and cannot silently fall back to the original user identity.
Acceptance adds executable fixture cases, input-retention and scope-label
interaction tests, linked evidence, compact layout and theme verification.

Local UX verification on 2026-09-11: all six seeded request cases resolve from
the current workspace; removing one of two grant sources, changing a default
policy revision, a nonmatching deny and a restrictive boundary produce their
documented distinct results. The user permission table labels these relations
as grant sources. The scenario picker is limited to user diagnostics so it
cannot unexpectedly replace a selected role-session identity. Its explanation
is associated with the labelled control for assistive technology.

The browser on the existing DEV port 4317 verified one-click MOCK entry,
duplicate-source evidence, resource-tag authorization, explicit denial,
English/light and Chinese/dark presentation. At 360px, content width remains
360px and the 640px evidence table scrolls within its own region. An explicit
same-account MOCK session for the log-review role permitted log search but
rejected a staging deployment that its caller could perform; revocation then
rejected that session's diagnostic request. No real credentials, cloud
mutations, scan flow or payment was used. The temporary session was revoked.

Verification passed: 465 frontend tests with two workers, the subsequent
five affected interaction regressions, three static-export normalization
tests, type checking, lint, architecture, 228 theme contrast pairs, production
static generation, and the existing Go UI-host tests/vet. The initial
default concurrent test run had five-second harness timeouts; limiting
workers resolved them without raising timeouts. This evidence verifies the
local preview slice, not the pending fixed-contract IAM integration or an
accepted release. The production export was synchronized into the existing Go
embed owner; a clean follow-up build matched all 213 generated files, and the
Go UI-host tests/vet passed against that boundary. Product-directory
provenance and the new backend attachment model still require their own
aligned integration gate.

Overview shortcuts identify the exact referenced policy. High-privilege review
uses allowed permission-management actions from the closed catalog, including
service wildcards and specific actions, in the current default version. The
same content classification owns editor, detail and role-creation warnings.
This is a review candidate, not an effective-access verdict: resource scope,
conditions, explicit denies and boundaries still apply. User review counts
include direct and inherited candidates once per user. Security guidance shows
workspace facts and inspection links, never a completed security assessment:
empty groups are not evidence of distributed permissions, unused keys are not
encouraged, and saved MOCK protection does not imply real MFA activation.
The MOCK user directory displays and filters direct/group policy associations,
not the live adapter's fixed-role bindings. Empty-group membership and a boundary
alone are not grants. A directory management action opens the same user detail;
the separately labelled platform-role view preserves the live contract.

The existing `auth` workspace domain/repository remains the owner of preview
invariants and state. Page composites remain in its renderers; shared
Wizard/Steps, Transfer, Table, Dialog, form fields and themed selection
controls remain in `@ui/xiak`. No generic workflow engine or new IAM backend
is introduced. Draft state is local to the active workflow; request/error
state does not rerender the whole console. Open a workflow or dialog before
loading data, and show a meaningful loading/error/retry state in its body.

Unsaved workflow protection has one public interaction owner, separate from
the feature-owned draft. User, group, policy and role workflows register only
dirty/busy status, localized confirmation copy and a focus-return target;
passwords, policy documents and identity selections never leave local state.
The console routes menu, product, favorite, search and imperative navigation
through the same leave decision, as well as explicit cancel and sign-out
actions. The console's read-only refresh preserves the mounted draft and is
not misrepresented as a discard. Confirmation precedes the router transition and skeleton.
Staying retains the current step, validation and every field; confirmed leaving
executes the original destination once. A save already in flight cannot be
discarded or silently queue another destination. Save completion clears the
guard; failed saves retain it. Forced authentication expiry remains authoritative
and clears the local workflow rather than being blocked by a draft.

Next Link retains prefetching, anchor semantics and modified/new-tab clicks,
using its supported [onNavigate boundary](https://nextjs.org/docs/app/api-reference/components/link#blocking-navigation).
Same-document browser history traversal uses the browser's cancellable
[Navigation event](https://html.spec.whatwg.org/multipage/nav-history-apis.html#fire-a-traverse-navigate-event)
and resumes the exact existing entry after confirmation. Do not patch router
internals, manufacture history entries or trap browser-forced traversal.
Refresh, document departure and browsers without a cancellable traversal use
the native [beforeunload safeguard](https://developer.mozilla.org/en-US/docs/Web/API/Window/beforeunload_event)
where the browser permits it; mobile process termination and non-cancellable
same-document traversal cannot be promised a confirmation. No draft is saved
to browser storage or reconstructed across a complete reload. Only the dialog
subscribes to pending confirmations; keystrokes and guard registration must not
invalidate the header or unrelated workspace content.

Policy authoring uses one content-area workflow for create, copy and content
editing: document -> metadata/optional associations -> review. The document
step preserves all statements when switching between visual and JSON modes;
templates require an explicit apply action and confirmation before replacing
an edited draft. Metadata tags organize a policy and are not permission
conditions. Review lists the exact selected identities without preselecting
new grants. Creation and optional associations commit atomically. At the
five-version limit the same draft can nominate a nondefault version for
removal, inspect that version and save the replacement atomically; failure
must preserve both the draft and all existing history. This workflow replaces
the modal authoring implementation, not a second maintained authoring path.

The executable preview language uses a closed action catalog for the existing
infrastructure, application hosting, PostgreSQL, log, delivery, monitoring and
IAM workspaces. It is a domain vocabulary, independent of navigation labels.
Read/list/write/permission-management categories and resource-level versus
operation-level granularity come from this catalog and are visible separately in
the action picker. These are explicit Matrix preview contracts, not rules
inferred from Create/List/Describe names or a copy of Tencent product capabilities.
An action pattern must match
at least one registered action. Canonical resource patterns are
`matrix:<service>:<tenant>:<region>:<type>/<id>`; only region and ID can be
`*`, and ID additionally allows a trailing prefix wildcard. Account and type
cannot be wildcarded. Concrete test resources have no wildcards. Account-level
operations require `resource: ["*"]` and do not support resource-tag conditions.
Unknown actions, incompatible resource types and cross-tenant references block
save/evaluation. Structured resource service/type choices and inventory entries
come from the selected operations, not every type offered by their product.
An incompatible existing resource remains in the draft and blocks saving; it
is not silently changed when the selected action set changes.

Supported `condition` keys are `resourceTag` (up to ten exact, case-sensitive
key/value pairs, all required), `sourceIp` (up to ten IPv4/IPv6 CIDRs, any range
may match), and inclusive UTC `notBefore`/`notAfter` bounds. Different condition
keys combine with AND. Empty or unknown conditions are not silently removed.
IPv4-mapped IPv6 request addresses normalize to IPv4; address parsing/CIDR
matching uses the small, pinned `ipaddr.js` dependency, not a network call.
The parser and editor share the selected actions' supported-condition
intersection. Existing incompatible conditions stay editable/removable and
produce a blocking validation result rather than being dropped; new unsupported
conditions cannot be selected. Policy summaries display every supported
restriction without merging distinct statements. Invalid drafts retain their
raw JSON. The visual editor preserves mixed-service statements through
its custom action-list mode rather than replacing them with one service.

The request-explanation view evaluates a selected synthetic user or preview
role session against current default policy versions and a code-owned synthetic
resource inventory. Users combine direct and group grants; sessions use only
the role's grants. Each decision retains policy/version/statement and source
evidence, including separately identified boundary restrictions. No matched
allow means implicit deny; matched deny wins, including over an allow from
another source. If a potentially applicable restriction needs missing or
invalid context, return indeterminate rather than allow. Role assumption is
checked separately before a preview session can be created; a direct user-policy
simulation cannot bypass trust or serve as a session.

Group creation is a three-step content-area draft: name/description, optional
policy selection, and review. No members are added during creation. The saved
group opens its detail with an explicit add-members action. Metadata editing,
membership changes and policy changes are separate commands; each changes only
its owned fields. Membership/policy commands apply explicit add/remove deltas,
bounded to 30 changes per operation, never a replacement of a partially loaded
directory. Selection uses the bounded public Transfer control, preserves
off-search choices and never preselects a new grant. Membership/policy changes
show additions, removals and the affected members before saving; cancellation
or failure preserves the original state. Removing a direct grant or membership
does not imply all access is revoked when another source still grants it.
Groups, users and policies cross-link to the precise referenced entity; the
IAM workspace accepts a URL entity identifier, including direct visits and
Back/Forward navigation, without trusting it as authorization.

Role creation is a content-area workflow: choose the carrier and explicit
trusted identities, choose permission policies and an optional boundary, enter
name/description/tags and session settings, then review. Nothing is granted by
default. The carrier type and role name are immutable after creation; metadata,
trust, attached-policy deltas, boundary and session settings have separate
commands. Account trust is limited to explicitly selected synthetic users in
the current tenant; cross-account and wildcard principals are not supported.
Service trust uses the code-owned workload inventory. Provider trust references
an existing enabled synthetic IdP; a federated subject must have an enabled
mapping to that role. Neither form validates a real assertion or connects STS.

Trust editing reviews the affected role and both the previous and proposed
identities before saving. Human-readable identity names and stable IDs identify
added/removed trust; the two complete Matrix trust documents remain inspectable.
The comparison stacks on compact screens instead of widening the page. Reordering
the same identity set is not a change. Empty or unsupported trust is rejected
before review using the same domain validator as the command. Saving revalidates
the proposed trust and changes neither role policies, metadata, settings nor
existing sessions. The review explains that trust removal is not immediate
session revocation and never grants the caller an assumption permission.
Role metadata, trust, policy, boundary, settings, session and delete dialogs
retain their draft/review after a failed command. The existing IAM dialog owner
focuses the localized error, prevents duplicate submission, and locks dismissal
only during the mutation. A retry is explicit; cancellation creates no partial
changes. Both the pending and error paths require interaction regression tests.

A user requesting a preview role session must pass both explicit role trust
and `iam:assumeRole` evaluation against that role's canonical resource. The
user's boundary also limits this request. Service/provider session demonstrations
only use known synthetic identities, never a typed-in identity as proof. A
session has a bounded duration, an immutable expiry and explicit revocation.
Assumption is checked again by the domain command when saving, not authorized
by a UI result. Existing sessions are not extended by changing role settings;
trust changes affect new sessions. Resource diagnostics resolve the role's
current policy versions and current boundary, never the caller's grants. A
deleted role/caller, expired or revoked session cannot allow access. The
diagnostic time supplied by the adapter cannot be overridden by request context.

Boundaries reference current default policy versions and only intersect grants;
they cannot grant permissions on their own. Their references protect policy
deletion and are visible separately from grant associations. The policy syntax
parser is separated from workspace transitions so the pure evaluator can be
used by session commands without a domain import cycle. This is a local MOCK
slice, not a replacement of FEAT-006 or a published live authorization API.

| Slice | Required outcome | State |
| --- | --- | --- |
| Policy lifecycle | Strict, lossless supported document handling; readable summary/JSON; metadata vs content editing; five-version history, protected effective version and reviewed rollback. | Implemented and locally verified for the supported effect/action/resource/condition MOCK dialect. Unsupported fields and condition keys are rejected without stripping the draft; summaries and history retain every supported restriction. |
| Policy authoring | Full-page generator/JSON/template flow, typed action/resource/condition selection, diagnostics, review and optional atomic associations. | Full-page create/copy/edit, lossless multiple statements, guarded template/service replacement, typed operations and resources, IP/tag/time conditions, metadata tags, review, optional atomic associations and capacity recovery are implemented. Shared in-app unsaved-navigation protection preserves even invalid JSON drafts. |
| Group authorization | Full-page creation, separate membership/policy operations, permission provenance and cross-navigation. | Three-step creation, isolated metadata updates, reviewed add/remove deltas, named policy sources and query-addressable user/group/policy/role details are implemented. Shared in-app unsaved-navigation protection preserves creation drafts. |
| Role authorization | Carrier-aware content wizard, trust vs permission vs boundary, bounded temporary-session preview and safe revocation explanation. | Four-step creation, isolated metadata/trust/settings commands, reviewed policy deltas, boundary and before/after trust changes, exact same-tenant account trust and known service/provider identities are implemented. Bounded preview sessions recheck assumption, retain immutable expiry and support individual revocation. Shared draft protection, unchanged/invalid trust, provider-reference rejection, pending locks, cancellation and failure/retry across role commands are locally verified. |
| End-to-end access explanation | A no-grant user, group-derived allow, explicit deny, default-version rollback, boundary intersection and role-session case all lead to reproducible resource/action decisions. | Domain and interaction tests cover direct/group grants, deny precedence, conditions, current-version rollback, user/role boundary intersection, dual trust/caller authorization and session expiry/revocation. A real local MOCK journey proves caller denial before an exact assumption grant, role-only resource access limited by a boundary, then denial after revocation. Locally functionally verified for the documented subset. |
| Supporting workspaces | Review overview, users, providers, SSO, settings and one-time MOCK keys against the documented scope without faking external activation. | Overview links and candidate guidance, source-aware user filtering, localized policy metadata, SAML/OIDC drafts, SSO/settings failure-retry, enterprise visibility/import and one-time MOCK keys are locally regression-verified. Scan/paid/live security flows remain skipped. |

Acceptance requires all of the following, not just screenshots:

1. Pure-domain tests prove default deny, deny precedence, tenant confinement,
   source-preserving group/direct grants, version immutability/limits/rollback,
   referential integrity and supported condition/boundary/trust behavior.
   Unsupported syntax and incomplete context never yield an allow.
2. Interaction tests cover create/edit/copy/cancel, required fields, unsaved
   drafts, filter/selection persistence, preview-before-confirm, failure/retry,
   keyboard/focus restoration and immediate loading feedback. Cancelling a
   wizard must leave every related collection and association unchanged.
3. Real browser checks cover the complete Matrix MOCK journeys, direct URLs
   and Back navigation, empty and populated lists, Chinese/English, light/dark
   themes, 360px compact layout and desktop. No page-wide horizontal overflow;
   tables/code have labelled local scrolling and the action footer does not
   obscure validation or focused controls. While pinned, the footer reaches
   the scrollport bottom without exposing continuing form content beneath it.
4. Existing UI type/lint/unit/architecture/style/contrast, static-export and
   Go host gates pass. Live IAM has no preview fallback or changed grants.
   No Tencent account identifier, private inventory or credential is stored
   in implementation, documentation, fixture, export or report.
5. Evidence explicitly distinguishes reference inspection, local MOCK
   acceptance and live backend support. Scan-dependent enterprise activation,
   real key issuance, MFA/security mutation, paid features and real SSO are
   skipped, not accepted through an alternate verification method.

#### Product-independent shell and design system

The console shell is product-independent. The global layer owns organization,
region scope, product discovery, cross-product search, a single message-center
bell with running-Operation access, and principal identity. Each bounded product owns
only its workspace entry, local navigation, resource pages, and
contextual workflow. This keeps the interaction model stable while private-
cloud foundation, PaaS, DevOps, and observability capabilities are added, and
does not require a second console shell if a later release introduces public-
cloud regions. Project membership remains resource metadata, not a global
header selector or a top-level product destination.

The preview has three distinct navigation responsibilities:

- the header service directory discovers all registered services by category,
  subgroup, keyword, recent visit, or favorite;
- the narrow rail contains only the user's favorite services and a stable
  Dashboard shortcut, not an ever-growing product inventory;
- the adjacent context sidebar contains only the current service's pages. Its
  header shows one localized product name beside its icon, without a duplicate
  English eyebrow. Pages follow directly, without a generic Service navigation
  caption; meaningful groups such as identity and permission management remain.

Product discovery exists only in the Header directory; the duplicate products
page and local-navigation entry are removed. Dashboard discovery actions open
that same directory. The console's local navigation contains Dashboard,
Resource Center, Operations and tasks, and the full Message Center.

The service registry owns category, subgroup, entry route, section ownership,
and local navigation. Directory, global search, Dashboard shortcuts, favorites,
and contextual navigation consume that source. It is a presentation registry,
not a runtime plugin loader, deployment control, or authorization boundary.
Frontend registration never grants backend authority. IAM is a service even
though it is an administrative workspace; billing can use the same model when
there is a supported workflow. Unimplemented billing or audit products are not
advertised as available solely to reproduce another vendor's directory.

```text
Matrix Cloud header -> Service directory
  -> Cloud foundation -> Regions and nodes
  -> Application hosting -> Applications
  -> PostgreSQL -> Instances / engine and plans / quotas
  -> DevOps -> Delivery overview / pipelines / environments
  -> Cloud Monitoring -> Overview / service health / alerts
  -> Log Service (MOCK) -> Overview / search / topics / collection
  -> Access management -> Overview and service-local IAM workspaces
```

The visual contract is owned by semantic tokens and `@ui/xiak`; feature
renderers may compose these primitives into a dashboard, resource collection,
or workflow but do not create competing control dimensions. The desktop
reference dimensions are:

| Component or region | Contract | UX purpose |
| --- | --- | --- |
| Global header | `64px` high; `40px` controls | Persistent brand, search, scope, one message-center bell, and identity |
| Header brand | `168 × 28px` proportional SVG; `36px` symbol below `840px` | One graphic M replaces the initial letter of MATRIX; the approved lockup proportions stay intact |
| Header typography | `14px` primary controls; `12px` descriptions | System UI fonts and stable text sizes; compact layout changes composition instead of shrinking labels |
| Header count badge | `18px` height; independent `10px` numeric font and `14px` line height | Stable centered digits independent of the Chinese body font; multi-digit counts expand horizontally |
| Login brand | Approved horizontal SVG, up to `480px` wide at its `1020:172` ratio; compact header lockup below `760px` | One visible brand placement per viewport, without an extra M or an unrelated illustration |
| Login composition | `1200px` maximum split layout; `44px` fields and submit; `440px` maximum compact form | Brand-led desktop entry and focused small-screen sign-in, with visible labels and a separate MOCK entry |
| Favorite-service rail | `64px` wide; `40px` targets | User-selected service shortcuts, synchronized with directory stars; overflow scrolls within the rail |
| Service directory | Full viewport below the `64px` header; `224px` desktop category pane; `44px` search and close targets | Three-column grouped discovery, two/single columns as available width falls, horizontal category strip on small screens |
| Product context navigation | `240px` wide; `48px` minimum item height | Product-local IA with label, description, and actionable count |
| Page context bar | `56px` minimum, one reading line on desktop; actions wrap at compact widths | One current page/object title, parent navigation and contextual actions; no repeated title/action band in the body |
| Primary controls | `32px` small, `40px` default, `44px` large | Predictable density and touch/click targeting by task importance |
| Status badge | `24px` high | Comparable state language without changing row geometry |
| Resource table | `40px` header; `56px` minimum data row; `12 × 16px` cell padding; `144px` minimum cell width | Rich cells may grow; a labelled, keyboard-focusable region owns horizontal scrolling below the greater of `640px` and its column/content requirements |
| Form dialog | `600px` desktop width; `8px` compact viewport inset | Fixed title and action footer, independently scrolling fields, native modal background isolation |
| Context workspace | `360px` default; `320–460px` adjustable | Review or inspect without losing the source page |
| Content canvas | Fluid aligned workspace; `24px` desktop gutter | Page context and content share their left edge; prose and forms retain their own readable width, data collections use available space |
| Panel geometry | `6px` panel/dialog radius; `4px` control and popup radius; `12/16/24/32px` spacing rhythm | Theme-owned geometry continues the restrained, angular Matrix brand through content and navigation |

The Matrix brand header uses a white surface with deep-cyan accents in light
mode, or deep navy with ice-cyan accents in mixed/dark modes. All share a
continuous solid `1px` divider without gradient or glow at the content boundary.
Product, scope, notification, account and search surfaces follow the global
shell mapping without overriding the workspace's theme. The vector brand
uses the same semantic accent and remains legible on both surface tones.
The full horizontal signature, header lockup, standalone M, and browser icons are local assets included
in the static export; no external font or image service is required. The
system font stack and native text rendering also apply to the content canvas.

Four page compositions are admitted: a cloud overview with readiness and
attention-first metrics; a collection page with local search, filters, table,
empty state, and resource links; a product dashboard with health or delivery
metrics and recent activity; and an action workflow with a contextual review
panel. New products must adopt one of these compositions before adding a new
template. A new public component requires demonstrated reuse or an existing
accessible interaction contract that warrants one owner; feature-specific charts, pipeline rows, and alert
summaries remain product composites meanwhile.

The compact information-flow revision uses one page context bar for lists,
details and creation workflows. ContentPage owns one persistent title element,
return control and action slot; it does not alternate a shell breadcrumb tree
with a feature-owned header tree. Same-level pages show only their title;
details and creation flows add explicit parent navigation. Route identity is
available before feature data loads, including creation parents and entity
deep links. Feature metadata updates that same title; contextual actions retain
their feature providers through an action-only portal. Input does not subscribe
the shell or title frame to draft changes, while return actions use the current
draft guard. Pending navigation masks outgoing actions; cancellation restores
the original context. The content begins with meaningful
resource summary, tabs or data, not another generic title, return toolbar or
repeated preview banner. Header MOCK identity and mutation-level limitations
remain visible; errors, risks and destructive confirmations are never hidden
as optional help. Details use aligned multi-column facts when space permits,
with a single-column compact layout and full readable values.

Collection search uses one keyword field per independently searched collection.
The shared TableToolbar separates commands, query, structured filters and result
status. Structured filters are disclosed from a labelled Filter control rather
than a permanently expanded row of selects. Active conditions remain visible as
removable chips while the controls are closed, with a visible count and reset.
Search clears independently from structured conditions. Results update with the
existing local/repository contract; filtering never claims to search unloaded
backend pages. Sorting and pagination remain distinct from filter conditions.
The visual hierarchy distinguishes object names, supporting descriptions and
identifiers without removing those facts. Neutral classification labels do not
pretend to be status indicators; state uses explicit text as well as color.
Table headers, selection hit areas, row rhythm and paging controls have one
public owner. User and policy directory commands use the same select-then-act
flow in the context bar, without a repeated operation column. Policy kind stays
visible beside the name, and full descriptions and permission scopes remain
readable. Existing batch limits, cross-page selection semantics, eligibility
reasons, review, cancellation and retry remain unchanged. The refinement must
work in light/mixed/dark and Chinese/English, retain local horizontal scrolling
on compact screens, and preserve the route/draft rendering-isolation gates.
The shared form label derives its required marker from the control's native or
ARIA required semantics, retaining the existing validation and accessible name.
Wizard spacing prioritizes fields and candidate rows over repeated headings;
its opaque sticky action bar remains inside the scroll boundary. Narrow Transfer
tables retain readable names in a local horizontal scroller instead of squeezing
identifiers into fragments. Resource names have consistent link affordances;
operation/message metadata uses the small-text token, and collapsed messages
allow two title lines while expanded messages expose the complete title.
Clearing structured conditions restores focus to the stable Filter trigger
without clearing the keyword or closing the disclosed panel. A themed select
accepts its focused choice and closes on Tab or Shift+Tab; the next Tab
continues from the trigger in the form's normal order. Escape cancels an
uncommitted choice and returns focus without dismissing the enclosing form.
Global search still discovers products/resources/pages; Transfer candidates and
policy operation explorers retain their own scoped search. They are separate
collections, not redundant fields to delete. Theme, locale, keyboard/focus,
empty/recovery states, selection limits and existing draft guards are preserved.

The public Theme foundation covers tables, dialogs, buttons, native radio and
checkbox controls, input/select fields, search and password affordances,
alerts, empty states, tabs, selection menus, statistics and progress. All
existing resource tables use one native semantic Table; rich cells remain
owned by their product. Input and Select share one control stylesheet. Button
can style a real navigation link through Radix Slot without nesting interactive
elements. Select owns a themed combobox/listbox over the existing non-modal
Radix menu primitives, sharing its option surface with SelectionMenu. Its
40px rows, bounded viewport, selected check, hover/focus, disabled and invalid
states follow Theme. A hidden native field preserves form submission,
required validation, empty values and reset; validation focuses the visible
control. Pointer and arrow/Home/End/typeahead selection, Escape restoration
and outside-focus behavior have one owner. Dropdowns inside native Dialog
portal into that dialog's top layer and Escape closes only the dropdown.
This composition adds no dependency or CSP exception. Card,
Table, Dialog and FormField own repeated geometry; renderers own composition,
data and workflows. Feature-specific charts, global combobox search and
service-directory navigation remain composites, not alternate primitives.
Search and notification popups use the compact variant of the same EmptyState;
shell recovery/status messages use Alert and navigation-close actions use
Button. Compact variants consume Theme dimensions instead of private style forks.

Console navigation keeps the global Header and shell mounted. One shared route
transition owner connects console links and global-search results to the actual
App Router transition. Clicking a destination immediately replaces the outgoing
content with its page-shaped PageSkeleton and updates the same title frame;
there is no delayed skeleton reveal or minimum artificial wait. A dedicated
route subscriber renders an indeterminate two-pixel progress track over the
global Header's bottom divider, without subscribing static Header controls to
its loading state. Local refresh feedback stays with its content. The public
indeterminate Progress animates only a clipped, paint-contained child transform,
not background position or layout dimensions; it owns no animation timer or
React frame state. The active child alone receives the compositor hint, and
reduced-motion preference presents a stationary indicator. Determinate task
progress remains a native element driven by real values.
Dashboard, table, card, list and access layouts share semantic Theme
tokens and a single announced loading label. The outgoing content is hidden and
inert while pending, but its draft remains mounted until the visit commits or is
cancelled. A committed page receives a fresh scroll container and a `180ms`
content-only fade. A thin indeterminate progress line communicates real route
and refresh activity without inventing a completion percentage. Fast cached
routes finish immediately; interrupted visits cannot overwrite a newer
destination. Reduced-motion preferences disable animated content, skeletons,
progress and refresh icons. Refreshing existing data retains the current page
and draft instead of pretending to navigate again.

Header open/close state is subscribed only by Header and its backdrop/inert
boundaries, not by the service-page renderer. IAM navigation subscribes to
stable capabilities independently of form pending/error state; the refresh
control owns its status subscription. Message details and their destination
links mount only when expanded. Optimizations must preserve region and locale
updates, permission changes, focus restoration and modal isolation. Measure
interaction work in a production build, including style/layout and paint, not
only React render time or development-mode click warnings. Motion is feedback,
not a substitute for removing blocking work.

Tokens control colors, typography, dimensions, spacing, borders, radii and
interaction states. The light scheme uses a contrast-safe deep-cyan action
color; dark and mixed-shell surfaces use ice cyan. The account popup provides the same
theme and language preferences as login, using shared native RadioGroup
controls. Changes apply without remounting the current task. Style gates reject
raw feature palette values, unresolved tokens, private native-table forks,
unlayered public-control CSS and missing CSS-module bindings. Feature selectors
target their own label wrappers instead of recoloring descendant status badges
or other shared controls.

IAM tenant creation and lightweight user management use the shared native Dialog. It focuses its
title, contains keyboard navigation, suppresses global shortcuts and restores
the initiating control on close. Escape, Cancel and X close an idle form;
pending mutations disable dismissal. Clicking the backdrop does not dismiss.
An initial data read must not gate opening: `Dialog` renders its title and X
immediately, with its localized `loading` skeleton instead of unavailable
content/actions. Reading does not lock dismissal. Failed reads show recovery
inside the same shell; request cancellation and stale-response protection stay
with the feature's data owner. Closed dialogs do not mount their content.
Already available local data is shown directly, without fabricated waits.
This form contract is separate from the service directory's trigger-or-X
contract below. IAM uses a default overview and grouped service-local links;
detail workspaces use semantic tabs for memberships, policies, trust and
security. Subuser creation replaces the dialog with a dedicated content-area
route at `/console/access/create-user/`. The public `Wizard` owns the form
frame, focused step heading and sticky action footer. The footer shares
`ContentPage`'s responsive scroll inset so its opaque surface reaches the
scrollport edge, not the padded content edge; it returns to document flow at
the end of the form. `Steps` owns completed, current and future states.
Compact containers show only the current title,
step count and segmented progress rather than wrapping five desktop labels.
The public `Transfer` composes the public `Table`, Checkbox and SearchInput for
available/selected choices, removal, clear actions and the stacked narrow-screen
layout. It renders twenty candidate rows per page by default, indexes names,
IDs, descriptions and supplied keywords, searches the entire supplied collection
and keeps off-page selections. Type-filter changes reset the page but preserve
the query and selection. Its header has unchecked, mixed and checked states;
bulk selection and explicit page deselection affect only eligible rows on the
current filtered page, in one callback, never the whole directory. A page that
would exceed the caller's remaining capacity cannot be partially bulk-added:
an inline explanation requests individual selection or prior removal. Removing
selected rows remains possible at capacity. The candidate header stays within
its bounded scroll region; narrow layouts wrap full names and translated column
headings. User permissions retain separate 30-item policy/group limits and
selected-count summaries; wildcard warnings identify broad statements without
claiming an effective-permission result. The same batch-selection contract is
used by group/role choices and policy-association target selection.
Live large collections will also need bounded repository reads; UI pagination
does not make an unbounded backend response acceptable.
Public Tabs roots can shrink
inside grids; only the tab strip scrolls horizontally, without widening nearby
alerts or the page. All geometry, colors and focus rules use semantic tokens.

The user directory includes the account's primary identity and subusers, with
independent type, access-method, authorization-source and status columns. The
primary row comes from the existing tenant-account/primary-principal relation,
not administrator grants. It is described as the current account's resource
owner, never as ungranted because it has no child-policy associations. Its
detail separates read-only identity, access and ownership permissions from
editable MOCK group membership. Child grant, disable, password-reset and delete
actions are not offered. Group membership explicitly accepts the current
account's primary principal; joining/leaving groups does not turn it into a
subuser or become the source of its owner permissions. Primary metadata stays
outside the subuser collection consumed by grant, permission-copy and key-owner
selectors. Only group-member selectors include both types. Application and
preview-adapter guards reinforce that boundary; the live IAM contract is not
expanded. Unknown primary display names/statuses or absent child access
profiles are not fabricated from the current actor or interpreted as disabled.
Type/status/source filters and keyword search cover the loaded page, explicitly
including the primary identity on each page. The directory has no trailing
operation column. Usernames open details; leading checkboxes and a More actions
menu beside Create user provide one command entry for single/bulk selection.
The shared `TableSelectionCell` owns cell geometry and mixed-checkbox semantics;
`TableActions` owns the menu, selection count, clear action, disabled explanations
and keyboard behavior. IAM supplies eligibility. Header selection covers only
the current filtered page, up to thirty users; changing filters, pages or data
clears selection rather than retaining hidden mutation targets. Primary/child
mixed selection permits group attachment but blocks child-only commands. Status
changes require compatible states and protect the current actor; unknown,
stale, unauthorized or ineligible targets reject the entire batch. Primary
ownership and existing memberships/grants/boundaries are preserved by additive
group/policy attachment. Review identifies every target; disable/delete require
explicit acknowledgement. Errors retain the dialog and selection for recovery,
and pending submission prevents duplicate writes and dismissal. The preview
adapter commits identities and workspace access atomically; shared single/bulk
deletion cleanup clones once and traverses each collection once. The live adapter
does not expose this batch capability or fan out into single-user APIs; existing
live management remains reachable through the username detail. The preview child detail always
opens on identity information, then exposes separate access, policies, groups,
security and credential tabs. Direct grants and named group inheritance remain
distinguishable; administrator authorization does not change a subuser into
the primary identity. Enterprise-WeChat, collaborator and message-recipient
type expansion is outside this slice; existing enterprise behavior is preserved.

The MOCK user flow has use-case, information/access methods, permissions, optional
tags and review steps. It supports direct policies, inherited group access and
explicit copying of another user's preview associations. Choices survive
step changes and searches; inline errors use locale-neutral codes. Creation
atomically adds the preview identity, policy associations, memberships and
profile tags without changing the live fixed-role contract. Team-member and
automation use cases both create ordinary subusers; they preset access methods,
not identity type or permissions. The owning account is visible during creation
and in the review. Console and programmatic access may coexist, independently
of policy grants, identity status and credential availability. Password and MFA
options are explicitly simulated; no real credentials or automatic API keys
are generated. Preview profiles reset with the session and can be inspected
in user details. The live-capability flow retains only identity, initial
fixed-role authorization and review, defaults to no grant and excludes
passwords from review and storage. Draft cancellation requires confirmation;
browser reload warns about unsaved edits. Submitted passwords are cleared on
success and failure. Reusable collection, selection, detail and dialog
compositions share public controls, responsive widths, keyword filtering,
pagination, empty states and confirmations. These controls, permissions,
settings, forms and safe feedback are localized. IAM retains role/state/error codes instead of Chinese strings in
application state; renderers translate them without fetching IAM again or
discarding a draft. Opening a password reset focuses its password field but
does not perform a mutation. Credentials and authorization remain owned by
IAM, not public controls.

Shell titles, navigation, tool labels, loading/recovery controls, workspace
actions, global search and notification chrome use keyed messages. Navigation
scenes carry stable service and message identifiers instead of display names.
Resource names, tenant names and user-entered display names are preserved as
data, not translated. Search includes translated resource types and stable IDs.
The Message Center contains firing-alert notices, terminal Operation results
and platform announcements. Its bell badge counts unread messages, separately
from the compact running-task link; an in-progress task is not an unread
completion notice. Task results use completion timestamps. Opening the center
does not mark messages read. Reading a detail or choosing Mark all read changes
only memory-local reading state, never an alert or Operation's actual state.
The popup and `/console/messages/` share MessageInbox: category tabs, details,
source navigation and reading state. The popup uses a light Only unread
checkbox; the full page adds keyword search and borderless All/Unread/Read
radio choices. An expanded message stays visible under the unread filter until
closed, so marking it read does not interrupt reading. MOCK reading state resets
on reload/sign-out and unavailable live message data stays explicitly unavailable.
Fixed timestamps have an explicit time zone, not perpetual relative ages.

Dashboard, resource, Operation, pipeline, monitoring, quota and installation
scenes retain numeric metrics, capacities, timestamps and lifecycle codes.
ConsoleMetrics is the shared feature-level metric composition over Statistic;
presentation formatters own locale-aware numbers, units and explicit UTC dates,
including distinct missing and invalid observations. Pipeline environment
summaries derive from the displayed runs instead of an unrelated static list.
The Dashboard attention list includes only running Operations. Fixed sample
metrics and event contents remain explicitly MOCK, not live observations.

Managed-service pages show their collection before a contextual order form.
The named quota/installation action opens the existing mounted workspace;
closing and reopening preserves the draft, while changing section closes the
panel. Closed content is inert and hidden from accessibility navigation.
Compact action headers wrap and retain the workflow label. Instance IDs expose
their bounded format through associated help, and quota quantity accepts only
integers from one through eight. Shared Alert, FormField, Input, Select and
Button retain the same theme and locale behavior throughout those workflows.

The login renderer composes the shared Brand and appearance controls with
account-login and mandatory-password-change forms. Public PasswordInput owns
reveal/conceal and Caps Lock feedback, FormField owns label/help association,
Alert owns error announcements, and Tabs/SelectionMenu own accessible
selection. Switching account type clears secrets, error state and reveal mode;
switching language or theme preserves the current draft. Submitting a failed
login clears its password, pending submissions disable conflicting actions,
and errors never expose upstream payloads. The MOCK entry remains explicit and
absent from production builds. There are no inert registration, password-reset,
or SSO controls for unsupported backend workflows. Normal primary-account,
IAM-user, and MOCK entry defaults to the Dashboard at `/console/`. An explicit
requested resource route is preserved through sign-in and mandatory password
change; IAM users are not unconditionally redirected to access management.
This navigation rule does not grant resource permissions or bypass the
mandatory password-change gate.

The interaction contract includes:

- one explicitly named product launcher and one `Ctrl/Cmd+K` search position
  on every page, including when compact layout hides the visible launcher text;
- product and region entries compose the public `Button` through one
  `HeaderPopoverTrigger`. It owns the shared 40px height, 14px/semibold text,
  18px leading icon, 14px chevron, 8px gap and 12px horizontal inset, with
  semantic theme tokens for geometry and state colors. Both chevrons turn on
  expansion. The brand/navigation and utility groups stretch across the same
  Header content height and center their controls; brand dimensions do not
  define a different group height. Parent components retain their panel state,
  selection, dismissal
  policy and focus restoration; responsive variants do not duplicate triggers;
- search uses an accessible combobox and active-descendant listbox with result
  counts, an explicit empty state, arrow-key selection, and direct navigation
  to the owning page. Clicking an already-focused input reopens the results
  after navigation or Escape; repeated clicks keep an open list open without
  navigating again. The compact search input opens below the header; Escape
  returns to the visible search trigger;
- the full-screen service directory paints its opaque surface and available
  content together, without a separate dimming backdrop or whole-panel
  opacity/translation entrance. Compact Header popovers retain their motion
  and backdrop dismissal. The directory focuses keyword search on open. Its Header
  trigger toggles it open/closed, and its top-right X also dismisses it;
  either dismissal restores trigger focus. Selecting a service navigates to
  that workspace. Blank-space clicks, blur, Escape, and global
  search shortcuts do not dismiss it. Background workspace and other header
  controls are inert while it is open; Tab stays within the dialog. The Header
  trigger stays pointer-operable and names its current open/close action.
  Categories and service results support arrow navigation;
  IME confirmation does not accidentally activate a result. Name, subgroup and
  bilingual capability aliases share normalized, case-insensitive keyword
  matching across categories. Clear and no-match reset have explicit controls;
- service favorites synchronize between directory, common-service cards and
  the narrow rail. Favorites and deduplicated recent visits are in-memory MOCK
  preferences, cleared at refresh or session exit, with that limitation stated
  in the directory. Empty favorites/history are honest empty states;
- message-center and account header popovers focus their first control on open
  and restore the triggering control when `Escape` dismisses them;
- persistent region scope immediately filters resource collections. One named
  header trigger uses the shared popup surface, selected-state checks, a
  keyboard-operable listbox, and focus restoration. Its resting surface is
  transparent and borderless, sharing hover, expanded and keyboard-focus
  treatment with the Products and services trigger. The same mounted picker
  works at every width; at `620px` and below its 96px trigger shows the localized
  region label without shrinking the font; at `420px` and below it becomes a
  40px icon-only control. The current selection remains in the
  accessible name and tooltip, with a visible mobile filtered indicator.
  Resizing an open popup never swaps to a second implementation or leaves an
  invisible popup or backdrop. Its labels and filtering guidance use keyed
  Chinese/English messages;
- at most one global product, search, region, notification, or account popup is
  open at a time;
- one global message-center bell, with unread status, categories and message
  time; its running-task link opens the retained Operations and tasks page;
- one global principal entry in the header; its account panel owns tenant and
  principal identity plus a grouped account-action menu, while product-local
  navigation contains no duplicate account dock. Appearance preferences and
  account actions share the panel surface, section-label typography and
  horizontal inset. The public `PanelSections` composition owns equal section
  padding and full-width subtle dividers for login identity, tenant/type,
  theme/language, account access and logout; it inherits the enclosing surface
  instead of assigning a background to individual sections. Account access and
  logout are visually separate sections within the same keyboard menu.
  Preferences remain labelled radio groups; actions remain menu items and
  logout retains its semantic danger treatment. The menu exposes `menu` and
  `menuitem` semantics, a separated dangerous logout action, roving arrow and
  `Home`/`End` focus, and `Escape` dismissal that restores trigger focus;
- access-management pages use bookmarkable links within one grouped service
  navigation. Detail tabs expose semantic `tablist` behavior; arrow keys and
  `Home`/`End` select and focus tabs. At compact widths the service menu is a
  focus-contained drawer, detail tabs remain horizontally browsable and
  card-header actions stack instead of compressing their labels;
- explicit loading, empty, unavailable, running, success, warning, and failed
  states; no spinner or success message substitutes for known progress;
- contextual workspaces are opened by business-task labels such as `激活配额`
  and `安装服务`, not generic panel terminology; their expanded labels state
  exactly which configuration or status surface will be collapsed;
- compact product-navigation and contextual-workspace drawers move focus into
  the active surface, keep `Tab` and `Shift+Tab` within it, and return focus to
  the invoking control when `Escape` dismisses it. The persistent desktop
  product navigation remains an ordinary navigation region rather than a
  modal focus context;
- operation history supports keyword and lifecycle-state filtering, announces
  the result count, and uses native summary disclosure for structured audit
  context and state-specific next-step guidance;
- `Escape` dismissal, visible focus, native selects, keyboard-resizable
  context panels, and reduced-motion handling;
- a product/context drawer below `920px`, compact global controls below
  `720px`, and a rail-free mobile workspace below `620px`. Collections may
  scroll within their own table region, but the page shell must not scroll
  horizontally at `360px`.

The design decisions use primary product guidance, not visual copying:
[Cloudscape service navigation](https://cloudscape.design/patterns/general/service-navigation/)
separates global search and utilities from task-oriented product navigation;
[Google Cloud resource organization](https://docs.cloud.google.com/docs/get-started/organize-resources)
anchors resources below organizations and projects;
[Azure portal structure](https://learn.microsoft.com/en-us/azure/azure-portal/azure-portal-overview)
keeps the global header, scope, search, notifications, service menu, and
working pane stable; and
[Alibaba Cloud Resource Center](https://www.alibabacloud.com/help/en/resource-management/resource-center/product-overview/resource-center-overview)
provides a cross-product, cross-region resource view that returns users to the
owning product console for operations.

Development builds, or builds explicitly configured with
`NEXT_PUBLIC_MATRIX_UX_PREVIEW=1`, expose a visibly labelled `MOCK` journey.
Its in-memory IAM, control-plane, resource, pipeline, health, alert, and
Operation repositories exist only to validate information architecture,
components, dimensions, layout, and interaction before every backend exists.
They never ship as implicit production truth and do not satisfy Gate B or Gate
C real-authority and installed-release evidence.

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

## Incremental acceptance

### Gate A: control-console foundation

1. The Phase 1 single-page configuration workspace is replaced, not retained
   as a parallel or compatibility route.
2. The locked Next.js static export is deterministic, copied into the Go embed
   boundary, and a drift gate proves generated assets match source without a
   network fetch or a production Next.js server. Static and dynamic route
   prefetch URLs return their non-empty segment payload through the Go handler,
   not a 404 or an HTML fallback.
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

- The current Theme/component, navigation and CAM-style IAM slice has 456 frontend tests across 35 test
  files; the complete suite passes with two workers at the default timeout
  (the long user-selection journey retains its explicit 15s timeout).
  Separate long IAM runs can still hit the default 5s timeout under development
  load; the typed-resource journey passed its focused rerun. Functional test
  success is not a performance acceptance claim.
  The policy-directory revision verifies all/preset versus custom-only columns,
  category/filter semantics, retained view context, and actual policy modification
  timestamps. All four creation methods are exercised through reviewed saves
  into the isolated preview store, with no live IAM calls. Tests cover required
  resource tags, selection retention, mode retention and refusing lossy feature
  conversion. Empty drafts from all four entries, cleared feature selections and
  incomplete tag conditions remain editable after JSON round trips; malformed
  or unrepresentable JSON remains intact. A browser check reproduces the reported
  template-selection/empty-JSON sequence and verifies all three alternate tabs
  are clickable without changing the draft or producing warning/error logs.
  Browser checks verify all four entry routes, tag-error correction,
  JSON projection, edit/review/return and discard protection. Chinese/English
  checks at 1475 x 866 and 360 x 800 cover the chooser, light/dark/mixed surfaces,
  and table-local horizontal scrolling with no page overflow. Project permissions
  and request-tag conditions remain unavailable; no Tencent authorization was
  created or changed.
  All 63 Header/shell and appearance regression cases across seven files pass, including
  immediate directory content without a dimming stage and retained compact-panel
  dismissal, shared-trigger Enter/Space activation, expanded/panel semantics and
  selection/closure focus restoration.
  Three static-export normalization tests, type checking, lint,
  architecture and semantic-style gates (228 contrast pairs across light,
  mixed and dark workspace/shell surfaces) pass. Theme tests prove saved preference
  restoration, cross-tab synchronization, live system changes and draft
  preservation. Browser checks cover light global navigation, product directory,
  search, scope/account/message popups, a native IAM dialog and portalled
  table filters, plus 360px Chinese/English theme controls without page overflow.
  Directory checks at 1468 x 866 and 360 x 800 verify full-viewport coverage below
  the Header, opacity 1, no entrance animation or dimming overlay, search focus,
  repeated trigger/X closure and background isolation. Fresh light-theme opening,
  dark/mixed surfaces and compact account-panel motion/backdrop are also checked.
  Account sections are browser-verified in light, dark and mixed with matching
  muted small-text/regular labels, shared 16px padding and full-width 1px rules.
  Desktop and 360px Chinese/English
  layouts retain one panel surface, aligned labels, bounded menu rows, danger
  text for logout and Home/End/Escape focus behavior.
  Shared product/region triggers are browser-verified with equal 40px height,
  14px/600 text, 18px icons and 14px chevrons in light, mixed and dark themes.
  Their outer groups share the Header's 63px content height; both button tops
  measure 11.5px and text tops 21px. The group, button, icon, visible label and
  chevron centers remain aligned at 31.5px in closed/expanded states, all three
  themes, English and Chinese, and the checked 360–1468px responsive widths.
  English layout checks at 1468, 1100, 1000, 720, 620, 420 and 360px retain
  bounded controls without page overflow; the 96px compact region entry fits
  its English label with padding. Chinese checks include the 421px compact
  boundary and 360px directory. Resize retains one region popup; selection,
  Escape, repeated product-trigger closure and X closure restore focus.
  The checked local browser interactions return no warning/error logs.
  The compact information-flow revision shares a 56px desktop context bar
  across collections, details and creation flows. The public ContentPage owns
  one persistent title/return frame; feature metadata updates that frame and
  only contextual actions use a provider-preserving portal. Regression tests
  retain the same title and parent elements through loading and registration,
  prove draft input causes no title-frame commits, and check that the return
  action still reads the latest draft. Loading-state tests prove static global
  Header controls do not rerender when the isolated route progress starts or
  stops; local refresh feedback stays inside the content header. Browser checks
  verify the equal 56px context bars for users and federations, detail and
  creation return controls, immediate destination titles/skeletons, progress
  inside the global Header, and current-draft leave/cancel protection without
  creating an account. Sidebar checks retain a 56px header with one complete
  localized product name for application hosting, no generic navigation caption,
  and the IAM identity/permission groups. The shell/scene suites cover the
  Chinese/English identity and navigation behavior. No new warning/error logs
  were reported for the navigation journeys above. These are
  render-isolation and UI checks, not a GPU/compositor trace or a claim of zero
  browser paints. Pending navigation hides outgoing actions
  immediately, cancellation restores the existing draft, and returning to a
  visited collection restores its scroll container position without retaining
  the old page DOM. User and policy queries survive detail navigation; user
  batch targets are intentionally cleared. Public collection toolbars provide
  one keyword query, disclosed structured filters, removable active criteria,
  independent query/filter clearing and explicit empty-result reset. The same
  composition is used by IAM directories, resources, operations, log search
  and full-page messages; compact message read choices remain text controls.
  Browser checks at 1468 x 866 and 390 x 844 cover the primary/child detail,
  user directory, criteria retention, page-level create-user return confirmation,
  light/mixed/dark and Chinese/English controls. Narrow pages retain bounded
  content and table-local horizontal scrolling. Resource keyword matching,
  failed-operation filtering, message keyword matching, and combined trace/topic
  log filtering are also verified. After a complete reload, these journeys
  produce no new warning/error logs; transient Turbopack CSS hot-update errors
  during source editing are not treated as runtime or production evidence.
  The visual refinement is browser-checked at 1475 x 866 and 360 x 800 across
  user/policy tables, identity details, group dialogs and member selection,
  the dashboard, resources, operations, messages and user creation. Checks
  include light Chinese, dark English and mixed English surfaces; 40px table
  headers, neutral classification, readable object/metadata hierarchy,
  selected/mixed checkboxes, visible eligibility and stable More-trigger focus
  after cancelling an association dialog. The compact user and Transfer tables
  scroll locally without widening the 360px document. Wizard checks preserve
  required-field errors, page selection counts, opaque footer and guarded
  cancellation; the temporary draft was discarded without creating an account.
  Fresh-reload message checks verify full expanded content and read-state
  feedback without new warning/error logs. Shared control tests cover required
  semantics, classification/status distinction, controlled paging and dialog
  focus return; existing large-candidate and batch/permission gates remain.
  All 442 frontend tests and three static-export normalization tests pass,
  alongside TypeScript, lint, architecture and 228 theme contrast checks.
  All 213 generated production files from 38 static routes match the Go-embedded export, and Go UI
  tests and vet pass. Tables, forms, dialogs, choices,
  feedback, tabs and metrics use the public controls and shared composition
  described above; source-provided data is not mistranslated as interface copy.
  Extended IAM tests cover group membership, inherited permissions, policy
  editing/version/association invariants, provider-role dependencies,
  enterprise visibility and ungranted member import, one-time MOCK secrets,
  disabled-before-delete keys, reset isolation, safe reports, all registered
  bookmarkable IAM subroutes and IAM navigation independent of PaaS reads.
  Account-identity regression cases prove the primary row is independent of
  administrator grants, unknown facts remain unknown, and access methods do
  not imply permissions. Primary group membership is covered from both the
  user and group workspaces, including add/remove round trips and rejection of
  primary child-grant, credential and lifecycle mutations. A local browser
  journey verified primary membership changes, user-to-group detail navigation
  and child identity/access tabs on desktop; Chinese/light and English/dark
  presentations preserved the active detail and returned no warning/error logs.
  The temporary MOCK membership was removed. These checks do not establish
  live Tencent mutation behavior or live Matrix group authorization.
  Four user-directory integration journeys and ten batch transaction cases
  cover no-selection and current-page/mixed selection, filter/page clearing,
  primary/self protection, additive associations, stale/invalid target atomicity,
  shared deletion cleanup, review/cancel, duplicate-submit suppression,
  failure/retry, locale-preserved review and live single-user fallback. The
  desktop MOCK browser check at 1468 x 866 verifies the removed operation
  column, selection-driven menu, disabled explanations and group append/review;
  the original membership and grants remain intact. The synthetic membership
  added during that check was removed. Batch writes remain preview-only.
  The policy directory combines independent kind/service/action-type/resource-
  scope filters with localized keyword search, sorting and pagination. Page
  context survives list/detail navigation in the current account session;
  filter keystrokes remain local instead of updating the console shell.
  Shared policy-specific compositions own the service summary and inline
  operation explorer, structured differences, diagnostics, resource selection
  and association review. Summary and operation rendering are paginated;
  only the selected service expands to operation rows. Allow/Deny groups retain
  their independent statement branches and the source wildcard rules. All
  controls continue to use the public UI and theme tokens.
  The strict preview parser remains the single validation authority; bounded
  diagnostics distinguish blocking errors, broad-access warnings and structural
  duplicate suggestions, with navigable statement paths. Action granularity
  comes from the explicit catalog, not read/write/list classification. Each
  operation also declares supported conditions. The same capability definition
  limits resource service/type choices, enables compatible conditions and
  blocks unsupported drafts without deleting their restrictions.
  Interaction and domain gates prove preservation of independent filters and
  pagination, inventory selection without overwriting manual resource patterns,
  tag-mode/JSON restrictions, unsupported-draft retention, additive batch
  association atomicity, confirmation before mutation and failure/retry.
  Removal review explains surviving direct and group paths. Version review
  identifies affected subjects and boundary references separately from grants,
  while comparing changed statements rather than asserting effective access.
  Service exploration was verified in Chinese/dark and English/light at
  desktop and 360 x 800. Compact tables present labelled vertical entries;
  the measured table width/scroll width was 292px and page width was 360px.
  Opening a low-positioned service reveals its heading; return preserves the
  search/page and restores the originating service's keyboard focus. A local
  create/review/save/detail journey retained two `logs:search` statements with
  separate synthetic resource/IP restrictions plus a `logs:delete` deny.
  Exploring review details did not submit the form; only explicit Save created
  the unassociated MOCK record. Its saved JSON was unchanged, the temporary
  record was removed, and original language/theme preferences were restored.
  The checked browser journey returned no warning/error logs. These checks
  prove the supported UI/model contract, not a live authorization or performance
  guarantee.
  Browser verification covered Chinese/dark and English/light, 1280 x 800 and
  360 x 800 layouts, tag-policy creation/association, edited conditions,
  semantic review, save, cancellation and default-version rollback. Desktop
  differences appear side by side, compact differences stack, and full JSON is
  disclosed on request. At 360px the dialog measured 344px, its scroll width
  342px and document width 360px. Cancel restored the original trigger;
  successful rollback restored focus to the version-list region after the
  trigger disappeared. A clean-tab edit/save/rollback journey returned no
  warning/error logs. Intermediate source hot reloads can reset the intentionally
  page-local preview session; no persistent credentials or draft storage were
  introduced. These checks validate the bounded MOCK experience, not Tencent
  syntax compatibility, live authorization or an INP performance target.
  The 2026-09-09 policy-lifecycle increment additionally proves unsupported
  restriction rejection without stripping the draft, lossless multi-statement
  handling, immutable names, description-only edits without new revisions,
  independent copies without inherited associations, the five-version limit,
  protected defaults, immutable revision contents and revision IDs that are
  not reused after deletion. Historical inspection does not activate a version;
  rollback confirmation presents the current and target documents with direct
  association impact. The semantic document viewer is shared by details and
  history; the public Dialog owns normal/wide sizing through theme tokens.
  Browser checks exercised content save, history, rollback and nondefault
  deletion, Chinese/dark and English/light presentation, desktop side-by-side
  comparison and stacked comparison at 360 CSS pixels. The compact dialog
  measured 344px with zero dialog/page horizontal overflow, an in-viewport
  footer and Escape restoring the version trigger. Detail navigation brings
  its toolbar into view without losing heading focus. No browser warning/error
  logs were returned during that local policy-lifecycle journey.
  Policy creation now uses the bookmarkable content-area `create-policy`
  route; copy and content edit share the same three-step workflow. The modal
  authoring path is removed. Interaction/domain tests prove multiple-statement
  visual/JSON round trips, ordering/removal, preservation of unsupported and
  non-representable drafts, template confirmation even after returning to an
  earlier step, localized validation, immutable edit names, metadata tags,
  cross-category selection retention, atomic creation/associations and
  failure/retry without a partial save. Capacity recovery explicitly nominates
  a nondefault revision and atomically replaces it only on successful save;
  defaults and original history remain unchanged after failure. The public
  TagEditor is shared with user creation, and policy association dialogs reuse
  the same bounded Transfer composition as the authoring workflow.
  Browser authoring checks covered Chinese/dark and English/light, creation
  with both user and group associations, saved tags, details, step navigation
  and explicit draft discard. At 360 CSS pixels there was no page-wide or
  content-element horizontal overflow. The English review footer measured
  73px high with all three actions aligned and visible inside the viewport.
  Shared Transfer labels now stack the name and description instead of
  squeezing both into a horizontal row. Desktop verification used 1280 x 720.
  A source hot-reload emitted a missing CSS-chunk error in the dev client;
  after a complete reload the checked route/step/cancel journey returned no
  warning/error logs. Parallel test runs under concurrent development or build
  load can exceed a long-input wizard test's five-second harness timeout. The
  final suite uses one worker and unchanged assertions/timeouts; longer fixture
  values in inventory/tag and condition round-trip tests use real paste
  interactions instead of redundant character-by-character setup.
  Neither observation is a new interaction-performance acceptance claim.
  Typed authoring now selects from 33 registered operations across the seven
  existing services, searchable by label/ID and filterable by access level.
  Structured resource rows retain tenant ownership, resource type, region and
  ID/prefix; account-level actions cannot silently widen an incompatible
  specific scope. Service replacement requires confirmation and retains
  conditions and other statements. IPv4/IPv6 CIDR, exact resource-tag and
  inclusive UTC conditions round-trip through visual/JSON/review/save.
  Unknown syntax, malformed or empty conditions and incompatible/cross-tenant
  resources block saving. The user-policy simulator has its own bookmarkable
  IAM route and reports direct/group origin, default version, statement and
  match reason. Unsupported role assumption is rejected, never simulated as
  a user-policy allow. Each distinct policy document is parsed once per request;
  evidence rendering is paged at 20 rows, and changing request inputs removes
  the previous result.
  The expanded tests cover mapped IPv6 normalization, condition AND/range OR,
  UTC boundaries, missing context, unknown identities/resources/actions,
  tenant confinement, group/direct provenance, explicit deny precedence and
  default-version rollback. Browser verification at 1280 x 720 and 360 x 800
  covered Chinese/dark typed authoring, scoped IP/tag conditions, review,
  creation and association to a synthetic user, then an allow result with
  that policy's provenance. English/light simulation retained complete
  localized copy and a 360px page width; the 640px evidence table scrolls only
  inside its labelled region. Result creation moves focus into the result.
  Visual validation now focuses and scrolls its error above the sticky footer:
  the measured compact error ended at 698px and the 73px footer began at 714px.
  Public FormField grid content aligns at the start, preventing an adjacent
  hint from stretching the input control.
  Local development and final Node gates used supported Node 24.19.0.
  The added IP dependency is pinned to 2.5.0; a scoped transitive js-yaml
  update removed the reported development advisory, and the full npm audit
  returned zero reported vulnerabilities. Source hot updates retained an
  older missing CSS-chunk log; no new warning/error appeared in the checked
  English/light journey after a complete reload. The unit harness still
  emits asynchronous act warnings from the existing Wizard, preferences and
  log-service tests; all tests pass, but those warnings are not a performance
  claim or suppressed by a longer timeout.
  Group creation now uses the bookmarkable three-step `create-group` route,
  replacing the combined metadata/member/policy dialog. Creation saves no
  members; metadata editing never replaces memberships or policies. Separate
  add/remove commands validate references and apply at most 30 explicit deltas
  without dropping members outside the loaded directory. Public Transfer
  controls retain off-search selections and distinguish an empty directory
  from an empty selection. Changes present selected objects and affected
  member counts before confirmation, and failures leave the same selection
  editable for retry. Membership review shows each selected member once;
  policy review additionally identifies affected members. Removing a source
  warns that direct policies or other groups can still grant access.
  User policy rows now identify each granting group by name. User, group,
  policy and role references open their exact detail through an encoded query
  ID; unknown/unloaded IDs show an unavailable state rather than another
  object. The console transition boundary preserves query URLs, and sign-in
  retains the selected entity instead of returning to its directory. Query
  content never controls the redirect path or acts as authorization. A user's
  simulation entry retains the selected principal; an unknown principal is
  not replaced by the first available user.
  Domain and interaction tests cover empty-group creation, duplicate names,
  invalid references, bounded deltas, unloaded-member preservation, metadata
  isolation, reviewed policy/member changes, failure/retry, cancellation,
  locale-preserved drafts and precise cross-navigation. The real MOCK browser
  journey created an empty group, associated an existing policy, added a
  synthetic member, explained the inherited allow, removed the source and
  confirmed implicit deny. The test-only group was deleted; no Tencent
  objects, real grants, users, policies or resources were deleted. Desktop
  English/light and compact Chinese/dark checks verified selection and review,
  no page-wide overflow at 360 x 780, bounded dialogs and visible footer
  actions. Back/Forward retained the selected user and full-reload sign-in
  preserved its query ID. Browser warning/error inspection after that final
  journey returned no entries. Header title and service navigation correctly
  identify the create-group workflow.
  Role creation now uses the four-step bookmarkable `create-role` route. It
  reuses public Wizard, Transfer, TagEditor, Select and Dialog controls and
  shared role-configuration fields. Trust, metadata, settings, attached-policy deltas and boundaries
  have isolated ownership. Role name and carrier are immutable; new roles
  receive no default grants. Boundary review shows the prior and proposed
  references and affected identity; policy details distinguish boundary use
  from permission grants and protect both from deletion. Read-only principals
  cannot enter mutating role workspaces or the creation workflow.
  Pure-domain tests cover explicit account trust plus an exact `iam:assumeRole`
  grant, caller boundary restrictions, known workload principals, enabled
  provider/mapping requirements, atomic invalid-input rejection, immutable
  session expiry, current policy/boundary versions, deleted identities and
  individual revocation. Request condition time cannot extend a session.
  Interaction tests cover role creation, locale-preserved validation, draft
  cancellation, before/after account and provider trust review, reviewed policy
  and boundary changes, exact cross-links and preview session creation/revocation
  without changing the current login. Failed creation, metadata, trust, policy
  add/remove, boundary set/remove, settings, session create/revoke and role delete
  commands retain the relevant draft/review and the original workspace state.
  Retry changes only the owned fields. A pending metadata write proves duplicate
  and Escape dismissal prevention until the write settles. Local trust validation
  rejects an empty set before review; equivalent reordered sets cannot submit.
  The shared workspace dialog focuses the localized error and retains recovery
  controls. The public dialog includes native disclosures in its keyboard order.
  The local browser journey created a synthetic account-trusted role with a
  separate log boundary. Trust alone produced caller denial; attaching an exact
  assumption policy to the selected synthetic user allowed a preview session.
  Its log-search result identified only the role grant and boundary, not caller
  policies. Revocation then rejected the same session. The current login stayed
  preview-admin; no real credentials were issued. Chinese/dark and English/light
  checks covered desktop and 360 x 780 layouts. The compact boundary dialog
  measured 344px inside a 360px page with wrapping copy and visible actions.
  A complete reload cleared the session-only test role, policy and session;
  their old entity URL correctly showed unavailable instead of another role.
  The final role-list/new-role journey returned no browser warning/error logs;
  the preview was restored to Chinese/dark. No Tencent objects or real grants
  were created, changed or deleted, and scan,
  payment and live security flows remained skipped.
  A separate local trust-edit journey verified empty-selection focus, explicit
  lin removal/chen addition, both complete JSON documents, and cancellation
  without a change. English/light confirmation changed only the synthetic role's
  trusted user; empty grants, no boundary and the 60-minute settings remained.
  Chinese/dark and English/light checks at 360 x 800 measured a 344px dialog
  inside a 360px page, with code-local sizing and footer actions fully in view.
  Keyboard Shift+Tab from the document disclosure reached the preceding control
  rather than jumping to Save. A full reload cleared the test-only role; the
  original two role fixtures remained. The restored Chinese/dark role directory
  returned no browser warning/error entries, and no Tencent data was touched.
  A shared public unsaved-changes boundary now protects the user, group, policy
  and role content workflows. Eight component tests cover exact-once leave
  actions, save-in-flight handling, retry after interrupted traversal, native
  listener lifetime, language updates, forced unmount and focus return after a
  source popup closes. A Profiler assertion verifies dirty-field input and
  confirmation state do not commit the unrelated header. Navigation tests
  prove confirmation precedes the pending state, preserve replace/scroll and
  modified-click semantics, and delay accepted-visit callbacks. Four IAM
  workflow cases retain their distinct unsaved fields, including invalid raw
  policy JSON, with no partial command writes.
  The local browser journey verified sidebar, product-directory and search
  leave requests, native Back cancellation/resumption and Forward without
  manufactured history entries, plus sign-out cancellation and confirmation.
  Cancelled service navigation did not increment recently visited services.
  Read-only refresh, appearance and locale changes retained the selected role
  principal. English/light at 360 x 800 had a bounded confirmation, wrapping
  copy and visible actions; Chinese/dark and the default viewport were restored.
  Warning/error log inspection returned no entries. Browser-forced or unsupported
  non-cancellable traversal and mobile process termination retain the limitations
  specified above; no draft storage or real credentials were added.
  Supporting-workspace regression adds sixteen cases: six action-classification
  cases and ten UI cases covering exact overview destinations, non-assessment
  security guidance, direct/group directory filters, localized policy metadata,
  SAML/OIDC format errors and retained retries, key-state cancellation/deletion,
  and isolated settings/SSO retries. Empty groups and boundaries alone are not
  displayed as grants. Existing enterprise tests prove visibility-constrained
  ungranted import, reference protection and session reset; report tests retain
  allowlisted fields without credentials or raw provider metadata.
  The browser verified overview-to-policy navigation and Back, matching user
  association details, provider validation focus and preserved inputs, and
  localized shared controls. At 360 x 800, Chinese/dark and English/light provider
  dialogs measured 344px wide within a 360px page, with the footer below 800px.
  Cancel returned focus to Create provider. Only synthetic provider data was
  saved. A user-SSO save preserved the current identity and remained visibly
  MOCK. Enterprise import exposed only the selected visible member, then the
  user directory showed the imported user without granting policies. Key owner
  choices excluded the primary account; closing its one-time window removed
  the nonfunctional value from the DOM. Settings explicitly disclaimed real
  MFA/password enforcement/session revocation. Browser warning/error inspection
  returned no entries. Metadata code scrolling is labelled and keyboard-focusable.
  A full reload removed the acceptance-only provider, enterprise member and key;
  the restored Chinese/dark overview showed the original two users, two groups,
  two roles and one provider. User SSO was disabled again, and the overview
  showed the single initial mock key. No reference-cloud state was changed.
  AppearanceProvider, LogServiceRenderer, Wizard and the SAML provider test still
  emit React act/suspension warnings despite passing; these test-harness warnings
  are not browser errors and are not silently suppressed.
  The documented CAM UX/MOCK subset has local functional acceptance. All
  authorization/session results remain diagnostics over synthetic data, not a
  production IAM or STS implementation or an accepted platform release.
  The separately documented slow-CPU performance work remains paused as requested.
  Browser verification opens every IAM workspace with no new console errors;
  group creation updates user-detail inheritance without another navigation
  reset. The content-boundary regression proves Header open/close does not
  invalidate the business renderer while region and locale updates still do;
  the IAM capability regression preserves permission changes without reacting
  to unrelated mutation pending state. Deferred-read Dialog tests prove opening,
  dismissing, failure and retry independently of data readiness. A 2,500-option
  Transfer test proves bounded available rows, full-collection search and
  retained off-page selection. Seven Transfer regressions cover atomic page
  selection, keyboard/mixed states, filtered page deselection, unavailable rows,
  capacity feedback and repeated filter resets. The user-wizard integration
  adds 42 custom policies, selects 20 on one page, reaches the separate 30-policy
  cap on the next, clears only that page, and retains group choices and locale
  changes without submitting a mutation. Broad-grant warnings are covered by
  the existing end-to-end mock creation test. Browser checks at 1468px desktop
  and 390/360px compact widths verify the native table, full narrow-screen
  names, bounded scrolling, retained selected panel, light/mixed/dark surfaces
  and English/Chinese controls. The 360px English table and page have no horizontal
  overflow after replacing decorative type badges with compact metadata text.
  A full reload removes stale development HMR CSS/old-prop errors; the repeated
  selector journey creates no new browser warnings or errors. No real user or
  policy association was submitted on either console. Policy parsing is cached by document text;
  collapsed message details and their destination links are not mounted.
  Wizard tests cover explicit access methods, permission selection, preview
  creation, the live fixed-role contract and access-only dirty-draft cancellation.
  Mobile browser checks verify the compact stepper and non-overflowing permission
  hints. Policy-wizard scroll checks at 2560 x 1271, 1468 x 866 and 360 x 800
  verify the footer reaches the viewport bottom with no exposed fields beneath
  it, including mid-scroll and the end of the form. At 360px all three action
  buttons remain on one row; submitting the empty policy name focuses its
  visible error above the footer without page-wide horizontal overflow.
  The shared Wizard/Steps/Transfer boundaries own that repeated interaction.
  Production MOCK checks at `1440 × 900px` measured representative Header
  click processing at 12–63ms and Event Timing durations at 40–112ms without CPU
  throttling. These are local observations, not a field-performance guarantee.
  The product directory still fails the slow-CPU target: a 4x-throttled production
  trace on the IAM roles page measured about 1,052ms interaction latency, including
  substantial first-mount style/layout work. The eager feature graph and first
  directory mount remain performance acceptance work; functionality passing is
  not a claim that all components now meet the responsiveness target.
  Production preview network checks confirm ordinary and dynamic segment
  prefetch returns 200 after normalization, with no console errors during the
  checked navigation and Header interactions. Go HTTP tests independently prove
  those segment payloads survive embedding. A `390 × 844px` production check
  verifies bounded Header panels, catalog search focus/background isolation,
  repeated trigger closure and lazily mounted message details.
  Chinese/dark and English/light checks include grouped navigation,
  immediate skeleton transitions, compact dialogs with retained action
  footers, Escape focus restoration and no horizontal page overflow down to
  a measured `319px` CSS viewport. Overview mini-tables fit their cards.
  Locale tests additionally preserve installation/alias drafts, safe IAM
  errors, operation filters and expanded details without another resource read.
  They verify explicit grants, native ID validation, quota quantity bounds,
  numeric health metrics, raw lifecycle states and safe timestamp formatting.
  Browser checks cover deep-navy and light surfaces, Chinese/English shell
  controls, menus, radio choices, search navigation/reopening, IAM management,
  Dashboard, resource/region views, operations, DevOps and monitoring. At
  `1440 × 900px`, metrics and service tables share density and status colors;
  at `840 × 600px`, collection tables scroll internally; at `360 × 600px`,
  named workflow actions remain visible, instance lists precede their forms,
  reopening retains the installation draft, and health/detail layouts stack
  without horizontal page overflow. Table cells retain a readable minimum
  width instead of compressing names character by character. IAM's `600px`
  desktop and `344px` compact dialogs have bounded scrolling, a visible action
  footer, native modal isolation, title focus, Tab containment, password-reset
  focus, Escape return and suppression of global search shortcuts. Directory
  keyword clear restores focus, blank clicks/Escape keep it open, and X or a
  repeated Header-trigger click closes it and restores trigger focus. Desktop
  and `360px` browser checks also verify repeated open/close cycles with no
  runtime errors; selecting a service loads its own navigation. Region-trigger
  checks at `1133px` and `360px` confirm transparent resting borders/background,
  retained selection, visible keyboard-focus return and no horizontal overflow.
  Header badges
  reflect unread messages independently of firing alerts and running tasks. A fresh Go
  static-server session switches theme/language and retains a dummy account
  draft without CSP or hydration errors; its production login has no MOCK
  entry. This is current frontend/static-host acceptance, not a new installed
  backend release or a claim to translate user-authored resource names.
  Navigation tests cover real suspended transitions, interrupted destinations,
  immediate hiding of the outgoing draft, cancellation recovery, committed-page
  scroll isolation, and five non-interactive skeleton layouts. Browser checks
  at `1133px` and `360px` confirm immediate target titles, fully visible skeletons,
  hidden outgoing controls, and no horizontal page overflow for menu and search
  navigation. A temporary loopback-only delayed-response preview exercised long
  route waits; the normal development route was also verified without that
  delay. The temporary preview was removed. All animation styling remains
  theme-owned; reduced-motion behavior is defined in the shared controls.
  Message tests distinguish unread counts from firing alerts and active tasks,
  share reading state between popup and full page, preserve expanded unread
  details, and prove session reset and unavailable live data. The Header has
  one bell; Dashboard discovery uses the single full-viewport directory.
  Shared Select tests cover labelled listbox semantics, selected focus,
  disabled choices/controls, keyboard typeahead, Escape, outside focus, form
  validation, empty values, reset and portal ownership. Browser checks at
  `1133px` and `360 × 600px` verified dark/light option surfaces, retained
  filters, bounded menus, the compact message filter and full-page text
  choices. In a native IAM dialog, the role list flips upward when needed and
  Escape closes only the list, restoring its trigger. No IAM mutation was
  performed for these component checks. A development CSS hot-update cache
  error cleared after reload; the refreshed interaction checks produced no
  new runtime errors. Production assets are verified separately from HMR.
- The branded login slice uses the approved full-size horizontal signature on
  desktop and a compact lockup on mobile, with no abstract decorative diagram.
  The signature is byte-identical to the approved local brand kit and its
  source asset participates in the deterministic build ID. Application-level
  dark/light/system themes and Chinese/English messages are integrated with
  shared Brand, PasswordInput, FormField, Alert, Tabs and SelectionMenu
  components. Development-browser inspection at `1440 × 900px` verified
  the `480px` proportional signature and `44px` inputs; `360 × 600px` inspection
  verified English and qualified IAM login, one visible compact brand, bounded
  preference menus and no horizontal page overflow. A real local Go static
  server served the production build without a MOCK entry; theme and language
  radio menus worked under the unchanged CSP, preferences survived reload,
  changing language retained a keyboard-entered account draft, and the browser
  reported no CSP or hydration errors. One-click MOCK entry also reached the
  themed console with the shared compact Header brand. This is frontend and
  static-host evidence, not a new installed backend release acceptance.
- Gate A implementation replaces the Phase 1 page with the complete donor-
  shaped App Router -> route -> provider -> repository -> scene -> renderer ->
  public-component chain, twelve static routes, memory-only IAM sessions,
  deterministic Go embedding, strict CSP hashes, and a four-region shell.
  The console layout retains its provider across child-route navigation.
  Source gates cover the light theme, 20 semantic contrast pairs, and 80
  frontend tests, including visible failed revocation, logout during failed
  or pending resource loads, keyboard workspace sizing, and native instance-ID
  validation. Application commit
  `29821adb012535d525d1ba274aff03143bc3c11c` produced the signed candidate
  `matrix-v1.8.0-29821adb0125` with manifest SHA-256
  `93bcd8dc15d66c83486d833922a0fdeb225d3093aa49a8a8a468cbc8c3bcc1e6`.
  It installed to `READY` in a fresh external-network-disabled Docker
  namespace and passed post-journey platform verification. Its real IAM browser
  session completed login, client-side catalog/quota/installation transitions,
  one development-shape quota activation, and one PostgreSQL installation from
  queued state to a running endpoint before logout revoked the session. The
  `360px` browser target yielded a narrower `319px` effective content viewport:
  the shell and access route had no page-level horizontal overflow, the service
  table owned its horizontal scroll, and both compact drawers contained and
  restored keyboard focus. Direct anonymous entry after logout rendered only
  the login surface with an empty password field and no console navigation.
- The tenant-account UI adds an independently loadable `/console/access/`
  route with user, permissions, user-settings, and bootstrap-only tenant
  management views. One qualified child-login field replaces a tenant selector;
  current account ownership and operator identity are displayed separately.
  Creation defaults to no role, every subsequent grant requires an explicit
  role selection, and disable/revoke/reset actions use real IAM contracts.
  Source, type, lint, architecture, contrast, component, and HTTP-adapter gates
  cover these changes. A desktop browser against the real IAM/PostgreSQL test
  instance completed primary login, no-role child creation, qualified child
  login and mandatory first password change, live role refresh, independent
  alias modification, old-alias rejection/new-alias login, disable/session
  invalidation, and logout after server-side revocation. The same browser
  verified that IAM remains navigable when the PaaS upstream is unavailable.
  Browser inspection informed the explicit-choice grant default. This is a
  development-runtime IAM gate, not the installed-release PaaS purchase/deploy
  journey. Compact development-browser inspection additionally proves a
  single-row horizontally browsable tablist, fixed refresh control, deliberate
  card-header action stacking, no page overflow, and arrow/`Home`/`End` focus
  movement at a viewport narrower than `360px`. Authenticated installed-release
  evidence from the `29821ad` candidate separately proves the same four-tab
  semantic navigation, arrow-key selection/focus, account-menu entry, and no
  page overflow at the `360px` browser target. Backend account and isolation
  evidence belongs to FEAT-006.
- The unified-cloud UX preview replaces the provisional console composition
  with the dimensioned shell and interaction contract above. It adds product
  and service discovery, a cross-product Resource Center, global region scope,
  searchable resources and pages, an Operation center, a
  notification center, DevOps delivery state, and observability health and
  alert views. Browser verification at the development runtime completed the
  one-click entry, product launcher, global search, direct product navigation,
  notification panel, region-scoped resource filtering, and the `390px`
  navigation drawer. A separate `360px` inspection proved the open drawer and
  resource workspace match the viewport width without page-level horizontal
  overflow. The brand-aligned `ConsoleHeader` now owns the global control
  composition and exclusive popup state; `GlobalSearch` owns search and its
  keyboard interaction. `RegionSwitcher` uses one shared popup and one option
  list for desktop and compact layouts. The global project selector, project
  filter state, and combined compact picker have been removed; resource
  ownership metadata is retained. Development-browser checks from `1440px`
  down to `360px` proved region selection, region-filtered resources, Escape
  focus return, and no page overflow. An open popup remained usable while
  resizing desktop-to-mobile-to-desktop. One-click entry reached the Dashboard
  with common products, recent resources, alerts, and running tasks. Component
  tests additionally prove primary-account and IAM-user default Dashboard
  entry, explicit requested-route return, and the mandatory first-password
  gate before either destination. Search arrow keys and Enter
  were exercised against the same development runtime. Regression tests and
  browser checks prove that pointer selection, keyboard navigation, and Escape
  all allow an already-focused search input to reopen on its next click;
  repeated clicks keep the list open without another navigation. The `1120px`, `840px`,
  and `720px` breakpoint edges were also checked for header overflow; mobile
  empty search, account-menu keyboard navigation, and notifications remained
  reachable at a `360 × 600px` viewport. The frontend and static-host gates
  reported above cover the current header slice.
  The shared frontend gates cover the directory slice, and Go static-host
  tests cover every new service
  subroute. The directory, search, favorites, Dashboard cards and local menus
  now share the service registry; feature-only entries for environments and
  alerts are removed from the global list. Application hosting has its own
  resource view; PostgreSQL retains its real quota/installation workflow.
  DevOps and Monitoring expose deep-linked local pages. Log Service is an
  explicitly labelled MOCK workspace with region-scoped overview, topic and
  collection pages, keyword/topic/severity filtering, and expandable event
  fields. Fixed sample timestamps never imply live collection. Browser checks
  at 1440px, 840px and 360px confirm full-viewport discovery, no page horizontal
  overflow, retained search while resizing, trigger/X closure, and inert
  background controls. Chinese/English and dark/light checks cover the new
  directory and logs workspace. The MOCK deep link returns to log search after
  sign-in; keyword search and expandable event fields work in the runtime.
  Product discovery and notifications now use independently
  tested `ProductLauncher` and `NotificationCenter` composites over one shared
  header-popover surface. Notifications restore focus on `Escape`; the service
  directory follows the trigger-or-X modal dismissal contract above. Principal
  identity and logout live in one global header
  `AccountMenu` composite instead of being duplicated in product-local
  navigation. Its grouped icon, label, description, separator, and danger-state
  rows have semantic menu behavior and keyboard focus management. The PaaS
  journey also activated a MOCK quota, submitted an
  installation, showed its pending Operation, and resolved it to a stable
  endpoint. Installation rows now derive one engine/version label from
  authoritative engine fields instead of duplicating a version already present
  in an offering display name, and workspace toggles expose the actual quota,
  installation, or platform-status task. Operation history now has searchable
  and status-filtered collection controls plus keyboard-native details instead
  of a static feed. Component tests cover requested-route return,
  global-header and compact-drawer focus, search keyboard navigation, scope
  filtering, route projection, and a mutable in-memory installation journey.
  This explicitly labelled MOCK evidence validates future-product IA and
  interaction only. The separate installed `29821ad` journey proves current
  real IAM, quota, installation, and runtime integration; MOCK data does not
  substitute for those backend authorities.
- Gate B authority is complete for the admitted PostgreSQL slice: the closed
  managed-service Go/OpenAPI contract now includes collection and single-
  resource reads for offerings, regions, quota entitlements, service
  installations, and installation Operations. Existing-role IAM actions,
  forced organization RLS, serializable quota reservation, idempotent replay,
  worker leases, fencing transitions, and transactionally coupled Audit facts
  pass unit and real PostgreSQL 18 tests. The installed `44fa1c7` candidate
  completed real IAM-authorized single-resource reads, quota and installation
  equal replay, changed-request rejection, unsupported-offering rejection,
  exhausted-quota rejection, and revoked-session rejection. Resource and
  Operation reads retained their identities across platform lifecycle changes.
  The UI polls only active installation resources and reloads quota truth once
  an Operation becomes terminal.
- Gate C execution is complete through the fixed PostgreSQL 18 image:
  server-generated file credentials, pull-never/no-build Compose, exact
  ownership labels, persistent bind data, bounded resources, normalized
  endpoint/credential references, retry, terminal quota release, and
  uncertain-create reconciliation. Signed runtime source
  `44fa1c7bb4cd20f2f807e12ec1e8a753b65688b3` produced Release A
  `matrix-v1.5.0-44fa1c7bb4cd` and Release B `matrix-v1.6.0-44fa1c7bb4cd`.
  An empty, external-network-disabled Docker namespace installed A, resumed a
  durable managed-service request after worker restart, and completed failed-
  upgrade automatic rollback, successful upgrade, explicit N-1 rollback,
  protected platform backup/recovery, and sanitized support evidence. A second
  PostgreSQL installation created after the first backup made that old backup
  ineligible: recovery returned normalized `PRECONDITION_FAILED` without
  changing either installation, quota, or database. A new backup containing
  both installations completed the remaining lifecycle. The installations
  retained their endpoints, credential references, consumed quotas, Audit
  facts, and pre- and post-upgrade probe rows. The unified lifecycle passed in
  351.20 seconds. Whole-engine restart followed by authenticated SQL reads of
  both databases and repeated status/verify passed in 26.45 seconds. This proves
  in-place preservation, not managed-database backup or cross-host migration.

The authenticated candidate identities are:

| Release | Manifest SHA-256 |
| --- | --- |
| `matrix-v1.5.0-44fa1c7bb4cd` | `bb05294f217729b6af88c1d14c3b212808ce6176c3e72d2944d570f1cdbedc79` |
| `matrix-v1.6.0-44fa1c7bb4cd` | `b1337fcd38e6bdf08249c315829e81e908f3c8c1dd38fd576a236600776f3ef3` |

The clean pushed `44fa1c7` runtime source passed `go generate ./api/...`, module
verification, full unit, vet and race suites, Linux local-machine tests,
20 repeated backup/recovery checks, and five repeated provisioner/inventory
checks. Clean PostgreSQL 18 managed-service tenant isolation, application
hosting, IAM HTTP, and Audit HTTP integration passed inside the isolated Docker
host. The release-owned PostgreSQL artifact used a separate disposable cluster
with loopback-only SCRAM authentication for those tests. Linux amd64 release
builds, all UI type/lint/architecture/style/test/embed gates, Markdown links,
donor-dependency and social-term scans, and `git diff --check` passed. Frontend
source and the fixed-donor adoption decisions are unchanged by this recovery
slice.

The former Phase 1-only release test owner is now
`app/service/installation/test/releasee2e`. Its one platform journey includes
the application and managed-PostgreSQL checks; PostgreSQL probes use the
release-owned client with passwords on standard input, not an installation
dependency or a credential-bearing command argument. Restart checks wait for
bounded platform readiness before asserting stable status and verification.
Linux behavior tests additionally prove that a backup is not published if its
managed-service inventory changes during the dump; recovery refuses inventory
drift before effects and again after stopping writers; an authenticated backup
without the required witness is rejected; and replay cannot replace the
original backup's witness. Provider inventory failures remain normalized and
do not expose native details.

The account slice was verified only in the disposable signed candidate
installation; an operator upgrade must continue to move its IAM and Audit
schemas and binaries together. No permission application/approval or expiring-
grant UI is implemented.

Gate A authenticated installed-release browser acceptance is closed by the
`29821ad` candidate: real IAM login/logout, client-side route transitions, real
quota and installation mutations, semantic keyboard interactions, compact
focus management, and narrower-than-`360px` layouts all passed before a final
platform `VERIFY` returned `READY`. API, source, component, MOCK, or anonymous-
page checks were not used as substitutes for that browser evidence. The
unchanged platform lifecycle and recovery evidence remains owned by Gate C.

## Deferred

Money movement, invoices, tax, discounts, metering-based billing, marketplace
publishing, MySQL, ELK, Redis, arbitrary Helm/Compose templates, customer
images, public-cloud accounts, VM/network provisioning, Kubernetes,
multi-region placement, high availability, read replicas, point-in-time
restore, engine upgrades, installation deletion, live external IdP/LDAP,
SAML/OIDC authentication, MFA enforcement, corporate-directory integration,
custom-policy authorization and mobile-native applications remain outside
this target. Access-management configuration previews do not implement these
backend security capabilities. Vendor-specific collaboration invitations,
message-only identities and batch account creation are not represented as
supported Matrix IAM contracts.

The product and source dependency boundaries remain owned by
[`ADR-0002`](../architecture/ADR-0002-product-boundary.md) and
[`DEPENDENCY-RULES`](../architecture/DEPENDENCY-RULES.md). Fixed donor
decisions are owned by the
[`FEAT-007 adoption review`](../adoption/FEAT-007-control-plane-console.md).
