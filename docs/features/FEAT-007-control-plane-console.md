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
    provides real tenant-scoped subaccount creation, direct user-policy
    attachments, status, and password reset. Its user-settings section allows an organization
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
    The view separates the resource-owning account identity from the current
    operator. The user directory presents the protected primary identity and
    IAM subusers as different identity types, not independent tenants. Creation
    defaults to no business authorization. Live permission management reads
    current, unretracted direct `USER` policy attachments and separate tenant
    and installation policy directories. It never derives management authority,
    identity type or effective access from a policy or role display name.
    Policy-list metadata is a management snapshot, not policy content, a list
    of affected subjects or an authorization decision. Tenant and installation
    directories are independently authorized: a 403 removes only that section;
    every other failure makes the live scene unavailable without substituting
    preview data. Attach and revoke commands bind exact policy/attachment
    resource versions, and a changed directory version requires reselection.
    The service opens an overview followed by bookmarkable user, group,
    policy, role, role-SSO, user-SSO, federated-account, API-key, login-session,
    user-settings and tenant-management workspaces. These use grouped service-local
    navigation, not another global product menu or a long top-level tab bar.
    Login-session management is intrinsic to the authenticated user and does
    not require user-directory authority. It lists only that user's active
    opaque login sessions, identifies the exact current session, uses normal
    logout for the current session and an idempotent revoke command for another
    session. An unknown revoke outcome retains the original credential,
    caller-session, target-session and request ID only in provider memory so an
    explicit retry cannot create a second intent; a new login clears it. The UI
    never presents a session as a physical device, recent activity, source IP
    or proof of online status, and it explains that ending a login session does
    not delete resources, revoke independent API keys or stop accepted work.
    An optional repository capability supplies the extended MOCK workspace.
    Its account-scoped data is isolated from the live IAM adapter and never
    grants real permissions. The live adapter has no such capability and
    renders an explicit unavailable state instead of inventing success.
    Preview workflows cover group membership and inherited policies; custom
    policy visual/JSON editing, versions and associations; role trust,
    session duration and console access; SAML/OIDC provider configuration,
    role mappings and user SSO; enterprise-directory visibility and member
    import; subuser key creation, status and deletion; password/session
    configuration; and allowlisted credential/security reports. The overview
    presents report evidence before export and distinguishes review,
    configured, not-applicable and unknown states; missing authenticator or
    activity evidence is never projected as false or safe. Referenced
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
    Product authorization definitions are server-owned capability metadata,
    not tenant-managed IAM objects and not grants by themselves. Product teams
    own their declarations from Product management; IAM owns trusted
    validation, immutable publication, revision and digest governance; tenant
    administrators only consume published definitions while authoring and
    attaching policies. The policy editor consumes one exact product-profile
    revision and digest to present stable action keys, declared authorization
    targets, resource shapes and trusted condition sources. A create action's
    optional result resource kind describes the resource produced on success;
    it never replaces the parent, instance or collection resource against
    which IAM authorizes the request. `callingService` constrains the
    authenticated calling service and is not a service role or delegated grant.
    Unavailable or unknown capabilities fail closed and never become wildcard
    access. Publishing a policy fixes the resolved action set, so later catalog
    additions cannot silently expand an existing policy. The isolated MOCK
    adapter may demonstrate this interaction, but the live console must not
    invent a catalog response or expose tenant publish, disable or registration
    controls before IAM owns a fixed query and lifecycle contract. Operators
    reach read-only permission definitions contextually from policy authoring;
    a Product-management publisher workspace is deferred until that authority
    and API exist. This follows the provider-owned permission inventories and
    contextual editors documented by the AWS
    [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html),
    Azure [resource-provider permissions](https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations),
    Google Cloud [custom-role permission selection](https://cloud.google.com/iam/docs/creating-custom-roles),
    and Tencent CAM [policy generator](https://cloud.tencent.com/document/product/598/37739),
    without copying their object models or visual systems.
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

The static host admits only bounded, singleton `id` queries on owned IAM
workspace routes and the four `method` values on policy creation. Invalid UTF-8,
control characters, duplicate values, unknown keys and authority selectors are
rejected. These queries never select different static content or grant API
authority; direct workspace entry preserves the same CSP and offline assets.

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

Table-backed directories use the public `Table.Footer` and `TablePagination`
composition: the page summary stays on the left and page-size plus icon-only
navigation controls stay on the right, including one-page results. A complete
client snapshot may expose its true page count and page size. A server cursor
uses the same visual control but does not invent a total or offer a page-size
choice the backend cannot honor. Selection always applies to the visible page.

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
| Overview | Identity counts link to directories; high-privilege associations, recent sensitive actions, account identity, login links and security guidance are separate blocks. | Keep one evidence-first information flow: counts and recent actions, then an actionable security snapshot, permission principles and high-privilege candidates. The snapshot derives from the same workspace state, keeps exports secondary, and never presents simulated protection as real MFA or a real security assessment. |
| Users | The subuser detail distinguishes access method from permission. The Owner detail exposes group management, while an ungranted user is guided to join a group, copy another user's permissions or attach policies. Adding permissions is a content-area selection/review flow. | Reuse the user wizard and permission selector, but treat the Tencent Owner group affordance as reference only. Matrix projects Account + RootIdentity as a compact owner summary and independent protected detail; only User rows participate in group, grant, credential and lifecycle tasks. Copying permissions must describe precisely which direct bindings or memberships are copied; it never clones passwords, keys, boundaries or role sessions. |
| Groups | Creation is a three-step content page: basic information, policy selection, review. Empty policy selection is allowed. The selector separates available/selected items and states its per-operation limit. | Matrix uses a two-step group-only journey: details, then review. Creation produces an empty group and opens its detail; each member or direct-policy relationship is a separately reviewed command. Group detail explains inherited-grant impact. A group is not a login identity and cannot be assumed. |
| Policy directory | All/preset views show policy name, product, permission category, description, last modified time and authorization action. Custom-only omits product and permission category. Presets cannot be deleted. | Adopt the directory task and compact search/filter hierarchy, but render only fields supplied by the fixed Matrix contract: stable ID, display name, management owner, tenant/installation scope, lifecycle status, default version and updated time. Product, description, permission category, policy content, affected subjects and effective access are not inferred. The bounded complete snapshot is paged only in the client; it is never presented as backend pagination. |
| Policy creation | Entry chooser offers generator, policy syntax, tag authorization, and product-feature/project authorization. The fourth entry carries upgrade guidance toward tags and the generator. Name becomes immutable after creation. | Four entry points share one content-area edit/configure/review draft and save contract. The fourth selects registered Matrix product functions; project permissions are explicitly unavailable. Templates copy into custom policies, never mutate presets. Resource-tag conditions remain distinct from policy metadata tags. |
| Policy editor | Select a service, then read/write/list/other actions, their authorization granularity, all/specific resources, and optional key/operator/value conditions. Structured resource input exposes service, region, owner, type and resource ID. The analyzer separates errors, warnings and suggestions. | Add a code-owned preview capability catalog and structured statement editor. Invalid drafts remain editable; errors block progression, warnings explain broad access. Unsupported syntax cannot be silently dropped when switching modes. |
| Policy detail | Syntax has readable service/resource/condition summary and JSON. Versions and usage are separate tabs; permission associations and boundary uses are separate sections. | Readable effect/action/resource summary, full JSON, bounded versions, exact linked subjects and separate boundary references are implemented. Group links lead to affected members and their named inherited grants. Previewing an old version never activates it. |
| Roles | Customer-managed roles select account users as trusted identities and separate trust, policies, tags and review. Service-owned roles use a distinct lifecycle and mutation boundary rather than accepting a tenant-entered service principal. External IdP principals remain unavailable until IAM publishes a fixed trust contract. | Matrix keeps `CUSTOMER` and `SERVICE_LINKED` roles as different product workflows. Customer-role create/edit accepts only explicit same-account `USER` identities and keeps trust, permission policies, optional boundary and sessions separate. Service access is observed or consented through the service-authorization workflow backed by a trusted template, registered service principal and exact workload binding; it never enters the customer-role editor as a free-form principal. |
| Role and user SSO | Role SSO uses an IdP and a role without mirroring employees as subusers; user SSO enters as an existing subuser. | Keep both routes under Identity providers, not Identity security, while distinguishing their future identity and session paths. IAM currently classifies `IdentityProvider` and `ExternalIdentity` as deferred and publishes no consumable object, mutation, login, mapping or external-trust contract. The console therefore renders only an explicit planned-state architecture, target journey and enablement prerequisites. It contains no provider or external-identity directory, fake record, writable MOCK lifecycle, provider Role principal, successful connection, sign-in or issued session. The current customer-role preview is same-account `USER` only; service-linked access remains a separate service-authorization workflow. |
| Enterprise accounts | The current entry requires an enterprise administrator to scan and activate it. | Reference activation was skipped without clicking activate. Matrix's existing synthetic member-import demonstration remains explicitly MOCK; it is not evidence of a tested Tencent import or a connected corporate directory. |
| Access keys and settings | Key entry warns against Root long-lived keys and states that Secret material is only shown after an applied creation. Settings group account, login and security concerns without absorbing credential lifecycle. | Keep AccessKey management User-scoped and explicitly MOCK: one-time Secret acknowledgement, versioned state changes, disabled-before-delete and unknown-result recovery remain distinct. Resource versions and idempotency identifiers remain command/recovery inputs instead of dominating the normal directory, detail or review hierarchy; an operation reference appears only when an uncertain result must be recovered. A carrier declaration links to the same User's permission-source inspection as the next task, but never presents that configuration review as a request-time permit. Reference key issuance, external workload verification, real security mutations and enrollment were not performed. |

The preview security snapshot follows the useful parts of AWS's
[credential-report value semantics](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html)
and Google Cloud's
[review-before-apply recommendation workflow](https://docs.cloud.google.com/recommender/docs/use-api),
without copying their product model. Matrix additionally requires an explicit
`unknown` state because the current IAM contract does not expose authenticator
enrollment, complete credential activity or a report collection watermark.
`Not applicable` is reserved for a control that truly does not apply to the
identity or credential carrier. This preview contract is aligned with
`63ad9fd6cfb29525fcf6a51bc652e791adc49fc5:IAM/FEAT-IAM-009-security-governance.md`
S4; it does not invent that document's pending report API, score risk, infer
effective access or automatically apply a recommendation.

#### MFA and self-session experience contract

The console may prototype the security experience before the IAM HTTP surface is
available, but it must not make an unimplemented protection look active. The
high-fidelity MFA preview follows the fixed S2/S3 design in
`6fa39fda:IAM/FEAT-IAM-009-security-governance.md` and the notification-address
clarification in `04041d2d3f7ed55225a5164bc2bc05251d25a6f1`. It does not import
those commits as a runtime dependency and does not claim that their private
keyring work exposes a usable MFA API.

The accepted password-only login and self-session milestones explicitly do
not cover MFA. Production MFA interaction remains owned by IAM-009's future
fixed public contract and its own real-browser acceptance; an in-progress
backend implementation or its CI status is not inherited as console evidence.

- Password success enters a challenge or restricted enrollment state without
  creating a normal login session. Only a fresh, unused authenticator code may
  complete login. A forced password change invalidates the old challenge and
  requires a new login attempt.
- First binding and lawful post-removal binding share a guided setup, but lost
  factor recovery never falls back to that path. A recovery code opens only a
  restricted rebind flow and never signs the user in. Installation recovery or
  missing recovery material remains unavailable rather than becoming an admin
  reset button.
- Replacement keeps the existing factor valid until the new factor is
  confirmed. Removal requires current policy to permit it plus fresh strong
  reauthentication. Recovery-code regeneration also requires strong
  reauthentication, invalidates the old batch, and shows the new batch once.
- Sensitive-operation proof is operation-, target-, version- and input-bound,
  short-lived and single-use. The preview must not present a reusable elevated
  session or imply additional IAM authority.
- When IAM proves a sessionless first-enrollment state but no trusted security
  notification address exists, the future flow must enter restricted address
  verification before authenticator setup. With no real delivery contract the
  step is unavailable and no session is issued. Email is security notification,
  not an MFA or password-recovery factor; the preview contains no fake send form.
- Demo codes, QR cells and recovery material are deliberately nonfunctional and
  page-local. They are not persisted in browser storage, returned after their
  one-time view, or sent to IAM. The settings page separates personal factor
  management from the account-wide `requiredForUsers` policy and labels
  unavailable delivery dependencies explicitly.

The interaction shape is consistent with Tencent CAM's documented next-login
MFA setup and virtual-MFA protection, AWS IAM's explicit virtual-device
registration, and Microsoft Entra's guided security-info registration:
the stable page shell renders immediately, only data-dependent regions load,
and setup requires explicit verification before activation. Reference sources:
[Tencent CAM identity security](https://cloud.tencent.com/document/product/598/73859),
[Tencent virtual MFA](https://cloud.tencent.com/document/product/598/117845),
[AWS virtual MFA](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html),
and [Microsoft combined registration](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-registration-mfa-sspr-combined).

The fixed self-session contract additionally exposes
`POST /v1/auth/sessions:revoke-others`. The console sends only the retained
`requestId`, verifies the complete account/user/current-session receipt, keeps
the current session, and reports the actual atomic revocation count. Unknown
outcomes retain and replay the exact original intent; they never create a
second bulk operation. Confirmation is shown inline in the content area so the
page title and action positions remain stable on desktop and compact layouts.

Acceptance evidence on 2026-09-20: 574 frontend tests and three export-
normalization tests passed, along with type checking, lint, architecture and
style checks (228 theme contrast pairs), 39-page production static generation,
217-file embedded-export equivalence, and the Go UI-host tests. Browser checks
covered the normal viewport and a 390 x 844 compact viewport for challenge,
sessionless first setup, QR/manual setup, personal security cards, compact page
actions and inline bulk-session confirmation. Browser warning/error inspection
was empty. The identity-security snapshot additionally passed a `360 x 800`
check with `clientWidth == scrollWidth == 360`; its export menu returned focus
to the trigger on `Escape`, and the evidence links navigated directly to their
owning IAM pages. This evidence accepts only the MOCK UX plus the fixed self-
session adapter; it is not evidence of a usable backend MFA, credential-report
or email-delivery API.

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
- Policy association changes use the same content-area workflow shell as other
  multi-step IAM work: select -> review -> confirm. The page header owns return
  navigation, the shared Wizard owns progress and sticky actions, and only short
  discard/error confirmations may use a dialog. Review names additions/removals
  and explains remaining group grants. Batch attachment is bounded, additive and
  atomic; it never replaces unrelated bindings.
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

The isolated current-access diagnosis is an explanation preview, not a login,
authorization switch, `Decision`, permit or proof that a resource exists. It
accepts only predefined synthetic scenarios; the browser cannot nominate an
arbitrary real subject, claim a product resource or manufacture trusted
network/time context. Fixed identity, Action, resource and provenance facts
render before the operator requests an explanation. The result then separates
identity-policy evidence, an optional permission boundary, SessionPolicy and
the unobserved product-execution boundary. Even an `ALLOWED` sample cannot
authorize an operation, be cached as authority or replace the current session.
Unknown or cross-tenant fixture resources are rejected before wildcard
evaluation. A future live diagnosis must be mediated by the owning product
service, carry its real request/resource context to the single IAM PDP and
remain non-authoritative. Enforcement still belongs to every owning backend's
read, list and mutation path; a hidden button, route guard or browser diagnosis
is not a security boundary. FEAT-006's closed live role/action contract remains
unchanged by this UX work.

#### Fixed IAM console contract

The live IAM contract, per-slice implementation status and acceptance belong to
[FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md); fixed source decisions belong
to the [adoption review](../adoption/FEAT-007-control-plane-console.md).
This FEAT owns the shared shell, navigation, visual system and isolated MOCK
experience. Its UX evidence does not accept an unintegrated live IAM runtime.

#### CAM implementation slices and acceptance

The scenario-driven preview uses the same pages and repository boundary as
future fixed-contract integration; its one-click DEV entry remains available
for ongoing UX review. Backend candidates without a fixed, accepted revision
are not integration evidence and never cause automatic fallback to MOCK.

The independent explanation slice uses a coherent six-scenario set covering
an ungranted console User, duplicate direct/group sources, resource-path and
resource-tag conditions, a matching explicit deny and permission-boundary
intersection. Examples select complete input fixtures; they never alter
associations or carry a canned result. Each run resolves the current isolated
workspace snapshot. Changing the scenario removes the prior explanation so a
stale result cannot be displayed beside new evidence.

The request region renders stable facts and their provenance immediately.
Only the local result region appears after the explicit action and receives
focus. Its information architecture follows the fixed current-access diagnosis
contract: the result is only `ALLOWED` or `DENIED`; denial uses the closed reason
codes; sources contain matched direct, group, Role or service-role associations
only; and user, Role and session restrictions are distinct ceiling layers. The
page never exposes unmatched statements, policy documents or actual condition
values as server evidence. An incomplete or indeterminate local result becomes
`UNAVAILABLE` instead of being disguised as `DENIED`. Resource existence and
business outcome remain explicitly `NOT_EVALUATED`. The LIVE route has no local
evaluator, no fallback and no submit action before the fixed backend dependency
is integrated; it renders `LIVE · NOT_CONNECTED` instead.

Overview shortcuts identify the exact referenced policy. High-privilege review
uses allowed permission-management actions from the closed catalog, including
service wildcards and specific actions, in the current default version. The
same content classification owns editor, detail and role-creation warnings.
This is a review candidate, not an effective-access verdict: resource scope,
conditions, explicit denies and boundaries still apply. User review counts
include direct and inherited candidates once per user. The identity-security
snapshot replaces the former duplicate guidance/download cards with one main-
column evidence flow: active long-lived keys, direct User grants, sign-in and
sensitive-operation policy settings, pending password changes and unavailable
MFA enrollment evidence. Every item links to its owning page when one exists;
exports remain a secondary menu. Review, configured, not-applicable and
unknown are separate states. Empty groups are not evidence of distributed
permissions, zero active keys do not complete a security assessment, and a
saved MOCK protection policy does not prove real MFA enrollment.
The MOCK user directory displays and filters direct/group policy associations;
the live directory displays only the fixed IAM contract's direct policy
attachments. Empty-group membership and a boundary alone are not grants. A
directory management action opens the same user detail. Role trust, sessions,
group inheritance and effective-access explanation remain explicit preview
workspaces until their own fixed live contracts are accepted; no live
platform-role projection or role-name inference remains.

The MOCK user-settings page presents an isolated password-rule design flow.
It labels proposed defaults as neither loaded nor effective account settings;
the operator can edit only an in-memory sample, review it, inspect denial,
stale-version and unknown-result designs, and compare ordinary, forced-change,
restricted-challenge and protected-identity new-password scenarios. The
scenario card now labels its source as an unpersisted draft or proposed sample,
never the current Account configuration or a User's actual requirement. Its
collapsed historical-completion explanation shows that an omitted password
section remains unavailable rather than being reconstructed from a draft or
newer configuration; ending the original caller Session does not end a later
authenticated Session. It does
not send or save a password setting, claim a successful change, or derive an
IAM permit. Protected identities retain the fixed product floor regardless of
the sample Account draft. The actual account policy and password-change
requirements must come from IAM-009's accepted, versioned contract; the
frontend does not synthesize that response from preview values. Tencent CAM's
[password-rule page](https://cloud.tencent.com/document/product/598/36249)
and AWS IAM's [account password policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html)
inform the information hierarchy, not Matrix's field limits or enforcement
semantics. The preview does not invent password expiry or lockout controls.
The policy author's statement rows are keyed and memoized with stable draft
commands, so editing one statement does not render every unchanged sibling.
At the development runtime the revised preview was inspected in the 4317
one-click MOCK at desktop and a 390px mobile viewport, including the expanded
historical-completion explanation; the document width stayed 390px without
page-level horizontal overflow. The full 45-file/792-case frontend run passed
with a 20-second test ceiling, including sample-only editing, invalid bounds,
review, protected identity, historical-result omission and unconfirmed-outcome
copy. Type, lint, architecture, 228 contrast pairs, 41-page static export,
228-file Go embed equality, three normalization cases and full Go test/vet
passed. This remains preview evidence, not IAM password-governance backend
acceptance.

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
actions. Read-only data revalidation preserves the mounted draft and is
not misrepresented as a discard. Confirmation precedes the destination frame,
router transition and regional loading feedback.
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
the action picker. Each operation row sizes to its name, identifier, description
and granularity inside one bounded scrolling list; filtering many operations must
never compress row tracks until adjacent content overlaps. These are explicit
Matrix preview contracts, not rules inferred from Create/List/Describe names or
a copy of Tencent product capabilities.
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

Group creation is a two-step content-area draft: name/description, then review.
It creates only an empty group and opens its detail; it cannot add members or
attach policies in the same request. Metadata, membership and direct-policy
changes are separate commands that each change only their owned fields. The
confirmed relationship-integration target changes one member or policy attachment at
a time, with an independent request intent; the UI must not present several
requests as an atomic batch. Selection uses the public Transfer control with a
one-item limit, preserves an editable choice through review and never
preselects a grant. Each change shows the selected object and affected members
before saving; cancellation or failure preserves that exact pending choice.
Removing a direct grant or membership does not imply all access is revoked when
another source still grants it.
The reusable group directory and detail consume normalized presentation records
and actor-relative action controls. Preview owns its local-record mapping; the
live adapter will own the fixed wire mapping and must not leak transport fields
into the presentation component. A member-count column is rendered only when
the repository supplies an authoritative total. The first live slice omits it
rather than reading every membership page or presenting the loaded page size as
a total; the isolated Preview may show its known complete local sample count.
The first live membership projection treats the stable user identifier as its
authoritative label. A same-account, exact-ID user summary already held by the
directory may enhance it, but a missing summary neither proves deletion nor
causes per-row reads. Relationship capabilities alone control displayed
mutations. Opaque continuation values are returned unchanged and never parsed
as identifiers or authority context.
Groups, users and policies cross-link to the precise referenced entity; the
IAM workspace accepts a URL entity identifier, including direct visits and
Back/Forward navigation, without trusting it as authorization.

Customer-role creation is a content-area workflow: choose explicit same-account
`USER` identities, choose permission policies and an optional boundary, enter
name/description/tags and session settings, then review. Nothing is granted by
default. The role type is fixed as `CUSTOMER` and its name is immutable after
creation; metadata, trust, attached-policy deltas, boundary and session settings
have separate commands. Cross-account, wildcard, external-provider and
free-form service principals are rejected rather than rendered as future-looking
success paths. Service access uses the separate service-authorization workflow:
a trusted platform template, registered service principal, Account consent and
exact `WorkloadRoleBinding` are independent from a tenant-managed customer role.

Trust editing reviews the affected role and both the previous and proposed
identities before saving. Human-readable identity names and stable IDs identify
added/removed trust; the two complete Matrix trust documents remain inspectable.
The comparison stacks on compact screens instead of widening the page. Reordering
the same identity set is not a change. Empty or unsupported trust is rejected
before review using the same domain validator as the command. Saving revalidates
the proposed trust and changes neither role policies, metadata, settings nor
existing sessions. The review explains that trust removal is not immediate
session revocation and never grants the caller an assumption permission.
Role metadata, trust, policy, boundary, settings and session changes use
content-area workflows and retain their draft/review after a failed command;
only destructive deletion keeps a focused confirmation dialog. The workflow
focuses the localized error, prevents duplicate submission, and locks exit only
during the mutation. A retry is explicit; cancellation creates no partial
changes. Both the pending and error paths require interaction regression tests.

A user requesting a preview role session must pass both explicit role trust
and `iam:assumeRole` evaluation against that role's canonical resource. The
user's boundary also limits this request. The customer-role preview never
creates a service/provider session; service-account sessions are read-only
observations owned by the separate service-authorization and administrator
session contracts. A customer-role session has a bounded duration, an immutable
expiry and explicit revocation.
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
| Group authorization | Full-page empty-group creation, separate one-relationship membership/policy operations, permission provenance and cross-navigation. | Two-step group-only creation, isolated metadata updates, reviewed one-item relationship changes, named policy sources and query-addressable user/group/policy/role details are implemented in MOCK. The fixed live group contract reuses the same normalized directory/detail components, keeps group requests local to the workspace, renders group facts before the independently loaded membership relation, omits non-authoritative member totals, discloses loaded-record search scope, keeps continuation representation out of presentation semantics and retries only an unchanged uncertain command. Preview retains its explicitly complete sample count. Shared in-app unsaved-navigation protection preserves creation drafts. |
| Role authorization | Customer-role content wizard, trust vs permission vs boundary, bounded USER temporary-session preview, plus a separate service-linked authorization boundary. | Four-step `CUSTOMER` creation, isolated metadata/trust/settings commands, reviewed policy deltas, boundary and before/after trust changes, and exact same-account `USER` trust are implemented. Generic service/provider principals are absent. Bounded preview sessions recheck USER assumption, retain immutable expiry and support individual revocation; service-linked authorization remains in its dedicated template/consent/binding workflow. Shared draft protection, unchanged/invalid trust, pending locks, cancellation and failure/retry across role commands are locally verified. |
| End-to-end access explanation | A no-grant user, group-derived allow, explicit deny, default-version rollback, boundary intersection and role-session case all lead to reproducible resource/action decisions. | Domain and interaction tests cover direct/group grants, deny precedence, conditions, current-version rollback, user/role boundary intersection, dual trust/caller authorization and session expiry/revocation. A real local MOCK journey proves caller denial before an exact assumption grant, role-only resource access limited by a boundary, then denial after revocation. Locally functionally verified for the documented subset. |
| Supporting workspaces | Review overview, users, provider/SSO readiness, settings and one-time MOCK keys against the documented scope without faking external activation. | Overview links and candidate guidance, source-aware user filtering, localized policy metadata, planned-state provider/SSO architecture, settings failure-retry, enterprise visibility/import and one-time MOCK keys are locally regression-verified. No provider directory, external-identity mapping or successful external session is fabricated. Scan/paid/live security flows remain skipped. |

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
| Page context bar | `56px` minimum; one reading line, with a `40px` trailing action-menu target at compact widths | One current page/object title, parent navigation and contextual actions; no repeated title/action band in the body |
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
the original context. ContentPage owns the header-to-content gutter for every
composition: compact canvases retain a `16px` block inset and `12px` inline
inset. Console navigation disables framework document-scroll adjustment because
the stable ContentPage viewport owns route scroll position; navigation must not
consume that inset or make content touch the context header. Same-path
collections, details and workflows contribute distinct scroll keys, replacing
feature-level `scrollIntoView` calls that could collapse the shared gutter.
Same-path workspace query changes use Next's supported native-history
integration instead of fetching another page tree. They retain draft guarding,
encoded entity IDs, replacement and Back/Forward behavior; cross-page visits
continue through the prefetched router transition with an immediate destination
frame and locally delayed loading placeholders.
The
content begins with meaningful resource summary, tabs or data, not another
generic title, return toolbar or repeated preview banner. Header MOCK identity and mutation-level limitations
remain visible; errors, risks and destructive confirmations are never hidden
as optional help. Details use aligned multi-column facts when space permits,
with a single-column compact layout and full readable values. The policy
overview separates its readable `16px` description from `12px` muted field
labels and `14px` semibold values; identifiers retain `13px` monospace text.
Classification badges keep intrinsic width instead of becoming a mobile banner.
The policy classification and description share one lead row at every width;
the description wraps only within the remaining inline space.

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
App Router transition. After any required draft-leave consent, clicking a
destination immediately switches the route-known title, parent context and
service-local navigation, hides outgoing content/actions and starts the Header
progress track. Resource readiness never delays this destination frame. A
frame is a projection of the existing scene vocabulary, not an empty resource
snapshot, an authorization result or another client router. Pending requests
cannot expose the old page after the product directory closes. Next still owns
the actual cross-page route commit, prefetch, history and interrupted visits;
same-page entity queries retain the existing native-history boundary.
Accepted-navigation side effects such as closing Products and services, global
search, notifications, the account panel or the compact service drawer run only
after the destination frame is in the DOM. This applies to every registered
service and prevents a closing overlay from revealing the outgoing page.
Regional PageSkeleton and labelled TableSkeleton acknowledge loading at once,
but mount their placeholder DOM/animation only after a sustained 200ms wait.
That timer belongs to the regional feedback component, not the shell or Header;
fast completion cancels it without imposing a minimum loading dwell. A dedicated
route subscriber renders an indeterminate two-pixel progress track over the
global Header's bottom divider, without subscribing static Header controls to
its loading state. The shell does not expose a universal manual refresh action:
mutation revalidation, retry and any product-owned refresh remain at the data
boundary they actually affect. The public
indeterminate Progress animates only a clipped, paint-contained child transform,
not background position or layout dimensions; it owns no animation timer or
React frame state. The active child alone receives the compositor hint, and
reduced-motion preference presents a stationary indicator. Determinate task
progress remains a native element driven by real values.
Dashboard, table, card, list and access layouts share semantic Theme
tokens and a single announced loading label. Product discovery itself performs
no product-resource read. Every accepted destination declares only the
server-owned resource slices required by that page: catalog reads offerings;
regions reads regions; quotas reads offerings and entitlements; installations
reads offerings, regions, entitlements and installations. The provider merges
only validated requested slices into a credential-owned cache and coalesces
overlapping in-flight slices. It never treats an unrequested slice as an
authoritative empty result or exposes its count in service navigation. Preview-
owned Applications, Logs, DevOps, Observability, resources, operations and
messages project directly from their authoritative ExperienceSnapshot and make
no managed-service request. IAM therefore remains independent of PaaS APIs,
and a denial or outage in an unrelated product collection cannot blank a page
that neither displays nor mutates that collection.

The projected content is visible but inert until Next commits the route,
consumes the pending destination query for detail/workflow identity, and keeps
the same content key across the commit so the target is not mounted twice. Any
read that the destination itself still needs, such as a live group directory or
entity detail, owns loading and retry feedback inside that data region. It does
not cause the shell to reload the cached IAM identity, policy or capability
scene. Prepared snapshots are scoped to the current session credential and are
never reused by a later login identity.

When no complete provider projection exists, the outgoing content becomes
hidden and inert immediately; its draft remains mounted until the visit commits
or is cancelled. The destination still renders its stable content structure,
including card or table identity and descriptive headings, while only the rows,
cards or other provider-owned data region receives delayed skeleton feedback.
The content viewport remains mounted across a committed visit rather than
replacing its background/scroll boundary. Only keyed route content is replaced,
with no full-canvas opacity transition. Initial resource loading and load
recovery keep the real Header, navigation and title mounted, changing only the
data area; they never substitute a second all-skeleton console frame or present
an empty count as a successful read. Mutation controls appear only with their
owned data/capabilities, not from the destination frame. A thin indeterminate progress
line communicates real route and scoped background activity without inventing a completion
percentage. Fast cached routes finish immediately; interrupted visits cannot overwrite a newer
destination. Reduced-motion preferences disable skeleton and progress motion.
Revalidating existing data retains the current page
and draft instead of pretending to navigate again.

Header open/close state is subscribed only by Header and its backdrop/inert
boundaries, not by the service-page renderer. IAM navigation subscribes to
stable capabilities independently of form pending/error state. Message details and their destination
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

`ContentPage.Commands` owns responsive commands for every page-context bar:
IAM lists/details and platform-status, quota and installation workspaces. One
command definition keeps at most one high-frequency primary command direct on
desktop and groups its secondary peers under one trailing More menu. A page
without a primary command keeps one secondary command direct, but groups two or
more secondary commands under More. At most `960px` of available content width
(also below a `760px` viewport for standalone headings), every command moves
into one Page actions menu. Pages without commands show no empty menu. Titles
keep their typography and truncate within their own slot; commands never wrap
into another title band.
On desktop, selection-dependent count, clear and batch commands grow toward
the title, with Create anchored at the trailing edge. Compact menus contain
Create and the same eligible batch commands plus Clear selection; selected
counts remain visible beside table results. `ActionMenu` shares themed surfaces,
keyboard handling, disabled reasons and destructive separators with `TableActions`.
Feature callbacks and access checks do not change. CSS selects the presentation
before paint without viewport subscriptions or shell remounts; closing a context
workspace restores the currently visible command even after a viewport change.
Feature workflows may name the exact command ID to restore on desktop; the same
request intentionally resolves to the visible page-action trigger in compact
mode instead of focusing its CSS-hidden direct button.
The removed universal Refresh button must not be recreated per
page; a future refresh control requires a scoped stale-data case, a visible
freshness contract and a repository operation that does not reload unrelated IAM
directories.

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

The user page projects Account + RootIdentity above the directory as a compact
resource-owner summary. It comes from the account ownership relation, never
from administrator grants, and remains discoverable while ordinary-user search
and filters change. Its detail separates read-only identity, access and
ownership permissions. RootIdentity is not a User: it does not enter groups,
receive ordinary permission attachments, own AccessKeys through this workspace,
or participate in grant, disable, password-reset and delete commands. Protected
account recovery and settings require their own capabilities. Unknown owner
display names or statuses and absent user access profiles are not fabricated
from the current actor or interpreted as disabled.

The live account-access projection and exact actor-relative capabilities are
specified in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md). Rendering
availability is advisory interaction data, not a client-side permit; MOCK
extensions cannot grant live access.

The directory table contains only daily manageable Users, with independent
type, access-method, authorization-source and status columns. Status/source
filters and keyword search cover the loaded user page; the redundant type
filter is omitted until more than one supported User kind exists. The table has
no trailing operation column. Usernames open details; leading checkboxes and a
More actions menu beside Create user provide one command entry for single/bulk
selection.
Other detail-first IAM directories use the same hierarchy without pretending
to support User-style bulk selection: Role, identity provider, federated
identity and enterprise-account names open their exact detail, and their edit,
status, import and destructive commands live only in the stable detail title
bar. They do not duplicate mutations in a trailing row-operation column.
Compact layouts therefore preserve one clear navigation target per record and
collect secondary commands in the shared page-action menu. Access keys use a
different, contract-owned hierarchy: select the owning User first, then manage
that User's exact key directory; the console does not fabricate an account-wide
key resource or reuse login-session semantics.
The shared `TableSelectionCell` owns cell geometry and mixed-checkbox semantics;
`TableActions` owns the menu, selection count, clear action, disabled explanations
and keyboard behavior. IAM supplies eligibility. Header selection covers only
the current filtered page, up to thirty users; changing filters, pages or data
clears selection rather than retaining hidden mutation targets. RootIdentity
never enters selection; every batch command therefore targets only Users, while
domain and adapter guards still reject a forged root ID. Status
changes require compatible states and protect the current actor; unknown,
stale, unauthorized or ineligible targets reject the entire batch. Existing
memberships, grants and boundaries are preserved by additive group/policy
attachment. Review identifies every target; disable/delete require
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
in user details. The live user-creation flow retains only identity, access
setup and review, defaults to no grant and excludes
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

### Current shared-navigation development evidence

Verified through 2026-10-07 against the current all-service navigation, compact IAM
shell, responsive access-analysis hierarchy and primary directory actions.

Current compact IAM evidence is fixed at `24e7a3780` and `88c21ccb3`, with the latter
also owning the synchronized embedded export. Fixed chrome, page title, back navigation
and the consolidated page-action trigger paint without waiting for directory data.
Access analysis keeps its three known primary sections on one row above 360 px; at or
below 360 px the same three controls become equal-width columns and may wrap their own
labels, without turning an arbitrary tab set into a second mobile implementation.

The public `Table.PrimaryAction` now owns the primary object entry for User, Group,
Policy, Role, security-report and Tenant directories. It preserves native button/link
semantics, focus visibility and disabled behavior, guarantees a 32 px minimum target,
and leaves metadata as ordinary table content instead of making the full row clickable
or restoring a generic operation column. A real `320 × 720` DEV pass measured every
one of those entries at 32 px or taller, kept document and viewport width equal on all
six routes, and opened the selected User directly in the existing content area with no
Dialog. The same 16-route IAM audit found no page overflow, duplicate IDs, extra `h1`,
unnamed actions or unlabelled tables; browser warning/error logs remained empty. The
complete 63-file/1,115-case frontend suite plus three normalization cases,
type/lint/architecture/228-pair style gates, 46-route export, 44 normalized paths,
synchronized embed, and repository-wide Go test/vet passed. This is shared shell and
interaction evidence; exact IAM semantics, LIVE authorization and remaining
real-runtime/browser acceptance stay with
[FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md).

The shared delayed-feedback regression matrix is fixed at `ba7e57a9a`. It now
exercises every loading-region branch used by Overview, Catalog, Quotas, Regions,
Applications, Resources, Installations, Operations, Messages, DevOps pipelines and
environments, Observability health and alerts, Log overview/search/topics/collection,
Audit and IAM overview/policy routes. Each destination must expose its stable named
region immediately, announce loading without placeholder DOM for the first 200 ms and
then mount placeholders only inside that region. The focused shell suite passes 82
cases; the complete frontend gate passes 62 files/1,082 cases, three normalization
cases, type/lint/architecture/228-pair style gates, 45-route export, 43 normalized
paths and 249-file embed equality. The synchronized Go UI host passes test and vet.
Repository-wide `go test -p 2 ./...` and `go vet -p 2 ./...` also pass against the
same synchronized assets. The maintained `127.0.0.1:4317` preview returned HTTP 200
for 25 canonical root, shared-service, service-subroute and IAM routes after the
asset sync, so the inspectable MOCK entry remains intact.
The same current DEV session used the compact product directory to enter all eight
published services at `390 × 844`: every route exposed its expected `h1`, document and
body client/scroll widths stayed at 390 px, no Dialog survived navigation and the
browser warning/error log remained empty. The viewport was reset after the audit.

| Gate | Evidence |
| --- | --- |
| IAM customer policy versions | LIVE detail retains lazy exact-version inspection and inline default/retirement review. Its CUSTOMER/TENANT version author offers JSON plus a catalog-driven visual path for one to 128 compatible exact Actions per statement, with paged choices and a selected-only filter; unrepresentable JSON remains untouched, and catalog denial is local to the visual path. Publication remains separate from default selection and authorization. The explicit MOCK editor and usage view remain separate. The current UX source passed real IAM browser publication → explicit default selection → old-version retirement in an isolated synthetic fixture; switching and retirement also cleared the obsolete publication notice. The compact follow-up removes the generic operation column from both LIVE and isolated MOCK version directories: the version identifier remains the semantic inspection entry, the default marker stays adjacent to it, and only a mutable non-default version receives the overflow menu for default selection and retirement/deletion. The shared row-action cell also owns the Role-session lifecycle/menu pairing, avoiding a second near-identical layout helper. Source/embed `2072b3639` passed 284 focused cases and the complete 57-file/933-case suite plus three normalization cases, type/lint/architecture/228-pair style gates, 42-route export, 233-file embed equivalence and full repository Go test/vet. At `390 × 844`, the version table exposed only Version and Created facts, kept its menu beside the non-default version, matched document/body to the viewport, and produced no Dialog or browser warning/error. This does not establish cross-session unknown-result recovery, authorization effect at a subsequent business request, installation or release acceptance. Exact semantics and evidence belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#策略版本读取与变更的开发验收证据). |
| IAM customer policy creation | The LIVE content-area author reuses the JSON and catalog-driven visual editor, requires an explicit Action and exact instance target by default, supports compatible multi-Action statements, then separates review, creation and attachment. The strict response parser accepts only the current Account's matching CUSTOMER/TENANT Policy and default document; uncertain transport/protocol outcomes retain the original request across IAM navigation, with byte-equivalent retry and explicit acknowledgement. The four-method MOCK author remains isolated; the same editor has a separate zero-write preview route. The current UX source passed a real IAM browser visual creation with an exact product Action and resource in an isolated synthetic fixture; cross-login unknown-outcome recovery and real attachment to a principal remain unaccepted. Contract and UX evidence belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#live-自定义策略新建的开发验收证据). |
| Compact user-permission methods | The isolated MOCK user-creation flow keeps its three fixed authorization methods in one visible three-column choice at widths up to 560px, while dynamic tab sets elsewhere retain the shared scrollable Tabs behavior. Labels may wrap inside their own column instead of clipping the final method behind horizontal scrolling. At a `360 × 800` real DEV viewport all three Chinese labels were visible, the tab list measured `292px` for both client and scroll width, the document and body remained exactly `360px`, and no Dialog or browser warning/error appeared. No user was submitted. Source and synchronized embed are fixed at `f7e5edf8f`; the focused 198-case workspace run and complete 58-file/1010-case frontend suite passed with three normalization cases, typecheck/lint/architecture/228-pair style gates, 45 generated pages, 43 normalized segment files, 249 embedded files and full repository Go test/vet. This is compact MOCK UX evidence, not acceptance of live user creation or backend authorization. |
| Compact policy editor modes | At a 360px viewport the four MOCK document modes now form two visible rows instead of clipping the final mode behind horizontal scrolling. The Product features mode was opened through its visible tab; the tab list and document both measured 360px without horizontal overflow. The existing statement picker and sticky footer did not overlap during top/mid/end scrolling. Desktop tabs and JSON draft ownership are unchanged. This is DEV visual evidence, not LIVE policy or IAM-process acceptance. |
| IAM policy diagnostic hierarchy | The isolated four-method MOCK policy author now separates security warnings, blocking errors, general warnings and optional suggestions instead of presenting every broad-permission pattern as one generic warning. Parse/contract errors retain first priority and block review; permission-management Actions, Action wildcards and unrestricted write or permission scope require explicit security review without claiming a final verdict about real resource exposure. Every group explains its effect and retains exact JSON-path focus. At `390 × 844`, the four diagnostic destinations form a visible 2 × 2 grid instead of hiding the final tab behind horizontal scroll; viewport, document and body were all 390px, with no Dialog or browser warning/error. The focused 74-case run and complete 54-file/884-case frontend suite passed with three normalization tests, type/lint/architecture/228-pair style gates, 41-page export, 228-file embed equality and repository Go test/vet. Source and synchronized embed are pushed at `a8f6dbbb`; this is local authoring guidance, not IAM validation, PDP execution or product-PEP exposure evidence. Exact IAM boundary ownership remains in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#策略版本-mock-的开发验收证据). |
| IAM current-access diagnosis preview | The bookmarkable `access-diagnosis` route remains separate from zero-evaluation `policy-configuration` and accepts only six predefined synthetic requests. Source/embed `59bb57843` aligns its domain projection and semantic request/result/source components to fixed S4b source `ef4483e25`: the stable pre-action binding shows USER subject, Action, resource kind/id, INSTANCE mode, exact synthetic Profile revision/digest and context summary; the result carries `apiVersion`/`kind`, scope, request/correlation references, closed sorted reasons, matched source associations with immutable `PolicyVersionReference`, exact restriction references and `resourceExistence`/`businessOutcome = NOT_EVALUATED`. Synthetic digest/attachment/membership references are labelled as fixtures rather than receipts, integrity proof, Decision, permit or replay authority. Incomplete evidence remains `UNAVAILABLE`. LIVE keeps `LIVE · NOT_CONNECTED` and now explains the required product-resource entry and product-control-plane/same-boundary-BFF credential handoff; it exposes no arbitrary-principal form, mounts no evaluator, calls no internal `/v1/authorize:diagnose` route and adds no repository wire. Three projection cases, the current 198-case workspace suite and the complete 60-file/1026-case frontend suite passed with three normalization cases, type/lint/architecture/228-pair style gates, 45 static pages, 43 normalized paths, 249 embedded files and full repository Go test/vet. Desktop and `390 × 844` DEV verified focus, compact restrictions, long-reference wrapping and an exact 354px table/viewport with no document overflow, Dialog or warning/error. This is isolated UX evidence only; real diagnosis remains product-service mediated through the single IAM PDP and requires separate LIVE acceptance. |
| IAM trusted-context authoring | The shared LIVE/isolated-MOCK visual policy author derives condition choices from the exact intersection of the selected Actions' Profile capabilities instead of a hard-coded condition list. It accepts the fixed PaaS revision-5 declarations for `request.source-ip` (`CALLING_SERVICE_NETWORK`, `IP`), `request.tag/environment` on `paas.application.create` (`CALLING_SERVICE_REQUEST_TAG`, `STRING`) and `resource.tag/environment` on `paas.application.read` (`CALLING_SERVICE_RESOURCE_TAG`, `STRING`). CIDR, operator, unique-value and cardinality checks fail closed; tag values are limited to 1–128 UTF-8 bytes, reject leading/trailing Unicode whitespace and control characters, and arbitrary tag keys never appear. One compact trusted-context region separates the producers: source IP comes from the calling service's trusted network boundary, request tags come from its business request, and resource tags come from the target resource's persisted state. Browser input and forwarded headers prove none of those facts and the author submits only policy syntax, never an internal authorization request or trusted fact. The resource-tag copy additionally states that a missing tag does not match, each real target must be checked again, and collection access does not imply access to every instance; the author therefore requires the selected Action's exact instance resource and never presents tag mutation as policy authoring. Review shows the exact key/operator/values. Resource-tag update/delete/CAS, arbitrary caller attributes and raw decision/debug surfaces remain unavailable. The revision-5 resource-tag candidate is isolated to MOCK until its IAM storage/authority gates are green; LIVE continues to expose only declarations returned by the strict Profile endpoint. IAM sources `e9b4989871e45a0fcd39a82327da4b124ee08ee5` and `355b12c4b67f3f88f464b055241eabf414e151b0` own the candidate semantics and fixture correction. The initial source and synchronized embed are pushed at `ccdb94c9`; wording-alignment source/embed are pushed at `d42b3b06`. The four-method preview now scopes its request-tag omission to that isolated experience and directs catalog behavior to the selected Profile instead of claiming a platform-wide limitation. The 57-file/920-case frontend suite, three normalization cases, type/lint/architecture/228-pair style gates, 42-page export, 233-file embed equality and repository Go test/vet passed. The wording follow-up independently passed the 174-case access-workspace suite, typecheck/lint, export/embed equality and UI host Go test/vet. Desktop and `430 × 900` DEV flows selected the exact Action, displayed the resource-fact boundary and completed review without a Dialog or horizontal overflow; a fresh `430 × 900` check of the aligned four-method copy kept viewport, document and body width at 430px with no Dialog. Exact backend semantics and LIVE acceptance remain owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md). |
| IAM policy catalog provenance | The shared LIVE/isolated-MOCK visual author now keeps the exact authorization-profile directory used for the current edit and shows only the product and revision that supply selected Actions. The final review labels these declarations as pending IAM validation and explains that the server revalidates its own directory, freezes the exact Action set and does not retroactively expand published versions when a Profile later grows. Product Profiles remain read-only authoring metadata: the browser cannot select or submit a Profile, digest, compilation, trusted request/resource facts or resolved Action expansion, and create/publish commands remain the authored document plus their existing concurrency/idempotency fields. After publication, the policy-version detail treats only the returned `PolicyVersion.compilation` as authoritative: a dedicated read-only provenance region shows the compilation contract and each exact product, revision and content digest, while the statement table independently distinguishes author syntax from the returned frozen Action expansion. Versions predating that contract show an explicit legacy state and are never reconstructed from the current catalog. The copy states that provenance is neither current catalog state nor an allow decision for the signed-in identity. The author exposes request- or resource-tag conditions only when the exact returned Profile declares the corresponding key, source and value type; it never infers a generic tag namespace. The 57-file/920-case frontend suite, three normalization cases, type/lint/architecture/228-pair style gates, 42-route static export, 233-file synchronized embed, and repository Go test/vet passed; focused behavior coverage verifies both fixed provenance and strict condition parsing. Desktop and compact DEV flows verified the authoring provenance block in edit and review without replacing the declaration content or introducing a Dialog. Exact publication semantics remain owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#策略版本读取与变更的开发验收证据). |
| IAM selected-Action declaration inspection | The shared LIVE/isolated-MOCK visual author now reuses the catalog's `AuthorizationActionTable` in both editing and final review. A default-collapsed content-area disclosure explains each selected Action's declared scope, resource and target shape, admitted subject and USER credential carriers, and trusted condition sources without opening a Dialog. It mounts only after an explicit request, renders at most the current ten-row page, and uses the shared `Table.Footer`; the author therefore does not mount all 128 possible selections or move stable actions while loading. The copy states that this current catalog declaration is neither the signed-in user's authorization result nor a policy compilation result, and no Profile, digest, compilation, trusted context or expanded Action set enters create/publish commands. This separation matches the capability-reference boundary documented by the [AWS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html) and [Azure role definitions](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions), rather than copying either console's visual design. Resource-tag conditions appear only on Actions whose exact Profile declares a trusted resource-tag source; tag mutation remains outside policy authoring. Source and synchronized embed are pushed at `d141f6e2`; the focused 97-case IAM run and complete 57-file/920-case frontend suite passed with three normalization tests, type/lint/architecture/228-pair style gates, 42-route static export, 233-file embed equality and repository Go test/vet. Desktop edit/review and compact review verified the lazy disclosure, stacked table and no Dialog. Exact catalog and publication ownership remains in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#权限能力目录片的开发验收证据). |
| Visual policy review | The shared LIVE/isolated-MOCK policy author presents one current statement's effect, exact Actions, resource selectors and conditions before optional full JSON; multiple statements switch through a labelled selector rather than mounting the full declaration. LIVE visual version publishing reuses that summary and keeps current/proposed JSON comparison collapsible. Free-form JSON still displays the full source/comparison because a partial summary could omit unknown fields. A `390px` real IAM catalog detail had no document overflow or warning/error; visual creation review and JSON version comparison completed in the isolated real browser fixture. Broader release acceptance remains open in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#策略版本读取与变更的开发验收证据). |
| Cross-service compact data tables | The shared native `Table` now offers a two-column labelled mobile grid in addition to the existing single-column stack and desktop table. Application resources, database instances and DevOps pipeline runs use one full-width identity row, paired facts and full-width long endpoint/timestamp fields; IAM table layout is unchanged. DEV inspection at `390px` showed all three records without horizontal dragging, and DevOps at `320px` measured table/document widths of 284/320px with no page overflow. At `1280px`, DevOps retained all six desktop columns. The focused shell suite passed 32 cases, the full 44-file run passed 780/784 with four unrelated policy-author interaction cases hitting their existing five-second limits, and an isolated rerun of that entire 154-case file passed with a fifteen-second limit. Type/lint/architecture/228-pair style checks, 41-page export, 228-file embed equality and all Go test/vet passed. This is DEV visual evidence, not real-IAM or installed-release acceptance. |
| Product directory visibility boundaries | The PostgreSQL instance directory labels its count as records currently loaded rather than an Account-wide total. The product-specification directory now applies the same truthful boundary at the first product PEP surface: isolated MOCK fixtures are explicitly not IAM-filtered; non-preview copy requires trusted server-side candidate filtering and never exposes denied rows or their count. A successful empty directory is distinct from service unavailability and does not leak hidden product names or denial reasons. Neither surface invents a tenant-facing batch-grant action, pagination, result coverage or an `/authorize:batch` integration. Focused renderer coverage locks MOCK/LIVE copy, empty-success semantics and absence of the misleading action. The complete 55-file/893-case frontend run, three normalization cases, type/lint/architecture/228-pair styles, 41-page export, 228-file embedded equality and repository Go test/vet passed. Desktop and `390 × 844` DEV inspection showed the notices before their data regions, document/body/viewport width 390px, no dialog and no browser warning/error. Source and synchronized embed are fixed at `28552769`; this is product-side UX and MOCK evidence only, pending a fixed IAM contract and product PEP integration. |
| IAM policy default-detail read | The LIVE policy directory opens an exact TENANT policy in the content area and reads only its current default immutable version on demand. Stable heading and metadata render first; only the document region loads or reports a local denial. Platform policy metadata never triggers a tenant detail request, and v2 authored Action families stay visually distinct from their frozen exact expansion. The explicit MOCK policy authoring/version/usage experience remains separate. Source and synchronized embed were pushed at `2c3dc421`; this earlier read-only gate is subsumed by the current policy-version row above. IAM contract and exclusions belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#策略版本读取与变更的开发验收证据). |
| Development verification host | Node 23.11.1 (outside the package engine range, not a supported release-runtime claim); source `46b72b04` passed type, lint, architecture and 228 light/mixed/dark contrast checks. Vitest passed 896/896 cases across 55 files with the original five-second per-case limit, followed by three static-normalization cases. The production build exported 41 pages and matched all 228 synchronized embedded assets; focused Go UI host test/vet passed. Full jsdom interaction files run serially because two large suites previously contended for CPU and produced false five-second timeouts; this changes test scheduling, not product behavior or timeout thresholds. Installed-release gates remain separate. Account-rule, activity-observation, authenticator-replacement, user-SSO, Passkey and session-expiry previews remain isolated MOCK, with exact IAM scope and exclusions in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md). |
| IAM group loading and relationship refresh | The shared collection surface now owns explicit loading and unavailable data regions. The LIVE Group directory keeps its heading, search and create command mounted through initial loading, failure and retry; it neither replaces the page with a coarse skeleton nor flashes an empty directory before a fast result. A direct Group detail keeps a stable heading and back path while only remote facts load or fail. Request generations reject late directory results. After a relationship change, the detail still retains its last verified member rows during authoritative refresh, disables relation commands, closes stale detail after a failed group read, and localizes a failed member read with retry. Focused tests cover delayed directory/detail, failure→retry and relation transitions. The current 50-file/839-case frontend run, three normalization checks, type/lint/architecture/228-pair style gates, 41-page export, 228-file embed and repository Go test/vet passed. A `390 × 844` DEV directory had exact viewport/document/body width and no browser warning/error. Source and synchronized embed are pushed at `255b9bf7`; exact IAM behavior and remaining real-process browser acceptance belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#用户组关系刷新片的开发验收证据). |
| IAM user-detail loading | A LIVE User selection now replaces the directory with a stable detail frame built only from its already verified directory identity. The exact `UserAccess` read owns a localized data skeleton; write actions remain absent until exact capabilities arrive. Failure retains the read-only identity context and retries in place without reloading the IAM scene or falling back to MOCK. Focused delayed and failure→retry tests passed within the 50-file/840-case frontend suite; type/lint/architecture/228-pair style gates, three normalization cases, 41-page export, synchronized embed and repository Go test/vet also passed. A `390 × 844` DEV MOCK detail had no document overflow or browser warning/error; it verifies the shared responsive surface, not a LIVE network failure. Source and embed are pushed at `74dfa01b`; exact semantics and remaining real-IAM browser acceptance belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#user-权限边界片的开发联调证据). |
| IAM group relationship content flow | MOCK and LIVE Group member/direct-policy add and remove now reuse the shared content-area form instead of a wide dialog. The exact select/review/submit flow, LIVE requestId and retry/readback semantics remain unchanged; destructive deletion remains a focused confirmation. Group detail owns its active tab across body replacement, so returning keeps the original member/policy context and restores focus to the source command, or to the stable edit command when an authoritative refresh temporarily disables the source. Focused cases cover MOCK failure/success/cancel, the fixed LIVE contract and policy-tab retention. Desktop and `390 × 844` DEV checks found no dialog, page overflow or browser warning/error. The complete 50-file/837-case frontend run, three normalization checks, type/lint/architecture/228-pair style gates, 41-page export, 228-file embed and repository Go test/vet passed. Source and synchronized embed are pushed at `a943c86c`; exact semantics and remaining real-IAM browser acceptance are owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#用户组关系刷新片的开发验收证据). |
| IAM User batch-association content flow | The capability-gated User directory keeps its stable title while Add to groups and Attach policies replace the directory body with one shared select → review → submit workflow instead of a wide dialog. Targets remain explicit, associations are additive, and the existing 30-target atomic MOCK command is unchanged. Cancel preserves selection and restores the stable More actions trigger; confirmed completion waits for the authoritative directory refresh before clearing selection and restoring Create user focus. Enable/disable/delete remain focused confirmation dialogs. Source and synchronized embed are pushed at `d8232a1a8`; the complete 58-file/974-case frontend suite plus three normalization cases, type/lint/architecture/228-pair style gates, 42-route export, 233-file embed equality and repository Go test/vet passed. Desktop and `390 × 844` DEV checks found no association dialog or horizontal overflow, and a clean tab produced no browser warning/error. This is isolated-MOCK UX evidence only: it adds no LIVE repository, wire contract or authorization claim. Exact semantics and exclusions are owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md). |
| IAM metadata editing consistency | The isolated MOCK User display-name, Group name/description and custom-Policy description editors now reuse one content-area form instead of separate dialogs. Entering the workflow keeps the stable page title/back path and removes competing page actions; closing it restores focus to the originating desktop action or the compact shared page-action trigger. Destructive delete and high-risk batch confirmations remain focused dialogs. Source and synchronized embed are pushed at `67ed0429a`; the complete 58-file/956-case frontend suite, three normalization cases, type/lint/architecture/228-pair style gates, 42-route export, 233-file embed equality and repository Go test/vet passed. At `390 × 844`, all three workflows rendered with zero Dialog, viewport/document/body widths at 390px and no browser warning/error. This is shared isolated-MOCK UX evidence and introduces no LIVE write wire; exact IAM exclusions are owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#非破坏性元数据编辑的开发验收证据). |
| IAM non-destructive entry workflows | The existing LIVE Group metadata editor now uses the same content-area form while preserving its fixed request/revision/conflict/readback contract; Group deletion remains a focused confirmation. The four isolated-MOCK custom-Policy creation methods are a navigational content-area entry rather than a modal: the chooser owns the stable page heading, returns focus to the desktop create command or compact page-action trigger, and projects the selected method directly into the existing unified draft workspace without briefly remounting the directory. Source and synchronized embed are pushed at `0a317163a`; the complete 58-file/957-case frontend suite, three normalization cases, type/lint/architecture/228-pair style gates, 42-route export, 233-file embed equality and repository Go test/vet passed. At `390 × 844`, all four choices rendered with zero Dialog, returning focused the compact page-action trigger, the JSON choice immediately opened `/console/access/create-policy/?method=json`, viewport/document/body widths stayed at 390px and browser warning/error logs were empty. This introduces no new LIVE Group or Policy wire; exact IAM boundaries belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#非破坏性元数据编辑的开发验收证据). |
| IAM account content workflows | Platform tenant creation and isolated-MOCK User security management now replace their large navigational dialogs with the same content-area workflow. Tenant creation preserves the existing request payload, initial-password clearing, busy state and in-place error focus; closing restores the desktop create command or compact page-action trigger. Returning from User security management keeps the Security tab selected and restores focus to its Manage action; destructive User deletion remains a focused confirmation dialog. Source and synchronized embed are pushed at `4296e6f20`; the complete 58-file/959-case frontend suite, three normalization cases, type/lint/architecture/228-pair style gates, 42-route export, 233-file embed equality and repository Go test/vet passed. At `390 × 844`, both workflows rendered with zero Dialog and no document overflow; the User return restored the exact Manage button, and browser warning/error logs were empty. This adds no new IAM wire and keeps User security management explicitly MOCK; exact exclusions belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#非破坏性元数据编辑的开发验收证据). |
| IAM deferred collaboration boundaries | Replacement-first source/embed `f5eee566b` removes the superseded browser-only enterprise directory instead of hiding it: `EnterpriseAccount`／`EnterpriseMember`, three enterprise write commands, preview fixtures, `wecom.*` User injection, connection/import/delete UI and their success tests no longer exist. The renamed Cross-account collaboration destination now reuses the existing IAM-EXT-06/09 trust-path and IAM-EXT-08 organization-governance projections as two read-only tabs. It creates no invitation, external trust, organization node, guardrail, resource share, anonymous-access switch, request ID or success state; WeCom stays absent until IAM-EXT-04 gains an approved environment and fixed contract. Focused 268-case behavior tests and the complete 63-file/1110-case frontend suite passed with three normalization cases, type/lint/architecture/228-pair style gates, 46-route export, 44 normalized segment files, 254-file embedded equivalence and repository Go test/vet. Desktop and `390 × 844` DEV showed no page-owned input, Dialog, write command, horizontal overflow or browser warning/error. Exact boundaries are owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#企业微信与外部目录的延期边界). |
| Theme and static-export boundary | 228 semantic contrast pairs passed across light, mixed and dark workspace/shell surfaces. Production preview was disabled; all 228 embedded files matched the normalized immutable export. |
| UI host and architecture | `go test ./...` and `go vet ./...` passed against the regenerated embedded console. |
| Static query boundary | Supported client detail/creation queries retained identical HTML and CSP; ambiguous, malformed and authority-bearing selectors were rejected. |
| Destination/frame boundary | Tests compare route-known metadata with loaded scenes for all seven directory services without constructing an empty business result or mutation workspace. Opening the static product directory performs no provider read and does not rerender the business-content boundary. An accepted destination requests only its missing declared slices; overlapping reads are coalesced per resource and cached only for the current credential. Applications, Logs, DevOps and Observability project immediately from ExperienceSnapshot with zero managed-service calls. Catalog reads only offerings, Regions only regions, Quotas offerings plus entitlements, and PostgreSQL installations all four required slices. A catalog read therefore remains usable even when an unrequested installation collection would be forbidden. Suspended IAM-to-Logs and IAM-to-PostgreSQL transitions expose the target frame immediately, hide the outgoing IAM page and never wait for unrelated collections. A navigation-order regression proves launchers and compact navigation receive their accepted callback only after the destination section is in the DOM. |
| Cross-service navigation focus | The shared navigation boundary announces an accepted destination through the stable page `H1` during the pending frame and focuses the same heading again after the Next route commit. This prevents product-launcher, sidebar and browser-history navigation from dropping focus onto the document after the destination is already visible; it does not remount the page, refetch unrelated data or replace feature-owned workflow focus. Regression holds the route bundle for Region, Application hosting, PostgreSQL, Logs, DevOps and Observability in turn: outgoing Resource content is either disconnected immediately or retained only as hidden/inert draft state while target data resolves; the destination title and service frame are visible at once; Header/navigation/H1 nodes remain stable; preview-owned targets perform zero managed-service reads; Region and PostgreSQL use only their declared read set. The test-only gate at `19f8c2ec` separately alternates IAM Group and Role navigation 200 times while both destinations are suspended, proves the latest click remains authoritative, then releases the stale request and proves navigation is still interactive with no residual pending marker. Current source/embed `46b72b04` passed the 55-file/896-case frontend suite, three normalization cases, type/lint/architecture and 228-pair style gates. Browser evidence is owned once by the Real DEV browser row below. This is shared DEV navigation evidence, not installed-release or real-IAM acceptance. |
| Loading/render isolation | The stable shell, destination `H1` and route-specific content region now render synchronously for every service and IAM. The shared loading adapter no longer substitutes a generic whole-page skeleton for Overview, Catalog, Quotas, Regions, delivery environments, Log search or IAM bundle suspension: known card and table boundaries mount immediately, their accessible loading status is announced at once, and only provider-owned rows/cards paint after the existing 200ms threshold. Fast results therefore cancel before placeholder DOM exists, while sustained waits remain local to the destination data region. The new card-grid skeleton is a shared regional primitive rather than another page layer. Skeleton shimmer now animates a paint-contained transform instead of `background-position`; reduced-motion remains static. Control-plane resource readiness is still independent from array contents, request generations reject old-credential results, and page-owned refresh does not propagate to unrelated services. Parameterized coverage locks seven representative destination structures plus delay/cancellation behavior; existing suspended-shell cases continue to prove stable Header/navigation nodes, immediate cached projections and page-scoped reads. Source and synchronized embed `6857313d7` passed the complete 58-file/967-case frontend suite plus three normalization cases, typecheck/lint/architecture/228-pair style gates, 42-route export, 233-file embed equality and repository Go test/vet. A `390 × 844` DEV path from Catalog → IAM → Logs → Log search showed the destination frame immediately, retained the thin Header progress boundary during commit, matched document/body width to the viewport and produced no browser warning/error. The cloud-overview follow-up at `d4d36fecf` closes the remaining cross-service mismatch: preview `/console/` no longer inherits the managed-database Overview placeholder or flashes “最近服务实例”. Its destination identity renders immediately, while metric, common-product, recent-resource, attention and readiness placeholders remain delayed and structurally aligned with the final dashboard. Tests hold both region data and the route commit to prove outgoing content is hidden, only the declared Region slice is read, and the correct cloud identity stays stable throughout. The complete 58-file/972-case frontend suite, three normalization cases, typecheck/lint/architecture/228-pair style gates, 42-route export, 233-file embed equality and repository Go test/vet passed. Desktop and `390 × 844` DEV rendered “控制台总览 / 欢迎使用 Matrix Cloud” with no Dialog, horizontal overflow or browser warning/error. Exact IAM semantics and browser-evidence limits belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#iam-初始场景加载的开发验收证据). |
| Audit-filter render isolation | Audit query drafts now live inside the filter panel instead of the page root. Typing actor, RoleSession and source lineage therefore rerenders only that local form; the existing result table, date formatting, loading state and page chrome update only when a valid query is submitted. Closing the panel discards unsubmitted edits and reopening begins from the last applied filter set, while validation remains local and successful submit still restores focus to the stable filter trigger. A fresh DEV audit session showed the operator-ID edit as the only accessibility-tree change, kept the result table mounted and emitted no browser warning/error. The complete 62-file/1056-case frontend suite, three normalization cases, type/lint/architecture/228-pair style gates, 45-route export, 249-file embed equality and repository Go test/vet passed. This changes render ownership only; the Audit wire, authority scope, cursor and validation semantics remain unchanged. |
| Contextual-workspace render boundary | The shared shell keeps the empty workspace frame available for stable geometry and accessibility relationships, but does not mount quota, installation or platform-status bodies until their named page action is first accepted. Hidden forms therefore do not subscribe to the control-plane context or participate in initial page/navigation commits. Collapsing an activated workspace keeps its local draft mounted and inert so reopening does not discard operator input; a different current workspace key cannot render the previous body. The behavior case proves zero initial forms, first-open mounting and draft retention after collapse/reopen. Source/embed `1509b0f0` passed the 55-file/896-case frontend run, three normalization checks, type/lint/architecture/228-pair style gates, 41-page export, 228-file embedded equality and focused Go UI host test/vet. A `1280px` DEV installation check measured zero closed-state forms before first use, retained the edited display-name draft after collapse/reopen, kept body width equal to the viewport and produced no browser warning/error. This is a shared rendering/performance boundary; it does not change product commands or IAM authority. |
| Responsive data hierarchy | The public native `Table` keeps horizontal scrolling as its default for dense comparison and selection surfaces and exposes an explicit stacked mobile layout for relationship, detail and compact workspace directories. The opt-in stack activates at a `560px` table-container boundary, retains table/header semantics in the accessibility tree and supplies each visible value with its column label. The tenant directory now uses that native contract: desktop retains Tenant/stable ID, root login, alias and lifecycle status columns; small screens render those four facts as labelled rows without clipping or inventing an operation column, while the tenant name remains the content-area detail entry. Component coverage proves the contract. Real DEV browser checks rendered the Role directory at `360px`, the IAM permission-capability directory at `539px` and the tenant directory at `390px` in both light and mixed themes without document overflow, dialog or warning/error. User, Group, Policy and Role detail relationships use the same opt-in contract. |
| Compact tab discoverability | The shared single-row `Tabs` keeps its existing semantic tablist, keyboard `Home`/`End` and horizontal-scroll behavior, but now renders a thin theme-aware scrollbar only when content overflows. This exposes additional destinations without adding React state, observers or parent rerenders. A `390 × 844` DEV User detail measured `306px` client width against `470px` scroll width, showed the overflow cue at the initial tab, and still reached the final Access keys tab by keyboard without document overflow. The 52-file/855-case frontend suite, three normalization cases, type/lint/architecture/228-pair style gates, 41-page export, synchronized embedded assets and repository Go test/vet passed. Source and embed are pushed at `7cda7000`; this is shared responsive UX evidence, not LIVE IAM integration acceptance. |
| IAM policy directories on compact canvases | The MOCK selection directory and LIVE metadata directory explicitly opt into the existing stacked `Table` contract at `560px` table width; the generic dense-table default remains scroll. The MOCK row keeps selection beside the name and omits only empty product/category values on compact layouts. Local CSS removes the directory's 900px/820px desktop minimum width inside the table container, so description and metadata wrap within the available width. A `390px` DEV check measured the MOCK table at 354px and document/body at 390px; at `1280px`, the original six-column table remained intact. Exact policy UX evidence and LIVE browser limitation belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#策略目录响应式体验的开发验收证据). Source and embed are pushed at `f6312fef`. |
| IAM compact-route and policy-summary audit | The 13 main IAM destinations were navigated through the compact product menu at both `390px` and `320px`; each showed its destination heading with document/body width equal to the viewport and no browser warning/error. At `320px`, the MOCK custom-policy detail exposed a separate information-density defect: a fixed badge/description flex row reduced long description text to a narrow column. The policy-overview container now uses inline flow below `380px`, keeping the badge beside the start of the description while later lines use the full content width; the measured description width is about 221px, with no page overflow. At `1280px`, the original flex layout is unchanged. The 156-case workspace suite, 228-pair style check, 41-page static export and 228-file embed comparison passed. This is DEV MOCK visual evidence, not a real-IAM or installed-release acceptance. |
| Compact table page selection | The shared native `Table` keeps current-page selection visible when a directory opts into the stacked `560px` layout. Only a header with a selection checkbox becomes a labelled compact control; other column headers retain accessible semantics without visual duplication, and tables without selection do not gain an empty bar. In `390px` DEV MOCK, the User and Policy directory controls selected 4/4 and 9/9 current-page rows respectively without document overflow or console warning/error. At `1280px`, the Policy table remained six columns with the compact label hidden. Shared keyboard and IAM directory tests passed within the 44-file/753-case frontend run; static export matched 228 embedded files and Go test/vet passed. Source/embed are pushed at `bdaa9835`; this does not claim LIVE bulk-action or backend browser acceptance. |
| Inline workflow focus | The live User permission-boundary editor focuses its newly mounted selector, restores that focus when returning from review, and returns focus to the stable Modify boundary trigger after cancellation or confirmed closure. A keyboard behavior test enters and cancels the workflow with `Enter` and proves that cancellation sends no mutation. Real-browser keyboard acceptance against the fixed IAM backend remains separate evidence. |
| Security workflow focus | Stage transitions in the MOCK authenticator binding/replacement wizard, account MFA-rule editor and login challenge focus the newly visible heading or rule input; cancellation returns to the triggering control or a stable section heading if that control became disabled. The stage key prevents ordinary code-input rerenders from taking focus. Component regression tests and mixed/light DEV browser keyboard checks passed; the `390px` checks had no document overflow. Source and embed are pushed at `8c3eff62`; this is isolated-preview UX evidence, not LIVE IAM browser acceptance. |
| IAM user relationship workflow | The MOCK User detail now manages direct policy associations and group membership through one content-area workflow instead of separate large dialogs. Selection, explicit added/removed/retained review, failure retention, retry and completion share the existing wizard grammar; direct grants, inherited group grants and the permission boundary remain visibly distinct. The 126-case IAM workspace suite and 605-case full frontend suite passed. A `539px` DEV review check reported no dialog, `clientWidth === scrollWidth === 539` for document/body and focus on the review heading. Source and synchronized embedded UI are pushed at `0ea49e06987453e5a09b3a5f0cba47cf51b24e31`; the workflow remains explicitly MOCK and introduces no LIVE API. |
| IAM user grant provenance | The isolated MOCK User permission page summarizes direct associations, unique inherited policies, policies whose current default document contains an explicit `Deny`, and permission-boundary configuration before the relationship table. Each policy row labels its default-version effect while retaining direct and inherited origins together. The explanation explicitly stops short of an effective-access verdict: request facts, applicability, explicit denies and the boundary still require evaluation. A focused behavior case locks those distinctions; the current 50-file/834-case frontend run, three normalization tests, type/lint/architecture/228-pair style gates, 41-page export, 228-file embed and repository Go test/vet passed. At `390 × 844`, document/body stayed within the viewport and a clean reload resolved the new locale messages without fallback keys or new warning/error. Source and synchronized embed are pushed at `29b93aac`; no LIVE PolicyVersion document or new backend contract is inferred. Exact IAM boundary ownership is in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#user-权限边界片的开发联调证据). |
| IAM role authorization hierarchy | The isolated MOCK Role detail now puts trust admission, permission-policy count, current-default documents containing explicit `Deny`, and permission-boundary state in one shared authorization overview before its tabs. The policy table labels each current default document as allow-only or containing an explicit deny. The explanation keeps trust, grants and the maximum-permission boundary distinct and refuses to present the summary as a request-level verdict. The component owns its responsive container instead of depending on the overview-page wrapper, so its four facts become a stable 2 × 2 grid at `390 × 844`; document/body matched the viewport and browser warning/error logs were empty. The current 50-file/836-case frontend run, three normalization tests, type/lint/architecture/228-pair style gates, 41-page export, 228-file embed and repository Go test/vet passed. Source and synchronized embed are pushed at `5a1f3013`; this remains a MOCK projection and does not invent LIVE Role-effect or target-User grant-source APIs. Exact boundary ownership is in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#user-权限边界片的开发联调证据). |
| IAM role directory hierarchy | The isolated MOCK Role directory now exposes the facts needed for first-pass administration without an operation column or repeated detail navigation. Each row groups exact trust subject/principal, attached-policy count and permission-boundary state, maximum new-session duration and console-entry state, then creation time. These remain configuration facts rather than an effective-access, assumability or runtime-authorization verdict. At `390 × 844` the existing stacked-table contract keeps every group labelled with viewport/document/body all at 390px; a fresh browser session emitted no warning/error. Source and synchronized embed are pushed at `68f059c45`; the complete 58-file/955-case frontend run, three normalization cases, type/lint/architecture/228-pair style gates, 42-route export, 233-file embed equality and repository Go test/vet passed. No Role update/status/delete, trust, attachment or boundary LIVE wire is inferred; exact ownership remains in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#roletrust-与会话-mock-的开发验收证据). |
| IAM group authorization hierarchy | The isolated MOCK Group detail now puts member inheritance, direct policy count, current-default documents containing explicit `Deny`, and the absence of a group permission boundary in the same authorization-overview grammar used by User and Role. Its policy table labels each current default document's effect. The overview and effect column render only when the caller marks current-document coverage complete; the LIVE Group adapter supplies no such projection and performs no policy-detail fan-out or denial-to-empty fallback. Focused behavior cases lock both sides. Desktop and `390 × 844` DEV checks kept the hierarchy readable, turned the four facts into a 2 × 2 grid and stacked policy fields without horizontal overflow. The current 50-file/837-case frontend run, three normalization tests, type/lint/architecture/228-pair style gates, 41-page export, 228-file embed and repository Go test/vet passed. Source and synchronized embed are pushed at `5476b3ad`; the exact LIVE-contract boundary remains owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#user-权限边界片的开发联调证据). |
| IAM policy security-review projection | One pure local projection now supplies the policy author's four-level diagnostics, the Account overview review list, policy detail, policy-to-identity association, Role creation and User group/direct-policy association. Read and mutation surfaces show the same policy names and individual security findings, while the author no longer repeats a second binary high-privilege alert. The overview labels these as policies requiring review instead of implying an effective-access verdict. Every surface states that explicit denies, boundaries, grant sources and the actual request context still require evaluation; the projection is not IAM publication validation, PDP execution or product-PEP evidence. Source and synchronized embed are pushed at `058ca1d3`. The focused 243-case run and complete 55-file/885-case frontend run passed with three normalization tests, type/lint/architecture/228-pair style gates, 41-page export, 228-file embed equivalence and repository Go test/vet. DEV browser inspection covered the JSON author, a system-policy detail and its inline association workflow. At `390 × 844`, detail and association document/body widths equalled the 390px viewport with no Dialog, overflow or warning/error; the findings render as a scan-friendly nested list. This remains isolated MOCK guidance and introduces no LIVE validation code or backend risk contract; exact IAM ownership is in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#策略版本-mock-的开发验收证据). |
| IAM permission-capability directory | The policy workspace now lazily mounts a shared read-only capability directory after explicit tab selection, leaving initial IAM scene and policy loading unchanged. The LIVE adapter strictly consumes the fixed CAT-06 response and localizes 403, route mismatch, transport and protocol failures without MOCK fallback; the DEV repository supplies a visibly marked same-shape preview. Product actions open inline, not in a dialog, and entering/returning restores both focus and useful scroll context. The explicit preview now continues from one exact product declaration into a three-stage product engineering → IAM validation → trusted release review, while final publishing remains disabled because no draft, approval, publish API or Action exists. The entry is absent from LIVE, performs no repository write and does not model tenant registration or catalog visibility as a grant. The initial full 42-file/658-case frontend run, three normalization checks, type/lint/architecture/228-pair style gates, 40-page export, 222-file embed equivalence and Go test/vet passed. `539px` and `360 × 800` DEV checks produced no page overflow, dialog or console warning/error. Initial source and synchronized embed are pushed at `5114dda3`. The follow-up at `8fef3f20` makes the policy workspace's current semantic section own its page commands: tenant policy selection and “create custom policy” appear only on the policy tab, while the capability directory, product declaration and internal onboarding review render no unrelated tenant mutation action. Returning to the policy tab restores both commands in their stable heading position. The current 53-file/883-case frontend run, three normalization tests, type/lint/architecture/228-pair style gates, 41-page export, 228-file embed equivalence and repository Go test/vet passed. At `390 × 844`, the capability directory had viewport/document/body all at 390px, zero policy-create action, no Dialog and no warning/error. The onboarding follow-up at `b79e4b1c` stops the internal checklist from visually implying a successful validation: every IAM review item is explicitly pending, and the final stage separates MOCK declaration input, unexecuted contract validation, unverified product-PEP evidence and unavailable trusted-registry publication into four independent gates. Source/embed `fcd31da82` replaces the former tenant-to-internal two-card diagram with the actual ownership flow: product engineering defines capabilities and enforces the PEP, IAM validates and publishes an immutable trusted declaration, and tenant administrators only consume that directory to author and assign policies. The three owners render horizontally on desktop and as one directed column at `390 × 844`; the complete 58-file/969-case frontend suite, three normalization cases, type/lint/architecture/228-pair style gates, 42-route export, 233-file embed equality and repository Go test/vet passed, with no Dialog, horizontal overflow or browser warning/error. Full contract and acceptance ownership remains in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#权限能力目录片的开发验收证据). |
| IAM capability catalog display paging | The shared LIVE/MOCK product directory displays only the current 10-row local page from the complete bounded snapshot, while product search resets to page 1 and detail return retains its prior page/focus. The Action pager remains independent and the footer explicitly avoids claiming backend paging. Its toolbar now keeps one persistent search and discloses exact authority-scope, admitted-subject and USER-credential filters only on request; active conditions remain visible as removable chips. One domain projection owns the sealed legacy credential ceiling for catalog search/filtering, declaration rows and AccessKey carrier inspection, so an omitted method set remains login-session-only and a non-USER Action has no USER credential. Filtering resets only the Action page and changes neither the declaration nor digest. Source and synchronized embed are pushed at `e79cb85d1`; the complete 57-file/931-case frontend suite and three normalization cases, type/lint/architecture/228-pair style gates, 42-route export, 233-file embedded equivalence and repository Go test/vet passed. Desktop and `390 × 844` DEV checks selected the AccessKey carrier, returned only the five exact USER-admitted declarations, kept document/body at the 390px viewport, and showed no Dialog, overflow or browser warning/error. This remains DEV MOCK evidence, not real-IAM browser acceptance; exact IAM contract and UX acceptance are owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#权限能力目录片的开发验收证据). |
| IAM Action declaration review | The capability directory and MOCK product-onboarding review share one four-column read-only Action table, grouping scope/resource/target and subject/credential while showing each trusted condition's key, declared source and value type. Search stays in the directory; onboarding mounts only the current 10-row local page. Its validation stage presents one diagnostics snapshot containing the immutable `product@revision` plus digest, unique condition fact sources, the calling service's PEP responsibility and an explicit “runtime evidence not verified” state. It does not invent an online validation result, PEP attestation, publish command or permit. Source/embed `ef480a5e4` makes the same-route workflow own its scroll transition: opening it from a scrolled product detail explicitly reveals the workflow title, every stage reveals its focused heading below the sticky page header, and leaving restores the original focused trigger in view instead of inheriting the previous content `scrollTop`. A `360 × 800` DEV check kept viewport/document/body at 360px, rendered no Dialog and emitted no browser warning/error; the unreleased publish control remained disabled and no repository write occurred. A 1,202-Action behavior case still proves only the current page mounts. The focused 198-case workspace suite, full 58-file/1,010-case frontend suite, three export-normalization tests, type/lint/architecture/228-pair theme gates, 45-page export with 43 normalized route files and 249-file embed equality, plus repository Go test/vet passed. This is isolated MOCK evidence, not trusted registry publishing or LIVE IAM/PEP browser acceptance; contract interpretation remains in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#权限能力目录片的开发验收证据). |
| IAM service authorization | LIVE service authorization is tenant-first in IAM and resource-first in the owning product. The role workspace reads the current Account's `ServiceLinkedRoleAccess` relations and keeps platform templates on a separate lazy tab. A selected managed-service installation keeps its stable product facts mounted while a local card reads the released `managedservice.installation-reader@v1` template, the matching current-Account relation and the exact `SERVICE_INSTALLATION` binding from cumulative fixed IAM source `a464299b6656becc73054cd53b4a31b44104540b`; Verification `36779942782` completed with all 14 tasks successful. The browser uses only the three customer read routes with the current `LOGIN_SESSION`, sends no Account selector, and requires the full `{id,version,contentDigest}`, purpose and workload identity to match. Template release, Account relation, exact resource binding and a future issued service session remain independent facts, so an Account may be shown as authorized while the current instance remains unbound. Account is only a response assertion, opaque cursors stay within one Account/Role, malformed or duplicate facts fail closed, and only the remote card loads or fails locally with no Dialog or MOCK fallback. `SERVICE_LINKED` Roles never enter ordinary role-edit, trust, attachment or boundary UI. The isolated product-resource preview completes the same three-step authorization review with a visibly labelled browser-memory-only success state that resets on refresh and never calls IAM, writes a role/binding or issues credentials. A bound instance also owns an inline exact-unbind review: it fixes the Account, resource and binding, states that only the current resource binding is removed, preserves the Account relation, and refuses to promise immediate invalidation of existing short-lived sessions. It displays the number of other bindings known to the current browser-only MOCK as operation-impact context without presenting it as an authoritative backend total. A multi-resource behavior case binds two exact resources under one Account, unbinds one, and proves the Account relation and the other binding remain active. Cancellation and completion restore focus to a surviving action and no Dialog is used. An unmounted strict product client now adapts fixed IAM source `92ea765b`: bind sends only the exact template reference, unbind sends only resource version on the exact installation/binding path, both retain a caller-owned idempotency key for unknown-result replay, and successful-looking receipts fail closed unless their complete fields, route identities, template digest, lifecycle version and UTC-microsecond times agree. The methods deliberately remain outside the mounted provider and LIVE UI because independent Verification `36701340805` has not passed. Account-relation revoke/delete and service-session actions remain absent from the service-authorization LIVE surface, and `/v1/internal/*` is never called. The existing browser-memory bind and exact-unbind reviews include an explicit result-recovery rehearsal without mounting LIVE writes. A network loss or `500`/`503`/`504` freezes the same path, body and request ID and offers only equal replay or return without claiming success. `SERVICE_ROLE_CONFLICT` and `404` return to an authoritative reread before any new user intent, while `IDEMPOTENCY_CONFLICT` stops as a client-state mismatch instead of retrying. `401` preserves the original command across future reauthentication, `403` stops, and `400`/`415` require a corrected contract plus a fresh review. The receipt still does not grant later business permission. The observation surface now also explains one service request as four independent outcomes: trusted-service authentication, `sourceType=SERVICE_ACCOUNT` short-lived-session issuance, product-PEP re-authorization and product-owned business execution. Every stage remains explicitly not verified/issued/evaluated/executed; the runtime chain exposes no credential, internal endpoint or permit. A separate isolated sample may show a non-secret session ID, lifecycle and revoke capability with a disabled review, but it cannot turn configuration state into a request permit. Desktop renders a compact 2 × 2 trace while `390 × 844` uses one column with viewport/document/body all 390px, no Dialog and no warning/error. A shared ownership region appears before either the account-relation or platform-template tab in both the isolated MOCK and strict read directory. It presents product-team definition and PEP enforcement, IAM validation/trusted publication, and tenant directory consumption/product-resource consent as a non-actionable three-stage boundary; it exposes no upload, publish, consent or revocation control and does not turn a tenant into a product registrar. Because the responsibility model is stable page context, it remains visible while either remote directory region loads or fails locally. The current-account observation now leads with a tenant-readable four-stage status summary: exact platform template, current-Account relation, exact resource binding and runtime observation are independent; the first three may be valid while runtime remains unobserved. It concludes only that the configuration relation is valid, never that a service session was issued or a business request succeeded. In alignment with the IAM owner, the MOCK states that a `REVOKED` exact binding forbids new issuance while refusing to promise immediate termination of an existing session; the session sample exposes only public non-secret identity/lifecycle/capability fields and no temporary credential, private issuance/result route or internal decision evidence. That four-stage summary stays mounted while technical evidence uses three content-area tabs for authorization configuration, exact resource bindings and runtime boundary. Only the selected technical region is visible, so mobile keeps the essential status stable without rendering one long undifferentiated evidence stream; the tabs introduce no refetch or contract change. Current source and synchronized embed are pushed at `0835f3b1c`. The focused MOCK/LIVE service-authorization run passed 9 cases, followed by the complete 62-file/1061-case frontend suite and three normalization cases, type/lint/architecture/228-pair style gates, 45-route export, 43 normalized paths, 249-file embed equality and repository Go test/vet. Desktop and `390 × 844` DEV showed the shared responsibility model before the directory tabs; the compact view measured viewport/document/body at 390px with no overflow or Dialog and an empty browser warning/error log. The shared chain used by LIVE Account/template views, product-resource cards and the isolated MOCK now also requires the fourth runtime stage explicitly; medium content widths render 2 × 2 and small containers render one column. Source/embed milestone `fc7c3b54` passed the current 55-file/889-case and complete export/embed/Go gates. This stage itself adds no service-authorization-page session request/revoke or product-PEP result; the exact session sample alignment is recorded in the next row. Cumulative IAM source `a464299b6656becc73054cd53b4a31b44104540b` keeps the production read wire/API unchanged, adds immutable-history, concurrent-count and exact-filter evidence, and has terminal-success Verification `36779942782`; this accepts only the three customer read routes, so LIVE bind/unbind stays closed pending its own fixed source and terminal evidence. This is strict read-client and accepted read-source evidence plus unmounted strict write-client preparation and isolated-MOCK UX evidence; it is not real-IAM browser, accepted backend bind/unbind or release acceptance. Exact semantics and exclusions are owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#live-服务授权只读目录的开发验收证据). |
| IAM service-session preview alignment | The fixed administrator RoleSession source `5435ea97faecc965b5010d0b7129b0bd26e45898` defines the public `USER | SERVICE_ACCOUNT` source union, `UNREVOKED | EXPIRED | REVOKED` lifecycle and per-session revoke capability. The isolated service-authorization preview now reuses that exact non-secret vocabulary for its local samples: service lineage is limited to installation/principal/purpose, terminal records expose no revoke review, and `UNREVOKED` is explicitly not current usability because source, binding or Policy state may have changed. It still sends no query or revoke request, creates no request ID, shows no credential/private lineage/product-PEP result and keeps final submission disabled; real LIVE query/revoke remains owned by Role detail. Source and synchronized embed are fixed at `a7c22679`; the current 55-file/889-case frontend, normalization, type/lint/architecture/228-pair style, 41-page export, 228-file embed and repository Go test/vet gates passed. Exact semantics and release exclusions belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#服务授权-mock-的开发验收证据). |
| IAM settings responsibility navigation | The long settings stream now starts with three stable local anchors for sign-in identity, personal security and account security. Each control focuses and scrolls to an already-mounted heading without changing route, introducing local state or refetching the current identity; LIVE and explicit MOCK map to their existing sections. A focused behavior case proves all three transitions with an unchanged identity-read count. At `390 × 844` in the light theme, the labels stay on one compact row and focus reaches the account alias, security notification and account MFA rule. Source is pushed at `87b0b4b4`; the same complete 861-case/export/embed/Go gate above passed. This changes information flow only and does not add a settings API. |
| IAM policy-version preview | Policy versions now use the same content-area interaction grammar as policy association and permission-boundary workflows. A version number opens read-only content inline; each non-default custom version exposes one overflow menu instead of three adjacent row buttons. Default-version review, full JSON comparison, affected identities, deletion and localized retry errors stay inside the policy detail with deterministic focus restoration and no dialog. The behavior case passed, and the full 121-case workspace run completed every case except one unrelated pre-existing tag-authoring test that reached 5033ms at the unchanged five-second boundary; its isolated rerun passed in 2.51s. Production export/equivalence and the Go host passed. Real DEV browser inspection at the default compact viewport and `360 × 800` reported no dialog, warning/error or page overflow. The data and mutations remain explicitly MOCK; IAM contract ownership remains in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#策略版本-mock-的开发验收证据). |
| IAM role/trust/session preview | Role metadata, policy attachment, boundary, trust and session settings remain content-area workflows; destructive deletion alone retains focused confirmation. The administrator session tab remains a non-secret directory, separate from member assumption. The isolated role model is now explicitly customer-managed: creation, trust editing and assumption accept only same-account `USER` identities and use the fixed IAM-006 `TrustPolicyDocument` shape. The former generic service-role fixture and free-form service-principal success path are removed rather than hidden. Service-linked access remains in the dedicated trusted-template, Account-consent and exact-resource-binding workflow. `iam.role.assume` stays a separate caller grant, not a result of trust. Access analysis no longer turns a synthetic Role into a configured external entry; it exposes evidence-source readiness and routes service access back to the separate authorization model. The focused four-file IAM run passed 329 cases; the complete frontend gate passed 63 files/1,101 cases plus three export-normalization cases, typecheck, lint, architecture, 228-pair theme styles, 46 generated routes, 44 normalized segment files and 254-file embedded-export equality. Full repository Go test/vet also passed. A fresh DEV browser exercised the Role directory/detail/create entry, service authorization and access analysis at desktop and `390 × 844`; fixed headings appeared before data regions, document/body widths matched the 390px viewport, no Dialog remained and the fresh warning/error log stayed empty. This is isolated-MOCK UX and strict-client evidence, not LIVE trust mutation, service consent or installed-release acceptance. Feature semantics remain in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#roletrust-与会话-mock-的开发验收证据). |
| IAM external-federation readiness | Replacement-first removes the superseded browser-only `IdentityProvider`, `ExternalIdentityPreview`, `RoleSsoMappingPreview`, fake provider Role and assertion-mapping access-analysis entry. Role SSO and User SSO remain bookmarkable information-architecture pages, but now show only their distinct target journey, security gates, enablement prerequisites and an explicit `planned · backend not connected` state. They expose no fake directory, identifier, issuer, subject, claim rule, configuration form, test connection, enablement, login, success state or write command. Generic customer-Role create/edit admits only current-account `USER` trust; it cannot manufacture a provider or service principal that the backend wire does not support. Access analysis likewise reports evidence-source readiness without generating a configured external entry from a synthetic Role. This follows IAM's deferred boundary for `IdentityProvider` / `ExternalIdentity` and preserves the backend-owned path for a future fixed contract instead of turning uncertainty into a product surface. Exact external-integration ownership remains in [FEAT-IAM-012](../../IAM/FEAT-IAM-012-external-integrations.md). |
| IAM member role self-service preview | The preview-only account menu opens a dedicated member route, separate from the administrator Role/session directory. Its exact Assume-only actor discovers eligible roles and reviews the source User, Account, Role version and duration without management reads. Denial, a known-fresh conflict and uncertain issuance have different recovery paths; an unknown original request is queried, and a credential-lost committed session is revoked before a new request ID is offered. No real credential is shown or stored, and the Header login stays unchanged. MOCK issuance now starts at the actual action time; the selected lifetime and a background-tab wake-up transition the identity to an expired, non-actionable state. The complete 756-case frontend run, 41-page export, 228-file embed match and Go/static gates passed. A `390px` DEV check found no document overflow or new warning/error. Source and embed are pushed at `e6ec141b`; preview semantics remain owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#成员自服务-role-承担-mock-的开发验收证据), while the separate LIVE client is recorded in the row below. |
| IAM Role and administrator-session management | The non-preview account repository strictly consumes Role list/read/create plus administrator RoleSession list/read/revoke from the fixed IAM-006 sources. Stable page chrome, heading, guidance, search and status controls render immediately; the session endpoint is not requested until its detail tab is selected, and only the session data region owns initial skeleton feedback. Role creation is a content-area, three-step workflow over exact same-account USER principals. It creates only Role metadata and the first immutable USER trust version: no policy attachment, permission boundary, password, long-lived key or temporary credential is implied. The adapter sends no Account selector and validates exact ownership, submitted metadata, ACTIVE state and initial trust; an unknown create result freezes the original payload and requestId and permits only an equivalent retry. Desktop commands share the title region and compact layouts expose the same actions through the common overflow menu. The administrator session directory now consumes fixed IAM source `5435ea97faecc965b5010d0b7129b0bd26e45898`: exact session, source-user or service-principal search composes with the closed `USER | SERVICE_ACCOUNT` source type and server lifecycle filters, while opaque continuation supports empty windows without inventing totals or completion. The strict source projection displays minimum User identity or immutable service installation/principal/purpose lineage; it rejects ambiguous mixed sources, private lineage and invented fields. Before either isolated MOCK or strict LIVE data, one shared stable guide explains that a source identifies who requested the temporary identity rather than where Role permissions originate: USER still requires Role trust plus separate `iam.role.assume`, while SERVICE_ACCOUNT uses exact installation/principal/purpose service authorization and is neither a tenant User nor a long-lived credential. The guide issues no request or command and invents no session row; it collapses from two columns to one in a narrow container. Member self-service remains USER-only. The adapter validates exact ownership, ordering, bounds, versions, timestamps, canonical trust digest, Role capability shapes, observed session lifecycle, source/session agreement and per-session revoke capability and never falls back to MOCK. Revocation stays inline and changes only the exact RoleSession, not the source identity or service authorization relationship. An uncertain revoke result is owned above keyed list/detail navigation and retains its original requestId across cancellation, tab remounts, returning to the Role directory and re-entering the same Role/Session; compare-and-set updates reject late callbacks, and Account/credential changes invalidate the intent. A later `REVOKED` read is not presented as proof that the uncertain command caused it, while authoritative `EXPIRED` is terminal and never offers revoke retry. Query and continuation requests use separate generations so a late old page cannot overwrite a newer filter. Source and synchronized embed are fixed at `aecdaac1c493929724813430e39c24bb9aad7a0e`; the complete 62-file/1,061-case frontend suite plus three normalization cases, typecheck, lint, architecture, 228-pair theme styles, 45-route export, 249-file embed equality and full repository Go test/vet passed. Desktop and `390 × 844` DEV verified the shared guide, responsive two-column/one-column hierarchy, zero horizontal overflow or Dialog and an empty warning/error log. This remains strict-client and isolated-MOCK UX evidence, not real-IAM process or release acceptance. Exact semantics and exclusions are owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#role-管理与管理员会话-live-客户端的开发验收证据). |
| IAM member Role self-service | The non-preview console consumes the fixed IAM-006 USER self-service contract for assumable-role discovery, AssumeRole, by-request lookup/revoke, CurrentRoleIdentity and Role logout. Source identity, discovery heading and the temporary-access boundary now remain mounted before directory data; only role cards own delayed skeleton feedback. An initial directory failure keeps the current USER identity, states that no RoleSession was created and retries in place, while an already verified directory survives later errors. The one-time Role credential becomes effective for product requests only after exact identity verification, is never persisted, and cannot be reconstructed from equal replay or by-request results. While ROLE or exit recovery is active, the shell hides USER IAM administration and blocks manual USER/session routes from reusing source authority. Logout stops product use immediately, preserves the same request IDs under uncertainty, and restores USER mode only after exact source `/auth/me` revalidation; the explicit fallback revalidates the source before revoking the original issuance. The original DEV MOCK remains independently checkable. Source and synchronized embed are pushed at `c0ad4901`; the 50-file/842-case frontend gate, three normalization cases, type/lint/architecture/228-pair styles, 41-page export, synchronized embed and repository Go test/vet passed. A `390 × 844` MOCK check measured viewport/document/body at 390px with no dialog or browser warning/error; LIVE delay/failure browser acceptance remains open. Exact contract and failure semantics belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#成员-role-自服务-live-客户端的开发验收证据). |
| IAM AccessKey lifecycle, network governance and authorization observation | The former account-wide key table remains replaced by a User selector and exact per-User directory. Stable title, boundary and rotation guidance render before data; only the user/key/account-security regions load, and a failure in the account layer leaves known key evidence visible instead of flashing or replacing the whole page. The strict LIVE adapter consumes fixed IAM source `91649497a0c53be1174d8835326a2df51fe74a55`: per-User list/read/create/set-status/delete, mandatory key `networkRestrictions`, required `usage.observedAt`, optional historical `lastAuthorization`, complete account password/session/key-network settings and dedicated `iam.access-key.set-network-restrictions`. Creation freezes the exact User version, requestId and canonical key networks, so no unrestricted key is created before a follow-up patch; uncertain replay keeps the same intent and never reissues the Secret. Account and key CIDR layers remain separate and are explained as cross-layer AND/layer-local OR. Key network editing uses the exact key version in the content area and never reuses the status action or a Dialog. The account-level editor now uses the fixed full-`AccountSecuritySettings` replacement contract in the same content area: stable account facts stay mounted, only dynamic regions load, and review plus password/TOTP step-up never opens a Dialog. It freezes the complete MFA/password/session/network target and factor revision, persists no password or TOTP, ends the calling login Session on success, and recovers an uncertain PUT only by the original request after a fresh login; a 404 keeps the command locked and never authorizes a new write. Historical Allow/Deny is not a current permit, business result, health or safe-delete signal; absent evidence stays unknown, and the browser never discovers or submits its own IP. The original explicit MOCK workspace remains available with the same information architecture and no LIVE fallback. Source/embed `63b4643bc` established the initial fixed read/key-mutation slice; the account-level follow-up passes all 62 frontend files/1,052 cases plus three normalization cases, type/lint/architecture/228-pair style gates, 45-route export, 249-file embed equality and full repository Go test/vet. Reloaded desktop DEV preserved the MOCK account-network section with viewport/document/body all 1280px, no Dialog and no new browser warning/error. IAM [Verification 37106511260](https://github.com/xiak/matrix/actions/runs/37106511260) completed all 15 jobs successfully for the fixed source. Real-IAM browser mutation, product PEP enforcement and installed-release acceptance remain open. Exact semantics and exclusions belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#访问密钥生命周期网络治理与授权观测的开发验收证据). |
| AccessKey product boundary preview | The AccessKey workspace separates credential lifecycle, product credential-carrier admission and effective authorization. Its default-collapsed programmatic-access region reads the current authorization Profile directory only when opened and lists only exact Actions whose declaration admits `USER` plus `ACCESS_KEY`; an omitted authentication-method set retains the sealed login-session ceiling and cannot be treated as broad support. The shared Table and Footer paginate the bounded result instead of mounting an eventual product-wide list. Copy states that product acceptance is not a grant: every request still revalidates the key, User, current policies, target resource, conditions and explicit denies. Only after that exact carrier set is non-empty, the surface offers one next-task link for the same User: MOCK and LIVE both open that exact User's detail, while MOCK deep-links directly to its permission-source tab so direct attachments, group inheritance, explicit Deny and the permission boundary are inspected together instead of seeding an unrelated generic Action. The link explicitly remains a policy/group source inspection and never claims a request-time permit. The browser neither retains the Secret, creates a signature nor sends a test business request. A denied, unavailable, expired or absent catalog remains unknown and never falls back to a fixture. Fixed IAM implementation `b6d15c89a` and status owner `018f34ec5` advance PaaS to revision 9 with digest `sha256:14aa8bee8819bde9b1a5434774b26308866ea1a17d9ccfd3cc3ccf252cb297c6`. The isolated MOCK copies only the six exact `USER + ACCESS_KEY` declarations: the five TENANT collection-create Actions `paas.application.create`, `paas.configuration.create`, `paas.configuration-revision.create`, `paas.application-revision.create` and `paas.deployment.create`, plus instance `paas.application.read`. The read retains its exact `APPLICATION` resource, prefix-capable instance shape and product-owned `resource.tag/environment` condition; Configuration, Revision, Deployment, Operation and Audit reads, lists and label writes remain outside the carrier set. No Action is inferred from method, namespace, collection shape or sibling support. One default-collapsed MOCK-only disclosure groups public outcomes by operation type instead of repeating a table per Action or turning the browser into a client. The create group retains `202 Operation`; the exact no-query/no-body GET group adds `200 Application` and post-authorization `404 NOT_FOUND`; both show `400 INVALID_ARGUMENT`, `401 UNAUTHENTICATED`, `403 PERMISSION_DENIED`, `409 CONFLICT` and `503 IDENTITY_UNAVAILABLE` with only verified nonce semantics. The UI does not expose internal subject resolution, signatures, nonces, request digests or Account selectors, and the LIVE surface still receives only the lazy read-only catalog client with no product call, Secret or fallback path. Independent CI `36853816880`, APISIX edge coverage and signed installation acceptance remain unfinished, therefore this is not LIVE product integration or release acceptance. Source and synchronized embed are pushed at `28c4202e2`; the two focused revision-9 cases and complete 57-file/931-case frontend suite passed with three normalization cases, type/lint/architecture/228-pair style gates, 42-route export, 233-file embed equality and full repository Go test/vet. Desktop and `390 × 844` DEV verified all six exact Actions, distinct create/read outcome groups, the exact `principal-lin` permission-source destination, labelled stacked rows, zero Dialog or overflow and a clean browser warning/error log. The owner-directory follow-up removes the repeated per-row management column and makes the User identity the single semantic detail entry while retaining search, complete-versus-cursor paging, disabled loading state and accessible names. Source/embed `818750989` passed the current 57-file/933-case suite plus three normalization cases and all existing type/lint/architecture/228-pair style, 42-route, 233-file embed and repository Go test/vet gates. Desktop and `390 × 844` DEV showed only the two informative User/status columns, exact navigation to the selected User's key directory, no Dialog or horizontal overflow, and no new browser warning/error after a clean reload. Revision 10 implementation `35e15da224e68bf0aa39d311254e123734b832f1`, evidence `452d021e17347feabbd6204c8d703c25fa45d38e` and digest `sha256:759bd751d03fc8ddceb69f6a5e827328401dcbd47d73a1e568a0b76c5a517256` are pushed but remain outside the accepted Action set until independent Verification `36858924218` reaches a successful terminal state. Revision 11 implementation `05336ad368996a500c0769fe62767204bd9333d0`, evidence `dcddcebd7f7a109f034a9d365bd85562e69a839e` and digest `sha256:ba8b808cc72c4ff1eb34d9eb933b5cde4ee95dde0f1a5c361058c2dab6937b48` are fixed, but independent CI `36864073811` remains pending; its Deployment writes therefore appear only in the isolated MOCK below and are not LIVE acceptance. The Audit follow-up at `1ecd350f6` copies only the fixed r3 carrier from implementation `620960989`: `audit.record.read` and `audit.integrity.verify`, both TENANT Collection-List, USER/ROLE and ACCESS_KEY/LOGIN_SESSION, with no condition. The same MOCK-only result disclosure explains `AuditRecordPage`, `ChainVerification` and public 401/403/409/422/503 semantics while marking every Audit Nonce result as unknown; it does not sign, send a request or expose an Account selector. Independent Verification `36876149921` remains pending, and the not-yet-fixed r4 source-IP condition remains absent. The current 57-file/940-case frontend suite, normalization, type/lint/architecture/228-pair style, 42-route export, 233-file embed and repository Go test/vet gates passed. Desktop and `390 × 844` DEV showed all four operation groups with no Dialog, page overflow or browser warning/error. The information-density follow-up at `f5364f6a7` replaces the four simultaneously mounted outcome tables with one labelled operation selector and one result table; changing among PaaS create/read and Audit query/integrity replaces the result in place and sends no request. Focused cases prove inactive results leave the DOM, while the complete 57-file/940-case frontend, export/embed and Go gates remain green. Desktop and `390 × 844` DEV mounted exactly one table with no scroll jump, Dialog, page overflow or browser warning/error. |
| Application Deployment lifecycle preview | Application Hosting now separates Application identity from mutable Deployment desired state, immutable generations and asynchronous Operations on the application detail. Stable summary facts include resource version, desired/observed generation and revision, placement policy/decision, phase, desired state, component readiness and current Operation. One primary update action plus an overflow rollback/stop cluster remains stable while all three workflows run in the content area without Dialog. Update and stop review the same closed `PUT /v1/deployments/{id}` boundary; stop preserves the full current spec and changes only `desiredState`. Rollback uses `POST /v1/deployments/{id}/rollback` and admits only earlier accepted `RUNNING` generations. Every review exposes the strong `If-Match`, product-owned IAM Action and one caller-owned request identity without Secret material. A first success is presented only as `202 / ACCEPTED`; equal replay after an unknown response may return `200` plus the original terminal Operation, so HTTP success is never presented as workload completion without `Operation.state` and a re-read Deployment. `412` reloads the Deployment and requires a new review/intent, `409` intent mismatch/no-change/active-operation and `403` never offer blind retry, while `503` or transport uncertainty retain exactly the original intent. The MOCK attribution uses only the fixed USER plus AccessKey ID vocabulary and remains labelled `MOCK · pending integration`. Source and synchronized embed are pushed at `1566e22c4`; the focused 76-case renderer/scene run and complete 57-file/937-case frontend suite passed with three normalization cases, type/lint/architecture/228-pair style gates, 42-route export, 233-file embed equivalence and full repository Go test/vet. Desktop and `390 × 844` DEV checks found no Dialog, horizontal overflow or browser warning/error. Product lifecycle invariants remain owned by [FEAT-004](FEAT-004-compose-application-execution.md); authorization release remains blocked on IAM revision 11 independent CI `36864073811`. |
| IAM policy-usage association directory | The explicit MOCK policy detail no longer renders every directly attached User, Group and Role or every permission-boundary owner in one unbounded table. Each semantic relationship keeps its own section, total and explanatory copy, but now reuses the shared table toolbar and footer for normalized search, local pagination and responsive labelled rows. Filtering is deferred and temporarily disables stale identity links; the two derived association snapshots are memoized, and exact entity navigation is preserved. Empty policy usage remains a concise relationship-specific explanation rather than a decorative empty table. The UI explicitly labels the data as a complete current MOCK snapshot and does not imply a LIVE server total or cursor contract. A generated 13-owner fixture proves the 10-row first page, search/result count, second-page navigation and exact Role link. The complete 57-file/915-case frontend run, three normalization cases, type/lint/architecture/228-pair style gates, 42-route static export, 233-file embed equivalence and full Go test/vet passed. Desktop DEV verified the stable search, empty-result recovery and zero browser warning/error; the shared stacked-table contract remains the compact presentation boundary. Source and synchronized embed are pushed at `7269ce6a`. This is scalable isolated-MOCK UX, not a LIVE policy-usage directory contract or effective-access result. |
| IAM Group relationship directories | Group detail member and direct-policy tabs now share one searchable, locally paginated and responsive relationship directory instead of growing unbounded tables. A complete direct-policy snapshot displays its exact total; a cursor-backed LIVE member prefix says only how many records are loaded, limits search and pagination to that prefix and offers the opaque next page from the shared footer. A temporarily hidden continuation action during refresh no longer turns that prefix into a false complete snapshot, and an empty cursor page does not claim that the Group has no members. Deferred filtering blocks stale row navigation while preserving exact User and Policy links. Focused fixtures prove an 11-member first page plus a two-member continuation, local second-page/search behavior, a complete 12-policy snapshot and compact stacked-table semantics. The complete 57-file/917-case frontend run, three normalization cases, type/lint/architecture/228-pair style gates, 42-route static export, 233-file embed equivalence and full Go test/vet passed. Desktop DEV verified both relationship tabs and their complete-snapshot footer; the compact contract is covered by the shared stacked-table behavior case. Source and synchronized embed are pushed at `ce444fad`. This is scalable MOCK/LIVE presentation over the fixed Group and opaque membership-cursor contracts; it does not introduce a Group total-count API or a new backend relationship contract. |
| Shared IAM relationship directory | The Group-specific relationship table implementation has been replaced by one feature-owned directory component now used by Group members, Group direct policies, User policy provenance, User group membership and MOCK Role policy attachments. Every surface retains its own domain columns and actions while sharing normalized deferred search, ten-row local pagination, responsive labelled rows, result recovery, footer grammar and stale-link blocking. Complete MOCK snapshots name their exact total; the existing cursor-backed Group member surface alone retains loaded-prefix semantics and opaque continuation. Generated fixtures prove 12-item User policy, User group and Role policy snapshots, first/second-page behavior, search and exact entity navigation without changing association commands, grant provenance or permission-boundary semantics. The complete 57-file/919-case frontend run, three normalization cases, type/lint/architecture/228-pair style gates, 42-route static export, 233-file embed equivalence and full Go test/vet passed. Desktop DEV verified User policy, User group and Role policy directories with their existing overview and command hierarchy. Source and synchronized embed are pushed at `88bcf2d7`. This is a shared presentation boundary over existing MOCK/fixed relationship facts; it adds no LIVE User/Role relationship directory or server total contract. |
| LIVE Role relationship navigation | The strict LIVE Role detail now treats its exact current policy attachments, permission boundary and USER trust principals as navigable relationships instead of dead identifiers. Policy relationships open the existing Policy detail and current USER trust principals open the existing User detail; the target page owns its own authorization and 403/404 handling. The Role surface performs no per-row metadata requests, never promotes immutable historical trust principals into current links and does not translate trust, an attachment or a boundary into an effective-access verdict. Native buttons preserve keyboard activation and no Dialog or operation column is introduced. The focused 19-case Role suite and complete 62-file/1,048-case frontend run passed with three normalization cases, type/lint/architecture/228-pair style gates, 45-route static export, 249-file embed equality and PaaS UI Go test/vet. Exact semantics remain owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#roletrust-与会话的契约对齐体验). |
| Personal security notification | Non-preview settings consume the fixed IAM contact, first-verification and replacement routes through one current-User Provider; the isolated MOCK remains a separate, explicitly labelled experience. Stable headings and both security cards paint immediately while only owned data regions load. A verified old address plus a bound TOTP gates replacement; the content area separates target review, current password/current TOTP proof, new-address delivery and eight-digit confirmation without a Dialog. Final code confirmation is the sole atomic commit: there is no invented review/save or cancel command. `VERIFIED + pendingVerificationId` keeps the old address authoritative, explains that the original intent must continue elsewhere and blocks a second replacement. Passwords and codes remain only in input memory; non-secret references survive route remounts only inside the current Session-scoped Provider. An unknown proof clears secrets and permits only original-StepUp inspection; a failed or unknown delivery start never repeats proof and only retries the frozen delivery request. A `401` proof is called credential rejection only after a successful same-bearer contact probe; an unavailable probe stays unknown. Unknown confirmation removes its write control and only rereads the original verification. A successful commit followed by failed contact refresh remains `COMPLETED`, exposes only authoritative reread and clears progress only after the N+1 address is observed. `ACCEPTED/250` remains SMTP channel acceptance, never receipt/read. Fixed IAM source [`2487b658`](https://github.com/xiak/matrix/commit/2487b6586697d10089c31adaee37c4a4603055d4) has completed 15-job [Verification 37161461635](https://github.com/xiak/matrix/actions/runs/37161461635); dual-mailbox evidence is fixed at `20632441`, while its [Verification 37170446801](https://github.com/xiak/matrix/actions/runs/37170446801) still reports queued. Source/embed [`228c06eb2`](https://github.com/xiak/matrix/commit/228c06eb2) pass the focused 118-case renderer and 107-case strict HTTP suites, complete 62-file/1,069-case frontend run, three normalization cases, type/lint/architecture/228-pair style gates, 45-route export, 43 normalized paths, 249-file embed equality and repository Go test/vet. Backend invariants are owned by IAM-012 at `336fe1b26`; exact console evidence and remaining LIVE browser + real IAM/SMTP gate belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#本人安全通知地址的开发验收证据). |
| Personal security notification delivery and code recovery | Against fixed IAM source `823a665e8d24b21c180134ab7893dc189d55599d`, the LIVE verification step can reread the original delivery observation without issuing another verification command, extending expiry or implying receipt/read. The status timestamp remains visible beside the fixed delivery state and attempt count; refresh failure stays inside this data region while the entered code and original intent remain available. Because the start route intentionally returns the same `401 iam.authentication.failed` for a wrong current password and an invalid bearer, the Provider performs a bearer-only contact read before expiring the console Session. A successful same-owner read proves the Session is still valid and converts only that start failure into a client-owned password rejection: the password field is cleared, focused and marked invalid while the email and login remain. A non-`401` observation failure preserves the Session but keeps the operation error generic because it cannot prove the password was wrong; only a second `401` expires the Session. IAM follow-up `c53abadc98b28a192ec676bf279a0b6c52343ce2` adds the corresponding direct HTTP regression without changing production wire. Code confirmation distinguishes the fixed failure classes instead of collapsing them into one alert: `422` clears and focuses the invalid eight-digit field for correction, while `429` fails closed by disabling further code submission and retaining only the original intent's read-only status refresh. Neither path creates another request ID or sends another code. No resend, replacement, removal, administrator-change or subscription control is rendered because no such LIVE contract exists. Current source and synchronized embed are pushed at `4e78947a9`; the focused 105-case account-access run and complete 58-file/979-case frontend suite passed with type/lint/architecture/228-pair style gates, three export-normalization cases, 42-route static export and repository Go test/vet. This is contract-aligned UI and provider evidence, not real SMTP delivery or LIVE browser acceptance; the explicit MOCK settings flow remains separate and unchanged. |
| Personal MFA lifecycle | The stable settings surface separates LIVE personal-factor/contact data from the isolated MOCK account rule. One-time recovery material is limited to the original Session and request; late results cannot cross a new Session or intent, while a fresh same-User Session may still read the original non-secret outcome. Only data-bearing regions load, and a Session change remounts private content without showing the prior User's facts. The 42-file/685-case frontend run, three normalization checks, type/lint/architecture/228-pair style gates, 40-page export, 223-file embed equivalence and Go test/vet passed. Source and synchronized embed are pushed at `3b954402`; exact contract, security tests and remaining real-IAM acceptance are owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#本人-mfa-生命周期的开发验收证据). |
| Isolated authenticator replacement preview | The DEV-only personal-security flow preserves the active authenticator until confirmation, freezes the original proof deadline and keeps LIVE replacement closed. Shared gates above passed; a `390 × 844` DEV flow had no document overflow or new warning/error. Source and synchronized embed are pushed at `49bc9722`; exact behavior and limitations belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#本人-mfa-生命周期的开发验收证据). |
| Fixed IAM login challenge client | Login consumes the strict IAM-009 `AUTHENTICATED` / `CHALLENGE_REQUIRED` union. `LOGIN/TOTP` remains sessionless until verification; exact `LOGIN/RECOVER` opens only the restricted recovery path, while a `RECOVERY` challenge is rejected from LoginResponse. Challenge-bound password replacement and recovery confirmation both clear restricted material and require a fresh login. Authentication generations discard late results after expiry, cancellation or a newer login. Unresolved recovery is scoped to the original loginName, so another identity's challenge is never routed into its result flow. The DEV MFA entry runs the same state machine for direct success, password replacement and irreversible recovery, with visibly labelled inputs and no browser persistence. The latest recovery source and synchronized embed are pushed at `d7d6333d`; full evidence and backend-candidate limitations are owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#受限自助-totp-恢复客户端的开发验收证据). |
| Account security settings | The explicit MOCK page now separates personal security, account policy and session security behind one stable security-configuration frame. Only the personal section mounts initially; account/session sections mount on first entry and then retain drafts while their inactive panels leave layout. The account MFA editor still requires bound personal TOTP and normal re-login, and its UNKNOWN recovery remains in content. Passkey and session-idle remain labelled previews and do not become live contracts. The LIVE page keeps its existing personal-security and read-only current-account surfaces; 403 remains local and unavailable data never falls back to MOCK. A fresh desktop and `390 × 844` DEV check found one, then two, then three mounted panels; inactive panels computed to `display:none`, no Dialog or document overflow appeared, and a clean tab emitted no warning/error. The 55-file/886-case frontend run, three normalization cases, type/lint/architecture/228-pair style gates, 41-page export, 228-file embed match and full Go test/vet passed at pushed source `937b9bbd`; this is not real-IAM browser or release acceptance. Exact contract and exclusions are owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#账号级-mfa-要求-mock-的开发验收证据). |
| IAM security-evidence preview | The identity-security overview now separates recommendation state from evidence coverage. Each check distinguishes observed, incomplete, unobserved and not-applicable evidence; a partial User directory yields incomplete or unknown results instead of being extrapolated to the whole Account. Even a non-empty partial directory with zero visible direct grants or pending password changes stays unknown; positive visible findings are only a lower bound. Missing authenticator inventory remains unobserved rather than becoming evidence of no enrollment or safety. The allowlisted MOCK export preserves the same coverage vocabulary and contains no password, Secret, raw entity descriptor, risk score, online/source fact or invented key last-used timestamp. The 123-case access workspace, complete 602-case frontend run, 40-page export, 222-file embed equivalence, Go host and architecture/style gates passed. Compact real DEV kept two readable 2×2 summaries and produced no new warning/error. Contract ownership remains in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#安全报告证据覆盖-mock-的开发验收证据). |
| IAM access-analysis LIVE and isolated preview | The bookmarkable `access-analysis` route keeps one stable heading, boundary and tab frame for both modes; only Analyzer, coverage and Finding data regions load, so fast responses do not flash a whole-page skeleton. Explicit preview mode retains the 123 deterministic MOCK findings, bounded ten-row local pages, failed-scan evidence retention and content-area review journeys. Non-preview mode never imports or falls back to those fixtures: it uses the optional IAM repository capability bound to the current credential and Account, while only a credential-scoped `401` expires that Session. The strict client consumes the fixed S4c-b Analyzer/Finding contract at IAM `91649497a0c53be1174d8835326a2df51fe74a55` and the fixed S4c-c disposition source at `694e0b314d2e78a31380b0a19709bc2f6508e82b`. It rejects unknown or foreign projections, reordered coverage, mismatched Finding targets, invalid lifecycle/recovery facts, missing or invented resolution reasons and illegal disposition combinations. Analyzer create/update and `:set-disposition` use server authority, stable request IDs and resource-version CAS. Finding filtering and pagination remain server-owned (`ALL / ACTIVE / ARCHIVED / RESOLVED` plus opaque cursor); the UI never invents a total or client sort. Archive/unarchive uses the exact Finding version in the content area and never disables the target; resolved findings accept only `CONDITION_CLEARED` or `AUTOMATIC_DISPOSITION`. Denial, unavailable routes, conflicts, invalid responses and authoritative empty results are distinct local states, and none substitutes MOCK data. Report-only is the mandatory default. Explicit opt-in admits only `UNUSED_ACCESS_KEY -> DISABLE_ACCESS_KEY`, requires a 1–30 day delay with fixed default 7 and names the separate `iam.access-analyzer.set-disposition` permission. It is non-retroactive: only a later scan under the new Analyzer revision can form a candidate. Root has no disposable AccessKey entry and platform-operator owners stay protected; User, console password and Role remain report-only. Analyzer and disposition rules use separate content-area edit/review flows. LIVE saves the exact fixed command and reloads authoritative state after a conflict; isolated MOCK changes only the current preview resource version and never calls a repository or changes a real object. The complete 59-file/1,023-case frontend suite plus three normalization cases, typecheck, lint, architecture, 228-pair theme styles, 45 generated pages, 43 normalized segment files, 249-file embed equality and full repository Go test/vet passed. The in-app browser exercised disposition summary/configuration at desktop and `390 × 844`; document/body/client/scroll width all remained 390px, no Dialog appeared, and browser warning/error logs were empty. The 4317 isolated preview remains HTTP 200 and browser-checkable. IAM [Verification 37106511260](https://github.com/xiak/matrix/actions/runs/37106511260) independently verified the exact S4c-b backend SHA with all 15 jobs `completed/success` and no failure, cancellation, timeout or skip. S4c-c [Verification 37121620003](https://github.com/xiak/matrix/actions/runs/37121620003) now reports an `authority-runtime` failure; its fixed source can still bound the fail-closed client, but no backend runtime or release acceptance is inherited. A real-IAM browser flow remains open; this row proves the reusable client/UX boundary, isolated preview and fixed source contracts, not installed-runtime or release acceptance. Exact semantics and exclusions belong to [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#访问分析-live-与隔离-mock-的开发验收证据). |
| IAM immutable account-security-report preview | The content-area confirmation still produces one synchronous, all-or-nothing MOCK result while the credential inventory stays separate. It mirrors the fixed IAM-only shape: Root counts toward the User limit; metadata includes the Account security-settings version; four exact sources are `COMPLETE` and five are `NOT_INCLUDED`; User and AccessKey evidence tables retain identity, state, resource version and bounded observations without Secret material. `NOT_OBSERVED_IN_RETAINED_IAM_STATE` is never translated into “never used,” and Allow/Deny is never presented as business success. Shared preflight enforces the 1000-User, 2000-AccessKey and 3001-row boundaries; the canonical 4 MiB body limit remains server-owned and CSV remains unavailable in MOCK. The former direct overview entry is replaced by a bookmarkable `security-reports` content page under Identity security. Because IAM currently exposes create, read and download only by `reportId` and has no list API, its three-row directory, search/filter states, coverage, readable/expiring/expired counts and relative expiry times are explicitly local fixtures. An expired row opens only synthetic metadata: no evidence body, CSV action, deletion or overwrite. A readable fixture opens the existing immutable detail; Generate opens the same scope review in the content area. LIVE renders `LIVE · NOT_CONNECTED`, sends no request and never falls back to fixtures. The directory is not a server collection, background job queue, cross-product posture, risk score or auto-remediation surface. Existing capacity regression `fccd0847f` continues to prove paged 1000-User/2000-AccessKey evidence. Source and synchronized embed are fixed at `c599c0a2c`; the focused 214-case contract/workspace run and complete 58-file/1004-case frontend suite passed with three normalization cases, typecheck/lint/architecture/228-pair style gates, 44 static routes, 244 embedded files and full repository Go test/vet. Desktop and `390 × 844` DEV verified the directory and expired-detail hierarchy, zero horizontal overflow and empty warning/error logs. Exact report limits and service semantics remain in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#安全报告证据覆盖-mock-的开发验收证据). |
| Real DEV browser | Using the real Products & services directory on the normal DEV server, IAM-to-Regions, Applications, PostgreSQL installations, Logs, DevOps, Observability and back-to-IAM navigation exposed the destination H1, product context and stable frame immediately; slow commits kept the outgoing IAM content absent while only destination-owned data feedback remained. The current 16 IAM destinations were then reached through the real compact product navigation at `360 × 800`, first in Chinese/light and again in English/dark. Every accepted client transition produced the exact localized H1; document and body width remained exactly 360px on every route, no Dialog survived navigation, and the clean browser session emitted no warning/error. Earlier desktop and compact interaction checks continue to cover shared page actions, content-area association, Escape focus return and service-to-service loading isolation. The audit restored Chinese/light and the default viewport before handoff. This is DEV shell/interaction evidence, not installed-release or real-IAM acceptance. |
| Own login sessions | The strict browser adapter consumes the fixed IAM contract at `3080922f6ae1871f1c351d5ee30f03551fc3c605`: owner-bound active sessions, opaque cursor and exact-target idempotent revoke only. Tests reject unknown fields, foreign account/user projections, invalid time windows, noncanonical ordering/cursors and mismatched revocation targets. Provider tests prove exact request-ID reuse after an unknown outcome, no replay across a new login and credential-scoped 401 expiry. Preview and renderer tests distinguish sessions from devices/online activity and keep the current logout separate from confirmed other-session revocation. The real DEV deep link rendered the fixed content and three MOCK sessions at desktop and `390 × 844px`; the page width remained 390px while only the 820px native table scrolled internally. Refresh, compact page actions and inline revoke confirmation remained reachable. A fresh reload/login emitted no new warning or error. No real session was revoked. This is frontend integration against the named contract, not inheritance of its backend acceptance. |
| Session-expiry rule preview | Below the own-session directory, DEV/explicit preview mode compares a server-recorded explicit action, background polling/ordinary bearer request, and the absolute session deadline. No fictional threshold, countdown, active setting, timer or API write is presented. The LIVE directory stays primary; production without preview hides this rule card. A direct component test covers scenario switching and absence of action/timer. In real DEV at `390 × 844px`, the card remained one column with document/body width 390px and no browser warning/error. This is an isolated MOCK explanation pending IAM's fixed idle contract, not a live expiration implementation; boundary ownership is [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#登录会话到期规则的隔离-ux-预览). |
| User reset review and password entry | The existing User reset action now reviews exact target identity and session impact inline before issuing its unchanged command; the temporary password never appears in review and is cleared before dispatch. New-password entry across User creation/reset, root recovery, first change and restricted challenge change now uses the fixed product bound of 15–128 Unicode code points/512 UTF-8 bytes without trimming or character-class guesses. Existing-password login remains unaffected; account-specific requirements and history are final IAM checks, not a client permit. This follows IAM-009 fixed candidate `3178b649` and its exact-SHA successful independent verification, but does not consume its unfinished settings/requirements API or inherit backend acceptance. The 45-file/786-case frontend run, type/lint/architecture/228-pair styles, 41-page export, 228-file embedded equivalence, three normalization cases and Go UI host test/vet passed. The 4317 isolated MOCK preview remains available. |
| User reset result feedback | An uncertain administrator reset retains its non-secret original request across IAM navigation and live same-identity reload. The user can explicitly query that request; 404, denial and unavailable responses keep the reset locked, while a strictly bound committed response permits finishing review. No unknown outcome offers a one-click unlock or a second password POST. The 45-file/806-case frontend run, three normalization cases, type/lint/architecture/228-pair theme gates, 41-page export, 228-file embedded comparison and Go UI test/vet passed. The 4317 MOCK entry remains reachable; this is client and isolated-MOCK evidence, not real-IAM browser or backend CI acceptance. Contract limits and runtime gates remain in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md). |
| User reset unknown outcome | Online reset currently has resource-version CAS but no result lookup or equal replay. The UI sends one stable request ID, treats explicit 400/401/403/409/422 responses as rejected, and treats transport/protocol/server uncertainty as **unconfirmed**, never as a safe retry. It clears the temporary password before dispatch and retains only account, actor, target, resource version and request ID in the current IAM view session. A warning remains visible across IAM navigation; while present it blocks another reset until the operator explicitly acknowledges overwrite risk. In LIVE only, the six non-secret fields are also saved as a best-effort tab-scoped reminder. A reload restores it only after the server confirms the same Account and actor; malformed or foreign records are ignored. MOCK uses no browser storage. Reminder loss or dismissal is not evidence of backend success, failure or permission to retry; the operator must investigate the original request ID. No automatic retry occurs. The 45-file/792-case frontend run, type/lint/architecture/228-pair styles, 41-page static export, 228-file embed equivalence, three normalization cases and full Go test/vet passed. This is not real backend reset acceptance. |
| Password-age and expiry-response preview | The isolated Account settings card keeps four distinct age-evidence scenarios and now previews both restricted change and administrator reset handling. `AGE_UNKNOWN` is never presented as confirmed expiry; the `ADMIN_RESET_REQUIRED` path offers contact/re-login guidance only, with no password form, identity recovery, resend or automatic session. Neither path reads live settings or issues a challenge, credential, reset request or session. At `390px`, the administrator-reset path rendered without document/body overflow and the expected guidance was visible. The 45-file/806-case frontend run, three normalization cases, type/lint/architecture/228-pair theme gates, 41-page export, 228-file embed match and Go UI test/vet passed. Source/embed are pushed at `0e537ec5`; this is MOCK UX evidence only, not acceptance of the unfinished IAM-009 S3c wire/runtime. Exact boundaries remain in [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#密码年龄与受限改密的隔离-ux-预览). |
| Draft-leave browser behavior | A temporary, unsubmitted JSON draft remained intact after Continue editing. Discard and leave then immediately displayed the Regions frame; the old editor and loading feedback were absent after the actual route commit. No policy or association was created or changed. |
| Cross-product Operation subject attribution | The MOCK operation center replaces its ambiguous actor string with the public PaaS `SubjectRef` shape from fixed source `b6d15c89a`: `type`, `id`, optional `accessKeyId` and optional Role-session lineage remain separate facts. A collapsed row shows only product, typed initiating identity and time; its content-area disclosure shows the exact identity, non-secret AccessKey ID or Role-session ID, and the Role session's source User or service account. Search includes those public attribution identifiers without exposing or accepting a Secret, signature, nonce, request digest, internal evidence or Account selector. A missing `accessKeyId` is not inferred to be another credential, and a Role is not collapsed into its source identity. This is a reusable MOCK projection over the existing public Operation response, not a new audit model, LIVE operation client or proof that a business request was authorized. The unpushed revision-10 Profile candidate is deliberately absent. Source and synchronized embed are pushed at `1fd55d773`; the focused renderer file passed 7 cases and the complete frontend suite passed 57 files/933 cases plus three normalization cases, type/lint/architecture/228-pair style gates, 42-route export, 233-file embed equality and repository Go test/vet. Desktop and `390 × 844` DEV verified the collapsed hierarchy and expanded AccessKey attribution with viewport/document/body all 390px, no Dialog, horizontal overflow or browser warning/error. |
| Audit query progressive disclosure | The Audit directory keeps its stable title, tenant boundary and current records visible while structured query controls stay collapsed by default. One persistent query trigger reports the number of applied semantic conditions, while refresh remains fixed at the opposite edge and never shifts when the filter form opens. Applying or resetting a valid query closes the form and restores focus to the trigger; invalid Role-session lineage remains local and keeps the fields available for correction. A later query preserves the last successful table with `aria-busy` and localized refresh status instead of replacing the whole content area with a short-lived skeleton. The UI consumes only the fixed Audit query contract: time, Action, typed actor lineage and page size; it does not invent an `operationId`, source, result or target filter merely because public Audit records contain those fields. The current directory follows public-cloud audit scanning hierarchy: the exact Action is the single semantic record entry, source/time/sequence form its secondary event line, and the former separate time column is removed. Non-secret AccessKey attribution and complete Role-session lineage remain visible beside the actor without exposing a Secret, signature or internal decision material. Record detail keeps Action in its event heading and now names the producer source as the primary source fact rather than repeating Action as both value and label. The result guide and record-specific evidence card distinguish `ACCEPTED`, `SUCCEEDED`, `ALLOWED` and `DENIED` from Operation completion, product execution, resource existence and business success; the browser therefore does not upgrade one immutable event into a current permission or final outcome. Source and synchronized embed are pushed at `3ba107f82`. The complete frontend suite passed 58 files/1010 cases plus three normalization cases, type/lint/architecture/228-pair style gates, 45-page export, 249-file embed equality and repository Go test/vet. A fresh `1280px` DEV session verified the directory guide and `ALLOWED` detail with no Dialog, horizontal overflow or browser warning/error; prior desktop and `390 × 844` checks covered the remaining result examples and compact hierarchy. This remains MOCK evidence over the fixed Audit projection, not a new filter, entity reverse lookup, LIVE mutation or authorization conclusion. |

The LIVE Role detail now reads the fixed IAM-006 immutable trust-version
directory from source `c53abadc98b28a192ec676bf279a0b6c52343ce2`. The tab is
lazy: stable Role facts and controls render first, and only its own table uses
loading feedback. Each response is rejected unless Account, Role, opaque
continuation, order and every canonical SHA-256 document digest agree. A
version opens read-only in the content area rather than a Dialog; historical
documents cannot be selected as current because no such mutation was added.
The Role workspace is keyed by Account and session revision, so an old session
cannot leave trust data mounted for a replacement credential. No trust update,
cross-Account principal, service-trust inference or MOCK fallback is introduced.
Source and synchronized embed are pushed at `9acdda9e5`; the complete
58-file/981-case frontend suite plus three normalization cases,
type/lint/architecture/228-pair style gates, 42-route export and full repository
Go test/vet passed. Real-IAM browser and release acceptance remain separate;
exact semantics are owned by
[FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#role-管理与管理员会话-live-客户端的开发验收证据).

The same LIVE Role detail owns the fixed mandatory permission-boundary read and
mutation lifecycle from IAM source
`c53abadc98b28a192ec676bf279a0b6c52343ce2`. Stable Role facts remain mounted
while only the boundary value loads or retries; strict parsing rejects a
mismatched Account or Role, unknown fields, invalid resource version,
noncanonical policy reference, non-lowercase SHA-256 digest and non-concurrent
write outcome. A null Role boundary is rendered as “no permission ceiling; role
assumption closed,” never as an unlimited ceiling or a generic missing setting;
a read failure stays unknown and cannot be converted into that null state. The
inline editor is controlled by the exact server-returned set/remove
capabilities, loads a fresh tenant policy directory only after opening, and
freezes policy version, boundary revision and request ID across review. A `503`
keeps the exact original command for byte-for-byte retry; a `409` rereads the
Role, boundary and eligible policy directory before requiring a new review; an
acknowledged write followed by failed readback is labelled applied and retries
only the authoritative read. No Dialog, optimistic success, inferred grant or
new backend error is introduced. The isolated MOCK remains available and keeps
the same fail-closed invariant: a Role may be created without a boundary, but it
cannot issue a new preview session, and removing the boundary cannot turn an
existing preview session into an unbounded one. Distinct User-boundary null
semantics are unchanged. Read-only source/embed began at `2febfb268`; the
complete GET/PUT/DELETE content-area workflow and synchronized embed are pushed
at `f366cdcd7`. The focused 221-case run and complete 58-file/995-case frontend
suite plus three normalization cases, type/lint/architecture/228-pair style
gates, 42-route export, 233-file embedded equality and full repository Go
test/vet passed. The DEV MOCK Role detail retained its inline editor with no
Dialog or browser warning/error. Real-IAM browser and release acceptance remain
separate; exact Role-boundary semantics remain owned by
[FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#role-管理与管理员会话-live-客户端的开发验收证据).

The Profile-driven Action selector now keeps its existing fail-closed statement
compatibility boundary visible instead of communicating it only through disabled
controls. It reports how many Actions can share the current resources and
conditions, and each incompatible row names whether resource shape, prefix
support, exact-instance targeting or an existing condition requires changing
the statement or creating another. These reasons are derived only from the
already-read Profile and are memoized across search, selected-only filtering
and pagination; no Action family, product resource, IAM wire or authorization
result is invented. Source and synchronized embed are pushed at `3ffca742`.
The 99-case LIVE account-access renderer file, typecheck/lint, architecture and
228-pair style gates, 42-route export, 233-file embed equality and UI-host Go
test/vet passed. Desktop and `430 × 900` DEV showed the count and row reason
without a Dialog; viewport, document and body width remained 430px.

Application hosting now owns a query-addressable resource-detail surface rather
than sending its resource row back to the same undifferentiated directory. The
same-path transition retains the shared console frame and immediately renders a
stable application locator, title region and return action; only the
product-data region changes, so it does not open a Dialog or replace fixed
content with a page-wide skeleton. The scene now carries the Application
directory source explicitly instead of forcing the renderer to infer it from
`resources: []`. Preview renders a visibly labelled isolated local-navigation
fixture and states that it is neither a server-side collection nor an
authorization result. Non-preview renders a distinct unavailable state with no
search, table, count or fixture fallback; it therefore cannot misrepresent an
unfixed product list as a successful zero-resource response. Neither state
claims a product list, cursor or paging contract. The separate exact-read
snapshot mirrors only the fixed
`GET /v1/applications/{applicationId}` response: `apiVersion`, `kind`, public
metadata, tenant scope and the strong response ETag. The current Account comes
from the authenticated identity; the browser never offers an Account or tenant
selector. A `200` state renders that returned Application, while `403` removes
the name, tenant metadata, Deployment and tag actions and explicitly refuses to
confirm whether the requested identifier exists. A `503` state likewise keeps
the stable locator but discards stale product data and offers only an equal
re-read of the same identifier. Neither state performs local policy evaluation
or upgrades directory visibility into authorization. Product-owned Deployment
and tag workspaces mount only after a readable Application. The isolated preview
then adds the product-owned tag snapshot, its ETag and an explicit mapping for
the one `resource.tag/environment` condition declared by the current MOCK
Profile. Other resource tags remain visibly outside that Profile. Its new
content-area workflow deliberately does not reuse the batch metadata editor:
one set/update or delete command owns one tag key, one review and one simulated
ETag advance. Review shows the exact resource, current version and old-to-new
value, warns when `environment` can change later IAM decisions, and states that
tags are searchable plain text rather than a place for secrets or personal
data. Invalid public PaaS label keys/values remain in the editor with focused
field feedback; draft-leave protection remains shared. The component identity
is the resource ID plus authoritative input ETag, so a server version change
replaces only this local workflow without an effect-driven synchronization
render. Unknown query identifiers and absent snapshots still fail closed.
Policy authoring never mutates persisted resource tags, and the MOCK apply never
calls a backend, changes a real resource or invents Audit proof. The workflow
now adopts the exact fixed candidate `e9ea19e65` as UI contract evidence without
claiming LIVE integration: review names `paas.application-label.set` or
`paas.application-label.delete` and the strong current ETag used by `If-Match`;
the simulated terminal result exposes only the returned Operation's safe
identity, Action, state, target, requester, completion time and replacement
ETag. It does not surface idempotency fingerprints, request digests or an
invented Audit event ID. LIVE will distinguish no-change and idempotency
conflicts, reload before retry after a 412 version conflict, and never invent a
422 branch. A collapsed MOCK-only response selector now proves those recovery
rules without cluttering the default success path: no-change, idempotency
conflict and denial offer no blind retry; a 412 replaces the reviewed snapshot
and ETag and requires a newly confirmed request identity; IAM unavailability
and response loss retain the original intent for an equal safe replay. The
backend SHA remains a fixed candidate until its independent CI is registered,
so no LIVE adapter consumes it yet. Source and synchronized embed are pushed at
`2ea35d477`. The complete
57-file/927-case frontend suite and three export-normalization cases,
typecheck/lint, architecture and 228-pair style gates, 42-route static export,
233-file embed equality and UI-host Go test/vet passed. Fresh desktop and
`430 × 900` DEV walked view → edit → stale-version response → refreshed review
→ newly confirmed terminal result with focus restoration, no operational Dialog
and viewport/document/body width all 430px; a fresh validation tab emitted no
warning or error. The original long-lived DEV tab still retains historical HMR
translation errors from before the message catalog landed; they are not
current-runtime evidence. This is application-side MOCK UX evidence, not real
resource-tag mutation, backend CI or authorization acceptance.

The Application read follow-up consumes only the fixed
`0f06607398f643311c5a284cf0867e931ed33d9b` product boundary and now integrates
the LIVE exact-resource endpoint at `/api/paas/v1/applications/{applicationId}`.
It deliberately does not consume the still-unfixed Application list, cursor or
page contract: a deep link can read one resource, while the LIVE directory
continues to render unavailable with no table, search, count or fixture
fallback. The public Application model and portable label validation now have a
single frontend domain owner shared by the adapter and MOCK tag editor. The
adapter rejects an invalid locator before I/O and parses successful responses
fail closed: exact fields and constants, route/body identity, TENANT scope,
positive safe resource version, ordered contract timestamps, bounded safe
labels and a canonical strong ETag equal to that version are all required.
Unknown fields, raw sensitive label material, a weak/missing/mismatched ETag or
cross-resource response becomes unavailable data rather than a partial success.

The detail frame owns only this local asynchronous read; it is not added to the
page-level resource cache and therefore does not invalidate the header,
navigation, directory or whole scene. Return action, destination title, stable
locator and state badge render immediately. A polite status appears immediately
and the six-field placeholder is delayed 200 ms within the data region, avoiding
a skeleton flash for a fast response. `401`, `403`, `404` and invalid locators
remain distinct from `5xx`; forbidden reads do not confirm existence or mount
tenant metadata, Deployment or tag actions, unavailable reads can retry only the
same locator, and neither case reuses stale data. Product-owned Deployment and
tag MOCK workspaces remain isolated and mount only for the preview's readable
snapshot; LIVE exact read does not invent those write contracts.

Source and the synchronized embed are pushed at `207f0e6ed`. The focused
repository/shell run passed 105 cases. The complete frontend suite passed 63
files/1,112 cases plus three export-normalization cases. Typecheck, lint,
architecture and 228-pair theme-style gates passed; the production build
generated 46 routes, normalized 44 segment files and synchronized 254 exact
embedded files, and the complete repository Go test/vet gates passed. Desktop
`1280 × 720` and compact `390 × 844` DEV retained the Application title, return
action and locator with viewport, document and body widths equal, no Dialog and
no browser warning/error. The visible MOCK state matrix exercised `200` → `403`
→ `503` → equal re-read recovery; adapter and shell tests cover the LIVE pending,
success, invalid, forbidden, absent and unavailable boundaries. This is a real
LIVE exact-read client boundary plus isolated product UX evidence, not an
Application list contract, browser-side policy evaluation, resource-existence
oracle, completed Deployment/tag integration or full-stack release acceptance.

Same-path detail-query tests retain encoded IDs, draft-leave protection and
replace semantics without a Next page-tree navigation. Real static deep links
and browser back/forward observations belong to the
[User-boundary evidence](../../IAM/FEAT-IAM-010-console.md#user-权限边界片的开发联调证据).
The one-click DEV MOCK entry still returns to the requested User directory.
The normal DEV preview remains independent. ContentPage and PageSkeleton own
the shared transition behavior; the control-plane loading renderer selects a
destination structure and feature-owned data-region placeholder rather than
giving individual pages navigation timers. The committed URL and business
selection remain Next-owned until the real page transition completes. An
immediate provider projection reuses only an authoritative preview or managed
snapshot and cannot create data or authority. A true managed-service cache miss
retains the destination structure plus regional loading feedback instead of
inventing an empty success scene.

The IAM service-authorization directory now follows the same addressable task
contract as the other content workspaces. The Role collection dispatches
`/console/access/service-authorizations/` instead of retaining an inline-open
flag; the service-authorization renderer alone owns its remote data and local
detail state. Direct parsing keeps the Role navigation item selected, the
shared content header supplies the Role parent/back route, and the DEV MOCK
entry returns to the requested deep link after its memory-only session is
re-entered. Focused scene, route, MOCK and LIVE renderer cases cover that
boundary; the browser observed the exact URL, selected Role navigation, no
Dialog, deterministic return to `/console/access/roles/`, and no warning or
error log. The complete 63-file/1,089-case frontend suite plus three export
normalization cases, typecheck, lint, architecture, 228-pair style gates,
46-page static build, 254-file embedded equivalence and repository Go test/vet
all passed.

These gates do not establish a universal click-latency budget, a new whole-repository
or PostgreSQL runtime regression, a new APISIX installation/upgrade, or complete
IAM acceptance. Earlier live User-boundary evidence retains its named source
and is not inherited as a new backend acceptance result.

| IAM AuthorizationProfile candidate diff preview | The isolated product-onboarding review now compares the current catalog declaration with a visibly synthetic candidate in its IAM-validation stage. It fixes both immutable references and reports only structural declaration additions, removals and changes across product/calling-service and the complete Action shape; invalid revisions, duplicate Actions and cross-product candidates fail closed. Revision order, digest and diff counts never become an expansion/reduction, identity-impact, Allow/Deny, migration, PEP, approval, rollback or publish conclusion. No upload, save, ACTIVE or publish control exists, the entry stays absent from LIVE and no repository write occurs. The three-column table mounts only the current 10-row page; a 1,202-change behavior case proves pagination, while desktop and `390 × 844` checks show no Dialog, overflow or browser warning/error. Source and synchronized embed are pushed at `6314911b2`; 197 focused cases and the complete 62-file/1,047-case frontend suite passed with three normalization tests, type/lint/architecture/228-pair style gates, 45-page export, 43 normalized paths, 249-file embed equality and repository Go test/vet. Exact exclusions remain owned by [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md#权限能力目录片的开发验收证据). |

### Retained shared UX and earlier named release evidence

- Live user and tenant cursor actions own their repository reads independently:
  user paging does not reload the current identity, tenant directory, policy
  directories or preview graph, and tenant paging does not reload the user or
  policy directories. The full refresh remains the explicit owner for related
  identity, capability and preview-workspace changes. A regression verifies the
  exact call boundary and signed cursor handoff for both directories; paging is
  never used as an implicit whole-account refresh.
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
  remain unavailable. The shared catalog-driven author supports only exact
  Profile-declared trusted request and resource conditions; the revision-5
  resource-tag example remains isolated MOCK until its backend gates are green,
  and tag mutation is not part of policy authoring. The separate four-method
  resource-tag preview now scopes its request-tag omission to that isolated
  MOCK and directs catalog-driven behavior to the selected product Profile,
  rather than implying a platform-wide limitation. No Tencent authorization
  was created or changed.
  Header/shell and appearance regression cases pass, including
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
  stops. Browser checks
  verify the equal 56px context bars for users and federations, detail and
  creation return controls, immediate route acknowledgement and delayed destination
  titles/skeletons for sustained waits, progress
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
  after cancelling an association dialog. A 1477px desktop selection check
  measured zero horizontal movement for both fixed Header commands: Users kept
  More/Create at x=1239/1349 and Policies kept More/Create at x=1200/1310 while
  selection count and Clear appeared to their left. The compact user and Transfer tables
  scroll locally without widening the 360px document. Wizard checks preserve
  required-field errors, page selection counts, opaque footer and guarded
  cancellation; the temporary draft was discarded without creating an account.
  Fresh-reload message checks verify full expanded content and read-state
  feedback without new warning/error logs. Shared control tests cover required
  semantics, classification/status distinction, controlled paging and dialog
  focus return; existing large-candidate and batch/permission gates remain.
  All 970 frontend tests and three static-export normalization tests pass,
  alongside TypeScript, lint, architecture and 228 theme contrast checks.
  All 233 generated production files from 42 static routes match the Go-embedded export, and Go UI
  tests and vet pass. Tables, forms, dialogs, choices,
  feedback, tabs and metrics use the public controls and shared composition
  described above; source-provided data is not mistranslated as interface copy.
  Policy-detail command composition is additionally browser-checked on desktop
  and at 390 x 844: Associate users / groups / roles remains the single direct
  desktop command; Edit, Copy as custom policy and Delete share one More menu;
  and the compact Page actions menu contains the same four commands without a
  second action row or title shift. The same public composition is exercised by
  account live roles, own sessions and every IAM workspace collection/detail;
  permission callbacks, disabled reasons and destructive classification remain
  feature-owned. Source and synchronized embedded UI are fixed at `6ce077f73`.
  Extended IAM tests cover group membership, inherited permissions, policy
  editing/version/association invariants, provider-role dependencies,
  enterprise visibility and ungranted member import, one-time MOCK secrets,
  disabled-before-delete keys, reset isolation, safe reports, all registered
  bookmarkable IAM subroutes and IAM navigation independent of PaaS reads.
  Account-identity regression cases prove the owner summary is independent of
  administrator grants, unknown facts remain unknown, and access methods do
  not imply permissions. RootIdentity is absent from the user table, select-all,
  group candidates and ordinary policy/credential/lifecycle commands; forged
  owner IDs are rejected by both batch and workspace transitions. Ordinary-user
  group membership and user-to-group detail navigation remain covered. These
  checks do not establish live Tencent mutation behavior or final Matrix
  resource authorization; live Matrix group-management evidence is described
  below.
  The fixed live IAM projection now replaces built-in-role inference with
  direct, revisioned USER policy attachments and independent tenant/platform
  policy metadata directories. `iam.account.read` and `iam.account.create`
  remain independent navigation and action capabilities: a reader can reach the
  tenant directory without being offered account creation. Tenant rows retain
  the approved object-name navigation instead of an operation column; the
  content-area account detail exposes status and root-credential recovery only
  from their exact per-account capabilities, explains stable restriction
  reasons before a dead-end click, and requires an impact review before either
  mutation. The protected installation account and a manageable preview tenant
  were browser-checked in light, mixed and dark themes without changing either
  account. RootIdentity entries returned inside `UserList` now invalidate the
  whole live scene rather than entering ordinary-user selection. Focused
  contract and renderer verification includes new-user default deny, missing platform metadata,
  403 section degradation, non-authorization failure closure, stale policy
  reselection, exact attach/revoke revisions and preservation of the explicit
  MOCK workspace. This is management-plane evidence only; it does not claim
  policy documents or final effective authorization from a directory response.
  A live user selection now replaces the directory immediately with a stable
  detail frame built from the directory's already verified identity. Only the
  exact-target region uses a local skeleton while the dedicated `UserAccess`
  route resolves; no write affordance appears before exact capabilities, and
  failure retains the read-only identity context with an in-place retry. The
  global shell and directory provider do not own that request's loading state.
  The resulting detail updates only `displayName`
  with optimistic resource-version concurrency and does not infer console
  access, programmatic access or credentials from user status. Irreversible
  deletion stays unavailable while IAM reports `TARGET_MUST_BE_DISABLED`; once
  available, the user must type the immutable login name after reviewing the
  retained identity and resource effects. The client accepts only the strict
  non-secret deletion receipt. Target-read failures remain local and never
  fall back to MOCK or distinguish forbidden, cross-account and absent users.
  Focused transport and renderer tests cover exact paths and payloads, closed
  capability parsing, immediate loading feedback, profile revision handling,
  the disabled-before-delete gate and typed acknowledgement.
  Four user-directory integration journeys and ten batch transaction cases
  cover no-selection and current-page/mixed selection, filter/page clearing,
  primary/self protection, additive associations, stale/invalid target atomicity,
  shared deletion cleanup, review/cancel, duplicate-submit suppression,
  failure/retry, locale-preserved review and live single-user fallback. The
  desktop MOCK browser check at 1468 x 866 verifies the removed operation
  column, selection-driven menu, disabled explanations and group append/review;
  the original membership and grants remain intact. The synthetic membership
  added during that check was removed. Batch writes remain preview-only.
  The group directory is now an action-free locator: Preview shows its complete
  local membership sample and direct-policy counts, while live pages show only
  aggregates explicitly supplied by IAM. Edit, delete and relationship changes
  live in the selected group detail; member rows no longer duplicate a trailing
  operation column, and the empty state no longer suggests that RootIdentity
  can join a group. Shared small-directory and policy searches defer list
  calculation from the controlled input update so large preview policy sets
  do not put synchronous filtering work on the keystroke path. The fixed live
  group slice uses exact capabilities and stable relation IDs, keeps the
  signed opaque continuation inside the strict transport boundary, performs no
  N+1 user lookups and never presents one-item relation commands as atomic
  batch writes. The adapter accepts only the fixed bounded `ic1.` shape,
  verifies stable ID order within a returned page and never compares the
  continuation to resource IDs; application and presentation layers only pass
  it back unchanged.
  Group detail now renders its stable identity, metadata and direct-policy
  facts as soon as the exact group read succeeds; it does not wait for the
  membership relationship page. The member region uses the shared public
  `TableSkeleton`, keeps its loading/failure/retry state local and disables
  relationship-changing actions until the member facts are ready. A failed
  member read therefore neither blanks the group object nor reloads its exact
  object route when the user retries.
  The focused group-contract regression has 214 passing tests across the HTTP
  adapter, live/Preview renderers and isolated workspace repository. A desktop
  browser check on the existing 4317 DEMO verified the shared group detail and
  immediate add-member dialog without submitting a relationship change. The
  complete frontend gate, static export, 213-file Go embed comparison, Go UI
  test and Go vet all pass for this slice.
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
  TagEditor is shared with user creation, and policy association pages reuse the
  same bounded Transfer and Wizard compositions as the authoring workflow.
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
  resources block saving. The bookmarkable IAM policy-configuration route is a
  configuration review, not a policy-coverage or effective-access result. It
  inventories direct/group/Role/boundary references, local default versions,
  statement fields and condition-key presence without calling a policy evaluator.
  It explicitly labels backend PDP, session/credential truth, resource policy,
  product PEP and business execution as `NOT_EVALUATED`; changing an input removes
  the previous worksheet before a new local inventory can be generated. The
  superseded policy-coverage component, route and embedded export were removed in
  the same replacement; the route parser and Go static-server tests retain only
  the truthful policy-configuration URL.
  The expanded UI tests cover invalid local identities, input reset, direct and
  group references, boundary-document inventory, raw Deny declarations without
  prioritization, empty references, condition-field presence, locale switching
  and the absence of evaluator decision text. Changing source IP cannot turn the
  worksheet into an authorization result. Browser verification at desktop and
  `390 × 844` covered the Chinese/light worksheet; its scope cards change from
  four columns to one and the statement table becomes a labelled vertical card
  instead of horizontal page overflow. Generating a worksheet moves focus into
  its heading. The pure preview evaluator remains separately tested for the MOCK
  flows that still own it, but it is not imported by this page or release evidence.
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
  Group creation now uses the bookmarkable two-step `create-group` route,
  replacing the combined metadata/member/policy dialog. Creation saves an
  empty group only; metadata editing never replaces memberships or policies.
  The group workspace owns reusable directory, detail, member-table and
  policy-table projections separately from its Preview adapter. It consumes normalized
  records and explicit action controls, disables mutating entries while a read
  or write is active, and renders the member-count column only when the adapter
  supplies an authoritative total. A focused interaction test proves that a
  live-style directory without that aggregate does not invent the column.
  Separate add/remove commands validate references and change one membership
  or direct policy attachment per independent intent, without presenting
  several requests as an atomic batch. Public Transfer controls retain the
  pending choice and distinguish an empty directory from an empty selection.
  Changes present the selected object and affected member count before
  confirmation, and failures leave the same choice editable for retry.
  Membership review shows the selected member once; policy review additionally
  identifies affected members. Removing a source
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
  invalid references, one-item UX deltas, unloaded-member preservation, metadata
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
  references and affected identity; policy details expose separately counted
  permission-policy and permission-boundary usage regions, while version impact
  and deletion protection cover both relationship types. Read-only principals
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
  Appearance and locale changes retained the selected role
  principal. English/light at 360 x 800 had a bounded confirmation, wrapping
  copy and visible actions; Chinese/dark and the default viewport were restored.
  Warning/error log inspection returned no entries. Browser-forced or unsupported
  non-cancellable traversal and mobile process termination retain the limitations
  specified above; no draft storage or real credentials were added.
  Supporting-workspace regression adds sixteen cases: six action-classification
  cases and ten UI cases covering exact overview destinations, non-assessment
  security guidance, direct/group directory filters, localized policy metadata,
  key-state cancellation/deletion and isolated settings retries. Empty groups
  and boundaries alone are not
  displayed as grants. Existing enterprise tests prove visibility-constrained
  ungranted import, reference protection and session reset; report tests retain
  allowlisted fields without credentials.
  The browser verified overview-to-policy navigation and Back, matching user
  association details and localized shared controls. The superseded synthetic
  provider and User-SSO mutation flows are removed; current federation acceptance
  is owned by the external-federation readiness row above. Enterprise import
  exposed only the selected visible member, then the
  user directory showed the imported user without granting policies. The
  AccessKey experience now supersedes the earlier window: it first selects a
  non-Root User, then manages that User's keys inline, and removes one-time
  Secret material from the DOM after acknowledgement. Settings explicitly disclaimed real
  MFA/password enforcement/session revocation. Browser warning/error inspection
  returned no entries. Metadata code scrolling is labelled and keyboard-focusable.
  A full reload removed the acceptance-only enterprise member and key;
  the restored Chinese/dark overview showed the original two users, two groups,
  two roles. The federation pages remained explicitly planned and read-only, and the overview
  showed the single initial mock key. No reference-cloud state was changed.
  AppearanceProvider, LogServiceRenderer and Wizard tests still
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
  selector journey creates no new browser warnings or errors. A later compact
  browser check found the shared policy/association Transfer still imposed a
  440px candidate table inside a 320px mobile viewport. The responsive table
  now removes that minimum and moves type annotations beside the option name;
  at 390px the user, group and role candidate tables each measure 320/320px
  table/viewport width, while the create-user policy table measures 280/280px
  at 360px with no document overflow. No real user or
  policy association was submitted on either console. Policy parsing is cached by document text;
  collapsed message details and their destination links are not mounted.
  Wizard tests cover explicit access methods, permission selection, preview
  creation, the live exact-capability contract and access-only dirty-draft cancellation.
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
  A prior 4x-throttled production trace on the IAM roles page measured about
  1,052ms interaction latency, including an eager product-wide provider read and
  substantial first-mount style/layout work. Product discovery no longer starts
  that provider read: regressions prove the IAM content renderer is untouched,
  while choosing a concrete service starts only that destination's declared
  resource slices. Preview-owned Applications, Logs, DevOps and Observability
  start no managed-service read; catalog, Region, Quota and Installation pages
  have distinct least-privilege read sets. A fresh
  memory-only DEV session measured 121ms automation wall time from click to the
  visible seven-service directory and 204ms from choosing PostgreSQL to its
  destination structure and loaded preview rows. These are unthrottled local
  observations, not a field-performance guarantee. First-mount style/layout still
  requires a new 4x production trace before closing the responsiveness target.
  Production preview network checks confirm ordinary and dynamic segment
  prefetch returns 200 after normalization, with no console errors during the
  checked navigation and Header interactions. Go HTTP tests independently prove
  those segment payloads survive embedding. A `390 × 844px` production check
  verifies bounded Header panels, catalog search focus/background isolation,
  repeated trigger closure and lazily mounted message details.
  Chinese/dark and English/light checks include grouped navigation,
  graduated navigation feedback, compact dialogs with retained action
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
  workflow commands remain available in the page-action menu, instance lists precede their forms,
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
  Current navigation acceptance is owned by the development evidence above.
  All animation styling remains theme-owned; reduced-motion behavior is defined
  in the shared controls.
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
  The responsive page-command and authorization-catalog regressions pass all
  513 frontend tests plus three static-export normalization tests. Type, lint,
  architecture and 228 semantic contrast checks pass. Policy authoring uses
  the shared native Table for the preview action catalog: its header checkbox
  selects only the current filtered results, retained selections survive
  filters, and read-only permission definitions expand in the content region
  without a Dialog. The definition separates the authorization target from an
  optional result resource kind and explicitly says that MOCK metadata is not
  an effective grant or product registration. Browser checks at default and
  `390 × 844px` widths verify bounded table scrolling, no page-wide horizontal
  overflow, automatic disclosure visibility below the sticky table header and
  compact mobile rows. Fresh development-browser checks at `360px`
  confirm a `56px` title bar and an identical trailing menu position on Users,
  Groups, Roles, Role SSO, Access keys and tenant directories. Policy selection
  leaves the title/trigger in place. Association now replaces the content area
  with the shared two-step Wizard instead of overlaying a large dialog; return
  navigation restores the policy detail or directory. English/dark and
  Chinese/light policy menus stay within the viewport with separated destructive
  commands. Installation-workspace checks restore the visible trigger when
  closing after both compact-to-desktop and desktop-to-compact resizes.
  The production static export, 213-file embed comparison and Go UI host tests
  pass for this slice; this is not an IAM backend release acceptance.
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
  single-row horizontally browsable tablist, stable trailing action placement, deliberate
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
SAML/OIDC authentication, production MFA enforcement pending IAM-009's fixed
public contract and independent browser acceptance, corporate-directory
integration, custom-policy authorization and mobile-native applications remain outside
this target. Access-management configuration previews do not implement these
backend security capabilities. Vendor-specific collaboration invitations,
message-only identities and batch account creation are not represented as
supported Matrix IAM contracts.

The product and source dependency boundaries remain owned by
[`ADR-0002`](../architecture/ADR-0002-product-boundary.md) and
[`DEPENDENCY-RULES`](../architecture/DEPENDENCY-RULES.md). Fixed donor
decisions are owned by the
[`FEAT-007 adoption review`](../adoption/FEAT-007-control-plane-console.md).
