# FEAT-007 adoption review: Control-plane console and PostgreSQL service activation

- Status: In progress
- Target: [`FEAT-007 Control-plane console and PostgreSQL service activation`](../features/FEAT-007-control-plane-console.md)
- Review date: 2026-08-26
- Direct donor dependency allowed: No

## Fixed baselines

| Donor | Commit | Worktree policy |
| --- | --- | --- |
| Complete Discord-style Next.js UI | `69336e51f94fa98f6aa278fa4c62382e224dbeaf` | Sole architecture and visual-style donor; read only through Git object commands and exclude its worktree. |
| PaaS product-design record | `338d9b5fcb820120c32265e380c55e5f171cdb75` | Product-boundary reference only; it is not a second UI architecture or style donor. |
| Matrix shared interaction fixes | `21b469b343d83a190acc0a3bb34a29b5294191ad` | This repository, fixed Git objects; backport bounded behavior to the existing cloud UI owner, not its replacement shell. |
| IAM account-access capability contract | `25202188f33ca5892880b72d6f6831e476c0bfb1` | Same repository, fixed after verification run `34797635592`. Selectively adapt its public IAM wire/domain semantics and boundary tests into the existing console; do not cherry-pick its generated UI, styles or backend runtime. |
| IAM group authority and management contract | `0bd6dd9dd8166fe31c67edb8cd49cd523606a401` | Same repository, fixed after verification run `34805149946`. Selectively adapt its group, membership, policy-source and relation-command contracts into the existing console; do not cherry-pick its backend, generated assets, UI shell or styles. |
| IAM signed directory continuation contract | `8117c54c112c842106d82fe934e460a280862549` | Same repository, fixed after verification run `34808378047`. Selectively adapt only its account/user/group/membership cursor wire validation and tests into the existing client; do not cherry-pick backend, generated assets or the IAM branch UI. |
| IAM current-identity and User permission-boundary contract | `32dc1a4aab4a69d1c6cb4d04437dd7f8fd739cb0` | Same repository, fixed after verification run `34944465086`. Adapt the mandatory boundary projection, closed nine-capability UserAccess and ACCOUNT collection sentinel into the original client; do not import its renderer, assets or runtime. |
| IAM online policy version and User-boundary integration baseline | `f15cc983a69092528a66eb49b0509b760392187c` | Same repository, fixed after verification run `34955695756`. Inspect public boundary/version references and use its opt-in real-process fixture as a reference; pair it with the UX branch's complete static host and export, not the donor UI. Policy authoring remains a separate integration slice. |
| IAM AccessKey network and authorization-observation contract | `91649497a0c53be1174d8835326a2df51fe74a55`, with production contract introduction at `472596b1edf5fc0fa3f908294bae0624d581dc4f` | Same repository, fixed after exact Verification `37106511260` completed with all 15 jobs successful. Adapt only the per-User public wire, complete account-security projection, strict network rules, historical authorization observation and dedicated AccessKey network mutation. Do not import the IAM branch UI, backend runtime or product-PEP claims. |
| IAM service-authorization observation, public product-write and service-session lineage sources | `a464299b6656becc73054cd53b4a31b44104540b` for the cumulative fixed read contract with terminal-success Verification `36779942782`; `92ea765b` for the public bind/unbind contract whose independent Verification `36701340805` has not passed; `aecc9f1c50f663af9a0bae8198bef0f66c9192af` for contract/Audit lineage acceptance only | Same repository, fixed Git objects. Adapt only the three current-`LOGIN_SESSION` customer reads and keep Account outside browser selection. Adapt only a strict, unmounted public write client while independent verification remains unaccepted. Use the service-source lineage slice only to constrain the MOCK information architecture until a customer-readable session projection is fixed; never call `/v1/internal/*` from the browser, expose an unaccepted LIVE action or inherit the donor UI/runtime. |
| Managed-service Account activation and service-definition contract | `b015b07864c2fcdf85129d57a0babe8332e3356f` (public activation wire unchanged from parent `599d994cddda5f1cb2ee1b4f53b84eafd1458e58`) | `ADAPT` the public service-definition reference, sorted directory, exact `activationCapability`, Account-scoped activation read/create routes, caller-owned idempotency key and Offering-to-service commitment. `REFERENCE` the backend validation and authority tests for the distinction between activation visibility, activation authority and product-resource authority. `REJECT` the donor backend/runtime, IAM implementation, generated UI and any compatibility shape based on the superseded Offering `kind`; keep the existing renderer owners and isolated MOCK. The Elasticsearch credential-isolation fix at the fixed head changes no public activation wire. |
| Managed-service bounded UNKNOWN recovery and service-template head contract | `964d7c85d2e9249541996d22b9b2d9b9189922ab` | `ADAPT` only the closed five public read-only command-result types, original `idempotencyKey`, opaque input commitment, strict non-secret result validation and current-bearer transport into the existing repository/provider/notice owners. `ADAPT` stable ACTIVE-template/workload semantic matching and preserve the exact received version/digest in product commands and portable intents. `REFERENCE` the server-owned current-head directory, Account/USER/Role-source isolation, seven-day/100-item window and immutable completion constraints. `REJECT` browser-pinned template versions, the superseded `f254f583c65546380a3a810e93c105667f6590ac` private-request-ID correlation, client-side hash derivation, caller selectors, generic receipt framework, donor backend/SQL/profile/runtime and copied UI. Local or cross-browser absence remains UNKNOWN, never proof that a new write is safe. |
| IAM original Account-lifecycle completion | `23e389c735caad2ba52f4a955fa715562273c5d6` | Fixed Git objects only. Adapt the strict current-USER completion GET and operation-specific immutable projection into the existing Account client, Provider and content frame. The inspected `api/iam/v1/openapi.json` blob has SHA-256 `49f97a710f51ab141c3833990f1a260bc47f80cdcf829c75635bc3ebde9834ff`. Do not import backend, SQL, profile/readiness changes, donor UI, FEAT/checkpoint state or acceptance results. |
| IAM independent exact-target read contracts | `08e1dc4a6ce81386ea7223e62d03356f82aeee58` | Fixed Git objects only. `REFERENCE` existing exact User, per-User AccessKey and independent service-template/consent authorization boundaries. `REUSE` this console's public clients and renderers; `ADAPT` their target selection and navigation. `REJECT` collection visibility or page membership as existence/authorization, added backend contracts, donor UI/runtime changes and inherited acceptance evidence. |

The FEAT-007 outcome, user journey, ownership, model, authority boundary, and
three acceptance gates were fixed before the following adoption decisions.
The earlier FEAT-006 rejection of the legacy UI applied only to the IAM/Audit
authority slice; it created no compatibility obligation and does not decide a
new UI-owned feature.

Architecture and visual style come from exactly one project: the complete
Discord-style Next.js/React application at `69336e51...`. Its `@ui/xiak`
facade is one layer of that application, not a separate component-library
donor. The PaaS design record below only helps confirm product and runtime
boundaries; when it overlaps UI structure or styling, the complete application
is authoritative.

## Legacy UI comparison

The fixed UI is a complete Next.js 16 and React 19 App Router project, not only
a component library. Its public `app/ui/src/ui/xiak` facade contains 158 files,
while the inspected workbench domain/application/repository/scene/renderer/
route chain contains 50 files. The fixed source has no PaaS login client,
PostgreSQL product, quota model, managed-service catalog, or installation
workflow. Its `billing` strings belong only to social user settings and are
not billing behavior.

| Slice at fixed commit | Decision | Rationale |
| --- | --- | --- |
| `src/ui/xiak/button`, `input`, `select`, `typography`, `icon(s)`, `badge`, `breadcrumb`, and `skeleton` | `ADAPT` | Preserve semantic Ant Design-style names, native element props, compound exports, explicit variants, focus/disabled semantics, and the stable `@ui/xiak` facade. Admit only primitives used by an accepted console scene; remove signal, social, and workbench-only dependencies. |
| `src/styles/globals.css`, theme structure, and component CSS Modules | `ADAPT` | Preserve the donor's layered visual grammar, dense control-plane shell, palette-to-functional-to-semantic token layering, scoped component styles, focus treatment, and theme-safe extension points. Adapt the palette through Matrix-owned tokens and the owning FEAT's theme requirements without flattening the application into a generic admin template. |
| `layout/Layout`, `Header`, `ContentPage`, `ContentLayout`, `Sider`, `App`, rail, user dock, and right-workspace regions | `ADAPT` | Preserve the complete four-region shell, explicit scrolling ownership, responsive overlay behavior, header/action ordering, resizable contextual workspace, and semantic compound components. Translate guild rail, channel sidebar, chat content, and workspace into product rail, service navigation, control-plane content, and order/Operation inspector. |
| App Router pages plus `features/groups/{domain,application,repositories,scenes,renderers,routes}` and `WorkbenchProvider` | `ADAPT` | Preserve the full route parser -> provider -> repository -> scene -> internal renderer -> public UI flow and loading/selection ownership. Rename it to the control-plane language and use a real public-API repository plus an injected test repository; reject the donor's social models and mock data as production truth. |
| Next.js 16, React 19, TypeScript aliases, App Router project layout, and package scripts | `ADAPT` | Keep the same application architecture and framework family. Configure a locked static export whose output is embedded by the existing Go UI process, so no Next.js server or package manager enters the installed runtime. |
| Zustand shell state | `ADAPT` | Use it only for transient state shared across shell regions, such as compact sidebar/workspace overlays. API resources, sessions, quotas, and installation truth remain in their owning provider or service. |
| dependency-cruiser rules and raw-color/no-inline-style checks | `ADAPT` | Preserve acyclic imports, feature-agnostic public components, pure scenes, and automated styling boundaries. Reimplement the checks for the Matrix Next.js source tree without copying donor baselines or historical exceptions. |
| Next.js server-only cookies and dynamic rendering, WebSocket mock, social cache, drag-and-drop, CDP/downloaded baselines, donor test results, and generated artifacts | `REJECT` | They do not protect the accepted password-login or managed-service journey. Static export, memory-only bearer handling, target-owned tests, and committed Go-embedded assets own those concerns. |
| `features/groups` business vocabulary and fixtures, `ui/xiak/chat`, `ui/xiak/social`, user-profile/settings pages, and social billing label | `REJECT` | They model a Discord-style social product, not Matrix PaaS. The architectural and visual pattern is adapted, but copying its business data would create misleading behavior with no corresponding authority. |

No donor business directory is copied wholesale. The complete application
pattern and shell style are selectively transplanted, while every admitted
component is owned under the target's PaaS props, tokens, accessibility, and
import contracts and must pass its own public-export and visual gate.

## PaaS product-design reference

The fixed design donor owns only `docs/paas/README.md` and its adoption
manifest at the reviewed commit. Its UI conclusions remain useful even though
its legacy DevOps/GitLab execution roadmap has been replaced by the accepted
Matrix Phase 1 product.

| Design slice | Decision | Rationale |
| --- | --- | --- |
| Independent `app/ui/paas`, no runtime dependency on donor source, explicit APISIX routes, and separately verifiable UI delivery | `REFERENCE` | These product and deployment boundaries align with ADR-0002 and the accepted Phase 1 Go UI process. The complete UI donor, not this record, supplies the application architecture and style. |
| First-candidate primitive list, layout redesign list, and exclusion of groups/chat/social | `REFERENCE` | Use only as a scope cross-check. Component semantics, shell composition, tokens, and interaction style are adapted from the complete UI donor. |
| Next.js 16 and React 19 as a proposed baseline | `REFERENCE` | This corroborates the selected framework family, but the fixed complete application owns the adopted App Router pattern. Installation still performs no package-manager or framework-server work. |
| transport parser -> view model -> page, unknown/stale/error states, server-side authorization, and no provider secrets in UI | `REFERENCE` | These are product constraints. The actual route -> provider -> repository -> scene -> renderer chain is adapted only from the complete UI donor. |
| legacy component projections, GitLab Provider, current DevOps scripts as source of truth, signed web assertion, and CLI/GitLab escape-hatch roadmap | `REJECT` | Phase 1 now owns application hosting, IAM, Audit, Operations, installation, and Compose execution inside this repository. Reintroducing the legacy execution authority or its compatibility routes would contradict the accepted product boundary. |

## Matrix shared interaction backport

The `cloudUxInteractionBackport` source entry fixes the inspected paths. Its
controls descend from this console's public UI; they do not introduce another
architecture, package or runtime dependency.

| Slice at fixed commit | Decision | Rationale |
| --- | --- | --- |
| `Select` Tab/Shift+Tab acceptance and close behavior, with Escape cancellation tests | `REUSE` | Correct the existing themed control's keyboard trap while retaining its dialog portal, disabled choices, form submission and theme ownership. |
| `TableToolbar` reset focus and behavioral assertions | `REUSE` | Restore focus to the stable filter trigger after its reset button disappears; preserve the keyword and disclosed conditions. |
| Platform-shell replacement, narrowed product catalogue and CAM/preview omission | `REJECT` | These changes do not preserve the cloud UX release's approved service discovery, complete MOCK workspaces and one-click preview. |
| Viewport-only brand breakpoint and suppression of shell actions by every local heading | `REJECT` | This console already owns container-responsive branding; its local commands and global refresh are not interchangeable. |

## IAM fixed-contract integration

The Account completion slice uses only fixed source
`23e389c735caad2ba52f4a955fa715562273c5d6`. `REUSE` the existing Account
repository/Provider, exact-target write forms and public themed Card, Alert and
input controls. `ADAPT` unknown-outcome handling to a non-sensitive original
actor/operation/target/request/version summary saved before dispatch, then a
strict, independently authorized completion read after reauthentication or
portable import. Replace the old credential-bearing frozen-command retry in
the same slice; do not keep a replay alias. `REFERENCE` the permanent,
operation-bound completion and actual commit-time Root-recovery status to
distinguish an original outcome from current Account facts. `REJECT` password,
bearer, complete-command or digest storage/export; caller identity selectors;
current-target GET as completion evidence; a missing-result retry permit; a
shared PaaS/IAM receipt framework; and the superseded ACTIVE-only Root-recovery
constraint. The USER-only recovery presentation remains outside directory-read
gates without manufacturing resource capabilities. The owning FEAT, not this
adoption record, retains UI gates and remaining runtime acceptance.

The production-export repair inspects only the fixed consumer
`89505567643ed1c8e71d80277d5a3527d7987605` and its exact frontend donor
`859a82a4d88ca76a9a2b6e7f49fafb283554ff21`. `REUSE` the existing static
export, filename normalizer, deterministic build-ID owner and strict embedded
inventory comparison. `ADAPT` the single Next.js configuration boundary so
the compiler and build ID share the same preview `1`/`0` interpretation, and
extend the owning embedded gate with actual unset/`0` production builds and
path/digest mismatch diagnostics. `REFERENCE` the fixed runner failure and
chunk/reference diff to distinguish a compiler-input mismatch from an OS
filename defect. `REJECT` a CI-only environment workaround, payload
normalization, one-sided OS asset replacement, QR-library replacement or
changes to component, IAM, API, SQL, profile and runtime behavior. Exact gate
results and remaining acceptance boundaries belong to the FEAT owner.

The authenticator setup slice reviews IAM-UI-01–06 only at fixed source
`9dd117e918aadfd6b0459e591d263dc98de99090`, against console owner
`dc6410238f40d1a91bdb236fa030a584d4703b0f`. `REUSE` the existing four LIVE
ceremonies, strict provisioning contract, Session/intent fences and one-time
custody. `ADAPT` only the repeated setup-material presentation into one local
SVG/manual-key component. `REFERENCE` the fixed delivery matrix to distinguish
missing interaction from remaining runtime acceptance. `REJECT` new endpoints,
fake writable forms, remote QR services, secret persistence, shared encoder
mutation and changes to Deferred identity boundaries. The pinned zero-dependency
`qrcode-generator` 2.0.4 is an encoding dependency, not a UI/architecture donor;
`jsqr` 1.4.0 is an independent test-only decoder, not shipped application code.
The existing lockfile's unrelated security advisories are not accepted or
silently repaired by this adoption.

The Audit evidence slice inspects only the public Event, validation and OpenAPI
at fixed IAM/Audit source `5effc802fa8116d14420188d9075d6fe3ab1ceaa`.
`REUSE` the console's exact-key reader, lowercase SHA-256 validation and
read-only evidence detail. `ADAPT` only the optional `authorityEvidenceDigest`
projection and its conditional localized display; historical omission remains
valid, while malformed present values and other unknown fields remain rejected.
`REFERENCE` the producer's evidence binding without copying its implementation
or treating the digest as a current authorization permit. `REJECT` raw evidence,
unknown-field bags, invented digests, authorization inference, new endpoints and
backend/API/SQL/profile changes. This is client-contract adoption, not inherited
signed-runtime acceptance.

The Role exit slice uses the console owner fixed at
`47d03fce2a04fba7a7d63b84397f094a1bcd0957`; the matching exit path was also
inspected only at signed source `c38a0093235bf3521c4ef32492d814d36f071a7e`,
not the IAM engineer's WIP. `REUSE` the existing RoleSessionProvider identity
fences and LiveRoleSelfService recovery UI; `ADAPT` only source-validation
completion and the shared shell's blocked data/workspace boundary. `REFERENCE`
the fixed same-Account/source-User checks and current Audit bearer boundary.
`REJECT` keeping the Role bearer active during logout, early USER fallback,
automatic source logout, document reload, write replay and new backend routes.

The quota-recovery companion uses the same fixed console baseline. `REUSE`
the existing command commitment/owner checks, resource repository, cache merge,
read errors and workspace dismissal. `ADAPT` the matched successful quota
recovery to invalidate and reread the observed entitlement field, retaining
per-resource latest-request and original-command fences. `REFERENCE` the fixed
separation between a command receipt and independently authorized resource
data. `REJECT` synthesizing a quota row from the receipt, retaining a stale
directory after read failure, replaying activation, or introducing another
cache/recovery framework or backend contract.

The application-load recovery slice inspects the existing console owner at
fixed `901009da1fd9a4e94bc93c244f03855b8935e997`, not the IAM engineer's WIP or
signed runtime. `REUSE` its public Dialog/Alert/Card/Checkbox, appearance and
Session composition; `ADAPT` only the application composition to attach one
explicit recovery owner and root/console route-error entries. `REFERENCE` the
fixed UI host's HTML no-store, immutable hash assets and unknown-asset 404, and
the pinned Next 16.3.3 loader's named error shape. `REJECT` broad automatic
reload, secret/draft persistence, replacement session models and preservation
of superseded bundles. This reference is not signed-install acceptance.

The IAM revisions are authority and transport donors, not another visual or
application-architecture donor. The existing FEAT-007 provider/repository/
scene/renderer chain and isolated UX preview remain the UI owners.

| Slice at fixed commit | Decision | Rationale |
| --- | --- | --- |
| `AccountPolicy`, `PolicyDirectory`, `UserPolicyAttachment`, tenant/installation scope, management owner, lifecycle status and optimistic resource versions | `ADAPT` | These are the accepted public objects needed to present truthful live policy metadata and direct user associations. The console retains its view models and localized presentation. |
| Separate tenant and installation policy-list routes with a complete, stable-ID sorted maximum of 256 records | `ADAPT` | Fetch and authorize the directories independently. Treat only 403 as a local unavailable section; every other error fails the live scene. Client pagination may make the bounded snapshot easier to scan but must not impersonate backend pagination. |
| Exact create/revoke policy-attachment commands and account lifecycle commands | `ADAPT` | Preserve target identity plus policy or attachment revision so stale selections conflict rather than mutating a different revision. Account opening, suspension/recovery and direct user associations remain server-authorized. |
| `CurrentIdentity`, `UserAccess` and `AccountAccess` with exact per-resource action capabilities | `ADAPT` | Display Account + RootIdentity separately from daily managed Users. Enable or explain each action from its exact action/resource tuple and closed restriction reason; missing, duplicate, foreign or unknown capability entries fail the whole response rather than degrading to a guessed role. |
| Targeted `UserAccess` read, display-profile update and irreversible user deletion | `ADAPT` | Keep the directory as a locator and load the selected User through its dedicated read boundary. Update only `displayName` with its resource version. Show `TARGET_MUST_BE_DISABLED` before deletion, require an explicit typed impact acknowledgement once available, and accept only the strict non-secret `UserDeletion` receipt. Uniform forbidden responses remain an unavailable target and never become an existence oracle. |
| Capability projection as advisory interaction data | `ADAPT` | Use availability only to prevent dead-end clicks and explain protection. Never cache it as a permit: every mutation still reaches IAM with the target and resource version, where authorization and current-state validation run again. |
| Mandatory CurrentIdentity boundary, exact User boundary GET/PUT/DELETE and nine base UserAccess capabilities | `ADAPT` | At the named fixed boundary revisions, require explicit null or a same-account/user/revision version reference with an exact sha256 digest. Keep the ceiling separate from positive grant sources. Freeze target/policy revisions and request ID for a reviewed command, reject foreign or malformed results, and distinguish uncertain writes from a confirmed write followed by a failed read. |
| ACCOUNT `collection` capability resource ID | `ADAPT` | Replace the superseded `accounts` sentinel atomically in parser, scene and preview. Do not retain an alias or infer instance access from collection visibility. |
| Opt-in `TestIAMConsoleBrowser` process support | `REFERENCE` | Run the fixed services against fresh owned PostgreSQL and the target UI binary. Retain its real Audit-fact and chain checks, but perform and record the target's own browser actions; no inherited donor visual, export, narrow-screen or release acceptance. |
| `91af2972fb16d6727845fc06c9485f8ea62ca80c` personal TOTP replacement/removal public contract | `ADAPT` | Extend the existing personal-security repository/provider and page with the closed `TOTP_REPLACE` and `TOTP_REMOVE` operations. Retain mandatory enrollment purpose, exact request/proof/factor correlation, original microsecond deadline, first-APPLIED-only material and read-only UNKNOWN recovery. Reuse existing enrollment confirmation/cancellation and removal result routes; replay/history never reauthenticates a later observer. No second API or secret persistence is introduced. |
| Same fixed IAM factor lifecycle implementation and acceptance design | `REFERENCE` | Inspect the server's original-session custody, Root/platform-attached protection and required-MFA restrictions to constrain interaction and negative cases. Source/frontend gates do not inherit backend, real-browser or signed-install acceptance. |
| Donor factor UI/backend/SQL/profile and synthetic completion from local state | `REJECT` | Keep the UX branch's public Card/form/focus owners and explicit MOCK. Do not import the donor implementation, use labels as authority, renew proof deadlines, recover secrets by GET, reopen uncertain writes from PENDING, or terminate a new login from an old historical completion. |
| `e24dbdae6b4ea420365a4527a0bd89b16e0d720f` account MFA settings mutation and completion | `ADAPT` | Keep `SECURITY_SETTINGS_UPDATE` proof bound to the frozen account version and boolean target; use exact update and original-request lookup routes, check the resulting account, one-step version increment and original-session-ended fact. The fixed CI succeeded, but this UX branch still consumes an older read-only IAM runtime; the write adapter is staged without a LIVE action, browser acceptance or release claim. |
| `Group`, `GroupAccess`, `GroupMembership`, `GroupMembershipAccess`, group policy attachments and direct/group `PolicyGrantSource` provenance | `ADAPT` | Present groups as non-login relationship containers. Preserve stable relation IDs, exact membership provenance and independent group/member/attachment lifecycles; never flatten a group-derived grant into a direct user attachment or an effective-access claim. |
| Closed group capability set and versioned single-relation commands | `ADAPT` | Drive list/read/update/delete, membership and attachment affordances only from their exact action/resource capability. Create an empty group first; add or remove one membership or attachment per command. Retain the exact request ID and payload after an uncertain outcome, while a version conflict refreshes state and requires a new user intent. |
| Signed account/user/group/member pages and deliberately absent aggregates/user summaries | `ADAPT` | At fixed revision `8117c54`, the strict transport adapter accepts only the bounded `ic1.` envelope shape, validates stable ID order inside each page and passes the continuation unchanged. It never compares opaque cursor text with resource IDs or treats a cursor as authority. Search and filter only currently loaded records and say so; load additional pages explicitly. Do not invent a global result count, load every membership to derive a total, or issue an N+1 user lookup merely to decorate membership rows. An exact same-account cached user summary may enhance a stable user ID but cannot determine existence or action availability. |
| IAM architecture analysis and fixed FEAT contracts | `REFERENCE` | Use them to explain object relationships, management snapshots and authorization boundaries. FEAT-007 owns only the browser behavior and does not restate IAM's domain contract. |
| AccessKey `networkRestrictions`, `usage`, account security settings and `iam.access-key.set-network-restrictions` at `91649497a0c53be1174d8835326a2df51fe74a55` | `ADAPT` | Require the fixed fields and closed capability vocabulary in the strict adapter. Keep account and key CIDR layers independent, combine them as AND only for explanation, and freeze the normalized key layer into create/retry intent. Show `lastAuthorization` only as retained historical IAM evidence; absent evidence stays unknown. Edit one key in the content area with its own version and request ID, never through a Dialog or the status command. A failed account-settings read may degrade only that layer and cannot erase known key evidence. |
| Browser source-IP discovery, synthetic last-used, health score and product-PEP enforcement inferred from IAM observations | `REJECT` | The browser is not a trusted request-context source. Historical Allow/Deny is neither a current permit nor business success, and the fixed IAM contract does not prove that every product enforces the network rule. Keep these claims absent from LIVE and MOCK alike. |
| `AuthorizationProfileAction.subjectTypes` and `.userAuthenticationMethods` at `29668fa330b2233b43ebd48ed37738623377f9de` | `ADAPT` | Preserve the optional sets independently in the strict HTTP adapter and read-only catalog. Reject explicit empty/null, duplicate/unknown members and USER credentials without USER admission. Omission retains the sealed USER/probe ceiling and LOGIN_SESSION-only USER admission, not all subjects or carriers. Do not mutate declaration bytes, recompute the digest or infer a grant. |
| `ENROLLMENT` challenge, initial/re-enrollment and first-contact/TOTP routes at fixed IAM `91af2972fb16d6727845fc06c9485f8ea62ca80c` | `ADAPT` | Extend only the existing login/personal-security providers, strict repository and challenge renderer. Preserve genuine `REMOVED` and its safe retained revision instead of aliasing it to `NEVER_BOUND`; restricted INITIAL enrollment may retain a proven removal revision without a Session. Keep the challenge carrier separate from bearer APIs and consume first-response-only materials. Caller state or a missing factor is not removal eligibility, and the DEV simulation is not LIVE evidence. |
| ServiceRoleTemplate directory plus current-Account `ServiceLinkedRoleAccess` and exact `WorkloadRoleBinding` reads at cumulative IAM source `a464299b6656becc73054cd53b4a31b44104540b` (Verification `36779942782`, 14/14 successful) | `ADAPT` | Reuse the already strict IAM decoders and only the three customer read routes. Match the full `{id,version,contentDigest}` reference, exact service purpose and exact workload kind/id; derive Account solely from the current `LOGIN_SESSION`, never from a browser selector. Keep template release, Account relation, workload binding and runtime observation as separate facts; an earlier `ACTIVE` layer is neither an issued credential nor a final authorization verdict. Only the remote data card loads or fails; stable product detail remains mounted. |
| Public product bind/unbind at `92ea765b` | `ADAPT` | Prepare only the strict product client: bind sends the exact template reference; unbind sends only resource version to the exact installation/binding path; both retain one caller-owned `Idempotency-Key` for equal replay and validate the complete route-bound receipt. Keep the methods outside the mounted provider and LIVE UI because independent Verification `36701340805` has not passed. Existing isolated browser-memory reviews remain the inspectable UX; Account-relation revoke/delete, service-session actions and browser calls to `/v1/internal/*` remain absent. |
| Service RoleSession source union and closed assume intent at `aecc9f1c50f663af9a0bae8198bef0f66c9192af` | `REFERENCE` | The public `RoleSession`, IAM `Subject` and Audit actor lineage now require exactly one of `sourceUserId` or `sourceServicePrincipalId`; the internal service intent accepts only binding, optional duration and request identity, so Account, Role, installation, purpose, template and Policy are never browser selectors. This fixed slice proves contract/Audit storage acceptance, not IAM issuance, managed-service execution or a customer-readable session directory. Keep the four-stage MOCK non-actionable and do not add a session ID, credential, internal endpoint, revoke action or LIVE parser until a separate northbound observation contract is fixed and accepted. |
| IAM branch UI styles, generated exports, route shell and wholesale commit | `REJECT` | They would replace the approved cloud UX and duplicate its owners. Only bounded contract semantics and tests cross the adoption boundary. |
| Superseded `BuiltinRole`, `RoleBinding`, role-name-to-authority inference, hidden MOCK fallback and synthesized policy content/effective access | `REJECT` | These projections are not the fixed IAM contract and could overstate authority. Unsupported role, policy-authoring and access-decision simulations survive only behind the explicit one-click preview repository. |

## Resulting implementation constraints

1. Replace the Phase 1 page in the existing independent UI delivery unit; do
   not keep a second configuration workspace, donor app, or compatibility
   route.
2. Build one end-to-end console chain before expanding component inventory:
   App Router entry, route parser, `ControlPlaneProvider`, real
   `ControlPlaneRepository`, `ConsoleScene`, internal shell renderer, and
   public `@ui/xiak` primitives.
   The primitives and the chain are two layers adapted from the same complete
   donor application, never two competing UI sources.
3. Keep public components semantic and feature-agnostic. Wire objects, scene
   types, renderers, IAM details, managed-service fields, and DOM-derived names
   cannot leak into the facade.
4. Use a small Matrix-owned token set and scoped styles. Do not copy donor hash
   classes, raw screenshots, group/social assets, baseline exceptions, or
   unused theme variables.
5. Retain the Phase 1 security properties: same-origin public API calls,
   memory-only user bearer, no UI process credential/proxy, offline assets,
   strict CSP, no external URL, and normalized failures.
6. Next.js, the React compiler, and the package graph are build-time inputs
   only. Production and offline installation use the committed deterministic
   static export embedded in the Go binary and never run a framework server or
   reach a package registry.
7. Managed-service business rules, quota truth, local-region authority, and
   provisioning effects remain target-owned implementations. No donor billing,
   catalog, IAM, provider, or persistence model is reused.
8. Tests assert the current semantic component, accessibility, security, and
   user journey contracts rather than donor markup, class names, screenshot
   pixels, file counts, or incidental render order.

No donor repository is a build or runtime dependency.
