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
| Matrix cloud-console service activation | `e14dec6351b759327cffc22105a0e1276b77ab8e` | Same-repository integration donor; inspect only the fixed Git object, never the UX worktree or its checkpoint. |
| Matrix IAM LIVE root user creation | `b28ef9c565e4e382302a67b62ceb4a6c1d6e2475` | Same-repository UX/UI donor whose parent frontend source is byte-identical to this branch's fixed `44b4ac334` source; consume only the fixed object and regenerate/verify delivery in this branch. |
| Matrix console stale-asset recovery | `7defb8fa5972540d56450c9cf776e99a61fd1d13` | Same-repository UX/UI donor; selectively consume only the nine fixed source files for the application error boundary and rebuild the embedded export in this branch. Do not import its generated assets, FEAT status, or checkpoint. |
| Matrix Role exit and recovered-quota convergence | `a661779a5a00aa731544e86fc571ad5f4dcf8e68` | Same-repository UX/UI donor whose six source/test parent blobs are byte-identical to this branch; consume only those fixed files, then rebuild and verify the entire embedded export here. Do not import its generated assets, FEAT status, or checkpoint. |
| Matrix Audit authority-evidence rendering | `dc6410238f40d1a91bdb236fa030a584d4703b0f` | Same-repository UX/UI donor whose seven selected source/test/message parent blobs are byte-identical to this branch; consume only the fixed parent-to-child delta and rebuild the embedded export from this branch's complete frontend source. Do not import its generated assets, FEAT status, or checkpoint. |
| Matrix portable termination-result recovery test | `33acaf49378332de98d78ad2c8e31f655368dfd1` | Same-repository UX/UI donor whose selected test parent blob is byte-identical to this branch; consume only the test delta that adds `TERMINATE_INSTALLATION` to the existing read-only recovery matrix. Rebuild delivery here and do not import generated assets or donor status. |
| Matrix Account lifecycle completion recovery | `ba2f7cb1e6bba16d5acf6eb93ebb224a2e868c13` | Same-repository UX/UI donor whose thirteen selected auth source/test/message parent paths are byte-identical to this branch or absent because the child creates them. Consume only those paths, keep credentials out of portable state, and rebuild the embedded export here. Do not import generated assets, FEAT/adoption status, or checkpoint. |
| Matrix IAM exact-target and source-local read isolation | `45251050879e23d23bb3fc7982ab8f7718bfbca9`, `ddd1a7760e2560e2ad2b2ea5fbe9ddffb27d6761`, with interaction-only follow-ups `14811b6118f39ca30d012d9fb54e1997cb1f4e3f` and `1090fcafabc14b541c70a41968d485cde5c347e7` | Same-repository UX/UI fixed objects. Selectively consume only the existing frontend source, interaction tests and messages; rebuild delivery in this branch. Do not import donor documentation, generated assets, checkpoint or verification status. The follow-ups only decompose long interaction cases under the unchanged five-second budget; they change no production code or assertion boundary. |
| Matrix LIVE Group deletion confirmation | `029a6ec3b9061efe46c30bfd496ece4135390926` | Same-repository UX/UI donor. Selectively consume only the five existing Group renderer/test/message paths. The follow-up `06198d737851eea032c2a15750a83fa3c5a721f7` contains donor-branch generated assets and is not an importable delivery artifact; rebuild the complete embedded export from this branch's final source. Do not import donor FEAT status or checkpoint. |
| Matrix customer Policy metadata and terminal retirement | `a0ade1100d1a009d57bcdb519b796093efa7293c` | Same-repository UX/UI donor. Selectively consume thirteen auth source/test/message paths, preserve this branch's prior renderer-test changes by a three-way adaptation, and rebuild delivery here. The generated-assets follow-up `2d60e050567c7222c34cced44a0215fafb196cc5`, donor documentation and verification state are not imported. |
| Matrix Group Membership original-command recovery | `c8981dd160474710868bf84712f2b7792f283973`, adapting the public contract fixed at `ffb305f859338cd8954f1476374b0d7d61c774b9` | `ADAPT` only the fixed frontend wire, exact-replay state and tests into the existing LIVE Group workspace. Preserve current-branch backend, FEAT facts and generated assets; rebuild delivery here. `REJECT` automatic replay, derived Membership IDs, current rows as original completion evidence, invented totals and treating a later denial or conflict as proof that an unknown write did not commit. |
| Matrix User profile/status original-result recovery | `343622a11d0ce4c65c763de0e717505e0b8dae9a`, parent `c8981dd160474710868bf84712f2b7792f283973` | `ADAPT` the purpose-limited `USER_UPDATE`/`USER_SET_STATUS` intent, completion GET client and existing User workspace integration against the published IAM87 contract. Preserve the consumption branch's later renderer tests and rebuild generated delivery here. `REJECT` generic command replay, current User state as original completion, replacement writes after 404/403/409/503, secrets in recovery state and the removed no-consumer generic `update-user` branch. |

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

## Current service-activation integration

| Fixed slice | Decision | Rationale |
| --- | --- | --- |
| Product routes, backend-projected service directory, exact activation capability, account-scoped activation state, deferred product-resource loading, and catalog-to-product navigation at `e14dec63...` | `ADAPT` | Use the UX owner's verified route/provider/repository/scene/renderer chain with the current FEAT-007 managed-service contract. Header and catalog entries come from the backend directory; the local registry supplies presentation and routes only for implemented products. The browser never infers activation authority from account type, role name, product ID, or a local service allow-list. |
| LIVE unknown-result recovery and credential/account scope isolation at `e14dec63...` | `ADAPT` | Preserve the original idempotency key, reconcile through the exact activation read, discard stale evidence immediately when the effective credential changes, and keep product-resource authorization authoritative on every request. Unknown services and unavailable directory results must not acquire invented links or mock fallbacks. |
| Root-only LIVE User creation, frozen sensitive command ownership and strict first notification address wire at `b28ef9c...` | `ADAPT` | Replace the closed LIVE create route with the existing wizard backed by the current Account/root/capability, one frozen request and an exact POST/read-back result. Preserve explicit no-boundary selection, zero implicit grants, secret clearing, same-Session retry and isolated MOCK behavior. Accept `FIRST_ADDRESS` only with resource version zero while retaining the distinct replacement contract. |
| Known stale Next.js chunk recovery at `7defb8fa...` | `ADAPT` | Recognize only a real `ChunkLoadError` with the pinned Turbopack/webpack message shape and a same-origin, query-free `/_next/static/chunks/*.js` target. Present one explicit warning and consent step, disclose loss of memory-only sessions, drafts and one-time material, and allow at most one document reload. Never auto-reload, replay a write, persist a secret, or turn an ordinary render/API error into an asset recovery. |
| Role source restoration and quota-result convergence at `a661779a...` | `ADAPT` | Keep the global Role recovery surface mounted until the original USER is authoritatively revalidated, then remount identity-scoped page/workspace state so stale Role errors, filters and cursors cannot survive. After a recovered quota activation succeeds, independently re-read the authorized quota list; never derive it from the receipt, replay the write, or let a failed/stale read rewrite the completed command. |
| Optional Audit `authorityEvidenceDigest` at `dc641023...` | `ADAPT` | Preserve the public Event field through the strict repository parser and display it as read-only evidence metadata after the request digest. Continue to reject malformed digests and unknown Event fields, keep historical events without the field valid, and state explicitly that the digest is not a current authorization permit. Do not add the field to requests or perform policy evaluation or hash-chain verification in the browser. |
| Portable termination-result test at `33acaf49...` | `ADAPT` | Extend the existing five-command recovery contract to prove that installation termination carries only its non-secret installation identity, maps to the exact `INSTALLATION_TERMINATE` result query, and never calls any managed-service write while recovering. This is a test of the current implementation, not a second recovery state machine. |
| Account create/status/root-recovery completion flow at `ba2f7cb1...` | `ADAPT` | Bind a portable original intent to the current actor Account and principal, target Account, operation, public request ID and expected resource version. Persist no initial password, bearer or private request identity. On an unknown response, permit only the exact completion GET; validate the immutable completion before displaying it, never project it into current Account facts or capabilities, and require a separate authoritative resource read. Different actors, malformed or extra fields, conflicts, terminal rejection and local-storage failure remain closed. |
| Exact IAM reads and source-local failure isolation at `45251050...`, `ddd1a776...`, `14811b61...` and `1090fcaf...` | `ADAPT` | Read a known User by stable ID even when the optional User directory is unavailable; keep per-User AccessKey and service-authorization reads on their own public contracts rather than gating them on User or Role collection visibility. Treat direct attachments as one authorization source, preserve known group-derived sources, and render unavailable console/programmatic switch state as unavailable rather than disabled. A failed optional source clears only its rows and advisory command state, exposes only a read retry, and cannot restore stale callbacks or replay a write. Keep the current-identity read strict and preserve the original interaction budgets and assertions. |
| LIVE Group deletion confirmation at `029a6ec3...` | `ADAPT` | Replace the preview/MOCK warning only for the LIVE Group route. Preserve exact typed-name confirmation, irreversible removal from the active directory, immutable Audit retention, authoritative removed-membership/revoked-attachment counts, and the explicit statement that Users, Policies and tenant resources are not deleted. Keep preview behavior isolated and require an independent real browser effect gate before accepting deletion. |
| Customer Policy rename, whole-Policy retirement and original-command recovery at `a0ade110...` | `ADAPT` | Use the existing public PATCH/DELETE contracts with original revision/request identity, strict result matching, separate authoritative rereads and exact typed-name retirement. The new purpose-limited workflow/storage owners protect a real browser side-effect boundary: one non-secret intent per Account/actor, exclusive Web Lock through network completion, fail-closed unavailable storage/coordination, explicit equal replay after relogin, and no late-response evidence deletion. Root and delegated identities use the same server PDP; no browser-generated Allow, implicit detachment, recovery API or generic receipt framework is introduced. |
| Generated embedded assets and donor-branch FEAT/checkpoint status at `6083f300...` and `06198d73...` | `REJECT` | Rebuild and verify assets in this branch. The build identity covers the complete frontend tree, including five source/test differences not adopted from the Group donor, so copying `06198d73` produced three manifest and 292 content mismatches even though the five selected business-source blobs were correct. The 324 embedded files must be reproduced from the consuming branch's final source; donor verification and progress records cannot substitute for this branch's acceptance gates. |
