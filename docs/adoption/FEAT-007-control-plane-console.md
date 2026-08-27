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
