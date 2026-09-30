# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `eeb6dd14`
- Pushed documentation milestone: `2206d988`

## Authoritative route

- IAM client requirements, status and boundary evidence:
  [`FEAT-IAM-010`](../../IAM/FEAT-IAM-010-console.md).
- Shared UX requirements, status and verification evidence:
  [`FEAT-007`](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed-source adoption decisions:
  [`FEAT-007 adoption review`](../../docs/adoption/FEAT-007-control-plane-console.md).
- Shared product boundary:
  [`ADR-0002`](../../docs/architecture/ADR-0002-product-boundary.md).

Do not restate or amend those owners here. Read this checkpoint only after
compaction or handoff, then validate it against Git and the linked FEAT.

## Durable pushed state

The independent MOCK console remains the inspectable UX surface and login
verification remains disabled. The current service-authorization UX keeps
platform template, Account consent/service-linked Role, exact workload binding
and runtime observation as four separate facts; configuration never implies
runtime use. Its local non-secret session examples now use the fixed public
`SERVICE_ACCOUNT` source, `UNREVOKED | EXPIRED | REVOKED` lifecycle and explicit
revoke capability. `UNREVOKED` is never presented as current usability.

The former permission simulator is replacement-first removed. Component, view,
route, localization, Go static-route and embedded-export ownership now use only
`policy-coverage`; no compatibility path remains. The worksheet inventories
only local fixture input, referenced policy/default-version statements and
boundary references, while runtime remains `NOT_EVALUATED`. User detail opens
the same route with the exact identity preselected. The page does not import the
preview evaluator and does not render match states, effective permission,
final Allow/Deny, a reason tree or remediation. Source IP and time remain
operator-entered information-architecture fields only.

The PostgreSQL product directory now treats resource visibility as a product
server boundary: the UI labels only the records currently loaded and never
infers an Account-wide total or coverage. Isolated MOCK fixtures are explicitly
not IAM-filtered; non-preview copy requires the product service to combine its
candidate resource list with IAM decisions before returning rows. The browser
does not hide denied rows, expose a tenant-facing batch-grant action, or claim
the unfinished `/v1/authorize:batch` candidate is integrated. Source/embed at
`eeb6dd14` passed 55 frontend files / 891 tests, static normalization,
type/lint/architecture, 228 theme contrast pairs, 41-page export, 228-file embed
equality and repository Go test/vet. Desktop and `390 × 844` inspection had no
Dialog, overflow or warning/error. Existing MOCK pages remain available.

The fixed administrator RoleSession northbound contract is consumed only by
Role detail. The service-authorization MOCK reuses its public fields but sends
no query/revoke request and keeps final submission disabled. Product-side LIVE
bind/unbind, Account-relation revoke and real product-PEP evidence remain
closed. Exact behavioral evidence and limits are owned by FEAT-IAM-010.

The earlier navigation stress gate remains unchanged: 200 alternating suspended
IAM Group and Role destinations preserve the latest click and clear pending
state after stale work completes.

## Continuation

Keep the DEV MOCK available for progress review. Coordinate only against fixed,
pushed IAM commits and record independent verification separately. IAM owner
prioritizes the service-authorization governance flow: immutable template,
current-Account consent/service-linked Role, exact workload binding, then
short-lived session observation and single revocation. Product-owned bind and
unbind remain the northbound mutation boundary; the browser never calls IAM
internal endpoints or moves Role-detail session authority into the product
authorization page.

Keep permission analysis as the explicitly isolated, non-evaluating worksheet.
Do not reintroduce a risk score, effective-permission result, Deny reason tree,
remediation action or future API. Trusted-tag authorization remains outside the
current executable UI. Treat IAM batch authorization only as a product-side
server filtering candidate until its exact pushed source, fields and calling
boundary are fixed; never reinterpret it as customer bulk authorization.

Continue the console-wide UX audit from the next uncovered customer workflow,
preserving fixed page structure, localized data loading, compact responsive
behavior and content-area actions. Do not move unrelated branches, enable login
verification before UX acceptance, merge, or claim release completion.
