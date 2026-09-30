# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `f74e51d1`
- Pushed documentation milestone: `d5678bce`

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
runtime use.

The former permission simulator is replaced by a policy-coverage worksheet.
It inventories only local fixture input, referenced policy/default-version
statements and boundary references, while runtime remains `NOT_EVALUATED`.
The page does not import the preview evaluator and does not render match states,
effective permission, final Allow/Deny, a reason tree or remediation. Source IP
and time remain operator-entered information-architecture fields only.

Source and synchronized Go embed at `f74e51d1` passed 55 frontend files / 889
tests, static normalization, type/lint/architecture, 228 theme contrast pairs,
41-page export, 228-file embed equality and repository Go test/vet. Desktop and
`390 × 844` browser inspection passed with responsive scope cards and a stacked
mobile statement table. Existing MOCK pages remain available.

IAM follow-up `a464299b` changes only `authority-roles` test evidence, not
production wire/API/SQL. Replacement Verification `36779942782` currently has
four successful lanes including `authority-roles`, but the whole run is not yet
terminal; product-side LIVE bind/unbind remains closed. Exact behavioral
evidence and limits are owned by FEAT-IAM-010.

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
internal service-session endpoints.

Keep permission analysis as the explicitly isolated, non-evaluating worksheet.
Do not reintroduce a risk score, effective-permission result, Deny reason tree,
remediation action or future API. Trusted-tag authorization and batch decisions
remain too unstable for high-fidelity executable UI.

Continue the console-wide UX audit from the next uncovered customer workflow,
preserving fixed page structure, localized data loading, compact responsive
behavior and content-area actions. Do not move unrelated branches, enable login
verification before UX acceptance, merge, or claim release completion.
