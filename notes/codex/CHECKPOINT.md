# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `23f09eb7`
- Pushed documentation/head milestone: `235532bf`

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

The existing independent MOCK console remains available and is the inspectable
UX surface. Its service-authorization review and exact-resource unbind flow are
browser-memory only; they preserve the Account relation and do not claim to
terminate unimplemented service sessions. The same inline flow now rehearses
the fixed public error boundary: uncertain results preserve one request intent
for equal replay, authorization-state conflicts require reread, idempotency
content conflicts and invalid requests stop, and authentication/authorization
failures never become a success state.

The observation surface also separates a future service request into trusted
service authentication, short-lived `source=SERVICE` session issuance,
product-PEP re-authorization and product-owned business execution. All four
remain explicit unverified MOCK states. It exposes no session ID, temporary
credential, internal endpoint or revoke action, and never turns configuration
state into a request permit.

The same isolated service-authorization workspace now makes the ownership
chain explicit: product teams define permission capabilities and business PEP
points, IAM validates and publishes immutable catalog facts, and tenant
administrators only consume those facts through product-resource consent and
binding. It provides no upload, product registration or publish action.

The shared policy workspace now also isolates commands by that ownership
boundary. Tenant policy selection and creation commands exist only on the
policy tab; the capability directory, product declaration and internal
onboarding review do not retain those unrelated mutation actions. Returning to
the policy tab restores its commands without remounting the catalog or changing
the IAM contract.

The internal product-onboarding preview no longer presents its checklist as if
validation had succeeded. Every IAM review item is pending, and the release
stage exposes four independent gates: MOCK declaration input, unexecuted IAM
contract validation, unverified product-PEP evidence and unavailable trusted
registry publication. It still writes nothing, publishes nothing and grants no
permission.

The isolated four-method policy author now separates security warnings,
blocking errors, general warnings and optional suggestions. Local broad-access
patterns require explicit review but are not presented as IAM validation, PDP
execution or product-PEP exposure evidence. At compact widths all four
destinations stay visible in a two-by-two grid and JSON-path actions retain
precise editor focus.

One pure local security-review projection now drives the Account overview,
policy detail, policy association, Role creation and User policy/group
association as well as the author's diagnostic vocabulary. The author no
longer duplicates a binary high-privilege alert, and the old parallel helper
has been removed. Read and mutation surfaces list each finding by policy and
state that denies, boundaries, grant sources and request context still require
evaluation; this is isolated MOCK guidance, not effective access or a backend
risk contract.

The former unused-access page is now one content-area Access analysis
workspace. It inventories only tenant-local federation mappings and service
roles, labels resource-side policy/ACL and cross-account coverage unsupported,
and keeps the real activity window unobserved. Configuration state never
becomes effective permission, external exposure or observed use. Synthetic
90-day unused-access samples remain a separate tab, and neither tab performs
automatic disable, deletion or authorization mutation.

The current-account observation now leads with a four-stage tenant-readable
status summary: exact platform template, Account relation, exact resource
binding and runtime observation. The MOCK may conclude that the first three
configuration facts agree while runtime remains unobserved; it never presents
that conclusion as an issued session or successful business request. It states
that a revoked exact binding forbids new issuance without promising immediate
termination of an existing session, and exposes no session ID, credential,
private issuance/result route, decision evidence or per-session revoke.

That stable summary now precedes three content-area evidence tabs for
authorization configuration, exact resource bindings and the runtime boundary.
Only the selected technical region is visible, so the mobile information flow
does not become one long evidence stream. The tabs are presentation-only: they
do not refetch, introduce a provider contract or turn an unobserved runtime
stage into a verified result.

Fixed IAM source `aecc9f1c50f663af9a0bae8198bef0f66c9192af` is classified as
`REFERENCE` only. It proves the strict USER/SERVICE RoleSession source union,
selector-free internal service-assume intent and Audit storage acceptance, but
publishes no customer-readable service-session or PEP-observation surface.
No LIVE parser or service-session action was added from it.

The product repository now contains a strict but unmounted public bind/unbind
client adapted from fixed IAM source `92ea765b`. It accepts a caller-owned
idempotency key for exact replay, sends only the published product request
shape and rejects successful-looking receipts that do not match the route,
template or lifecycle. These methods are deliberately outside the mounted
provider and LIVE actions because IAM Verification `36701340805` has not
passed. No browser path calls `/v1/internal/*`; Account-relation retirement and
service-session actions remain absent.

The current milestone passed the complete frontend suite, export/embed gates,
architecture/style/type/lint checks and repository Go test/vet. Exact counts,
browser evidence and limitations live in FEAT-007, not this checkpoint.

## Continuation

Coordinate with the IAM engineer using a fixed pushed commit and accepted
verification result, never another task's dirty working tree. Once the public
bind/unbind implementation has passed its independent gate, inspect the new
fixed source and update the existing adoption decision before mounting the
client. Then add the product-owned LIVE review/state handling, preserve the
stable page shell and local loading regions, and run real IAM-process browser
acceptance. Unknown outcomes must retain the exact original body and
idempotency key; do not manufacture a new intent or infer Account-relation
deletion from the last visible binding.

Do not move unrelated branches, replace the approved console with another
renderer, enable login verification before UX acceptance, merge, or claim
release completion. Replace this file only at another committed-and-pushed
milestone. Do not append command logs, secrets, raw provider payloads or
machine-local paths.
