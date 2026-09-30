# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `fc7c3b54`
- Pushed documentation milestone: `59023f71`

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
verification remains disabled. The permissions catalog now separates tenant
consumption from trusted product-team/IAM publication instead of placing the
internal onboarding action beside a tenant resource title.

The administrator RoleSession client now consumes fixed IAM source
`5435ea97faecc965b5010d0b7129b0bd26e45898`. Session records and source displays
are strict `USER | SERVICE_ACCOUNT` unions. The directory composes exact
session, User or service-principal IDs with the closed source-type and lifecycle
filters, and service rows expose only immutable installation, principal and
purpose lineage. Member Role self-service remains User-only. Single-session
revocation does not claim to delete the source identity, service relationship,
Role or policy, and private lineage or mixed-source responses fail closed.

The LIVE platform service-role template tab consumes the current complete,
release-owned `{items[]}` snapshot. It uses deferred local search, purpose and
state filters, and bounded ten-row pagination; the Account authorization list
continues to use only its server-owned opaque cursor and does not fake global
search over one page. A future fixed template cursor replaces this local
pagination instead of creating a parallel model.

The shared service-authorization chain now requires four explicit facts:
platform template, current-Account consent/service-linked Role, exact workload
binding and runtime observation. LIVE read views, product-resource cards and
the isolated MOCK all show runtime as unobserved instead of deriving it from
configuration. The responsive chain uses four columns only when space permits,
2 × 2 at medium content widths and one column on small containers. It adds no
session query/revoke, credential, internal route or product-PEP conclusion.

Source and synchronized Go embed at `fc7c3b54` passed 55 frontend files / 889
tests, static normalization, type/lint/architecture, 228 theme contrast pairs,
41-page export, 228-file embed equality and repository Go test/vet. Existing
MOCK pages remain available; the LIVE administrator session path still lacks
real-login browser evidence. IAM follow-up `a464299b` changes only the
`authority-roles` test evidence, not production wire/API/SQL; its replacement
Verification `36779942782` is still pending, so product-side LIVE bind/unbind
remains closed.
Exact behavioral evidence and limits are owned by FEAT-IAM-010.

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

Permission analysis may advance only as an explicitly isolated MOCK information
architecture. Do not invent a risk score, effective-permission result, Deny
reason tree, remediation action or future API. Trusted-tag authorization and
batch decisions remain too unstable for high-fidelity executable UI.

Continue the console-wide UX audit from the next uncovered customer workflow,
preserving fixed page structure, localized data loading, compact responsive
behavior and content-area actions. Do not move unrelated branches, enable login
verification before UX acceptance, merge, or claim release completion.
