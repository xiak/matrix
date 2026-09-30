# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `96afde8c`
- Pushed documentation milestone: `fd536208`

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

The service-authorization runtime preview now includes a non-secret
`ServiceRoleSession` sample directory and inline detail. Its source is a strict
`USER | SERVICE` union, while this service-authorization scene deliberately
shows only `SERVICE` examples. Account, source, target Role, issue, expiry and
revocation fields are explicit, with separate active, expired and revoked
records. Expired and revoked records expose no revoke action, and revocation
copy does not imply deletion of the Role, binding or permission ceiling. The
directory reuses the shared collection primitives and IAM-wide `WorkspaceTime`;
it exposes no credential or authorization proof and sends no request. LIVE
service-session query and revoke remain absent until IAM publishes a fixed
northbound contract.

The LIVE platform service-role template tab consumes the current complete,
release-owned `{items[]}` snapshot. It uses deferred local search, purpose and
state filters, and bounded ten-row pagination; the Account authorization list
continues to use only its server-owned opaque cursor and does not fake global
search over one page. A future fixed template cursor replaces this local
pagination instead of creating a parallel model.

Source and synchronized Go embed at `96afde8c` passed 55 frontend files / 887
tests, static normalization, type/lint/architecture, 228 theme contrast pairs,
41-page export, 228-file embed equality and repository Go test/vet. Existing
MOCK desktop and 390 x 844 DEV checks show the three lifecycle states without a
Dialog, page overflow, warning or error; the LIVE template directory and
service-session route still lack real-login browser evidence.
Exact behavioral evidence and limits are owned by FEAT-IAM-010.

## Continuation

Keep the DEV MOCK available for progress review. Coordinate only against fixed,
pushed IAM commits with accepted verification. When IAM publishes a page-owned
contract delta, inspect that exact source and replace the MOCK section in place;
do not add a parallel model or infer LIVE capability from backend WIP.

Continue the console-wide UX audit from the next uncovered customer workflow,
preserving fixed page structure, localized data loading, compact responsive
behavior and content-area actions. Do not move unrelated branches, enable login
verification before UX acceptance, merge, or claim release completion.
