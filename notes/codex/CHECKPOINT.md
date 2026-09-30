# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `ed978ba9`
- Pushed documentation milestone: `482aec3e`

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
`ServiceRoleSession` sample directory, inline detail and a disabled single-
session revoke review. It exposes no credential, proof/decision, private
endpoint or bootstrap summary; it sends no request and produces no request ID
or success state. LIVE service-session query and revoke remain absent until IAM
publishes a fixed northbound contract.

Source and synchronized Go embed at `ed978ba9` passed 55 frontend files / 886
tests, static normalization, type/lint/architecture, 228 theme contrast pairs,
41-page export, 228-file embed equality and repository Go test/vet. Desktop and
390 x 844 DEV checks had no Dialog, page overflow, warning or error. Exact
behavioral evidence and limits are owned by FEAT-IAM-010.

## Continuation

Keep the DEV MOCK available for progress review. Coordinate only against fixed,
pushed IAM commits with accepted verification. When IAM publishes a page-owned
contract delta, inspect that exact source and replace the MOCK section in place;
do not add a parallel model or infer LIVE capability from backend WIP.

Continue the console-wide UX audit from the next uncovered customer workflow,
preserving fixed page structure, localized data loading, compact responsive
behavior and content-area actions. Do not move unrelated branches, enable login
verification before UX acceptance, merge, or claim release completion.
