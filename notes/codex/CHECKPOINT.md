# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `937b9bbd`
- Pushed documentation milestone: `da8a431e`

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
verification remains disabled. Access analysis, product authorization,
product-onboarding, policy diagnostics and security settings preserve their
explicit MOCK/LIVE boundaries; no unverified IAM route or secret-bearing
service-session field is mounted.

User settings now has two top-level responsibilities: sign-in identity and
security configuration. The explicit MOCK security workspace separates
personal security, account policy and session security. Only personal security
mounts initially; another section mounts on first entry, stays mounted to retain
its draft, and leaves layout while inactive. The shared Tabs inactive-state
rule and the workspace-specific display rule prevent retained panels from
appearing together.

TOTP and current Account security-settings remain the only relevant real IAM
objects for this surface. Passkey/WebAuthn and idle-session policy stay explicit
previews with no real-success claim. The IAM engineer confirmed that the current
service RoleSession work adds no stable northbound field for this page and must
not be consumed before a fixed pushed source and successful independent gate.

The source and synchronized Go embed at `937b9bbd` passed the complete frontend
suite, export/embed equality, architecture/style/type/lint checks and repository
Go test/vet. Exact counts, browser evidence and limitations live in FEAT-007.

## Continuation

Keep the DEV MOCK available for progress review. Coordinate only against fixed,
pushed IAM commits with accepted verification. When IAM publishes a page-owned
contract delta, inspect that exact source and update the existing adoption
decision before replacing a MOCK section in place; do not add a parallel model
or infer LIVE capability from backend WIP.

Continue the console-wide UX audit from the next uncovered customer workflow,
preserving fixed page structure, localized data loading, compact responsive
behavior and content-area actions. Do not move unrelated branches, enable login
verification before UX acceptance, merge, or claim release completion.
