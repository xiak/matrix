# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-04
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed branch head: `6c499c664`
- Pushed source/embed milestone: `ba7e57a9a`
- Pushed documentation milestone: `6071f2a5e`

## Authoritative route

- IAM console behavior and acceptance evidence:
  [`FEAT-IAM-010`](../../IAM/FEAT-IAM-010-console.md).
- Shared console outcome and current UI evidence:
  [`FEAT-007`](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed donor decisions:
  [`FEAT-007 adoption review`](../../docs/adoption/FEAT-007-control-plane-console.md).
- AccessKey and product-enforcement contracts:
  [`FEAT-IAM-007`](../../IAM/FEAT-IAM-007-programmatic-credentials.md) and
  [`FEAT-IAM-008`](../../IAM/FEAT-IAM-008-product-enforcement.md).

Do not restate or amend those owners here. Read this checkpoint only after
compaction or handoff, then validate it against Git and the linked FEAT.

## Latest pushed milestone

The inspectable DEV MOCK remains available at `http://127.0.0.1:4317`; login
verification remains disabled for UX review. Merge `6c499c664` joins UX head
`6071f2a5e` with fixed IAM head `08469334a`. The integrated tree takes the IAM
head's complete API, service, deployment, test and Go-module closure while the
console source remains owned by FEAT-IAM-010/FEAT-007. No backend conflict was
resolved by inventing a third contract, and the separate inspectable MOCK remains
available.

Acceptance at this milestone: complete frontend 62 files / 1,082 tests; three
static-normalization tests; typecheck, lint, architecture and 228 theme-contrast
pairs; 45-route production export, 43 normalized paths and 249-file embed
equality; repository-wide `go test -p 2 ./...` and `go vet -p 2 ./...`. Exact
IAM semantics and the remaining real IAM + PostgreSQL 18 + SMTP/Maildir browser
acceptance remain in the IAM owner.

## Continuation boundary

Keep the MOCK preview available. The next release gate is the real
NotificationContact replacement browser journey against IAM, independent
PostgreSQL 18 and SMTP/Maildir; do not let a new security-report UI slice replace
or weaken that gate. Consume later IAM changes only from fixed, pushed sources
with terminal evidence. The replacement source is accepted only as a client
contract until the remaining real IAM/SMTP browser gate passes.
AccessKey and service-authorization reads still need installed-runtime
acceptance; product PEP enforcement, current permit and cloud-product
credential usability must not be inferred from IAM observations. Product
Profile draft, approval and publication remain absent until IAM fixes a public
contract. Do not call `/v1/internal/*`, invent product selectors or mount a
write action without accepted source and terminal evidence. Preserve the
current page shell, local data feedback, shared tables and content-area actions.
