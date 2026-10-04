# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-04
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `0835f3b1c`
- Pushed documentation milestone: `f34a20faf`

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
verification remains disabled for UX review. Source/embed `0835f3b1c` makes the
service-authorization responsibility model stable shared context for both the
isolated MOCK and strict LIVE read directory. Before either account-relation or
platform-template data loads, the page distinguishes product-team definition
and PEP enforcement, IAM validation/trusted publication, and tenant directory
consumption/product-resource consent. It exposes no publisher, consent,
revocation or repository-write command.

Desktop renders the responsibility model in three columns and `390 × 844`
uses one column; both have no Dialog, horizontal overflow or browser
warning/error. Full acceptance at this milestone: 62 frontend files / 1,061
tests, three static-normalization tests, typecheck, lint, architecture, 228
theme-contrast pairs, 45-route production export, 43 normalized paths,
249-file embed equality, repository `go test -p 2 ./...` and
`go vet -p 2 ./...`. Documentation milestone `f34a20faf` records the exact
semantics and exclusions in the owning FEATs.

## Continuation boundary

Keep the MOCK preview available. Consume IAM changes only from fixed, pushed
sources with terminal evidence. AccessKey and accepted service-authorization
reads still need real-IAM browser and installed-release acceptance; product PEP
enforcement, current permit and cloud-product credential usability must not be
inferred from IAM observations. Product Profile draft, approval and publication
remain absent until IAM fixes a public contract. Do not call `/v1/internal/*`,
invent product selectors or mount a write action without accepted source and
terminal evidence. Preserve the current page shell, local data feedback,
shared tables and content-area actions.
