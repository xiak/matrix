# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-04
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `aecdaac1c`
- Pushed documentation milestone: `bb45f0de0`

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
verification remains disabled for UX review. Source/embed `aecdaac1c` gives the
isolated MOCK and strict LIVE administrator RoleSession directories one shared,
stable source guide before dynamic data. It separates `USER` from
`SERVICE_ACCOUNT`, distinguishes session source from Role permission source,
and keeps lifecycle observation separate from product PEP authorization. The
guide issues no request or command and invents no session row or credential.

Desktop renders the guide in two columns and `390 × 844` uses one column; both
have no Dialog, horizontal overflow or browser warning/error. Full acceptance
at this milestone: 62 frontend files / 1,061 tests, three static-normalization
tests, typecheck, lint, architecture, 228 theme-contrast pairs, 45-route
production export, 43 normalized paths, 249-file embed equality, repository
`go test -p 2 ./...` and `go vet -p 2 ./...`. Documentation milestone
`bb45f0de0` records the exact semantics and exclusions in the owning FEATs.

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
