# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-04
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed branch head: `2397586e2`
- Pushed source/embed milestone: `0114419d2` / `80789db67`
- Pushed documentation milestone: `2397586e2`

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
verification remains disabled for UX review. Notification replacement source
`228c06eb2` keeps proof, delivery and atomic confirmation as distinct states,
retains completed or unknown intents until authoritative reread, and preserves
the separate MOCK experience. Source `0114419d2` and generated embed
`80789db67` additionally keep the access-analysis primary tabs single-line and
stable on small screens, with local overflow only when their content cannot fit.

Acceptance after the mobile delta: 62 frontend files / 1,069 tests, three
static-normalization tests, typecheck, lint, architecture, 228 theme-contrast
pairs, 45-route production export, 43 normalized paths, 249-file embed equality,
and UI-host Go test/vet. The earlier notification replacement milestone also
passed repository-wide Go test/vet. Documentation head `2397586e2` records the
exact IAM semantics, mobile evidence, fixed sources and remaining real
IAM/SMTP browser gate in the owning FEAT.

## Continuation boundary

Keep the MOCK preview available. Consume IAM changes only from fixed, pushed
sources with terminal evidence. The replacement source is accepted only as a
client contract until the remaining real IAM/SMTP browser gate passes.
AccessKey and service-authorization reads still need installed-runtime
acceptance; product PEP enforcement, current permit and cloud-product
credential usability must not be inferred from IAM observations. Product
Profile draft, approval and publication remain absent until IAM fixes a public
contract. Do not call `/v1/internal/*`, invent product selectors or mount a
write action without accepted source and terminal evidence. Preserve the
current page shell, local data feedback, shared tables and content-area actions.
