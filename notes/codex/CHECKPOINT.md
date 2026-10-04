# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-04
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed branch head: `5d30a0324`
- Pushed source/embed milestone: `ba7e57a9a`
- Pushed documentation milestone: `5d30a0324`

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
verification remains disabled for UX review. Source and synchronized embed
`ba7e57a9a` extend the shared delayed-feedback regression matrix across every
currently routed Overview, Catalog, Quota, Region, Application, Resource,
Installation, Operation, Message, DevOps, Observability, Log, Audit and IAM
loading-region branch. Each destination exposes stable named chrome immediately,
waits 200 ms before painting placeholders and confines them to the data-owning
region. The earlier compact IAM and notification-replacement behavior remains in
place, including the separate inspectable MOCK.

Acceptance at this milestone: focused shell 82 tests; complete frontend 62 files /
1,082 tests; three static-normalization tests; typecheck, lint, architecture and
228 theme-contrast pairs; 45-route production export, 43 normalized paths and
249-file embed equality; synchronized repository-wide Go test/vet. Documentation head
`5d30a0324` records the current shared gate; exact IAM semantics and remaining
real IAM/SMTP browser acceptance remain in the IAM owner.

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
