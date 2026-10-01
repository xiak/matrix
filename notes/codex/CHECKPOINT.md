# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `b8c73ae4`
- Pushed documentation milestone: `19540aa8`

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

## Latest pushed milestone

The independent DEV MOCK remains available at `http://127.0.0.1:4317`, and
login verification remains disabled for UX review. MOCK and LIVE AccessKey
entry now reuse one User-owner directory. Complete User snapshots search and
page locally; partial snapshots state that search covers only the loaded page,
follow the opaque IAM cursor and do not invent an Account-wide total. Keys are
still loaded only after choosing one User. The directory takes loading, busy
and page-read behavior as explicit inputs instead of subscribing to the whole
IAM Provider.

Source and synchronized 233-file embed are pushed at `b8c73ae4`; FEAT evidence
is pushed at `19540aa8`. The milestone passed 57 frontend files / 914 tests,
three normalization cases, type/lint/architecture checks, 228 theme contrast
pairs, a 42-route static export, embed equality and repository Go test/vet.
Desktop and `390 × 844` DEV checks covered search, User selection and responsive
labelled rows with no page overflow or browser warning/error.

The previously pushed policy-compilation provenance, service-authorization,
policy-coverage, Audit, cross-service loading/navigation and other console
milestones remain owned and indexed by FEAT-007; load only the relevant row
when resuming that work.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits. Resource-tag LIVE editing stays disabled until IAM publishes
and independently verifies its contract. Continue from the next uncovered
customer workflow without reintroducing whole-page loading, hidden broad
Context subscriptions, fabricated totals, duplicate components or login
verification before UX acceptance.
