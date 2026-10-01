# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `7269ce6a`
- Pushed documentation milestone: `3a361fc9`

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
login verification remains disabled for UX review. Policy permission uses and
permission-boundary uses now keep separate semantics while sharing searchable,
locally paged table controls and the common footer. Filtering is deferred,
stale identity links are disabled during transitions, and derived relationship
snapshots are memoized. The page explicitly describes a complete MOCK snapshot
and does not imply a LIVE server total or cursor contract.

Source and synchronized 233-file embed are pushed at `7269ce6a`; FEAT evidence
is pushed at `3a361fc9`. A 13-owner fixture proves first/second-page behavior,
search counts and exact Role navigation. The milestone passed 57 frontend
files / 915 tests, three normalization cases, type/lint/architecture checks,
228 theme contrast pairs, a 42-route static export, embed equality and
repository Go test/vet. Desktop DEV verified search and empty-result recovery
with no browser warning/error.

The previously pushed AccessKey owner directory, policy-compilation provenance,
service-authorization, policy-coverage, Audit, cross-service loading/navigation
and other console milestones remain owned and indexed by FEAT-007; load only
the relevant row when resuming that work.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits. Resource-tag LIVE editing stays disabled until IAM publishes
and independently verifies its contract. Continue from the next uncovered
customer workflow without reintroducing whole-page loading, hidden broad
Context subscriptions, fabricated totals, duplicate components or login
verification before UX acceptance.
