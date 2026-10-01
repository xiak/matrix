# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `db01dd6da`
- Pushed documentation milestone: `32875b00a`

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
login verification remains disabled for UX review. Application Hosting now has
a same-path, content-area resource detail reached from its resource directory.
Known identity, state, project, region and product facts remain stable while the
query changes; the journey does not open a Dialog or replace the page with a
whole-content skeleton. The explicit preview shows the product-owned resource
tag snapshot, ETag and the current MOCK Profile's one declared
`resource.tag/environment` condition. Other tags remain visibly outside the
Profile, and policy authoring remains unable to mutate resource tags. Unknown
resource IDs fail locally without fabricating a detail.

Source and synchronized embed are pushed at `db01dd6da`; FEAT evidence is
pushed at `32875b00a`. The 57-file/922-case frontend suite, three normalization
cases, typecheck/lint/architecture/228-pair style gates, 42-route export,
233-file embed equality and UI host Go test/vet passed. Desktop and `430 x 900`
DEV verified directory → detail plus browser back/forward with no Dialog,
warning/error or overflow; viewport, document and body width stayed 430px.

The previously pushed AccessKey owner directory, policy-compilation provenance,
service-authorization, policy-coverage, Audit, cross-service loading/navigation
and other console milestones remain owned and indexed by FEAT-007; load only
the relevant row when resuming that work.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits. The revision-5 resource-tag example remains isolated MOCK until
IAM's storage/authority gates are green; LIVE exposes only declarations returned
by the strict Profile endpoint. Resource-tag update/delete/CAS, arbitrary caller
attributes and raw decision/debug surfaces remain unavailable. Continue from
the next uncovered customer workflow without reintroducing whole-page loading,
hidden broad Context subscriptions, fabricated totals, duplicate components or
login verification before UX acceptance.
