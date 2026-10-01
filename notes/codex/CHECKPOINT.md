# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `ccdb94c9`
- Pushed strict-contract test follow-up: `160b6be4`
- Pushed documentation milestone: `27bf4def`

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
login verification remains disabled for UX review. The catalog-driven visual
policy author now distinguishes trusted request facts from target-resource
facts. Its PaaS revision-5 preview exposes `resource.tag/environment` only on
`paas.application.read`, requires an exact instance resource, and explains
missing-tag, per-resource recheck and collection-boundary behavior. The browser
authors only policy syntax; it never submits or overrides trusted resource
facts and does not present resource-tag mutation as policy authoring.

Source and synchronized 233-file embed are pushed at `ccdb94c9`; FEAT evidence
is pushed at `27bf4def`. Strict negative coverage at `160b6be4` rejects unknown
resource-tag keys, wrong trusted sources, wrong value types and invalid tag
values without changing production behavior. The milestone passed 57 frontend files / 920 tests,
three normalization cases, type/lint/architecture checks, 228 theme contrast
pairs, a 42-route static export, embed equality and repository Go test/vet.
Desktop and `430 x 900` DEV verified the exact Action, resource-tag condition
and review flow without a Dialog or page overflow.

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
