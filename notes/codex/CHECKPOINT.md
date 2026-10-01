# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `682e27702`
- Pushed documentation milestone: `3fbe4208d`

## Authoritative route

- IAM client requirements, status and boundary evidence:
  [`FEAT-IAM-010`](../../IAM/FEAT-IAM-010-console.md).
- AccessKey protocol and product-enforcement evidence:
  [`FEAT-IAM-007`](../../IAM/FEAT-IAM-007-programmatic-credentials.md) and
  [`FEAT-IAM-008`](../../IAM/FEAT-IAM-008-product-enforcement.md).
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
login verification remains disabled for UX review. The Audit directory now
keeps its title, tenant boundary and last successful table stable while its
structured query form stays collapsed by default. The persistent query trigger
shows the applied-condition count; refresh remains fixed at the opposite edge.
Apply/reset closes the form and restores focus, while invalid Role-session
lineage remains open for correction. Later queries retain the current table
with `aria-busy` and localized refresh status instead of briefly replacing the
content region with a whole-table skeleton.

The UI consumes only the fixed Audit query contract and does not invent an
`operationId` filter from the record shape. Source and synchronized embed are
pushed at `682e27702`; FEAT evidence is pushed at `3fbe4208d`. The focused
renderer passed 4 cases and the complete frontend gate passed 57 files/933
cases plus three normalization cases, typecheck/lint/architecture/228-pair
style checks, 42-route export, 233-file embed equality and repository Go
test/vet. Desktop and `390 x 844` DEV verified collapsed and expanded states
with viewport, document and body all 390px, no Dialog, overflow or browser
warning/error.

Earlier AccessKey carrier, same-User permission-source handoff, Application tag
recovery, service authorization, policy compilation/provenance and shared
navigation/loading milestones remain owned and indexed by FEAT-007; load only
the relevant evidence row when resuming them.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits with an explicit consumable confirmation. The IAM owner is
running the independent revision-10 gate; do not add its
Configuration/Revision/Deployment/Operation reads to an accepted carrier set
until the owner confirms the final pushed SHAs and CI outcome. Deployment
update/stop/rollback is a later candidate and may only appear as isolated MOCK
before that boundary is fixed. Do not label programmatic product access LIVE or
add a browser signature/test-request flow. Continue without reintroducing
whole-page loading, hidden broad Context subscriptions, fabricated totals,
duplicate components or login verification before UX acceptance.
