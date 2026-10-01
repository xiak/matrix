# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `402ce0b62`
- Pushed documentation milestone: `4dd6e441a`

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
login verification remains disabled for UX review. The misleading IAM
policy-coverage concept was replaced by the bookmarkable
`/console/access/policy-configuration/` configuration review. It inventories
local policy documents, sources and boundaries while keeping every runtime
authorization stage explicitly `NOT_EVALUATED`; the old component, route,
static-server query path and embedded export were removed together.

Source and synchronized embed are pushed at `402ce0b62`; shared-console and
IAM-client FEAT evidence is pushed through `4dd6e441a`. The complete frontend
gate passed 57 files/938 cases
plus three normalization cases, typecheck/lint/architecture/228-pair style
checks, 42-route export, 233-file embed equality and repository Go test/vet.
Desktop and `390 x 844` DEV checks found no Dialog or horizontal overflow; a
fresh post-build browser tab produced no warning/error logs.

Earlier Deployment lifecycle, AccessKey carrier, same-User permission-source
handoff, Application tag recovery, service authorization, policy
compilation/provenance and shared navigation/loading milestones remain owned
and indexed by FEAT-007; load only the relevant evidence row when resuming them.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits with an explicit consumable confirmation. The IAM engineer has
fixed Audit Profile r3 at implementation `620960989`, FEAT/head
`0c688302b9dea1050653eded2b9442a6b1322155`, digest
`sha256:83a1c4665b2363af22d882202f318f1ebb7ed16d33244723d18183ee3a404186`
and independent run `36876149921`; that run remains pending, so the Audit
AccessKey carrier is not yet an accepted LIVE console dependency. Product
Profile publication, service-related roles and permission boundaries already
have backend-owned contracts and must not receive parallel frontend models.
An authoritative effective-access/policy-simulator API does not exist; keep the
configuration review non-evaluating and do not create a decision-shaped MOCK.
Continue without reintroducing whole-page loading, hidden broad Context
subscriptions, fabricated totals, duplicate components or login verification
before UX acceptance.
