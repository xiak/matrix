# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `f5364f6a7`
- Pushed documentation milestone: `7996f07ab`

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
login verification remains disabled for UX review. The read-only capability
directory and User-scoped AccessKey workspace carry the isolated fixed Audit
r3 declaration and its public query/integrity result boundaries. A labelled
operation selector now mounts only one PaaS/Audit outcome table at a time. The
browser still does not sign, retain Secret material or send a product request;
the pending backend verification keeps this outside LIVE acceptance.

Source and synchronized embed are pushed at `f5364f6a7`; shared-console and
IAM-client FEAT evidence is pushed through `7996f07ab`. The complete frontend
gate passed 57 files/940 cases plus three normalization cases,
typecheck/lint/architecture/228-pair style checks, 42-route export, 233-file
embed equality and repository Go test/vet. Desktop and `390 x 844` DEV checks
found no Dialog or horizontal overflow and no browser warning/error logs.

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
Audit Profile r4 and its trusted-edge `request.source-ip` condition are not
fixed or pushed and therefore remain absent from the UI; the browser must not collect
or submit a client IP for this decision. Product
Profile publication, service-related roles and permission boundaries already
have backend-owned contracts and must not receive parallel frontend models.
The IAM owner confirmed that existing AccessKey, Role and Group surfaces now
have integration/acceptance gaps rather than missing UI contracts: do not
rebuild them without an actual fixed-object diff.
An authoritative effective-access/policy-simulator API does not exist; keep the
configuration review non-evaluating and do not create a decision-shaped MOCK.
Continue without reintroducing whole-page loading, hidden broad Context
subscriptions, fabricated totals, duplicate components or login verification
before UX acceptance.
