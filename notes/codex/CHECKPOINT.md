# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `ef81bb30c`
- Pushed documentation milestone: `2efd6d363`

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
uses the exact Action as the single semantic record entry. Source, occurrence
time and sequence share one secondary event line, removing the low-value
standalone time column. Actor context exposes only public non-secret AccessKey
attribution or complete Role-session lineage. Record detail makes producer
source the primary source fact instead of repeating Action as both label and
value. The fixed tenant boundary, collapsed structured query, signed opaque
cursor, integrity verification and no-LIVE-fallback behavior are unchanged.

Source and synchronized embed are pushed at `ef81bb30c`; FEAT evidence is
pushed at `2efd6d363`. The focused renderer passed four cases and the complete
frontend gate passed 57 files/937 cases plus three normalization cases,
typecheck/lint/architecture/228-pair style checks, 42-route export, 233-file
embed equality and repository Go test/vet. Desktop and `390 x 844` DEV checks
found no Dialog, horizontal overflow or browser warning/error.

Earlier Deployment lifecycle, AccessKey carrier, same-User permission-source
handoff, Application tag recovery, service authorization, policy
compilation/provenance and shared navigation/loading milestones remain owned
and indexed by FEAT-007; load only the relevant evidence row when resuming them.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits with an explicit consumable confirmation. Revision 10 is pushed
at implementation `35e15da224e68bf0aa39d311254e123734b832f1`, evidence
`452d021e17347feabbd6204c8d703c25fa45d38e` and digest
`sha256:759bd751d03fc8ddceb69f6a5e827328401dcbd47d73a1e568a0b76c5a517256`,
but independent Verification `36858924218` is not terminal. Revision 11 is now
fixed at implementation `05336ad368996a500c0769fe62767204bd9333d0`, evidence
`dcddcebd7f7a109f034a9d365bd85562e69a839e` and digest
`sha256:ba8b808cc72c4ff1eb34d9eb933b5cde4ee95dde0f1a5c361058c2dab6937b48`;
its independent CI `36864073811` is still pending. Do not add revision 10 or 11
Actions to the accepted carrier set until the applicable independent run is a
successful terminal result. Revision 11 Deployment update/stop/rollback may
only appear as isolated MOCK meanwhile. Revision 12 is pushed at implementation
`4433b7ac00fec3ae7e2fdae35fad4bbdc4cf9238`, attack-gate evidence
`c83c38d7b91aa17003c2d217fd509eaba37d98d5`, FEAT/remote head
`76048c52db248da2619d9d3e662394551e6f1ab1` and digest
`sha256:ec6ef98cd9b4939cbbdd05632c8fbd28ff8ce79d98466ce98103c3fae30699b6`;
its independent CI `36870473445` is pending, so its Application-label
AccessKey work is not a LIVE console dependency. Do not label programmatic
product access LIVE or add a browser signature/test-request flow. IAM is
currently validating a later tenant Audit query/integrity AccessKey carrier;
consume it only after the engineer returns fixed exact Actions, Profile
revision/digest, public request boundary and independent gate status.
Continue without reintroducing whole-page loading, hidden broad Context
subscriptions, fabricated totals, duplicate components or login verification
before UX acceptance.
