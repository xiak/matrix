# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `1fd55d773`
- Pushed documentation milestone: `7ff9fd2b5`

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
login verification remains disabled for UX review. The cross-product Operation
center now projects the public PaaS `SubjectRef` instead of an ambiguous actor
string. Its stable collapsed row shows only product, typed initiating identity
and time; the content-area disclosure separates exact identity, non-secret
AccessKey attribution, Role-session identity and Role-session source. Search
includes those public identifiers. Secret, signature, nonce, request digest,
internal evidence and Account selectors remain absent.

This milestone consumes only the already fixed public Operation shape from IAM
implementation `b6d15c89a`; it does not add a LIVE Operation client or adopt an
unfinished Profile revision. Source and synchronized embed are pushed at
`1fd55d773`; FEAT evidence is pushed at `7ff9fd2b5`. The focused renderer passed
7 cases and the complete frontend gate passed 57 files/933 cases plus three
normalization cases, typecheck/lint/architecture/228-pair style checks,
42-route export, 233-file embed equality and repository Go test/vet. Desktop
and `390 x 844` DEV verified the disclosure hierarchy with viewport, document
and body all 390px, no Dialog, overflow or browser warning/error.

Earlier AccessKey carrier, same-User permission-source handoff, Application tag
recovery, service authorization, policy compilation/provenance and shared
navigation/loading milestones remain owned and indexed by FEAT-007; load only
the relevant evidence row when resuming them.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits. IAM revision 10 was still an unpushed candidate at this
checkpoint; do not add its Configuration/Revision/Deployment/Operation reads
to an accepted carrier set until the IAM owner publishes the fixed commit and
independent gate. Do not label programmatic product access LIVE or add a browser
signature/test-request flow. Continue without reintroducing whole-page loading,
hidden broad Context subscriptions, fabricated totals, duplicate components or
login verification before UX acceptance.
