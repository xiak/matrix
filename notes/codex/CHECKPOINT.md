# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `1566e22c4`
- Pushed documentation milestone: `47b5915aa`

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
login verification remains disabled for UX review. Application Hosting now
has an inspectable Deployment lifecycle preview that keeps Application
identity separate from desired Deployment state, immutable generations and
asynchronous Operations. Update, stop and rollback use stable title actions
and content-area review instead of Dialogs. Stop changes only `desiredState`;
rollback admits only earlier accepted `RUNNING` generations. Reviews expose
the strong ETag, IAM Action and caller request identity without Secret data.
The preview distinguishes initial `202 / ACCEPTED` from equal-replay `200`
with the original terminal Operation, re-reads Deployment after completion,
requires re-review after `412`, and never offers blind retry for `403` or the
closed `409` outcomes.

Source and synchronized embed are pushed at `1566e22c4`; FEAT evidence is
pushed at `47b5915aa`. The focused renderer/scene run passed 76 cases and the
complete frontend gate passed 57 files/937 cases plus three normalization
cases, typecheck/lint/architecture/228-pair style checks, 42-route export,
233-file embed equality and repository Go test/vet. Desktop and `390 x 844`
DEV checks found no Dialog, horizontal overflow or browser warning/error.

Earlier AccessKey carrier, same-User permission-source handoff, Application tag
recovery, service authorization, policy compilation/provenance and shared
navigation/loading milestones remain owned and indexed by FEAT-007; load only
the relevant evidence row when resuming them.

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
product access LIVE or add a browser signature/test-request flow.
Continue without reintroducing whole-page loading, hidden broad Context
subscriptions, fabricated totals, duplicate components or login verification
before UX acceptance.
