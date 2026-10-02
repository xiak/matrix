# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-03
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `d8232a1a8`
- Pushed documentation milestone: `48c61de09`

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

The inspectable DEV MOCK remains available at `http://127.0.0.1:4317`, and
login verification remains disabled for UX review. Capability-gated User batch
association now uses the shared content area for Add to groups and Attach
policies, with explicit targets and select/review/submit stages. Cancel keeps
the directory selection and restores More actions; confirmed completion waits
for the authoritative refresh before clearing selection and restoring Create
user. User status and delete operations remain focused confirmations. This is
still isolated MOCK only and adds no LIVE repository or wire contract.

Source and synchronized embed are committed at `d8232a1a8`; FEAT evidence is
committed at `48c61de09`. The complete frontend gate passed 58 files/974 cases
plus three normalization cases, typecheck, lint, architecture, 228-pair style
checks, 42-route export, 233-file embed equality and repository Go test/vet.
Desktop and `390 × 844` DEV showed no association Dialog or horizontal
overflow; a fresh browser tab had no warning/error. Earlier shared loading,
page-command and content-workflow milestones remain owned by FEAT-007 and
FEAT-IAM-010.

Earlier Account security report, federation replacement, Deployment lifecycle,
AccessKey carrier, Application tag recovery, service authorization, policy
compilation/provenance and shared navigation/loading milestones remain owned
and indexed by FEAT-IAM-010 and FEAT-007; load only the relevant evidence row.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits after the IAM owner explicitly marks the contract consumable.
The IAM engineer is currently completing signed same-source A/B installation
plus real PostgreSQL and SMTP receipt gates. SMTP installation settings are
operator-private configuration, not a tenant IAM browser object; do not add
host, password, CA or dispatcher controls to the tenant console.

The IAM engineer has been asked for the next backend-not-yet-implemented areas
that are safe to prototype, with actor/owner, planned contract, allowed MOCK
states and forbidden inferences. The engineer is still completing the signed
A/B installation and real PostgreSQL/SMTP release gate. Until an answer is
fixed, new UX may explain responsibilities and content flow only; it must not
add a parallel domain model, decision-shaped authorization result, LIVE
adapter, publish action or fabricated success. External assertions remain
configuration-only, and the Account security report remains information
architecture rather than a mounted LIVE client.

Continue without reintroducing whole-page loading, hidden broad Context
subscriptions, fabricated totals, duplicate components or login verification
before UX acceptance.
