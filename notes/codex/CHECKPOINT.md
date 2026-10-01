# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-02
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `8e3361a84`
- Pushed documentation milestone: `de7fb4217`

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
login verification remains disabled for UX review. Existing enterprise
connection, visibility editing and member import now use the shared content-area
workflow instead of large Dialogs. Entry focuses the workflow heading; cancel
or completion restores the exact directory, detail or import trigger. Only the
destructive disconnect keeps a short confirmation Dialog.

This remains browser-memory UX only: it scans no QR code, installs no app,
connects no external directory, sends no invitation, grants no permission and
does not imply SSO. LIVE still exposes no entry, repository, HTTP contract or
successful receipt. Source and synchronized embed are pushed at `8e3361a84`;
documentation is pushed at `de7fb4217`. The focused enterprise case and
complete frontend gate passed 58 files/969 cases plus three normalization
cases, typecheck, lint, architecture, 228-pair style checks, 42-route export,
233-file embed equality and repository Go test/vet. Desktop and `390 × 844`
DEV confirmed the same content-area semantics, no workflow Dialog, heading
focus and cancel focus restoration.

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
states and forbidden inferences. Until that answer is fixed, new UX may explain
responsibilities and content flow only; it must not add a parallel domain model,
decision-shaped authorization result, LIVE adapter, publish action or fabricated
success. External assertions remain configuration-only, and the Account security
report remains information architecture rather than a mounted LIVE client.

Continue without reintroducing whole-page loading, hidden broad Context
subscriptions, fabricated totals, duplicate components or login verification
before UX acceptance.
