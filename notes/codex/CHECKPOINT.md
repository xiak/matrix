# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `dc9ee5f8e`
- Pushed documentation milestone: `3a002f924`

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
login verification remains disabled for UX review. Application Hosting owns a
same-path, content-area resource detail and a one-key-at-a-time tag workflow.
Fixed resource identity stays visible; only product-owned mutable data changes.
Review presents the exact resource, IAM Action, strong `If-Match` ETag,
old-to-new value and permission-impact warning. A simulated success replaces the
local snapshot and displays only the terminal Operation fields safe for users;
it does not expose idempotency fingerprints, request digests or an invented
Audit event ID. Policy authoring cannot mutate resource tags, and unknown
resource IDs still fail closed.

Source and synchronized embed are pushed at `dc9ee5f8e`; FEAT evidence is
pushed at `3a002f924`. The 57-file/924-case frontend suite, three normalization
cases, typecheck/lint/architecture/228-pair style gates, 42-route export,
233-file embed equality and UI host Go test/vet passed. Desktop and `430 x 900`
DEV verified view → edit → review → terminal result with focus restoration, no
Dialog or overflow; viewport, document and body width stayed 430px. A fresh
validation tab emitted no warning or error. Historical HMR errors remain only
in the original long-lived tab's retained log buffer.

The previously pushed AccessKey owner directory, policy-compilation provenance,
service-authorization, policy-coverage, Audit, cross-service loading/navigation
and other console milestones remain owned and indexed by FEAT-007; load only
the relevant row when resuming that work.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits. IAM/PaaS candidate `e9ea19e65` fixes the single-key set/delete,
strong `If-Match`, idempotency, Operation and Audit contracts, but its newest
independent CI is not yet registered. Keep the UI on MOCK until that exact SHA
is accepted and a strict LIVE adapter is delivered; 412 must reload before a
new confirmation, 409 must distinguish no-change from idempotency conflict, and
the client must not invent a 422 branch or Audit ID. Arbitrary caller attributes
and raw decision/debug surfaces remain unavailable. Continue without
reintroducing whole-page loading, hidden broad Context subscriptions,
fabricated totals, duplicate components or login verification before UX
acceptance.
