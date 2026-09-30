# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-30
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `9ad0856e`
- Pushed documentation/head milestone: `975ce4d2`

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

## Durable pushed state

The existing independent MOCK console remains available and is the inspectable
UX surface. Its service-authorization review and exact-resource unbind flow are
browser-memory only; they preserve the Account relation and do not claim to
terminate unimplemented service sessions. The same inline flow now rehearses
the fixed public error boundary: uncertain results preserve one request intent
for equal replay, authorization-state conflicts require reread, idempotency
content conflicts and invalid requests stop, and authentication/authorization
failures never become a success state.

The observation surface also separates a future service request into trusted
service authentication, short-lived `source=SERVICE` session issuance,
product-PEP re-authorization and product-owned business execution. All four
remain explicit unverified MOCK states. It exposes no session ID, temporary
credential, internal endpoint or revoke action, and never turns configuration
state into a request permit.

The product repository now contains a strict but unmounted public bind/unbind
client adapted from fixed IAM source `92ea765b`. It accepts a caller-owned
idempotency key for exact replay, sends only the published product request
shape and rejects successful-looking receipts that do not match the route,
template or lifecycle. These methods are deliberately outside the mounted
provider and LIVE actions because IAM Verification `36701340805` has not
passed. No browser path calls `/v1/internal/*`; Account-relation retirement and
service-session actions remain absent.

The current milestone passed the complete frontend suite, export/embed gates,
architecture/style/type/lint checks and repository Go test/vet. Exact counts,
browser evidence and limitations live in FEAT-007, not this checkpoint.

## Continuation

Coordinate with the IAM engineer using a fixed pushed commit and accepted
verification result, never another task's dirty working tree. Once the public
bind/unbind implementation has passed its independent gate, inspect the new
fixed source and update the existing adoption decision before mounting the
client. Then add the product-owned LIVE review/state handling, preserve the
stable page shell and local loading regions, and run real IAM-process browser
acceptance. Unknown outcomes must retain the exact original body and
idempotency key; do not manufacture a new intent or infer Account-relation
deletion from the last visible binding.

Do not move unrelated branches, replace the approved console with another
renderer, enable login verification before UX acceptance, merge, or claim
release completion. Replace this file only at another committed-and-pushed
milestone. Do not append command logs, secrets, raw provider payloads or
machine-local paths.
