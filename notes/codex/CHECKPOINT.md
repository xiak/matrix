# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-04
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `3e206bad1`
- Pushed documentation milestone: `7bfeb0edf`

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
login verification remains disabled for UX review. The cross-account concept
preview now separates IAM Role assumption from direct product-resource sharing.
Role assumption requires source permission plus target trust and yields a
short-lived RoleSession. Direct sharing remains product-owned and appears only
after that product declares a resource-policy or ACL contract and enforces it at
its PEP. Neither mode exposes actions, generic Principal editing, anonymous
access or fabricated success.

Source and synchronized embed are pushed at `3e206bad1`; FEAT evidence is
pushed at `7bfeb0edf`. The focused 196-test renderer suite and complete
62-file/1041-test frontend suite, three static normalization tests, typecheck,
lint, architecture, 228-pair style checks, 45-route production export,
249-file embed equality and repository Go test/vet passed. Desktop and
`390 × 844` DEV showed no horizontal overflow, buttons, Dialog or console
warning/error in this preview.

Earlier User SSO, notification-address replacement, paginated policy Action
catalog, organization governance, Role SSO journey, Access Analyzer recovery
trust, Account security report, federation replacement, Deployment lifecycle,
AccessKey carrier, Application tag recovery, service authorization, policy
compilation/provenance and shared navigation/loading milestones remain owned
and indexed by FEAT-IAM-010 and FEAT-007; load only the relevant evidence row.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits after the IAM owner explicitly marks the contract consumable.
The next fixed northbound slice is IAM commit `07aa50627318708ed4d3ac9ce481b1e5829669d6`:
consume only the four `/v1/auth/notification-contact` first-email verification
APIs from a real full `LOGIN_SESSION`. Do not add Account/User selectors,
replacement, subscriptions, SMS, ENROLLMENT or STEP_UP. An unverified address
is never shown as bound; 401 expires the current Session rather than becoming a
code error; 422 rejects verification without clearing the Session; secrets and
responses use `no-store`. Keep the explicit MOCK preview isolated.
The client recovery invariant is implemented, but installation backup recovery
has not yet been inherited as a running or release-accepted integration. When
the IAM owner fixes and publishes that integration, verify the exact epoch,
command/time provenance, `RESTORE_GAP` rebuilding window and no-auto-disposition
behavior against the installed runtime before changing the LIVE status.

The earlier managed-service Profile/template compatibility milestone remains
release validation only: it is not Account consent, Role relation, binding,
RoleSession or permission. Browser code must not call IAM internal bind/session
endpoints, and real managed-service consent/unbind remains MOCK until its
northbound/BFF wire is mounted and browser-verified.

Continue without reintroducing whole-page loading, hidden broad Context
subscriptions, fabricated totals, duplicate components or login verification
before UX acceptance.
