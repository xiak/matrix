# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-04
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `ed4e3e69c`
- Pushed documentation milestone: `09686b7c5`

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
login verification remains disabled for UX review. The existing Passkey/WebAuthn
concept component now explains unconfigured, configured-but-not-production-ready,
and IAM-authoritative available/restricted states. It fixes trusted RP ID/origin,
target-bound registration/deletion step-up, exact Session ownership, fail-closed
credential-risk handling and controlled recovery without displaying a fake
device directory or exposing registration, deletion, reset, recovery or save
actions. Initial mount no longer steals focus from the page title.

Source and synchronized embed are pushed at `ed4e3e69c`; FEAT evidence is
pushed at `09686b7c5`. The complete 62-file/1046-test frontend suite, three
static normalization tests, typecheck, lint, architecture, 228-pair style
checks, 45-route production export, 249-file embed equality and repository Go
test/vet passed. Desktop and `390 × 844` DEV showed no horizontal overflow,
inputs, Dialog, or submit-success state in this preview.

Earlier notification-address replacement, paginated policy Action catalog,
organization governance, cross-account collaboration, Role SSO journey, Access
Analyzer recovery trust, Account security report, federation replacement,
Deployment lifecycle, AccessKey carrier, Application tag recovery, service
authorization, policy compilation/provenance and shared navigation/loading
milestones remain owned and indexed by FEAT-IAM-010 and FEAT-007; load only the
relevant evidence row.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits after the IAM owner explicitly marks the contract consumable.
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
