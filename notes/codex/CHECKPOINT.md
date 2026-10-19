# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-19
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source-only candidate: `323d7417ae230cf20d83d3903429b2492c0efb7f`
- Source parent: `bd730cb0835a7f0de2ff132f79140d2c85a28281`

## Authoritative route

- Shared console outcome, current implementation and exact gate evidence:
  [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed public contract adoption:
  [FEAT-007 adoption](../../docs/adoption/FEAT-007-control-plane-console.md).
- IAM console behavior and real-IAM acceptance:
  [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md).

## Pushed milestone

The earlier recoverable-command UX remains intact. Historical inspection of an
UNKNOWN Account security-settings command now updates the retained intent but
does not expire a later authenticated Session or invent a sign-in notice;
successful submission and a real `401` retain their existing Session boundary.

LIVE Group deletion now closes its busy dialog into an immutable receipt page
containing the stable Group identity, original request ID, result revision,
authoritative relationship counts and deletion time. It does not navigate or
read the current directory until the operator explicitly finishes. The later
directory read is independent and never substitutes for the command result.

The complete Account-access, access-workspace and navigation owners pass
240/216/20 cases. Typecheck, full lint, architecture and 234 theme contrast
pairs pass; locale JSON and diff checks are clean. The complete frontend gate
passes 77 Vitest files / 1,969 cases and all eight export-boundary cases. Exact
evidence and limitations belong to FEAT-007. A real pre-fix Group deletion gate
independently proved one write, one removed membership, one revoked direct
attachment, retained User/Session, subsequent permission denial and consistent
completion/outbox/Audit state. It reproduced the old missing-receipt UX but is
not browser acceptance of this source.

## Continuation boundary

Preserve the inspectable isolated MOCK and existing composition. Generated
assets are unchanged; the consuming IAM branch must selectively adapt the
fixed source, rebuild and independently pass CI and signed runtime/browser
gates. No backend/API/SQL/profile, shared DEV, real resource or mandatory
authentication setting changed. Phase 1 keeps email only for contact
verification and security-notification receiving; email login/MFA, phone
login, SMS, phone binding and physical-phone integration remain excluded.
Read only published fixed IAM Git objects, not the engineer's working tree.
