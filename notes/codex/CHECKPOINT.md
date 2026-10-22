# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-22
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Last pushed UX evidence: `31675da0d`
- Source commit: `31675da0d14ad95d0febc73c940bdbd9585a027b`

## Authoritative route

- Shared console outcome, current implementation and exact gate evidence:
  [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed public contract adoption:
  [FEAT-007 adoption](../../docs/adoption/FEAT-007-control-plane-console.md).
- IAM console behavior and real-IAM acceptance:
  [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md) and
  [FEAT-IAM-011](../../IAM/FEAT-IAM-011-acceptance.md).

## Pushed milestone

The current candidate preserves the shared product navigation and exact-IAM
read composition, then adds strict LIVE Role-deletion receipt handling at
`f0dbf742c` and a deliberately separate MOCK completion at `31675da0d`.
The MOCK result names its browser-session scope and never pretends to be a
server receipt. The maintained `4317` preview exercised confirmation,
retained completion and explicit return to an independently rendered Role
directory. The final source passes 79 frontend files / 2,075 cases, all eight
Node export-boundary cases, production/export/embed equality across 59 pages
and 324 files, and PaaS UI Go test/vet. Exact evidence and limits are recorded
once in FEAT-007; IAM semantics and real-process acceptance remain with
FEAT-IAM-010/011.

## Continuation boundary

Preserve the inspectable `4317` isolated MOCK and existing composition. LIVE
Role deletion still needs the IAM-owned real-browser write, Audit and
authorization postconditions; this branch must not infer them from its strict
client tests or MOCK journey. Continue from the smallest unaccepted FEAT-007
slice instead of replaying accepted navigation, attachment or preview gates.
The UX branch has changed no backend/API/SQL/profile, real resource or
mandatory authentication setting. Phase 1 still keeps email only for contact
verification and security-notification receiving; email login/MFA, phone
login, SMS, phone binding and physical-phone integration remain excluded.
