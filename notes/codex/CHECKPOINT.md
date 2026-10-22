# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-22
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Last pushed UX evidence: `8c40091ec`
- Source commit: `8c40091eca162912a2f40596eb6c29458a48181b`

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
read composition, retains the Role-deletion receipt boundary at `f0dbf742c`
and `31675da0d`, and adds strict LIVE User-deletion plus same-tab recovery at
`8c40091ec`. The User intent is persisted and read back before its one POST;
storage failure closes the write, uncertain outcomes remain locked across IAM
navigation/reload/same-owner re-login, and obsolete-owner replies cannot clear
or replace current evidence. MOCK deletion remains browser-memory-only and
never pretends to be an IAM receipt. The final source passes 80 frontend files
/ 2,087 cases, all eight Node export-boundary cases, type/lint/architecture/
theme gates, production/export/embed equality across 59 pages and 324 files,
and PaaS UI plus architecture Go gates. Exact evidence and limits are recorded
once in FEAT-007; IAM semantics and real-process acceptance remain with
FEAT-IAM-010/011.

## Continuation boundary

Preserve the inspectable `4317` isolated MOCK and existing composition. LIVE
Role and User deletion still need IAM-owned real-browser writes, Audit and
authorization postconditions; User deletion additionally has no completion
lookup and therefore must remain locked after an uncertain result. Do not
infer those gates from strict-client tests, same-tab reminders or MOCK
journeys. Continue from the smallest unaccepted FEAT-007 slice instead of
replaying accepted navigation, attachment or preview gates. The UX branch has
changed no backend/API/SQL/profile, real resource or mandatory authentication
setting. Phase 1 still keeps email only for contact verification and
security-notification receiving; email login/MFA, phone login, SMS, phone
binding and physical-phone integration remain excluded.
