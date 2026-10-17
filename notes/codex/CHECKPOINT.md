# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-17
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source-only candidate: `343622a11d0ce4c65c763de0e717505e0b8dae9a`
- Source parent: `c8981dd160474710868bf84712f2b7792f283973`

## Authoritative route

- Shared console outcome, current implementation and exact gate evidence:
  [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed public contract adoption:
  [FEAT-007 adoption](../../docs/adoption/FEAT-007-control-plane-console.md).
- IAM console behavior and real-IAM acceptance:
  [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md).

## Pushed milestone

The User workspace retains original display-name and status commands across
content navigation and tab reload. UNKNOWN permits only the fixed original
completion lookup, not another write or an inference from current User state.
The semantic command editor and receipt notice reuse public content forms,
feedback, controls and leave/focus owners. Session, repository, actor and User
boundaries reject late results. Earlier Group Membership recovery remains a
different protocol: explicit exact replay, not the User completion lookup.

The isolated, fixed frontend source passed the complete supported Windows
frontend gates. Exact evidence and limitations belong to FEAT-007. Generated
assets are unchanged; this is not a newly built or deployed UI. The consuming
IAM branch must selectively adapt the source, rebuild assets and independently
pass its build, CI and signed-IAM browser/runtime gates. No older browser,
backend or embedded-asset result is inherited by this source candidate.

## Continuation boundary

Preserve the inspectable isolated MOCK and existing composition rather than
replacing the UI shell. No backend/API/SQL/profile, shared DEV, real resource
or mandatory authentication setting changed in this milestone. Phase 1 keeps
email for contact verification and security-notification receiving; it does
not add email login, email MFA, phone login, SMS or phone binding.

User deletion recovery and PolicyAttachment reminder-storage hardening are
not included in the User profile/status milestone. Keep the remaining work
and signed-browser acceptance with their existing FEAT owners. Read only
published fixed IAM Git objects, not the engineer's working tree or WIP.
