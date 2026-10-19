# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-19
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed candidate: `82954bcefe2abcad4d3f1d9c2189e0d5e6408a66`
- Source parent: `4d52ca50486aef230ae33df264756d45967e489b`

## Authoritative route

- Shared console outcome, current implementation and exact gate evidence:
  [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed public contract adoption:
  [FEAT-007 adoption](../../docs/adoption/FEAT-007-control-plane-console.md).
- IAM console behavior and real-IAM acceptance:
  [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md).

## Pushed milestone

Direct User and Role policy-relationship commands are bound to the concrete
repository and Session owner. Replacement owners restore the original
non-secret UNKNOWN reminder; late old success and `401` results cannot clear
it, render success or expire the current Session. A current-owner direct User
submission still expires its Session on `401`. Recovered User CREATE/REVOKE
results now retain the same explicit immutable operation/request/target/Policy/
attachment/revision/time receipt used by Group and Role until acknowledgement.

The follow-up candidate also requires the replacement repository to finish
current-identity verification before direct User attachment/revocation review,
submission or UNKNOWN-completion inspection becomes actionable. An early
User-detail read cannot cross that boundary; the frozen UNKNOWN reminder stays
available and becomes read-only inspectable after verification.

The focused User/Role suites pass 269 cases. Typecheck, full lint, architecture
and 234 theme contrast pairs pass; locale JSON and diff checks are clean. The
complete frontend gate passes 77 Vitest files / 1,974 cases and all eight
export-boundary cases. The 59-page build normalizes 57 segment files and the
unset/zero production exports match all 324 synchronized embed files. Full
repository Go test/vet pass. Exact evidence and limitations belong to FEAT-007.
No current-source browser write was performed or claimed.

The two new replacement-owner regressions first failed against the previous
source and then passed with the complete 245-case Account access renderer
file. Typecheck, changed-file lint, architecture and diff checks pass. This
source-only follow-up does not rebuild embedded assets or inherit CI/browser
acceptance; the consuming IAM branch owns those combination gates.

## Continuation boundary

Preserve the inspectable isolated MOCK and existing composition. Generated
assets are synchronized in the pushed candidate; the consuming IAM branch must
selectively adapt the fixed source and independently pass CI and signed
runtime/browser gates. No backend/API/SQL/profile, shared DEV, real resource
or mandatory authentication setting changed. Phase 1 keeps email only for contact
verification and security-notification receiving; email login/MFA, phone
login, SMS, phone binding and physical-phone integration remain excluded.
Read only published fixed IAM Git objects, not the engineer's working tree.
