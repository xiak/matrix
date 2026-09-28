# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-28
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/phase3-mfa-enabling`
- Verified pushed milestone: `3d9016d81f831f682a8ca56707d23a4f2c9eafa0`.
  [Verification 36374469333](https://github.com/xiak/matrix/actions/runs/36374469333)
  completed successfully for Go, UI, authority-process and node-process.
  The exact composition is IAM 45/Audit 26/PaaS 6, revision 16; its fixed
  signed enabling predecessor is `ec701f54f1cecf216a2225d74dc67cf5fa6bd316`
  at IAM 40/Audit 24/PaaS 6, revision 15.
- Earlier preparation: `302a1120` pins the release-specific login wire contract
  and establishes legitimate MFA before the current same-profile backup;
  [Verification 36318140174](https://github.com/xiak/matrix/actions/runs/36318140174)
  verified that fixed source.
- Retained migration fixture: `ef88d8d6` (separates the retained-data historical migration
  from the current same-profile failure/rollback/recovery fixture, independently
  verified by [Verification 36315956026](https://github.com/xiak/matrix/actions/runs/36315956026)).
- The exact historical preparation commitments remain verified at `ba037e30`
  by [Verification 36314399263](https://github.com/xiak/matrix/actions/runs/36314399263).
- The bridge's cross-profile rollback refusal remains verified at `47c4e573`
  by [Verification 36312625241](https://github.com/xiak/matrix/actions/runs/36312625241).
- Real database-target runtime DSN fixture: `d078d456`,
  independently verified by
  [Verification 36055308970](https://github.com/xiak/matrix/actions/runs/36055308970).
- Native one-time join cleanup: `397d5952`, independently verified by
  [Verification 36053002247](https://github.com/xiak/matrix/actions/runs/36053002247).
- Earlier bounded authentication-recovery snapshot consumer: `8028738c`,
  independently verified by
  [Verification 36049571005](https://github.com/xiak/matrix/actions/runs/36049571005).
- Accepted host self-enrollment baseline in this branch's ancestry:
  `be3c4a96b4381426c01cd6315eaa3713c2855982`

## Resume route

1. [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md)
   owns the signed MFA recovery requirement, evidence and bounded acceptance.
2. [FEAT-008](../../docs/features/FEAT-008-linux-host-management.md)
   owns the accepted host self-enrollment target and evidence.
3. [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md)
   owns the LIVE first-enrollment browser ceremony.
4. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md)
   owns the separate IAM/Audit multi-tenant authority extension; consume only
   its independently verified fixed commits, then rerun the combined release
   gates before claiming the whole Phase 3 goal.

Do not treat this checkpoint or the accepted task-local signer as a production
release. Preserve Phase 2 and remote machines; remove isolated test resources
after use.

The real PostgreSQL process gate now proves the fixed IAM 40 executable's
retained-data upgrade to IAM 45: identities, credentials and original Audit
facts remain intact, old Sessions without new security-settings proof fail
closed, and fresh login and migration replay/restart work. The old IAM 3 local
recovery gate retains credential lineage and Audit facts under that same
fail-closed Session rule. Cross-service tests reauthenticate after platform
role grant/revoke before testing the tenant boundary; a stale bearer cannot
substitute for an authorized actor.

The combined release remains open. Full-profile admission still governs any
supported upgrade; this checkpoint grants no cross-profile rollback/recovery
permission. The final signed lifecycle must prove positive v5 recovery and
the two-host runtime with the real LIVE enrollment consumer. A DEV page,
process-only gate or this CI result does not establish that acceptance.
Preserve Phase 2 and remote machines; remove isolated test resources after
use. This checkpoint records no uncommitted or machine-local state.

Replace this checkpoint only at another committed-and-pushed milestone.
