# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-27
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/phase3-mfa-enabling`
- Pushed milestone: `ef88d8d6` (separates the retained-data historical migration
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
3. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md)
   owns the separate IAM/Audit multi-tenant authority extension; consume only
   its independently verified fixed commits, then rerun the combined release
   gates before claiming the whole Phase 3 goal.

Do not treat this checkpoint or the accepted task-local signer as a production
release. Preserve Phase 2 and remote machines; remove isolated test resources
after use.

The combined release remains open: current published installation profile is
IAM 40/Audit 24/PaaS 6 with contract revision 15. Do not enable backup v5,
recover from an old backup automatically, or claim the signed multi-host gate
until a fixed IAM producer/restore source is selectively integrated and the
exact combined profile, signed runtime and browser gates pass. This checkpoint
records no uncommitted or machine-local test state. The final signed fixture
must prove predecessor migration and the successor's same-profile lifecycle,
with legitimate MFA qualification established before its positive v5 backup;
an unsupported old-backup restore cannot be used to continue a failure test.

Replace this checkpoint only at another committed-and-pushed milestone.
