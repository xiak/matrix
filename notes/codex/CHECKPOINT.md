# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-25
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/phase3-mfa-enabling`
- Pushed milestone: `397d5952` (native one-time join cleanup survives a
  canceled gate, reports remote failure and passed Linux race plus independent
  [Verification 36053002247](https://github.com/xiak/matrix/actions/runs/36053002247))
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
records no uncommitted or machine-local test state.

Replace this checkpoint only at another committed-and-pushed milestone.
