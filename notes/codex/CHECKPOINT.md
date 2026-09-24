# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-25
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/phase3-mfa-enabling`
- Pushed milestone: `25781fec` (FEAT-005 exact signed A/B authentication
  recovery extension accepted for its task-local test pair)
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

Replace this checkpoint only at another committed-and-pushed milestone.
