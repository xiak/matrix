# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-08-27
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam-xxx`
- Pushed implementation milestone: `b66d77db0499b227f42b3b14d1869329aabcca30`

## Resume route

1. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md) owns the
   multi-tenant target, current behavior, remaining gates, and actual evidence.
2. [FEAT-006 adoption](../../docs/adoption/FEAT-006-platform-authorities.md)
   owns fixed-source decisions.
3. [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md) owns
   console implementation and browser acceptance.
4. [ADR-0002](../../docs/architecture/ADR-0002-product-boundary.md) owns the
   cloud-platform direction and optional-provider boundary.

The milestone retains fixed account source `6a0f417` on baseline `9fd45b0`,
the primary/platform credential guard in `686efca`, public installation
source `6401e96`, historical producer proof in `26f3569`, lifecycle in
`c9fa43d`, and actual process-login correction in `cf003e4`. The old DSN
helper serialized the migration login; do not reuse its old executable
least-privilege claim. FEAT-006 owns the corrected evidence and limits.
Independent CI `33065779664` passed all three jobs (`go`, `authority-process`,
`node-process`) for this milestone. Local console source/component/export
checks pass, including 69 tests and two identical bounded production exports.
FEAT-007 owns its real browser and measured narrow-screen evidence; FEAT-006
owns the task-local live executor, workload/data preservation and audit replay
evidence. Do not equate that runtime with the CI pending-record fixture.

The user chose Alibaba-style protected primary ownership plus revocable
child administrators. Daily handoff never transfers primary identity; online
tenant recovery restores only its original primary and refuses any unrevoked
platform binding. Real account/lifecycle, forced password replacement and
resource isolation paths pass; keyboard-only end-to-end acceptance remains
open. Signed populated offline upgrade/rollback/backup/recovery and the complete
installed-release browser gate also remain open. IAM/Audit schema version 2
does not prove N-1 compatibility: the release profile must pin authority
versions and a contract revision that includes the seven-column IAM claim.
No mutually verified offline profile covering this lifecycle is available yet.

Phase 2 owns its console branch; Phase 3 owns host/Operation work and the
offline profile boundary. The IAM/Audit lifecycle contract edit window remains
coordinated with that owner. Integrate only mutually confirmed verified fixed
commits, never another worktree's uncommitted state. Work and push only this
feature branch with task-owned test resources; do not start extra agents or
user tasks. The persistent goal remains active until its remaining gates pass.

Replace this checkpoint only at another committed-and-pushed milestone.
