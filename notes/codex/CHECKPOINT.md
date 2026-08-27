# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-08-27
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam-xxx`
- Pushed implementation milestone: `f4ffd2af8fb120d4b14ad352e5f3cd11dfcbddba`

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
source `6401e96`, historical producer proof in `26f3569`, and lifecycle in
`c9fa43d`. The process gate's old DSN helper serialized the migration login;
do not reuse its old executable least-privilege claim. Fixed `cf003e4` proves
actual process logins, populated old-IAM upgrade and dual-tenant resource
isolation in real PG18 and passed independent CI `33060772852`. FEAT-006 owns
the corrected evidence and its limits. The console milestone passes its
source/component/export gates; confirm its own independent CI separately.
IAM and Audit schemas are independently version 2; this is not a release
profile, N-1 dispatcher contract or offline downgrade acceptance.

The user chose Alibaba-style protected primary ownership plus revocable
child administrators. Daily handoff never transfers primary identity; online
tenant recovery restores only its original primary and refuses any unrevoked
platform binding. The existing console now has lifecycle and original-primary
recovery controls. Its full real-browser, keyboard and narrow-screen paths
remain unaccepted, as do live-workload preservation and the signed populated
offline upgrade/rollback/recovery gates. Phase 2 owns its console branch;
Phase 3 owns host/Operation work and the offline schema-profile boundary. The
IAM/Audit lifecycle contract edit window is coordinated with that owner.
Integrate only mutually confirmed verified fixed commits, never another
worktree's uncommitted state. Work and push only this feature branch with
task-owned test resources; do not start extra agents or user tasks.

Replace this checkpoint only at another committed-and-pushed milestone.
