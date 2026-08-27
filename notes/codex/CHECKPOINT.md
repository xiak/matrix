# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-08-27
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam-xxx`
- Pushed implementation milestone: `26f3569269ba6e8bf3ac55b3c596c55590e1144a`

## Resume route

1. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md) owns the
   multi-tenant target, current behavior, remaining gates, and actual evidence.
2. [FEAT-006 adoption](../../docs/adoption/FEAT-006-platform-authorities.md)
   owns fixed-source decisions.
3. [ADR-0002](../../docs/architecture/ADR-0002-product-boundary.md) owns the
   cloud-platform direction and optional-provider boundary.

The milestone retains fixed account source `6a0f417` on baseline `9fd45b0`,
the primary/platform credential guard in `686efca`, and adapts public
installation/Audit source `6401e96`. Event-bound historical producer proof,
real retained IAM/Audit upgrades and independent process gates are recorded
in the FEAT. IAM and Audit schemas are independently version 2; this is not
a release profile or offline downgrade acceptance.

The user chose Alibaba-style protected primary ownership plus revocable
child administrators. Daily handoff never transfers primary identity; online
tenant recovery must not recover a platform-bound identity. Continue the
unfinished tenant lifecycle/primary recovery slice in FEAT-006, then its own
console/browser and remaining release gates. Phase 2 owns its console branch;
Phase 3 owns host/Operation work and the offline schema-profile boundary. The
IAM/Audit lifecycle contract edit window is coordinated with that owner.
Integrate only mutually confirmed verified fixed commits, never another
worktree's uncommitted state. Work and push only this feature branch with
task-owned test resources; do not start extra agents or user tasks.

Replace this checkpoint only at another committed-and-pushed milestone.
