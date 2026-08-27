# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-08-27
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam-xxx`
- Pushed implementation milestone: `cdc6209a4b88685aeac2518d02aafa4510eee745`

## Resume route

1. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md) owns the
   multi-tenant target, current behavior, remaining gates, and actual evidence.
2. [FEAT-006 adoption](../../docs/adoption/FEAT-006-platform-authorities.md)
   owns fixed-source decisions.
3. [ADR-0002](../../docs/architecture/ADR-0002-product-boundary.md) owns the
   cloud-platform direction and optional-provider boundary.

The milestone adapts fixed account source `6a0f417` onto `9fd45b0` and
preserves platform-role separation. Its own real PG18 authority/process gates
are recorded in the FEAT; it is not full multi-tenant or release acceptance.
Continue the first unfinished vertical slice there. Phase 2 owns its console
branch; Phase 3 owns installation identity, public Audit partitioning, and
host/Operation work. Integrate shared changes only from mutually confirmed
verified fixed commits, never another worktree's uncommitted state. Work and
push only this feature branch with task-owned test resources.

Replace this checkpoint only at another committed-and-pushed milestone.
