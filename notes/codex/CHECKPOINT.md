# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-07
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/host-self-enrollment`
- Accepted pushed source: `be3c4a96b4381426c01cd6315eaa3713c2855982`
- Verification: [run 34093252964](https://github.com/xiak/matrix/actions/runs/34093252964)
- Final signed offline gate: 542.27s, log SHA-256
  `a3761e44c0a547cd3ef8acf0f2530d2ad893d22bafed6fdba37ea3ab4d46aaa7`

## Resume route

1. [FEAT-008](../../docs/features/FEAT-008-linux-host-management.md) owns the
   iterative roadmap, requirements, status and acceptance evidence.
2. [FEAT-008 adoption](../../docs/adoption/FEAT-008-linux-host-management.md)
   owns fixed-source decisions.
3. [ADR-0002](../../docs/architecture/ADR-0002-product-boundary.md) owns the
   cloud-platform direction and optional-provider boundary.

FEAT-008 records the complete P3-6 acceptance evidence and is accepted on the
exact source above. Keep Phase 2 isolated and preserve its branch, worktree and
runtime. Follow AGENTS.md's single-owner documentation and behavior-based
testing rules for any successor work.

Replace this checkpoint only at another committed-and-pushed milestone.
