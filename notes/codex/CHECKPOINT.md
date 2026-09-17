# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-17
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/host-self-enrollment`
- Accepted host-enrollment source: `be3c4a96b4381426c01cd6315eaa3713c2855982`
- Accepted K2 successor release source:
  `16b42679a3f19d73ee41af016e81ef2b95b938fd`
- Verification: [run 35214563892](https://github.com/xiak/matrix/actions/runs/35214563892)
- Final platform profile: IAM 30 / Audit 18 / PaaS 6, contract revision 12;
  node runtime revision 7
- Final real-host gate: one-time command enrollment of `172.30.1.161` reached
  `READY`, produced advancing CPU/memory/filesystem observations and delivered
  its registration Audit fact; its join material and every task runtime object
  were removed without rebooting either remote VM

## Resume route

1. [FEAT-008](../../docs/features/FEAT-008-linux-host-management.md) owns the
   iterative roadmap, requirements, status and acceptance evidence.
2. [FEAT-008 adoption](../../docs/adoption/FEAT-008-linux-host-management.md)
   owns fixed-source decisions.
3. [ADR-0002](../../docs/architecture/ADR-0002-product-boundary.md) owns the
   cloud-platform direction and optional-provider boundary.

FEAT-008 records both the complete P3-6 acceptance and the K2 successor release
closure. Keep Phase 2 isolated and preserve its branch, worktree and runtime.
Follow AGENTS.md's single-owner documentation and behavior-based testing rules
for any successor work.

Replace this checkpoint only at another committed-and-pushed milestone.
