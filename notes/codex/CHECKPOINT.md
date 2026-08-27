# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-08-27
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam-xxx`
- Pushed implementation milestone: `c9fa43d9452b5eda6cfef67f153ac0c106864e7a`

## Resume route

1. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md) owns the
   multi-tenant target, current behavior, remaining gates, and actual evidence.
2. [FEAT-006 adoption](../../docs/adoption/FEAT-006-platform-authorities.md)
   owns fixed-source decisions.
3. [ADR-0002](../../docs/architecture/ADR-0002-product-boundary.md) owns the
   cloud-platform direction and optional-provider boundary.

The milestone retains fixed account source `6a0f417` on baseline `9fd45b0`,
the primary/platform credential guard in `686efca`, and public installation
source `6401e96` with historical producer proof in `26f3569`. Platform tenant
opening/status/original-primary recovery, sealed owner/chain claims and real
PG18/five-process evidence are recorded in FEAT-006. Local gates passed;
confirm this implementation's independent CI before calling it CI accepted.
IAM and Audit schemas are independently version 2; this is not a release
profile, N-1 dispatcher contract or offline downgrade acceptance.

The user chose Alibaba-style protected primary ownership plus revocable
child administrators. Daily handoff never transfers primary identity; online
tenant recovery restores only its original primary and refuses any unrevoked
platform binding. Continue this branch's existing console/lifecycle UI, real
browser, remaining resource-isolation and release gates. Phase 2 owns its console branch;
Phase 3 owns host/Operation work and the offline schema-profile boundary. The
IAM/Audit lifecycle contract edit window is coordinated with that owner.
Integrate only mutually confirmed verified fixed commits, never another
worktree's uncommitted state. Work and push only this feature branch with
task-owned test resources; do not start extra agents or user tasks.

Replace this checkpoint only at another committed-and-pushed milestone.
