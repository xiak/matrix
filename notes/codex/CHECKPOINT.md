# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-08-27
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/control-plane-console`
- Phase 2 implementation baseline: `8700095fb60385932fab32ef09d699e46eff48b0`
- Goal: Matrix PaaS Phase 2 control-plane console

## Authoritative route

- Requirements, target, implementation status, acceptance gates, and evidence:
  [`FEAT-007`](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed-source decisions:
  [`FEAT-007 adoption review`](../../docs/adoption/FEAT-007-control-plane-console.md).
- Shared product boundary:
  [`ADR-0002`](../../docs/architecture/ADR-0002-product-boundary.md).

Do not restate those owners here. Read this checkpoint only after compaction or
handoff, then validate it against Git and the linked FEAT.

## Durable pushed state

- Local `main` and `origin/main` are both
  `a3f71cfebc7f45326b1ec5679fe69333f8139551`; the feature branch contains that
  commit and is pushed to `origin/feat/control-plane-console`.
- The complete Discord-style Next.js/React application fixed at
  `69336e51f94fa98f6aa278fa4c62382e224dbeaf` is the sole UI architecture and
  visual-style donor. Its component facade is one application layer, not a
  second donor. The PaaS design record at `338d9b5...` is product-boundary
  reference only. Neither is a build or runtime dependency.
- The branch contains the donor-shaped App Router -> route -> provider ->
  repository -> scene -> renderer -> public-component chain, username/password
  IAM flow, PostgreSQL catalog and quota activation, read-only local-machine
  region view, managed installation worker, PostgreSQL 18 provisioner, Audit
  outbox, and signed offline release integration.
- `8700095` adds organization-scoped single-resource reads for offerings,
  regions, quota entitlements, installations, and installation Operations.
  The UI now polls only active installation resources and refreshes collection
  state once an Operation becomes terminal. OpenAPI, PostgreSQL RLS reads,
  HTTP authorization, provider behavior, identity correlation, and generated
  embedded assets are covered by current tests.
- The pushed source passed module verification, generation drift, full unit,
  vet and race suites, repeated critical tests, UI type/lint/architecture/style/
  test/embed checks, Linux amd64 cross-build, Markdown links, donor dependency
  and social-term scans, a clean PostgreSQL 18 tenant-isolation journey, and a
  real fixed-image PostgreSQL lifecycle test.

## Continuation

Continue from the owning FEAT's open acceptance items. Do not recover work from
old Phase 1 branch names, duplicate the donor application, add fake MySQL/ELK
products, or move installer-owned machine secrets into the browser.

Replace this file only at another committed-and-pushed milestone. Do not append
command logs, chat transcripts, secrets, raw provider payloads, or machine-local
paths.
