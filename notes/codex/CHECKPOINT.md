# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-08-27
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/control-plane-console`
- Verified runtime source: `44fa1c7bb4cd20f2f807e12ec1e8a753b65688b3`
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

The feature branch contains `origin/main` at
`a3f71cfebc7f45326b1ec5679fe69333f8139551`. The runtime baseline above carries
the light console theme, interaction recovery fixes, and managed-service
inventory guard for platform backup/recovery. The unified release lifecycle
test in `app/service/installation/test/releasee2e` covers the application and
managed PostgreSQL together; no parallel Phase 1-only runner remains. Signed
releases from this source passed the offline lifecycle and whole-engine restart
gates. Evidence and remaining acceptance work belong only to the linked FEAT.

Phase 2 continues in Docker-in-Docker. The user has started separate Phase 3
host-management work; do not move its branch, alter its working tree, or add
host-management features to this slice. Inspect `git worktree list` and use the
checkout of `feat/control-plane-console`, not whichever branch happens to be
in the original repository directory.

## Continuation

Continue from FEAT-007's open acceptance items. Preserve existing user
installations and perform release tests only in a fresh owned Docker
namespace. Do not substitute API-only checks for real browser acceptance,
duplicate the donor application, or move installer-owned secrets into the UI.

Replace this file only at another committed-and-pushed milestone. Do not append
command logs, chat transcripts, secrets, raw provider payloads, or machine-local
paths.
