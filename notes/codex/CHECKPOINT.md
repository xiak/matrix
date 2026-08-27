# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-08-27
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/control-plane-console`
- Pushed account-console source: `6a0f417743948a5303d3a3342cb1e8902c9d17f2`
- Prior installed-release source: `44fa1c7bb4cd20f2f807e12ec1e8a753b65688b3`
- Goal: Matrix PaaS Phase 2 control-plane console

## Authoritative route

- Account and authority requirements, status, acceptance gates, and evidence:
  [`FEAT-006`](../../docs/features/FEAT-006-platform-authorities.md).
- Console requirements, status, acceptance gates, and evidence:
  [`FEAT-007`](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed-source decisions:
  [`FEAT-006 adoption review`](../../docs/adoption/FEAT-006-platform-authorities.md)
  and
  [`FEAT-007 adoption review`](../../docs/adoption/FEAT-007-control-plane-console.md).
- Shared product boundary:
  [`ADR-0002`](../../docs/architecture/ADR-0002-product-boundary.md).

Do not restate those owners here. Read this checkpoint only after compaction or
handoff, then validate it against Git and the linked FEAT.

## Durable pushed state

The account-console source above is committed and pushed to the feature
branch. Its development verification is not final release acceptance. The
earlier installed-release evidence applies only to its named source; this
milestone did not upgrade a user's installation. Evidence, current limitations,
and remaining acceptance work belong only to the linked FEAT owners.

Phase 2 continues in Docker-in-Docker. The user has started separate Phase 3
host-management work; do not move its branch, alter its working tree, or add
host-management features to this slice. Inspect `git worktree list` and use the
checkout of `feat/control-plane-console`, not whichever branch happens to be
in the original repository directory.

## Continuation

Continue from the owning FEAT's open acceptance items. Coordinate the separate
IAM and Phase 3 work through fixed pushed commits, never another task's dirty
working tree. This checkpoint does not authorize a merge or runtime upgrade.
Preserve existing user installations and perform release tests only in a fresh
owned Docker namespace. Do not substitute API-only checks for real browser
acceptance, duplicate the donor application, or move installer-owned secrets
into the UI.

Replace this file only at another committed-and-pushed milestone. Do not append
command logs, chat transcripts, secrets, raw provider payloads, or machine-local
paths.
