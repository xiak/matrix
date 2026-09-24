# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-25
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed UI source: `bdaa9835`

## Authoritative route

- IAM client requirements, status and boundary integration evidence:
  [`FEAT-IAM-010`](../../IAM/FEAT-IAM-010-console.md).
- Shared UX requirements, status and verification evidence:
  [`FEAT-007`](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed-source UI adoption decisions:
  [`FEAT-007 adoption review`](../../docs/adoption/FEAT-007-control-plane-console.md).
- Shared product boundary:
  [`ADR-0002`](../../docs/architecture/ADR-0002-product-boundary.md).

Do not restate those owners here. Read this checkpoint only after compaction or
handoff, then validate it against Git and the linked FEAT.

## Durable pushed state

The UI source above is committed and pushed to this feature branch. Its
development verification is not complete IAM, installation, upgrade or release
acceptance. Evidence, limitations and remaining work belong only to the linked
FEAT owners. Integrate fixed backend contracts while preserving this branch's
UI, full static host/export and independent MOCK entry; do not replace them
with another branch's renderer or inherit that branch's UI acceptance.

The current milestone keeps the independent MOCK preview, fixed-contract LIVE
paths and synchronized static Go host. It aligns Root UX with the IAM target
architecture and gives policy and user directories readable compact rows with
visible current-page selection, without adding a LIVE contract. The shared
development gates passed; detailed
behavior, evidence and open real-process gates remain only in the FEAT owners.

## Continuation

Continue from the owning FEAT's open acceptance items. Coordinate IAM through
fixed pushed commits, never another task's dirty working tree. Inspect Git and
worktrees and select `feat/cloud-console-ux`, not the unrelated CI/CD or IAM
checkout in the original directory. Do not move those branches or introduce
their unrelated features. This checkpoint does not authorize a merge or runtime
upgrade. Preserve existing user installations; use an owned fresh test
environment. Real browser acceptance cannot be replaced by MOCK or API-only
checks. Do not duplicate the donor application or move installer-owned secrets
into the UI.

Next integration must select one fixed boundary from the owning FEAT. Do not
infer account-security update, remaining Role or SSO wire contracts from the
MOCK UI or from another task's unpushed work.

Replace this file only at another committed-and-pushed milestone. Do not append
command logs, chat transcripts, secrets, raw provider payloads, or machine-local
paths.
