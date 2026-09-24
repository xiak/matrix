# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-24
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed UI source: `a2366dda` (documentation: `9481f436`)

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

The current milestone preserves the purpose-limited recovery-code client,
strict LIVE read-only Account MFA settings and independent MOCK security surface.
The MOCK Account-rule response-lost path requires normal TOTP re-login before
original-request inspection. The Account overview now separates preview Session
issuance from unknown Key, Role and business-use evidence, and the allowlisted
MOCK report retains collection gaps. Real settings update and S4 report APIs
remain unavailable in LIVE. The complete shared gates passed. Detailed contract
behavior, evidence and real-process limitations remain only in the FEAT owners.

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
