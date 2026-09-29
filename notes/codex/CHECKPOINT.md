# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-29
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed UI source: `cf11b8cb`
- Pushed documentation head: `1e070738`

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
paths and synchronized static Go host. Its access simulator now separates
principal-policy evaluation, optional permission-boundary evaluation and their
final intersection, and classifies evidence as `MATCH`, `NOT_MATCH`,
`CONTEXT_MISSING` or `CONTRACT_UNAVAILABLE`. Request-context guidance remains
truthful: source IP and time are operator-constructed preview facts, browser and
forwarded-header values are not trusted, and the UI does not claim to simulate
a gateway, proxy or product PEP. The product-onboarding MOCK now also exposes
the immutable Profile reference and digest, condition fact sources, the calling
service's PEP responsibility and an explicit unverified runtime-evidence state.
These are diagnostics, not a permit or published registry state. No LIVE
condition key, Profile publication or unpushed IAM network-context work was
adopted. The existing LIVE member Role self-service and independent MOCK Role
journey remain intact. Exact behavior, verification evidence and replacement
rules belong to the linked FEAT owners. Real IAM-process Role/network browser,
product PEP, installation and release acceptance remain open.

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

Next integration must select one fixed boundary from the owning FEAT. Session
activity/touch, Passkey registration and trusted network request context remain
MOCK until IAM provides a fixed, pushed commit with their required gates. The
Role self-service client still requires real IAM-process browser verification;
do not infer additional Role, SSO, session or network-context endpoints,
persisted fields, operators or credentials from the MOCK UI or from another
task's unpushed work.

Replace this file only at another committed-and-pushed milestone. Do not append
command logs, chat transcripts, secrets, raw provider payloads, or machine-local
paths.
