# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-02
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/product-onboarding-release`
- Committed and pushed implementation milestone: `f6ac580463d94046d429f7c2f9046562969c2cee`.
- Active user goal: finish ELK product onboarding and its release closure, then
  reuse that same path for Redis. Product teams should reuse platform authorities
  and lifecycle instead of duplicating them or changing IAM evaluation logic.
- Delivery: PRs [#11](https://github.com/xiak/matrix/pull/11),
  [#12](https://github.com/xiak/matrix/pull/12) and
  [#13](https://github.com/xiak/matrix/pull/13) are merged into `main`.
  [PR #14](https://github.com/xiak/matrix/pull/14) targets `main` and is a draft;
  check current GitHub status before changing its delivery state.

Follow `AGENTS.md` and repository-local Git identity.

## Reading route

- Target, implementation boundaries and fixed-source evidence:
  [FEAT-007 product onboarding](../../docs/features/FEAT-007-control-plane-console.md#产品团队接入契约).
- Product-team workflow: [onboarding guide](../../docs/product-guide/managed-service-onboarding.md).
- Executed commands: [onboarding runbook](../../docs/runbooks/managed-service-onboarding.md).
- Current implementation: `app/adapter/managedservice/locallogstash`, shared
  `localcontainer` lifecycle/configuration/ingress, and `test/managedserviceonboarding`.
- For platform authorization and dependencies, additionally read
  [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md).
- For signed delivery, additionally read [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md)
  and the [installation runbook](../../docs/runbooks/platform-installation.md).

The milestone replaces the separate Logstash sample implementation with the
real adapter and reuses MySQL's isolated ingress without changing MySQL's
installed entrypoint/migration document. Windows/Linux focused checks pass;
fixed-source local runtime passed in 592.79 seconds with eleven checks, including
Logstash's two tenant scopes. Product onboarding CI 41400154620 passed and its
non-secret report was inspected. Full PR Verification was still running at this
checkpoint; recheck the latest PR head instead of treating that as complete.

The default catalog, live worker registration, UI and signed release still have
four products. Next is the independently testable Logstash platform/release
slice, then Kibana's authorized Elasticsearch dependency, then Redis. Keep P1/P2
unaccepted until their real users, dependency authorization, explicit resource
cleanup, browser and signed-release gates pass. A source adapter or S2 report is
not formal product publication. Kibana's test fixture has no general tenant
network guarantee; shared-host Docker isolation is not physical isolation.

Secrets, account credentials and machine-local runtime state are not portable
memory and are excluded from this checkpoint.
