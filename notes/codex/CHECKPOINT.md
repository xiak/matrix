# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-02
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/product-onboarding-release`
- Committed and pushed milestone: `2e87c6501` records the next acceptance target.
- Outcome: product-team onboarding must be repeatable for products like E/L/K,
  reusing the existing platform authorities and lifecycle. The user agreed to
  merge the existing handbook/onboarding delivery and advance formal integration.
- Delivery: [PR #11](https://github.com/xiak/matrix/pull/11) and
  [PR #12](https://github.com/xiak/matrix/pull/12) are merged into `main`.
  [PR #13](https://github.com/xiak/matrix/pull/13) remains open and now targets
  `main`; this branch includes its verified MySQL isolation implementation.
  Recheck GitHub before changing that delivery state.

Follow `AGENTS.md` and the repository-local Git identity.

## Reading route

- Current target, boundaries and evidence: [FEAT-007 product onboarding](../../docs/features/FEAT-007-control-plane-console.md#产品团队接入契约).
- Product-team workflow: [onboarding guide](../../docs/product-guide/managed-service-onboarding.md).
- Executed acceptance commands: [onboarding runbook](../../docs/runbooks/managed-service-onboarding.md).
- Existing executable owners: `api/adapter/managedservice/v1` and
  `test/managedserviceonboarding`; published products remain in their existing
  catalog, adapter, worker, UI and release owners identified in the guide.
- For dependency authorization, additionally read [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md).
- For signed installation delivery, additionally read [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md)
  and the [installation runbook](../../docs/runbooks/platform-installation.md).

The current L/K code still proves product-team examples only. No formal L/K
catalog, real dependency authorization, browser or signed-release implementation
was added at this milestone. Follow the FEAT's independently testable Logstash,
then Kibana slices; do not mark either published from S1/S2 evidence. MySQL's
verified shared-host isolation does not establish L/K network isolation or
physical isolation.

Secrets, test-account credentials and machine-local deployment state are not
portable memory and are excluded from this checkpoint.
