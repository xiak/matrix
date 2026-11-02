# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-02
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/product-onboarding-lk`
- Committed and pushed milestone: `d5625ec86b42cca0969749d3430aca27bd316c16`
- Outcome: product teams have a public deployment contract, executable
  Logstash/Kibana examples, and reproducible onboarding and acceptance workflows.
- Scope confirmed by the user: contract, runnable examples, tests and handbooks;
  L/K publication in the default catalog and signed release is deferred.

Follow `AGENTS.md` and the repository-local Git identity. This branch builds on
`feat/handbook-mysql-iam` at `e723dc4797be43aa49aebfc8b8363b0488f63a89`.
[PR #11](https://github.com/xiak/matrix/pull/11) owns the preceding illustrated
MySQL/IAM handbook work. Check GitHub for current base and review status.

## Reading route

- Contract, boundaries and evidence: [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#产品团队接入契约).
- Product-team workflow: [onboarding guide](../../docs/product-guide/managed-service-onboarding.md).
- Verified commands and recovery guidance: [onboarding runbook](../../docs/runbooks/managed-service-onboarding.md).
- Public implementation boundary: [adapter v1](../../api/adapter/managedservice/v1/README.md).
- Runnable examples and acceptance gate: [managedserviceonboarding](../../test/managedserviceonboarding).

The local sample gate passed on host Docker without DinD. Do not infer platform
integration or release acceptance from that result. Consult the feature owner
and the branch's independent GitHub checks for acceptance scope and current CI.
Secrets and machine-local deployment state are excluded from this checkpoint.
