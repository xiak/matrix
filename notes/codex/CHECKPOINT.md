# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-29
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/user-handbook`
- Committed and pushed milestone: `d5c42b769`
- Outcome: local Docker installation without DinD, first use, daily operations,
  upgrade, protected backup/recovery, and the illustrated Chinese handbook are
  validated within the scope recorded by their existing owners.

## Durable context

Follow `AGENTS.md`, including pragmatic DDD, replacement-first changes, exact
 documentation ownership, and repository-local commit identity. The handbook
uses real installed UI screenshots. Secrets and machine-local deployment
 details are excluded from Git and from this portable checkpoint.

The fixes are committed as `bafc3491f` (managed-service image selection and
first-password Session activity) and `63e5a02d6` (purpose-only IAM image
selection for backup/recovery). The final installed signed test candidate is
`matrix-v0.3.0-handbook.3-63e5a02d69f7`, built from the latter clean commit.
First password change succeeds directly into the console. The branch has not
been merged into main; these local candidates are not an accepted public
release or a complete offline Gate C.

## Reading route

- Reader workflows: [user handbook](../../docs/user-guide/README.md).
- Executed operator commands: [installation runbook](../../docs/runbooks/platform-installation.md).
- Installation, upgrade, recovery, negative identity-drift check, and exact
  runtime evidence: [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核).
- First-use regression and browser evidence: [FEAT-IAM-010](../../docs/features/iam/FEAT-IAM-010-console.md#首次改密修复与验证).
- Screenshot scope and real service/UI observations: [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#用户手册界面复核).

Do not infer that platform recovery restores managed business data, admits
arbitrary older IAM state, or supports a different machine. Consult the
existing owners before extending any of those boundaries.
