# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-10-30
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/handbook-mysql-iam`
- Committed and pushed milestone: `5f9aed721`
- Review: [PR #11](https://github.com/xiak/matrix/pull/11); check GitHub for current review and CI status.
- Outcome: the existing Chinese handbook now includes a real MySQL installation
  and connection example, plus IAM team access and credential workflows with
  real screenshots. DevOps is explicitly deferred by the user.

Follow `AGENTS.md` and the repository-local Git identity. User workflows belong
to the existing handbook, evidence to the owning FEAT, and executed operator
commands to the existing runbook. Secrets and machine-local deployment state
are excluded from Git and this checkpoint.

The Role instance-read fix is `cb08643262d93fd312e6f4abebcbc956c074bd05`.
The private signed candidate `matrix-v0.3.0-handbook.4-cb08643262d9` was built
from that clean commit and upgraded over `.3` on local Docker without DinD.
Its bounded runtime checks passed; it is not a public release or complete
Gate C. The exact code commit's full push CI passed. Consult the PR for the
separate PR-check result rather than inferring status from an earlier run.

## Reading route

- Reader workflows: [user handbook](../../docs/user-guide/README.md).
- MySQL page and protocol evidence: [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#用户手册界面复核).
- IAM flows, Role fix, cleanup and remaining validation limits: [FEAT-IAM-010](../../docs/features/iam/FEAT-IAM-010-console.md#用户手册的团队授权与凭据复核).
- Signed upgrade and local fixture recovery evidence: [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核).
- Verified operator workflow: [installation runbook](../../docs/runbooks/platform-installation.md).

Do not generalize these journeys to all release features, managed-data backup,
external SMTP delivery, physical phone authenticator compatibility, or a full
IAM test matrix. The owning FEAT records the actual acceptance scope.
