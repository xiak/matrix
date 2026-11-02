# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-02
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/managed-tenant-isolation`
- Committed and pushed implementation milestone: `6b37737a7ffdf774072ce6a27e40bff5268f7156`
- Outcome: the local Docker/MySQL slice isolates two real tenants and preserves
  the other tenant when one instance is terminated. Existing direct-port
  instances migrate without changing their data, credentials or endpoint.
- Delivery: [PR #13](https://github.com/xiak/matrix/pull/13), based on
  `feat/product-onboarding-lk`. Check GitHub for current review and CI state;
  do not infer a merge or a complete release from the local runtime evidence.

Follow `AGENTS.md` and the repository-local Git identity.

## Reading route

- Contract, scope and runtime evidence: [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#docker-mysql-租户隔离).
- Signed local candidate and upgrade evidence: [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核).
- Executed operator workflows: [installation runbook](../../docs/runbooks/platform-installation.md).
- User workflow: [managed services guide](../../docs/user-guide/services-and-applications.md#多个团队使用时).
- Runtime owners: `app/adapter/managedservice/localmysql`, the existing
  `TestLocalMySQLRealRuntime` and `TestManagedProductProviderProcesses` gates.

The verified local scope is shared-host Docker/MySQL isolation. It does not establish
physical isolation, general VPC/CNI support, other products' isolation, K8s/VM
connectivity, a complete Gate C, or old-worker lifecycle support for the new
MySQL topology. Consult the FEAT owners rather than extending this checkpoint.

The preceding [PR #12](https://github.com/xiak/matrix/pull/12) delivers the product
onboarding contract, runnable L/K examples and acceptance handbook. The user
deferred adding L/K to the default catalog and formal release.

Secrets, test-account credentials and machine-local deployment state are not
portable memory and are excluded from this checkpoint.
