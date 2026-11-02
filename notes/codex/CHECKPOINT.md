# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-02
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/product-onboarding-release`
- Pushed implementation: `c34eec1a1cd8472afbbb842a656e232cb2834838`.
- Active goal: finish ELK onboarding and release closure, then reuse the same product contract for Redis.
- [PR #14](https://github.com/xiak/matrix/pull/14) remains draft; the current candidate is not a public release.

Follow `AGENTS.md` and repository-local Git identity. Read the relevant owner only:

- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#产品团队接入契约): contract, completed Logstash candidate, Kibana platform implementation and actual local acceptance.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [verified commands](../../docs/runbooks/managed-service-onboarding.md).
- [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md): current dependency-use permission; [FEAT-IAM-001](../../docs/features/iam/FEAT-IAM-001-authorization-profile.md) owns the Profile declaration.
- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): signed runtime profile and lifecycle admission.

Kibana is now composed through the public typed Elasticsearch reference, current instance-use authorization, immutable same-Account/version/region database binding, serialized dependency reservation/termination, queue, production worker, catalog, release inventory and shared console. Read permission is insufficient; even equal replay rechecks current use permission. Failed provisioning may terminate without endpoint references, and cleanup retries retain the original reserved/consumed quota kind. Dependency protection remains until actual cleanup.

The actual adapter manages native Elasticsearch credentials through bounded HTTP inside the exact observed dependency container. The earlier worker-loopback failure is fixed. Kibana data traffic still uses the dedicated exact-dependency entry. There is no generic plugin engine or IAM evaluator product-name branch.

Local six-product production-process P1 passed in 611.82 seconds, including Kibana exact-resource authorization, revocation, shared data-view use and dependency deletion protection. Three final real PostgreSQL 18 storage gates passed with race. The full frontend suite passed 83 files / 2164 tests, nine export checks, type/lint/architecture/style gates and deterministic 352-file embedded output. Affected Go packages, race, vet and generation checks passed. Their boundaries and older S2 evidence stay in FEAT-007.

Independent CI for that exact pushed implementation is pending:
- [push Verification 41452216037](https://github.com/xiak/matrix/actions/runs/41452216037)
- [PR Verification 41452227411](https://github.com/xiak/matrix/actions/runs/41452227411)
- [Product onboarding 41452227464](https://github.com/xiak/matrix/actions/runs/41452227464)

Read actual conclusions and the twelve-check report before accepting them. The previous deb7287 adapter baseline had a successful push suite and product report but a PR MySQL runtime-state failure; the current fixture reports safe observed runtime details if it recurs. Do not hide a failed run behind another successful run.

Current source is IAM/Audit/PaaS 88/40/9 at runtime revision 41. The accepted private Logstash candidate remains 88/40/8+r40. Cross-profile upgrade and rollback remain rejected: the old worker cannot manage the new Elasticsearch network/dependency topology. The new source has not been installed over that candidate.

Next finish exact-source independent CI, signed current-profile runtime and real browser/handbook acceptance, including lifecycle/data/credential retention. Preserve the accepted installation and do not infer a complete cold-cache disconnected Gate C or public release from bounded local tests. Then implement Redis as the next vertical product slice. Redis has no implementation yet.

Preserve user installations/data. No global Docker prune, user-image removal, DinD or host-wide security changes. Shared-host Docker isolation is not physical isolation. No legacy repository inspection occurred in this slice.

Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
