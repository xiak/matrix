# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-03
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/product-onboarding-release
- Outcome: ELK/Redis product onboarding, signed release, user/product-team documentation and owned test cleanup are accepted.
- [Matrix v0.3.0](https://github.com/xiak/matrix/releases/tag/v0.3.0) is public. Signed payload and tag: fd1eaa88879edb5d18879c2e55fb9175a190711d. Release ID: 432360073.
- PR #14 delivered the products; PR #15 delivered publication recovery. Both are merged. User and product-team documentation is also in main.

Follow AGENTS.md and repository-local Git identity. Load only the owning document:

- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): exact signed identities, production runtime/browser/transport evidence, recovered publication and supported maintenance limits.
- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#产品团队接入契约): product contract, adapter/platform acceptance, isolation and product-specific limits.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [verified commands](../../docs/runbooks/managed-service-onboarding.md): reusable adapter-to-platform handoff.
- [User guide](../../docs/user-guide/getting-started.md), [product examples](../../docs/user-guide/services-and-applications.md), and [installation commands](../../docs/runbooks/platform-installation.md): illustrated user workflows and operator handoff.

Production native job 125744139260 in run 41583699116 accepted the original signed payload. The old overall run remains failed because of its draft-lookup bug; it must not be relabelled successful. Protected recovery run 41599590448 succeeded using the same accepted artifact and draft, without rebuilding or signing. Its repaired publisher source is 63c1fcc82f6a66af20770db1c2db048f7cce7ec2. Both PR Verification 41595424725 and direct-main Verification 41599492116 passed all twenty jobs. Actual seven-product P1 logs passed in 395.98 and 401.01 seconds. FEAT-005 owns detailed evidence.

All eight public asset digests match the original delivery. Downloaded manifest/signature/public trust independently verify; the evidence ZIP has the identical 22 public files and twelve visually reviewed screenshots. Unauthenticated Release/tag lookup and exact manifest download passed. Release notes link to fixed handbook commit 2c33fd38ee1c92fe180f89ee9d6fa0e358f934ab, whose user/product-team/installation guides were fetched publicly and compared with Git. Runtime payload identity remains unchanged by later publication/documentation commits.

The unused test resources and failed partial local download were removed. The original installation was retained and freshly confirmed READY with nineteen healthy platform services. Do not delete its data or treat a stopped user instance as disposable. No local Docker workload or large download remains necessary for this release.

The user authorized formal release, merging and dedicated signing custody. Reuse matrix-release-20261103; never regenerate it as a retry. The protected release environment remains main-only. Preserve the original older Logstash installation: its 88/40/8+r40 profile is not a maintenance source for this fresh-install-only 88/40/9+r41 release. Shared-host Docker does not establish physical tenant isolation. Redis is single-node AOF; platform backup does not back up product business data. Future work must retain these published boundaries or explicitly replace them with newly accepted support.

No implementation or release gate remains open for this goal. Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
