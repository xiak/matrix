# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-03
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/product-onboarding-release
- Goal: complete ELK/Redis product onboarding and signed release closure, including documentation and owned test cleanup.
- [v0.3.0 is public](https://github.com/xiak/matrix/releases/tag/v0.3.0), Release ID 432360073, published 08:02:24 UTC. The signed payload and tag remain fd1eaa88879edb5d18879c2e55fb9175a190711d.
- PR #14 delivered the product implementation; PR #15 delivered publication recovery. Both are merged. The publisher repair is 63c1fcc82f6a66af20770db1c2db048f7cce7ec2; it does not change runtime payload code.

Follow AGENTS.md and repository-local Git identity. Load only the relevant owner:

- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): official signed identities, actual cold/runtime/browser/transport evidence, recovery, publication and supported limits.
- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#产品团队接入契约): contract, adapter/platform gates, native isolation and product limits.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [verified commands](../../docs/runbooks/managed-service-onboarding.md): reproducible product handoff.
- [User guide](../../docs/user-guide/getting-started.md), [product examples](../../docs/user-guide/services-and-applications.md), and [installation commands](../../docs/runbooks/platform-installation.md): download-to-first-use and maintenance workflows.

Production native job 125744139260 in run 41583699116 accepted the original signed payload. The original overall run remains failed because of its old draft-lookup bug. Recovery run 41599590448 succeeded on main with the repaired publisher, reusing artifact 13210432139 and the same draft without rebuilding or signing. All eight uploaded digests match the original evidence; independent downloaded Ed25519 verification passed. The downloaded evidence ZIP has the same 22 public files and all twelve visually reviewed screenshots. Unauthenticated Release/tag lookup and exact manifest download passed. FEAT-005 owns detailed proof.

The repair passed all twenty PR Verification jobs in 41595424725; actual seven-product P1 was 395.98 seconds. Thirty-three publication-boundary tests passed locally, on Linux CI and in the protected recovery job. The redundant branch run was cancelled only after proving identical Git trees. Direct-main automatic Verification 41599492116 is still running; observe that existing run, do not start a duplicate. The signed payload already has its accepted exact-main Verification and Product onboarding gates, as recorded by the FEAT owners.

This documentation delivery repairs the stale four-product catalog statement, connects the public package to installation/first-use and product-team workflows, and records the completed release. Finish by confirming main contains this branch, observing the existing main verification to completion, linking Release notes to the final handbook commit, and making a final bounded public-release/local-cleanup check. Then update this checkpoint at the completion milestone and mark the goal complete. No new local Docker test or multi-GB download is needed.

The user authorized merging, formal release and dedicated signing custody. Reuse matrix-release-20261103; never regenerate it as a retry. The protected release environment remains main-only. Preserve the original installation and user data. The older local Logstash profile is 88/40/8+r40; this official package is 88/40/9+r41 and is fresh-install-only. Shared-host Docker does not establish physical tenant isolation. Redis is single-node AOF; platform backup does not back up product business data.

Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
