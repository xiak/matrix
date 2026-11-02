# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-03
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/product-onboarding-release
- Current product implementation: 764cff427698377f70c24264be59a9fc5606d123, committed and pushed.
- Active goal: complete ELK onboarding/release closure, then reuse the product contract for Redis.
- [PR #14](https://github.com/xiak/matrix/pull/14) remains draft; no public release is accepted.

Follow AGENTS.md and repository-local Git identity. Load only the relevant owner:

- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#redis-接入切片): current Redis contract, native evidence and remaining platform/release acceptance; earlier sections retain fixed-source ELK evidence.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [verified commands](../../docs/runbooks/managed-service-onboarding.md): reusable adapter-to-platform handoff.
- [User workflow](../../docs/user-guide/services-and-applications.md#示例为-elasticsearch-开通-kibana): accepted actual ELK browser illustrations; Redis illustrations remain to be added after runtime verification.
- [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md): dependency Use and immutable template versions.
- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): signed identities, accepted ELK lifecycle receipts and remaining release gates.

ELK runtime a162c1cc25591139aaa9ec5f662488da7ad30084 passed independent CI and the local signed same-profile install/browser/upgrade/rollback/recovery gate; its illustrated evidence is committed. Those private, warm-cache results are not complete cold-cache disconnected Gate C. Expanded-product failed-upgrade injection and public release remain open.

Redis 8.2.11 now reuses existing catalog, worker, authority, UI, artifact and lifecycle owners. Its adapter owns authenticated AOF configuration; the bounded RESP probe is shared by existing S2/P1 suites. Linux host-Docker S2 passed all eighteen ELK/Redis checks in 1526.59 seconds, including Redis authentication/ACL, TTL, durable restart, network/data/credential isolation, lost-response replay and independent deletion. Related Go/race/architecture and three real PostgreSQL storage gates passed. Two frontend inventory expectations were corrected; their focused retest and an unchanged five-second timeout case passed. The initial full local frontend suite did not pass; exact-source CI remains authoritative for the complete rerun. Production exports are byte-for-byte reproducible and match all 367 embedded files; nine export tests passed.

Exact-source CI is running: push Verification 41485948364, PR Verification 41485956975 and Product onboarding 41485956945. Real seven-product P1, signed Redis maintenance/browser proof and user illustrations are pending. Do not infer acceptance from catalog presence or the S2 report's PASSED; its platform/release status remains NOT_RUN.

A failed local P1 run exposed exhausted default Docker address pools. A bounded probe reproduced the eighth-network failure and removed its seven owned probe networks. Only the two stopped ELK candidate stacks' containers and networks were reclaimed, preserving installation directories and data; the original installation's nineteen services remain healthy. No global prune, daemon changes or DinD were used. Keep user installations/data/images intact. Shared-host Docker isolation is not physical isolation.

Current Redis and accepted ELK use IAM/Audit/PaaS 88/40/9+r41; accepted Logstash uses 88/40/8+r40. Exact older installed inventories are accepted only as authenticated sources. Rollback still rejects missing current managed-product components; no cross-profile transition is claimed. No legacy repository inspection occurred in this slice.

Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
