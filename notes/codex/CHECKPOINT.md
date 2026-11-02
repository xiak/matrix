# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-03
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/product-onboarding-release
- Product implementation: 764cff427698377f70c24264be59a9fc5606d123. The signed cold-cache gate and native CI driver are committed and pushed through 3eaf53d6b; this is still a candidate, not a public release.
- Active goal: complete ELK onboarding/release closure, then reuse the product contract for Redis.
- [PR #14](https://github.com/xiak/matrix/pull/14) remains draft; no public release is accepted.

Follow AGENTS.md and repository-local Git identity. Load only the relevant owner:

- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#redis-接入切片): current product contract, S1/S2/P1, real browser and independent-delete evidence, exact CI and limits.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [verified commands](../../docs/runbooks/managed-service-onboarding.md): reusable adapter-to-platform handoff.
- [Redis user workflow](../../docs/user-guide/services-and-applications.md#示例开通并验证-redis): three actual screenshots, activation/quota/create/native read-write/maintenance/termination.
- [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md): dependency Use and immutable template versions.
- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): exact signed identities, lifecycle receipts, original-installation restoration and remaining release gates.

Fixed runtime 764cff427 passed all nineteen push Verification jobs (41485948364), including seven real product providers in 325.39 seconds. The checkpoint-only e3128822c passed nineteen PR Verification jobs (41486683660) and all eighteen ELK/Redis S2 checks (41486683645, actual artifact 13164025331). Local full native S2 and three real storage/race gates passed. Failed local Windows P1 attempts remain failed evidence in FEAT-007; no deadline was enlarged.

Signed Redis .1 declares accepted ELK .3 as its predecessor, so it is an upgrade-only candidate, not a fresh-install package. Exact ELK→Redis .1 and Redis .1→.2 upgrades, .2→.1 rollback, selected-backup recovery and final verify passed on host Docker. Both Redis instances retained their native identities, endpoints, credentials and data; post-backup business keys survived, the post-backup unused quota was removed, old Matrix Sessions were rejected and the original password could log in again. An incompatible rollback to ELK was rejected. Both disposable Redis instances were then terminated through the public API with precise cleanup, peer survival and quota return verified.

The original installation was restored to the same nineteen healthy containers and passed verify. Its stopped PostgreSQL remained untouched and its 173 MySQL data files matched the prior checksum. The independent Redis candidate is retained and stopped. Local test SMTP aliases now match the configured hostname, with DNS verified. Do not use candidate credentials against the restored original installation. No DinD, global cleanup or user-data deletion was used.

The existing phase1e2e owner now creates all seven managed products and retains ELK/Redis across failed upgrade, upgrade, rollback, selected-backup recovery and engine restart. It checks original runtime identities, endpoints, mounts, networks, all top-level protected material digests/permissions and preexisting business data before reverse dependency-order deletion. Custody is captured after Kibana creates shared dependency encryption keys. These expanded paths are implemented but have not yet completed Gate C.

The native offline workflow assembles fresh-install A and exact successor B, then uses an empty native Docker data root inside private mount/network namespaces. No container hosts a daemon. Its separate runtime probe uses a different engine and does not populate the acceptance engine. Release assembly now exports the authenticated observed runner image identity for both classic and containerd image stores. The isolated host explicitly creates an owner-only XDG runtime directory after replacing /run; otherwise containerd cannot create exec process specifications. The fd763f512 probe and cold installation reached READY with nineteen healthy platform services. Commit 3eaf53d6b then corrected the stale port assertion to include the existing authenticated node-enrollment listener. Its offline run 41513378512 passed install/verify, IAM authority, signed AccessKey, primary/member revocation, SMTP, MFA and access-analyzer checks, then FAILED after 670.44 seconds at devops-admin-control-plane. Actual artifact 13175124013 has SHA-256 8de610bf7fe07c9abf3d04bb94a73e948bb2adae13dc9bf195a969c9dab2baef. Current diagnostics retain only a fixed DevOps operation stage and HTTP status, not server bodies, headers or transport errors; no acceptance assertion was relaxed.

Product onboarding run 41513385952 at 3eaf53d6b independently passed all eighteen ELK/Redis checks in 862.61 seconds. Its actual artifact is 13174628091, SHA-256 eebbadb5c698c1d5c155a2489438da85ac4def5997461fcab9650ae661a3c6e9. This proves S2 only. The offline workflow is configured to retain the exact fresh-install A/B pair and public trust file only after the whole gate succeeds; this package has not yet been accepted. The acceptance-only ephemeral key is not a production release key. Private signers and installation data are never uploaded.

Full disconnected Gate C, expanded-product failed-upgrade/restart proof, a retained fresh-install delivery and public release remain open. Continue through the existing installation phase1e2e owner. Never disable networking or prune Docker globally on the user’s machine. Current Redis/ELK is 88/40/9+r41; accepted Logstash is 88/40/8+r40. Exact older installed inventories are authenticated sources only; rollback cannot discard required managed products.

Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
