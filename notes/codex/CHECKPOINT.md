# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-03
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/product-onboarding-release
- Managed-product implementation: 764cff427698377f70c24264be59a9fc5606d123. The signed cold-cache gate, native CI driver and complete protected-file custody proof are committed and pushed through 3c7127f29. The current gateway fix changes the installer; this is still a candidate, not a public release.
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

The native offline workflow assembles fresh-install A and exact successor B, then uses an empty native Docker data root inside private mount/network namespaces. No container hosts a daemon. Its separate runtime probe uses a different engine and does not populate the acceptance engine. Release assembly exports the authenticated observed runner image identity for both classic and containerd image stores. The isolated host creates an owner-only XDG runtime directory after replacing /run so containerd can execute processes. The fd763f512 probe and cold installation reached READY with nineteen healthy services; 3eaf53d6b corrected the stale node-enrollment port assertion. All nineteen independent push checks at 3eaf53d6b passed (41513379340).

Latest completed offline run 41525046240 at 737c2c51b passed the real APISIX selected/unselected routes and closed enrollment TLS gate. The manifest-selected DevOps route fix is now exercised by a signed package. A raw image archive is resolved through its exact observed signed identity, without assuming the installer's derived alias. Cold installation reached READY and passed IAM, signed AccessKey, primary/member revocation, SMTP, MFA and access-analyzer checks, then FAILED after 731.06 seconds at devops-foreign-tenant-boundary. Artifact 13179429825 has SHA-256 5316f2fdb91cb40df85da07e849d083dd0b2b2f4ed9957c107555af1d30c024a. The old cross-tenant fixture used the disabled beta Account and its invalidated primary Session. The current fix uses active alpha and its separately retained valid Session, preserving beta's disabled state and both original Session revocations. A boundary regression and the full phase1e2e unit package pass on Windows and native Linux. The complete fixed lifecycle still needs a successful run.

Product onboarding run 41525056959 at 737c2c51b independently passed all eighteen ELK/Redis checks in 832.66 seconds. Its actual artifact is 13180048181, SHA-256 a551c9a39015d6644cadfb7399e3c04387e7e64e84961417a0c1e8578f5f76e0. This proves S2 only. The user guide now explicitly identifies the installation-host operator as the business-credential handoff owner and asks readers to provide Account and instance IDs. The offline workflow retains the exact fresh-install A/B pair and public trust file only after the whole gate succeeds; this package has not yet been accepted. The acceptance-only ephemeral key is not a production release key. Private signers and installation data are never uploaded.

Full disconnected Gate C, expanded-product failed-upgrade/restart proof, a retained fresh-install delivery and public release remain open. Continue through the existing installation phase1e2e owner. Never disable networking or prune Docker globally on the user’s machine. Current Redis/ELK is 88/40/9+r41; accepted Logstash is 88/40/8+r40. Exact older installed inventories are authenticated sources only; rollback cannot discard required managed products.

Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
