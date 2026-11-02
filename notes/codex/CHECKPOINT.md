# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-02
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/product-onboarding-release`
- Verified implementation: `67a8dee905b060d24ec510609bcb0fac865f4e7a`.
- Active goal: finish ELK product onboarding and release closure, then reuse the same contract for Redis.
- PRs #11, #12 and #13 are merged. [PR #14](https://github.com/xiak/matrix/pull/14) remains draft. Do not merge a later implementation on the strength of earlier CI.

Follow `AGENTS.md` and repository-local Git identity. Read the relevant owner only:

- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#产品团队接入契约): product contract, current Logstash acceptance and pending Kibana dependency slice.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [executed onboarding commands](../../docs/runbooks/managed-service-onboarding.md).
- [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md): product authorization and dependency use.
- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): exact signed candidates, upgrade/rollback/recovery evidence and remaining Gate C limits.

Logstash's fixed implementation passed all 19 jobs in [Verification 41420489245](https://github.com/xiak/matrix/actions/runs/41420489245), including 2,141 console tests and five-product authority processes. [Product onboarding 41420489173](https://github.com/xiak/matrix/actions/runs/41420489173) passed; artifact 13130505645 was read and contains all 11 checks, with platform/release explicitly NOT_RUN in that adapter-only report. A separate local Logstash run passed six checks; its concurrent Kibana dependency did not become ready in time, so that local full run remains failed.

Signed Logstash .3 from the fixed source passed upgrade from .2, compatible rollback to .2, re-upgrade, explicit backup, recovery and final verify/status on host Docker without DinD. Recovery removed an unused quota created after backup, invalidated the old browser session and retained product events written after backup. Exact identities and command correlations belong to FEAT-005. Real installation/running/termination screenshots and user workflows are in the existing guide. This accepts the bounded private-candidate functionality, not cold-cache disconnected installation, public release or automatic expanded-upgrade failure injection.

The real terminated detail currently says the instance will disappear from the visible catalog, while authorized terminal records remain listed. Correct that wording in the next shared UI slice.

Current design work proceeds to Kibana: add a typed immutable same-tenant READY Elasticsearch dependency; separately authorize current dependency use; lock reserve/delete transactions against dangling dependencies. Preserve dependency-owned saved-object keys; issue and revoke only each Kibana's own service credential. Isolate Elasticsearch first and route only the exact allowed Kibana-to-Elasticsearch connection. The existing sample still relies on trusted test fixtures and is not a platform product. Redis follows accepted ELK. Reuse existing lifecycle, IAM evaluation and UI owners rather than creating a generic plugin or workflow engine.

Before a risky replacement, keep this verified predecessor committed and pushed. Preserve user installations and data; do not use global Docker prune, remove user images for an offline test, enable DinD or change host-wide network security. Shared-host Docker isolation is not physical isolation.

Secrets, account credentials, absolute checkout paths and uncommitted machine-local state are excluded.
