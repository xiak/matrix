# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-02
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/product-onboarding-release`
- Implementation: `a162c1cc25591139aaa9ec5f662488da7ad30084`; this checkpoint's containing commit adds accepted local ELK evidence and the illustrated user workflow.
- Active goal: complete ELK onboarding/release closure, then reuse the product contract for Redis.
- [PR #14](https://github.com/xiak/matrix/pull/14) remains draft; no public release is accepted.

Follow `AGENTS.md` and repository-local Git identity. Load only the relevant owner:

- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#产品团队接入契约): product contract, accepted bounded Logstash and Kibana evidence, current limits, Redis next slice.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [verified commands](../../docs/runbooks/managed-service-onboarding.md).
- [User workflow](../../docs/user-guide/services-and-applications.md#示例为-elasticsearch-开通-kibana): actual installation, dependency selection, business login/data view, maintenance and termination screenshots.
- [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md): current dependency Use and immutable template versions.
- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): exact signed identities, lifecycle receipts and remaining release gates.

Fixed a162 source passed both independent Verification runs 41462108500 and 41462128410 (19 jobs each). Product onboarding 41462126164 and actual artifact 13150478207 passed all twelve S2 checks; that report correctly keeps platform/release gates NOT_RUN. Earlier c34/e1 failures and the local Windows six-minute deadline remain failed historical evidence in the FEAT owner.

Signed same-profile ELK .3/.4 passed the local host-Docker install, real authenticated browser workflow, upgrade, direct-predecessor rollback and selected-backup recovery. Seven product containers and seven protected materials were unchanged through maintenance. Original data and saved views survived; post-backup unused quota was removed and pre-recovery Matrix Sessions were rejected. Dependency deletion protection remained effective after recovery. Public API cleanup revoked the precise Kibana service token, preserved Elasticsearch data/view/shared keys, then removed the remaining disposable E/L instances and returned all quotas. The original control plane was restored with the same 19 healthy containers and successful verify; the separate candidate installations remain retained and stopped. No DinD or global cleanup was used.

Current ELK remains IAM/Audit/PaaS 88/40/9+r41; accepted private Logstash is 88/40/8+r40. Cross-profile transitions remain rejected. Full cold-cache disconnected Gate C, expanded-product failed-upgrade injection and public release remain open; the local functional result does not satisfy those separate gates.

Redis has no implementation yet. Its next independently testable vertical slice must reuse existing catalog, provider, authority, worker, UI, artifact and acceptance owners, with a fixed supported version and real persistence/auth/isolation/delete evidence. Do not copy workflow or introduce an unconstrained template/plugin engine. No legacy repository inspection occurred in this slice. Preserve user installations, data and images; shared-host Docker isolation is not physical isolation.

Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
