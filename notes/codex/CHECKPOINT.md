# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-02
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/product-onboarding-release`
- Implementation: this checkpoint's containing commit; the preceding Kibana integration is `c34eec1a1cd8472afbbb842a656e232cb2834838`.
- Active goal: finish ELK onboarding and release closure, then reuse the same product contract for Redis.
- [PR #14](https://github.com/xiak/matrix/pull/14) remains draft; no public release is accepted.

Follow `AGENTS.md` and repository-local Git identity. Read only the relevant owner:

- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#产品团队接入契约): product contract, Logstash candidate, Kibana P1/S2 and failed signed UI evidence.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [verified commands](../../docs/runbooks/managed-service-onboarding.md).
- [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md): dependency Use and immutable service-role template versions.
- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): signed runtime/lifecycle admission and the new public-console verification.

Kibana integration includes the typed immutable Elasticsearch dependency, current exact-instance Use permission (also rechecked on equal replay), same-Account/version/region and READY validation, serialized dependency custody, queue/worker/catalog/release inventory and shared console. Cleanup retains dependency protection until actual success. Bounded container-local HTTP handles native Elasticsearch credential effects inside the real worker topology. Shared Kibana saved-object/report keys belong to the dependency; per-instance service credentials/session keys remain independent.

The c34 local six-product production-process P1 passed in 611.82 seconds. Its exact independent Product onboarding run 41452227464 attempt 2 passed all twelve S2 checks; actual artifact 13147966162 explicitly excludes platform/release gates. The c34 Verification 41452216037 and e1e5e83 PR Verification 41452442408 failed; their failures are retained in FEAT-007, not hidden by successful S2.

This checkpoint fixes:
- route-growing CSP headers that made the signed c34 ELK candidate return APISIX 502 despite healthy containers; each HTML now carries only its own inline script hashes;
- installer verify now requires a bounded credential-free 200 HTML read through the public gateway;
- published service-role templates v1/Profile4 and v2/Profile7 remain byte-for-byte fixed, while v3 explicitly binds Profile8; migration does not invent old consent on fresh install;
- current directory assertions include Kibana;
- intentional MySQL restart acceptance waits for both actual container health and SQL;
- the plaintext gate proves retained Session target authority before ignoring a random six-digit ID collision; free text and longer credentials remain checked.

Full UI race, localmachine race, architecture, focused IAM/template/source/plaintext tests and affected vet checks passed. Actual IAM predecessor migration passed (52.97s), and Profile advance passed (51.24s). The complete Windows authority process exceeded its original six-minute fixture deadline and remains failed; do not extend the gate or claim an overall local PASS. Independent Linux CI for the fixes is the next acceptance boundary.

Signed c34 candidates elk.1/elk.2 are not accepted: the installed elk.1 had the actual console failure above. Rebuild a clean fixed-source signed same-profile pair, then execute real browser/handbook and lifecycle/data/credential retention. Do not patch a signed candidate in place. The current profile remains IAM/Audit/PaaS 88/40/9+r41; accepted private Logstash is 88/40/8+r40. Cross-profile upgrade/rollback/recovery remain rejected. Complete cold-cache disconnected Gate C is still unproved.

Redis has no implementation yet. Finish ELK before adding its next vertical slice. Preserve user installations/data; no global Docker prune, user-image removal, DinD or host-wide security changes. Shared-host Docker isolation is not physical isolation. No legacy repository inspection occurred in this slice.

Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
