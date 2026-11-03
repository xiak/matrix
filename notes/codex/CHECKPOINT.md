# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-03
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/product-onboarding-release
- Goal: complete ELK onboarding/release closure, then reuse the product contract for Redis; remove disposable test resources after verification.
- [PR #14](https://github.com/xiak/matrix/pull/14) remains draft. No public Release is accepted.

Follow AGENTS.md and repository-local Git identity. Load only the relevant owner:

- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#redis-接入切片): product contract, S1/S2/P1, independent CI and limits.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [verified commands](../../docs/runbooks/managed-service-onboarding.md): reusable adapter-to-platform handoff.
- [User workflows](../../docs/user-guide/services-and-applications.md): real illustrations, activation, quota, native use, credential handoff, maintenance and termination.
- [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md): dependency Use and immutable templates.
- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): signed identities, lifecycle acceptance, delivery and remaining release gates.

The ELK/Redis candidate is 88/40/9+r41. The older accepted Logstash profile is 88/40/8+r40; cross-profile upgrades/rollbacks remain rejected. Redis is single-node with AOF. Platform backup does not back up product business data. Shared-host Docker isolation is not physical tenant isolation. Product teams have a reusable contract, runnable native examples, eighteen real acceptance checks and platform handoff gates.

Fixed source 8b06d49c377d1be57ed36f0d3e4b7cb0db7e1edc passed the complete native empty-cache disconnected Gate C in run 41557209199. No DinD. Pre-restart lifecycle passed in 3083.29 seconds, native-engine restart in 277.69 seconds, and the real Chromium journey in 196.75 seconds. All seven managed products ran; retained ELK/Redis identity, networks, mounts, protected material and business data survived failed upgrade, normal upgrade, rollback, selected-backup recovery and restart. Reverse dependency-order deletion and final status/verify passed. Browser acceptance passed all 27 checks with zero page/server errors; twelve actual screenshots were inspected.

Actual evidence artifact 13199096150 was downloaded and SHA-256 verified as fa0a1d77d8c32e32ada7bcab7e0838d3d08e48151ca8809fec0cd4e06dfa4d51. Retained candidate artifact 13199880241 contains the exact A/B acceptance pair and public trust only. CI compared the archive against the original files; bounded remote ZIP-directory and gzip-header reads verified the retained object without downloading its multi-GB payload. Signed identities and archive digest belong to FEAT-005. This pair uses an ephemeral acceptance signer and is not a production release.

Fixed source ff688e24fce3a7bf80e07bfe7cadc591bfef181f passed all nineteen push Verification jobs (41565287724), all nineteen PR Verification jobs (41565295181), and all eighteen Product onboarding checks (41565294637). Actual seven-product P1 pass logs were inspected. Onboarding artifact 13199897022 was downloaded and digest verified; its platform/release status remains NOT_RUN. Full digest and scope belong to FEAT-007.

The same source's cold run 41565287835 FAILED. Setup, native isolation probe and signed A/B assembly passed; lifecycle failed and GitHub reported that the hosted runner lost communication. Public evidence/upload steps were skipped; the log object returned 404. The failure does not establish a product root cause, and the prior fixed-source success cannot substitute for new-source acceptance. The run has completed, so it no longer holds workflow concurrency.

The user authorized a dedicated production signing key, local custody and GitHub publishing Secret. Reuse key matrix-release-20261103; never regenerate it as a retry. The protected release environment contains MATRIX_RELEASE_SIGNING_KEY and matching public variable MATRIX_RELEASE_TRUST_ROOT, with only branch main allowed. Metadata, public byte equality and policy were verified. FEAT-005 owns its public fingerprint. CI production-mode use still requires actual execution.

The offline workflow supports main-only prepare_release dispatch. Production first requires successful exact-source Verification and Product onboarding, then runs complete cold lifecycle/restart/browser acceptance with the protected signer. Fresh-install A is the delivery; same-source successor B is an unpublished acceptance fixture. Archive comparison, fresh extraction comparison, transport-chunk comparison and SHA-256 verification precede draft preparation. The publisher checks source/version/trust/signature, exact inventory, remote asset sizes/digests and safe lost-response resumption; it never publishes automatically.

The delivery also retains acceptance-evidence.zip with an explicit whitelist of 22 public files, including twelve real screenshots, so proof survives temporary Actions retention. Thirteen publisher tests passed with real Ed25519 and simulated GitHub effects. All Bash/Python workflow blocks parsed, and the actual evidence exporter processed the digest-verified 8b artifact successfully with 22 entries, twelve images and valid ZIP CRCs. These checks do not replace protected production execution.

Next: verify the committed delivery changes in CI; update/review and merge PR #14 after its required gates pass. On exact main, dispatch Verification and Product onboarding if absent, then Offline release acceptance with prepare_release=true, release_version=v0.3.0 and successor_version=v0.3.1. Review actual production proof and draft inventory/signatures before publishing. Record the fixed release result in the existing owners. Keep local disk use bounded; do not download multi-GB candidate archives for metadata checks. Clean owned disposable test containers/images/caches while retaining original installations, required runtime images, data, backups and signing custody.

Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
