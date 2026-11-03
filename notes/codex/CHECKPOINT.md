# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-03
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/product-onboarding-release
- Goal: complete ELK onboarding/release closure, then reuse the product contract for Redis; remove disposable test resources after verification.
- [PR #14](https://github.com/xiak/matrix/pull/14) is merged. Main was fast-forwarded to the verified implementation commit fd1eaa88879edb5d18879c2e55fb9175a190711d without changing its identity.
- No production-signed package or public Release is accepted yet.

Follow AGENTS.md and repository-local Git identity. Load only the relevant owner:

- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#redis-接入切片): product contract, S1/S2/P1, independent CI and limits.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [verified commands](../../docs/runbooks/managed-service-onboarding.md): reusable adapter-to-platform handoff.
- [User workflows](../../docs/user-guide/services-and-applications.md): real illustrations, activation, quota, native use, credential handoff, maintenance and termination.
- [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md): dependency Use and immutable templates.
- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): signed identities, lifecycle acceptance, delivery and remaining release gates.

The ELK/Redis candidate is 88/40/9+r41. The older accepted Logstash profile is 88/40/8+r40; cross-profile upgrades/rollbacks remain rejected. Redis is single-node with AOF. Platform backup does not back up product business data. Shared-host Docker isolation is not physical tenant isolation. Product teams have a reusable contract, runnable native examples, eighteen real acceptance checks and platform handoff gates.

Fixed source fd1eaa888 passed all nineteen push Verification jobs (41576453984) and all nineteen PR Verification jobs (41576457997). The actual seven-product P1 logs passed in 332.70/390.91 seconds respectively. Product onboarding 41576458008 passed all eighteen checks in 818.39 seconds; artifact 13204241730 was downloaded, digest verified and read. Its report still excludes platform/browser/release gates. PR merge and head Git trees are identical. FEAT-007 owns the full source/digest/scope evidence.

Fixed source 8b06d49c377d1be57ed36f0d3e4b7cb0db7e1edc passed the complete native empty-cache disconnected Gate C in run 41557209199. No DinD. Pre-restart lifecycle passed in 3083.29 seconds, native-engine restart in 277.69 seconds, and real Chromium in 196.75 seconds. All seven products ran; retained ELK/Redis identities, networks, mounts, protected material and business data survived maintenance and restart. Exact deletion and final status/verify passed. Browser acceptance passed all 27 checks with zero page/server errors; twelve actual screenshots were inspected. Actual evidence artifact 13199096150 was downloaded and digest verified. CI compared the retained A/B archive (13199880241); bounded remote directory/header reads verified its object without a multi-GB local download. Identities and digests belong to FEAT-005. This is ephemeral acceptance-key evidence, not a production release.

Git comparison proves api, app, deploy, test, go.mod and go.sum are unchanged between accepted runtime 8b06d49c3 and fd1eaa888. Later changes are confined to release scripts/workflows and documentation. This supports runtime review but does not waive the actual protected production gate.

At 2026-11-03 04:51 UTC, the 5ab41d4c1 cold run 41573934644 (job 125712995821) was still executing its combined lifecycle/restart/browser step without a failed step. Current-source cold run 41576454021 was pending behind it under workflow concurrency. Both must be observed by their existing handles; do not restart because an observation times out. Earlier ff688e24f cold run 41565287835 failed with GitHub's hosted-runner communication-loss annotation, skipped evidence upload and a 404 log object; no product root cause was established.

The production source guard now requires successful exact-source Verification and Product onboarding runs directly on main, with push or workflow_dispatch events. PR runs cannot authorize signing because their head metadata need not identify the synthetic merge checkout. Eighteen release-boundary tests passed locally with real Ed25519 and simulated GitHub effects, including wrong branch/event/source, missing/failed runs and malformed/unavailable metadata. Thirteen workflow Bash steps, embedded Python and both Python modules passed syntax checks.

After main integration, direct-main Verification 41580270859 (push, source fd1eaa888) started automatically. Product onboarding 41580343839 (workflow_dispatch, main, same source) was explicitly dispatched once at 04:49 UTC and is running. These are the required main-source runs; the already passed feature/PR runs cannot substitute for them. An unrelated Dependabot dynamic run is not a release gate.

The user authorized a dedicated production signing key, local custody and GitHub publishing Secret. Reuse key matrix-release-20261103; never regenerate it as a retry. The protected release environment contains MATRIX_RELEASE_SIGNING_KEY and matching public variable MATRIX_RELEASE_TRUST_ROOT, with only main allowed. Metadata, public byte equality and policy were verified. FEAT-005 owns the public fingerprint. Production-mode execution is still required.

The offline workflow supports main-only prepare_release dispatch. After exact main-source checks pass, run the complete cold lifecycle/restart/browser gate with the protected signer. Fresh-install A is delivered; same-source successor B is an unpublished acceptance fixture. Archive comparison, fresh extraction comparison, transport-chunk comparison and SHA-256 verification precede draft preparation. The publisher verifies source/version/trust/signature, exact inventory, remote asset sizes/digests and safe response-loss resumption; it never publishes automatically. The delivery includes acceptance-evidence.zip with 22 explicit public files, including twelve real screenshots. Its exporter successfully processed the verified 8b evidence with valid ZIP CRCs.

Next: observe the two existing main-source runs and the pending/running cold runs. After main-source gates pass, dispatch Offline release acceptance on main with prepare_release=true, release_version=v0.3.0 and successor_version=v0.3.1. Review actual production proof and draft assets, then publish the verified Release. Keep main at fd1eaa888 during this process so the dispatch signs the accepted source. Documentation-only integration evidence can be committed/pushed on the already merged feature branch; do not advance main for those edits before production acceptance/publication. After publishing, update the owning FEATs and checkpoint with fixed release evidence, push the documentation and fast-forward main if it remains unchanged. Clean owned disposable resources, preserve original installations/data/backups/signing custody, and keep local downloads bounded.

Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
