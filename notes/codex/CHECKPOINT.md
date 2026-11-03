# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-03
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/product-onboarding-release
- Goal: complete ELK onboarding/release closure, then reuse the product contract for Redis; remove disposable test resources after verification.
- [PR #14](https://github.com/xiak/matrix/pull/14) is merged. Main was fast-forwarded to fd1eaa88879edb5d18879c2e55fb9175a190711d without changing its identity.
- No production-signed package or public Release is accepted yet. Main must remain at that implementation source until production acceptance/publication.

Follow AGENTS.md and repository-local Git identity. Load only the relevant owner:

- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#redis-接入切片): product contract, S1/S2/P1, independent CI and limits.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [verified commands](../../docs/runbooks/managed-service-onboarding.md): reusable adapter-to-platform handoff.
- [User workflows](../../docs/user-guide/services-and-applications.md): real illustrations, activation, quota, native use, credential handoff, maintenance and termination.
- [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md): dependency Use and immutable templates.
- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): signed identities, lifecycle acceptance, delivery and remaining release gates.

The ELK/Redis candidate is 88/40/9+r41. The older local Logstash installation is 88/40/8+r40; cross-profile upgrades/rollbacks remain rejected. Preserve the original installation. Redis is single-node with AOF. Platform backup does not back up product business data. Shared-host Docker isolation is not physical tenant isolation.

Fixed main implementation fd1eaa888 passed direct-main Verification 41580270859: all nineteen jobs succeeded, and the actual bounded P1 log confirms TestManagedProductProviderProcesses PASS in 409.50 seconds. Direct-main Product onboarding 41580343839 is also SUCCESS. Its actual artifact 13205378632 was downloaded, digest verified and read: all eighteen native checks passed; the report still excludes platform/browser/release gates. FEAT-007 owns detailed evidence. Earlier feature/PR gates passed too, but the production guard uses only the exact main-source runs.

Protected production run 41583699116 was dispatched exactly once on main at 05:24:05 UTC with prepare_release=true, release_version=v0.3.0 and successor_version=v0.3.1. API 204 and unique run readback confirmed source fd1eaa888, branch main and workflow_dispatch. Job 125744139260 is live. Its exact-source preflight, release-input tests, protected signing input, native execution probe and signed A/B assembly passed. The combined cold lifecycle/restart/browser step passed at 06:29:47 UTC after starting at 05:32:13 UTC. The job is packaging the accepted pair; no evidence artifact was visible yet. This is a completed step, not final Gate C or public-release acceptance: actual reports/screenshots, transport packaging, retained artifacts and draft preparation still require inspection. Observe this existing run, never dispatch a duplicate because a polling request times out.

Cold run 41573934644 at fixed source 5ab41d4c1a4b0a51ea217d974c566f27d7664df6 is now SUCCESS, including archive retention. The actual small evidence artifact was downloaded, SHA-256/ZIP CRC/inventory verified, all lifecycle and restart PASS steps read, and all twelve browser screenshots visually inspected. The browser report has all 27 checks and zero page/server errors. A bounded remote ZIP-directory/header read verified the retained A/B archive without downloading multiple GB. FEAT-005 owns identities, durations and digests. This uses an ephemeral acceptance key, not the production signer.

The unstarted duplicate feature cold run 41576454021 was explicitly cancelled only after confirming zero jobs and main's exact source; readback is completed/cancelled. It is superseded by the still-required complete protected production gate on main. It was not a failed test or timeout retry. Earlier ff688e24f run 41565287835 failed with GitHub's hosted-runner communication-loss annotation and unavailable diagnostic logs; no product root cause was established.

Git comparison proves api, app, deploy, test, go.mod and go.sum are unchanged between accepted cold runtime 5ab41d4c1 and fd1eaa888. Their differences are confined to the production source guard, its tests, workflow and FEAT-005. The guard requires successful exact-source Verification and Product onboarding runs directly on main, from push or workflow_dispatch. PR run metadata cannot authorize signing. Eighteen release-boundary tests passed locally with real Ed25519 and simulated GitHub effects; the running production job must execute them on Linux before loading its signer. Runtime identity does not waive that full protected gate.

The user authorized a dedicated production key, local custody and GitHub publishing Secret. Reuse key matrix-release-20261103; never regenerate it as a retry. The release environment contains MATRIX_RELEASE_SIGNING_KEY and matching public variable MATRIX_RELEASE_TRUST_ROOT, with only main allowed. At 05:16 UTC the policy, unchanged Secret metadata and exact public-byte equality were rechecked. FEAT-005 owns the fingerprint. The protected production run must still finish successfully. No v0.3.0 tag or Release existed at the last check.

Next: observe protected production run 41583699116 to completion. Review the actual protected cold lifecycle/restart/browser reports, all twelve screenshots, signature/trust, transport comparisons and matching draft assets; then publish the verified Release. Fresh-install A is delivered; same-source successor B is an unpublished acceptance fixture. The delivery retains 22 explicit public evidence files, including twelve actual screenshots. Do not download large candidate archives locally.

Documentation-only evidence is committed/pushed on the already merged feature branch; do not advance main for these edits before production acceptance/publication. After publishing, update owning FEATs and checkpoint with fixed release proof, finish release-to-handbook links, push documentation and fast-forward main if unchanged. Clean owned disposable resources, preserve original installations/data/backups/signing custody, and verify the public Release and local restoration before marking the goal complete.

Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
