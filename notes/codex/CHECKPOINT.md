# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-03
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/product-onboarding-release
- Goal: complete ELK onboarding/release closure, reuse the product contract for Redis, and remove disposable test resources.
- PR #14 is merged; accepted implementation source is fd1eaa88879edb5d18879c2e55fb9175a190711d.
- The protected production native gate passed. Public Release is not yet accepted: its draft publisher failed after creating the correct empty draft.

Follow AGENTS.md and repository-local Git identity. Load only the relevant owner:

- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核): signed production identities, actual runtime/transport evidence and publication recovery boundary.
- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#redis-接入切片): product contract, S1/S2/P1, direct-main CI and limits.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [verified commands](../../docs/runbooks/managed-service-onboarding.md): reusable adapter-to-platform handoff.
- [User workflows](../../docs/user-guide/services-and-applications.md): real illustrations and product lifecycle.
- [Installation guide](../../docs/user-guide/getting-started.md) and [verified installation commands](../../docs/runbooks/platform-installation.md): remaining download-to-install handoff.

Fixed main source fd1eaa888 passed direct-main Verification 41580270859 (nineteen jobs, actual P1 log PASS) and Product onboarding 41580343839 (eighteen actual native checks). Their exact-source evidence remains authoritative. Publication-only changes do not change the accepted signed payload.

Production run 41583699116 used the protected signer. Native job 125744139260 SUCCESS includes cold lifecycle, engine restart, browser journey, A/B archive comparison, fresh extraction comparison and byte-identical chunk transport. The actual evidence artifact was downloaded, digest/CRC/inventory checked, all reports read, and all twelve screenshots visually inspected. FEAT-005 owns durations, signed identities and digests. The whole run is FAILURE because draft job 125771308138 queried an unpublished draft through the tag endpoint, which returned 404. Release ID 432360073 is the matching unpublished v0.3.0 draft at fd1eaa888; it had no assets at the last read.

The repaired publisher uses bounded authenticated release-list pagination and refuses ambiguous/foreign/public releases. Thirty-three tests pass locally with real Ed25519. The existing workflow now supports main-only accepted_run_id recovery, which verifies the original completed dispatch, successful native and independent source gates, unique retained artifact, outer digest/size and safe ZIP before the ordinary signature/asset checks. It preserves original source/run identities and does not load a signing key or rebuild payloads. Verification has an independent publication-boundary job. Python/YAML/Bash checks passed. Actual Linux CI/recovery is still required.

Next: push and inspect the publisher repair CI, merge it to main without changing the accepted payload identity, then dispatch offline-release.yml on main exactly once with prepare_release=true, release_version=v0.3.0 and accepted_run_id=41583699116. Do not rerun the failed old job: it uses the old publisher. The retained delivery artifact is 13210432139 (expires after three days); FEAT-005 owns its digest. Recovery must produce the matching verified draft, never a second draft. The original same-source successor B is only an acceptance fixture.

The user authorized merging, full release and the dedicated production key. Reuse matrix-release-20261103; never regenerate it as a retry. Protected release environment is main-only, with the existing signing Secret and byte-identical public trust variable. Keep private material out of output and repository. Production has already proved actual use of the key.

After recovery, independently inspect exact uploaded inventory, sizes/digests, public trust/signature and screenshot evidence, then publish the verified draft. Update the owning FEATs and download-to-handbook links, commit/push final evidence, and merge remaining documentation. Never call the failed original workflow successful. Inspect the public Release and local restoration before marking the goal complete.

Preserve the original local Logstash installation (88/40/8+r40); ELK/Redis is 88/40/9+r41 and cross-profile maintenance remains rejected. Shared-host Docker isolation is not physical tenant isolation. Redis is single-node AOF; platform backup does not back up product business data. Earlier cleanup restored the original platform and freed roughly 40 GiB on C and 174 GiB on D. No new local Docker workload is needed. Avoid multi-GB local downloads; release recovery transfers within CI. Remove only owned disposable files/resources, preserving original user data, backups and signing custody.

Secrets, absolute checkout paths and uncommitted machine-local state are excluded.
