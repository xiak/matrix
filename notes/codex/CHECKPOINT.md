# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-10
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `7584848`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Gate A and Gate B are complete. Pushed baselines through `5cca59e` provide
  the physical source-to-check path, guarded Recheck and unified-browser
  baseline, DevOps-selected offline lifecycle harness, and release-carried
  purpose-separated source-credential lifecycle.
- Pushed `ab1013f` fixes the endpoint-scoped private-provider CA UX,
  architecture, installation ownership, recovery policy, and acceptance
  contract without adding CA material to public resources.
- Pushed `3850ba4` implements that boundary: strict bounded canonical CA
  bundles, tenant-and-exact-origin filesystem identity, authenticated
  `mx devops source-trust apply|remove`, selected-only read-only topology
  mounts, per-effect custom-only/system-root selection, invalid-present
  fail-closed behavior, and the optional safe UI command. The source-process
  gate no longer uses process-global `SSL_CERT_FILE`.
- Pushed `8aa7c3c` closes the portable-recovery policy gap: after authenticated
  database restore and migration, but before target startup, recovery validates
  every selected DevOps trust record, replayably clears only those records, and
  retains an empty bind-mounted root. Unsafe shape blocks startup before any
  proved record is deleted.
- Pushed `eef57d8` extends the signed A/B offline lifecycle harness through the
  strict source-trust CLI: apply/equal replay, verify/upgrade/rollback
  preservation, deliberate recovery reset, operator reapply plus Recheck,
  restart preservation, support-evidence exclusion, and idempotent removal.
- Pushed `8dc319d`, `97ace6c`, `1b9ac1e`, `d1b8494`, and `7584848` align the
  signed Gate C harness with the selected runner-gateway port, ordinary-user
  password response, RFC problem media type, cross-tenant fixture cleanup, and
  Docker's signed reference plus resolved image identity.
- Exact signed releases A `matrix-v0.1.0-3850ba4faa2b` (`3850ba4`) and B
  `matrix-v0.2.0-7584848f226a` (`7584848`) passed the disconnected fresh-host
  A/B lifecycle in 466.91 seconds. A real host stop/start then passed the
  post-restart phase in 27.46 seconds. This accepts the deliberately
  unresolvable-provider credential/trust, APISIX multi-role/cross-tenant,
  upgrade/rollback/recovery, PaaS-preservation, Audit, support-zero-leakage,
  and restart boundary. It is not local-provider source-to-check or dedicated-
  runner acceptance.
- Full Windows tests, architecture tests, vet, JavaScript syntax, affected race
  and twenty-run suites, custom-root TLS execution, and Linux/amd64 compilation
  of the source-process, recovery, and offline-lifecycle gates pass through
  `7584848`. All disposable Gate C Docker and filesystem resources were removed
  after acceptance.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue Gate C with the pending local HTTPS Gitea source-to-check journey and
its dedicated runner, using the accepted release-carried credential/trust
boundaries without exposing CA, credentials, or host paths. Then exercise the
committed platform shell through the real APISIX edge for the remaining role,
state, accessibility, and `360px` matrix.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.

On this Windows host, keep disposable build, test, download, and container data
on D-scoped storage and remove task-owned resources immediately after use.
