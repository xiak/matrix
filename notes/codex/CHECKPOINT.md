# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-10
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `3850ba4`

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
- Full Windows tests, architecture tests, vet, JavaScript syntax, affected race
  and twenty-run suites, custom-root TLS execution, and Linux/amd64 compilation
  of the source-process gate pass at `3850ba4`. This is implementation evidence,
  not signed local-provider runtime acceptance.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue Gate C in the existing offline lifecycle. Run the exact signed A/B
DevOps lifecycle against a local HTTPS provider whose CA is not system-trusted,
apply trust with the release-carried CLI, and prove the full source-to-check
journey plus lifecycle preservation without exposing CA, credentials, or host
paths. Then exercise the committed platform shell through the real APISIX edge
for the remaining role, state, accessibility, and `360px` matrix.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
