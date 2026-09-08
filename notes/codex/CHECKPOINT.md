# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `0c8bf84`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `972f70a` fixes the accepted three-process executor security boundary
  and two-role mTLS transport in FEAT-007. Pushed `0c8bf84` moves request and
  terminal-receipt ownership from the service-local port into the versioned
  `api/adapter/devopsbuild/v1` cross-process contract, adds canonical strict
  documents, deterministic execution identity, and exact length/digest-bound
  archive streaming, and leaves the local port as capability plus outcome
  errors only.
- Full tests and vet, architecture tests, focused race and 20-run suites, and
  focused tests in the fixed disconnected Go 1.26.8 Linux/amd64 image pass.
  Short, changed, and trailing archives and noncanonical/unknown documents fail
  closed. The physical gateway, runner transport, sandbox, normalized logs,
  and reporter remain pending.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the smallest independently testable physical-execution
slice behind the accepted BuildExecutor port: the executor gateway's private
durable spool and build-worker-only admin boundary, followed by the separate
runner role. Keep runner authority away from PostgreSQL, source/report
credentials, IAM, Audit, PaaS, and admin operations. Do not claim repository
code is isolated until the dedicated Linux/amd64 runner, pinned offline
toolchain, gVisor, no-egress, resource, malicious-repository, restart, and
sanitized-log gates really pass; do not couple it to PaaS execution or begin
formal UI integration before that real boundary passes. Preserve pragmatic
DDD, replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
