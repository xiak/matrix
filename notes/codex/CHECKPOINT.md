# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `c9acd5f`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `c9acd5f` adds the outbound-only production runner client and its
  independent private journal behind the strict TLS 1.3 gateway. Canonical
  assignment metadata and a complete-request digest bind staging before archive
  consumption; verified source is atomically published before an effect marker,
  then immutable generations preserve renewal, cancellation, recovery fencing,
  normalized terminal receipt, and acknowledgement. Certificate-derived runner
  identity, OS-exclusive directory ownership, strict file shape, and archive,
  request, state-chain, identity, symlink, and restart checks fail closed. A real
  mTLS journey persists claim through acknowledgement and recovers it after
  restart without giving the journal any network, database, product, provider,
  Docker, or process-execution authority.
- Full tests and vet, architecture tests, focused race and 20-run suites, and
  the same focused suites run twenty times in the fixed disconnected Go 1.26.8
  Linux/amd64 image with read-only source and no module lookup. The physical
  build-worker and runner process composition, sandbox, normalized logs,
  reporter, UI, and offline release remain pending.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the smallest independently testable physical-execution
slice behind the accepted BuildExecutor port: compose the table-blind build
worker and dedicated runner processes around the accepted gateway/client/journal
boundary, without executing repository code until the sandbox gate is present.
Keep runner authority away from
PostgreSQL, source/report credentials, IAM, Audit, PaaS, and admin operations.
Do not claim repository
code is isolated until the dedicated Linux/amd64 runner, pinned offline
toolchain, gVisor, no-egress, resource, malicious-repository, restart, and
sanitized-log gates really pass; do not couple it to PaaS execution or begin
formal UI integration before that real boundary passes. Preserve pragmatic
DDD, replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
