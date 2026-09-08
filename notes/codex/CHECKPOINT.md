# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `e8a0afd`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `e8a0afd` adds the strict TLS 1.3 executor-gateway transport over the
  versioned admin/runner documents and private durable spool. The real-socket
  admin client streams exact input and recovers create/observe/cancel; separate
  admin and runner mTLS handlers enforce distinct roots, exact build-worker or
  runner-namespace identity, authority-free requests, certificate-derived
  opaque runner ownership, archive-only first assignment, current lease/fence,
  cancellation, and idempotent terminal completion. The independent gateway
  binary reads canonical protected key/certificate inputs, rejects overlapping
  role signing roots, holds one OS-level spool lock, and couples its two bounded
  mTLS listeners without receiving any product, database, provider, Docker, or
  process-execution authority.
- Full tests and vet, architecture tests, focused race and 20-run suites, and
  focused tests in the fixed disconnected Go 1.26.8 Linux/amd64 image pass.
  Equal/changed replay, restart, deadline cap, cross-role/cross-runner access,
  stale fence, unsafe authority/header/body/file shapes, TLS downgrade,
  symlink, and content tamper paths fail closed. The same focused suites pass
  20 times in the fixed disconnected Go 1.26.8 Linux/amd64 image. Physical
  executor-gateway process composition. The physical build worker and runner,
  runner journal and sandbox, normalized logs, and reporter remain pending.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the smallest independently testable physical-execution
slice behind the accepted BuildExecutor port: add the outbound-only runner
client and independent runner journal against the now-physical gateway, then
compose the table-blind build worker and runner processes. Keep
runner authority away from
PostgreSQL, source/report credentials, IAM, Audit, PaaS, and admin operations.
Do not claim repository
code is isolated until the dedicated Linux/amd64 runner, pinned offline
toolchain, gVisor, no-egress, resource, malicious-repository, restart, and
sanitized-log gates really pass; do not couple it to PaaS execution or begin
formal UI integration before that real boundary passes. Preserve pragmatic
DDD, replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
