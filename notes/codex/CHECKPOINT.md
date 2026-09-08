# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `d66511a`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `d66511a` extends the versioned executor contract with separate admin
  observation/cancellation and runner claim/assignment/renewal/completion
  documents, then adds the private durable executor-gateway spool. The spool
  atomically publishes exact inspected input, journals consecutive digest-
  chained state, fences 30-second assignments, allows archive-free recovery
  only to the same runner identity, carries cancellation through renewal, and
  accepts only exact current-fence terminal receipts.
- Full tests and vet, architecture tests, focused race and 20-run suites, and
  focused tests in the fixed disconnected Go 1.26.8 Linux/amd64 image pass.
  Equal/changed replay, restart, deadline cap, different-runner takeover,
  stale fence, unsafe file shape, symlink, and content tamper paths fail closed.
  The physical mTLS gateway/client processes, runner journal and sandbox,
  normalized logs, and reporter remain pending.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the smallest independently testable physical-execution
slice behind the accepted BuildExecutor port: build-worker-only and runner-
only mTLS HTTP listeners over the accepted spool, followed by the separate
process composition and runner journal. Keep runner authority away from
PostgreSQL, source/report credentials, IAM, Audit, PaaS, and admin operations.
Do not claim repository
code is isolated until the dedicated Linux/amd64 runner, pinned offline
toolchain, gVisor, no-egress, resource, malicious-repository, restart, and
sanitized-log gates really pass; do not couple it to PaaS execution or begin
formal UI integration before that real boundary passes. Preserve pragmatic
DDD, replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
