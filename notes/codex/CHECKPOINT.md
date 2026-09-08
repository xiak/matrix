# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `bfe834b`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `bfe834b` adds table-blind PostgreSQL persistence for the existing
  fenced `VERIFY` use case. Generic claims are now `REPORT`-only; build claims
  atomically bind the immutable revision and source receipt to a database-time
  execution window, preserve that window across fencing takeover, and store a
  strict digest-bound terminal receipt before `REPORTING` can be entered.
- Full tests, vet, architecture tests, focused race and 20-run suites, a
  Linux/amd64 CGO-disabled full build, a fresh PostgreSQL 18 build journey, and
  the four-product PostgreSQL migration journey pass. Receipt shape, binding,
  digest, stale-fence, renewal, missing-receipt bypass, and passed/failed paths
  are exercised. The physical isolated runner, transport, sandbox, normalized
  logs, and reporter remain pending.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the smallest independently testable physical-execution
slice behind the accepted BuildExecutor port: a selected-only control-plane
process and authenticated runner transport that keep the runner away from
PostgreSQL, source/report credentials, IAM, Audit, PaaS, and administrative
executor operations. Do not claim repository code is isolated until the
dedicated Linux/amd64 runner, pinned offline toolchain, gVisor, no-egress,
resource, malicious-repository, restart, and sanitized-log gates really pass;
do not couple it to PaaS execution or begin formal UI integration before that
real boundary passes. Preserve pragmatic DDD, replacement-first pre-v1
changes, optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
