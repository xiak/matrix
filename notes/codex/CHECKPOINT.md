# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `502f7ac`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing. Earlier accepted slices are
  preserved in Git and summarized there rather than repeated here.
- Pushed `502f7ac` closes normalized-log relay and tenant persistence over the
  prior runner workflow. The runner publishes canonical labeled-line batches
  under its mTLS identity and gateway fence; the private gateway spool stores
  at most two ordered batches with exact replay; the build worker drains them
  while its database lease remains active and persists them before completing
  VERIFY.
- PostgreSQL owns tenant-leading forced-RLS log batches and a table-blind
  current-fence append function that independently proves execution, chunk, and
  batch digests, ordering, normalization shape, equality/conflict, and the
  fixed 14-day retention deadline. A failed or unproved drain retains the
  command for fenced observation.
- Evidence on that worktree: full `go test ./...`, full `go vet ./...`, focused
  Windows race detection with twenty repetitions, and twenty focused runs in
  the fixed disconnected Go 1.26.8 Linux/amd64 image with read-only source and
  module cache all pass. A clean fixed PostgreSQL 18.6 instance passes double
  migration, catalog verification, current/stale fence, replay, tamper,
  ordering, retention-deadline, and completion-closure checks.
- This proves durable normalized-log persistence, not its public IAM/Audit read
  surface, physical runner process, selected release topology, or real
  repository execution.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the tenant-derived public normalized-log read boundary:
define bounded cursor/page contracts, authorize `devops.log.read` against the
exact PipelineRun through IAM, commit one sanitized Audit fact, and expose only
stored normalized chunks. Then compose the dedicated runner process and
selected release topology around the pushed workflow.

Do not claim repository-code isolation until a dedicated Linux/amd64 runner
with the pinned offline toolchain and `runsc` passes the real no-egress,
resource, malicious-repository, restart, and log-sanitization gates. Keep runner
authority away from PostgreSQL, source/report credentials, IAM, Audit, PaaS,
and executor-admin operations. Do not begin formal UI integration before that
real boundary passes. Preserve pragmatic DDD, replacement-first pre-v1 changes,
optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
