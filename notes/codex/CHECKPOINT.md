# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `1bfba7c`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing. Earlier accepted slices are
  preserved in Git and summarized there rather than repeated here.
- Pushed `1bfba7c` closes the public normalized-log read slice over the prior
  durable runner-to-PostgreSQL relay. `GET /v1/runs/{runId}/logs` accepts only
  one canonical optional cursor, authorizes `devops.log.read` against the exact
  PipelineRun, and returns at most four retained normalized chunks in a bounded
  `no-store` page. Executor identities, native counters, commands,
  environments, paths, and integrity digests remain private.
- PostgreSQL derives tenant and time, conceals foreign runs, reports retention
  truncation, and atomically records one sanitized IAM-bound log-read Audit fact
  through an API-only table-blind function. The IAM action no longer invents a
  separate `PIPELINE_LOG` resource; Go, OpenAPI, and database catalogs bind it
  to `PIPELINE_RUN`.
- Evidence on that worktree: full `go test ./...`, full `go vet ./...`, focused
  Windows race detection with twenty repetitions, and twenty focused runs in
  the fixed disconnected Go 1.26.8 Linux/amd64 image with read-only source and
  module cache all pass. A clean fixed PostgreSQL 18.6 instance passes double
  migration, function privilege verification, four/two-chunk continuation,
  empty reads, forced tenant concealment, expiry truncation, transactional
  Audit, and independent resource/action/payload tamper checks; the combined
  IAM/Audit authority journey also passes.
- This proves durable normalized-log persistence and its public read boundary,
  not the physical runner process, selected release topology, reporter effect,
  or real repository execution under gVisor.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 by composing the dedicated runner process around the pushed
runner workflow and adding only the selected DevOps release topology. Preserve
the existing mTLS runner-only authority, private journal/workspace roots,
closed Docker/gVisor eligibility, fixed toolchain, bounded renewal, and
restart-before-effect rules; add process/readiness and architecture gates
before attempting the real repository journey. Reporter effects remain a
separate subsequent slice.

Do not claim repository-code isolation until a dedicated Linux/amd64 runner
with the pinned offline toolchain and `runsc` passes the real no-egress,
resource, malicious-repository, restart, and log-sanitization gates. Keep runner
authority away from PostgreSQL, source/report credentials, IAM, Audit, PaaS,
and executor-admin operations. Do not begin formal UI integration before that
real boundary passes. Preserve pragmatic DDD, replacement-first pre-v1 changes,
optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
