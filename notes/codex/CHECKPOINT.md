# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `a47cdc8`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `a47cdc8` exposes IAM-authorized `GET /v1/runs/{runId}` and bodyless
  `POST /v1/runs/{runId}/cancel` with exact ETags, `If-Match`, deterministic
  idempotency equality/conflict, and tenant-concealed lookup.
- Cancellation records a canonical public request time and atomic user Audit
  fact. Effect-free runs terminate with a separate control-actor fact; a run
  with an intent remains pending, invalidates its old lease/fence, and recovers
  that same intent only in `OBSERVE`. Future stages are forbidden while a
  definitive observed terminal remains truthful.
- API and worker identities remain table-blind outside exact protected
  functions. A fresh PostgreSQL 18 journey produced 17 mutations, 16
  SourceEvents, 32 PipelineRuns, nine task intents, four cancellation facts,
  six terminal facts, and 71 Audit operations/outbox facts.
- A data-bearing upgrade from pushed `3139ecf` preserved all
  `13/16/32/9/66/66` records, backfilled all three historical cancelled runs,
  reapplied cleanly, and passed current catalog verification.
- Full tests, vet, affected race and 20-run repeated suites, five-second state
  fuzzing, Linux/amd64 CGO-disabled builds, fresh PostgreSQL 18 integration,
  and data-bearing upgrade verification passed.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the public manual replay boundary. A replay must select
the exact original SourceEvent and immutable PipelineRevision, create one
linked new PipelineRun under a deterministic command identity, and never
resolve mutable source or pipeline configuration again. Do not invoke source
acquisition, executor, or reporter effects yet. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
