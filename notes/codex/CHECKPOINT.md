# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `fd96275`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `fd96275` adds IAM-authorized, bodyless terminal PipelineRun replay
  with exact preconditions, stable idempotency, direct-source lineage, sealed
  input reuse, shared queue capacity, and one atomic replay Audit fact.
- Exact retry returns the stored creation snapshot after later transitions;
  replay descendants remain outside provider-delivery fan-out and create no
  worker task before claim.
- API and worker identities remain table-blind outside exact protected
  functions. The fresh PostgreSQL 18 journey produced 20 mutations, 16
  SourceEvents, 34 PipelineRuns, nine task intents, two replay facts, five
  cancellation facts, seven terminal facts, and 75 Audit operations/outbox
  facts.
- A data-bearing upgrade from pushed `10fea16` preserved the prior
  `17/16/32/9/71/71` records, backfilled original-run creation identities,
  admitted a replay through the upgraded API, and reapplied/verified cleanly.
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

Continue FEAT-007 from its owning pending list with the smallest source-health
reconciliation and operator secret-provisioning slice before adding source,
executor, or reporter effects. Reuse the existing SourceConnection contract
and installation-owned secret boundary; first tighten the FEAT acceptance
contract, then implement and verify the vertical slice. Preserve pragmatic
DDD, replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
