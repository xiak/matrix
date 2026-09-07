# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `3139ecf`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `565ff98` closes the fenced provider-neutral run lifecycle; pushed
  `3139ecf` makes every terminal worker transition atomically emit one
  deterministic Audit Operation/outbox fact with closed outcome and reason.
- Audit canonicalization/OpenAPI/SQL accept outcome and reason only for the
  `devops.pipeline-run.completed` action. Nonterminal transitions cannot emit
  that fact, stale fences cannot duplicate it, and the legacy unaudited worker
  function is deleted on upgrade.
- API and worker identities remain table-blind outside exact protected
  functions. Fresh and repeat PostgreSQL 18 journeys produced five facts for
  five terminal transitions; a data-bearing upgrade from pushed `7363b29`
  preserved 13 mutations, 16 SourceEvents, 32 PipelineRuns, nine task intents,
  and all 61 existing Audit facts.
- Full tests, vet, affected race and 20-run repeated suites, Linux/amd64
  CGO-disabled build, Audit authority integration, and delivery integration
  passed.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the authorized public PipelineRun read/cancel boundary.
Cancellation must stop future stages, expose pending cancellation while an
effect may exist, and never claim an uncertain effect did not happen. Do not
invoke source acquisition, executor, or reporter effects yet. Preserve
pragmatic DDD, replacement-first pre-v1 changes, optional-product isolation,
and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
