# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `565ff98`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `565ff98` closes the provider-neutral run-lifecycle foundation. The
  pure domain owns the legal state graph, stage-safe failure reasons,
  cancellation completion, monotonic versions, and terminal immutability.
- A delivery-owned task row persists one deterministic command identity before
  a future adapter effect. First claims are `EXECUTE`; every expired-lease
  takeover keeps that identity and is `OBSERVE`. Database-time renewal and
  monotonic fences reject stale results and stale renewals.
- Reporting uncertainty retains the original report intent through at most ten
  inconclusive observations; only then can the current fence commit manual
  intervention. Admission and claims share a tenant lock enforcing two active
  and 32 queued runs under concurrency.
- API and worker identities remain table-blind outside their exact protected
  functions. A PostgreSQL 18 data-bearing upgrade backfilled all 32 runs from
  pushed baseline `ca47883`, and fresh, repeat, cross-schema, and live-task
  migration verification passed.
- Full tests, vet, affected race and 20-run repeated suites, Linux/amd64
  CGO-disabled build, and a five-second lifecycle fuzz run passed.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 by closing terminal lifecycle Audit and the authorized public
run read/cancel boundary before invoking source acquisition, executor, or
reporter effects. Preserve pragmatic DDD, replacement-first pre-v1 changes,
optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
