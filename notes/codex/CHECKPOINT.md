# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `bd602ba`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Pushed `bd602ba` adds an opt-in source-process recovery gate against a clean
  PostgreSQL 18 database and the fixed Gitea `1.27.3` image. It starts the
  actual source-observer and source-fetcher binaries, rejects a forged
  signature, admits one valid pull-request event, preserves equal-replay
  identity, and rejects changed-byte replay.
- The first fetcher performs exactly one Gitea `upload-pack` and atomically
  publishes the source archive, then is killed before PostgreSQL acknowledgement.
  Its replacement claims fence two, observes the immutable archive without a
  second provider fetch, stores one receipt, completes FETCH, and advances the
  same run to `VERIFYING`. Archive, database, and process evidence contains no
  credential or private path.
- The source-fetcher process loop now cancels and waits for its active cycle on
  graceful shutdown. The final real journey passed in 2.34 seconds. Full
  repository tests and vet, affected Windows race and twenty-run suites, and
  affected disconnected Go `1.26.8` Linux suites pass.
- The earlier standalone VERIFY-to-REPORTING execution recovery and source-
  archive isolation gates remain present. The two passing subjourneys are not
  yet joined through the physical DevOps HTTP process, check reporter, provider
  outcome, and Audit dispatcher; full Gate B and product UI Gate C remain open.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Join the passing source and execution recovery subjourneys through the physical
DevOps HTTP process, check reporter, correlated provider outcome, and Audit
dispatcher. Complete malicious repository/resource-abuse and oversized-log
cases plus remaining external-effect restarts with no duplicate provider
outcome. Only after the complete Gate B passes begin formal Matrix UI
integration from the accepted UX baseline.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
