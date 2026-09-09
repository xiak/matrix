# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `11f49bc`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Pushed `11f49bc` adds the opt-in standalone execution-process recovery gate.
  A clean PostgreSQL 18 database drives the actual build-worker, TLS 1.3 mTLS
  gateway, outbound runner, Docker `29.6.2`, and pinned `runsc` from VERIFY to
  REPORTING.
- The gate kills the first worker after durable submission and the first runner
  during the exact running sandbox effect. Replacement processes increase both
  fences, observe before retry, finish both immutable steps, persist one receipt
  and normalized logs, acknowledge the journal, and leave no business or probe
  container. Role-specific process output contains no database password or key.
- Real shutdown exposed and fixed premature runner-loop exit and a runsc-
  sensitive ten-second probe cleanup edge. Shutdown now waits for the active
  cycle, and preflight cleanup is bounded at thirty seconds.
- The final real journey passed in 174.76 seconds. Full repository tests and
  vet, affected Windows race and twenty-run suites, and affected offline Linux
  suites pass. The earlier real archive-to-receipt isolation gate, dedicated-
  node installer, fixed Gitea adapter, check reporter, authority journey, and
  selected-product topology remain present.
- This milestone is the PostgreSQL VERIFY execution/recovery subjourney, not the
  signed source-to-provider Gate B journey and not product UI Gate C.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Extend the passing VERIFY recovery gate in bounded slices: drive a real signed
Gitea change through the standalone source fetcher, then add the physical check
reporter plus correlated Audit/provider evidence. Complete malicious resource-
abuse and oversized-log cases and remaining external-effect restarts with no
duplicate provider outcome. Only after the complete Gate B passes begin formal
Matrix UI integration from the accepted UX baseline.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
