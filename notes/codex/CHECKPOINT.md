# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `7152063`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Pushed `7152063` completes the check-report control-plane slice. A dedicated
  table-blind PostgreSQL identity and physical `matrix-devops-check-reporter`
  process now own `REPORT` claims, provider reconciliation, normalized check
  receipts, terminal PipelineRun transitions, heartbeat, and readiness. The
  build worker no longer has report authority, and the replaced generic run
  queue/transition implementation is absent from the tree.
- The fixed Gitea `1.27.3` adapter creates one exact terminal commit status and
  observes uncertain outcomes without another create. Its real fixture passed
  source observation, immutable source fetch, status creation, and status
  reconciliation. A real PostgreSQL 18 journey passed concurrent task claims,
  monotonic fencing, exact six-function reporter authority, receipt tamper
  rejection, terminal facts, and migration replay.
- Selected-product installation now provisions a separate reporter DSN and
  source-egress process with only the report credential root. The DevOps
  scratch release image carries the fixed system CA bundle. A real PostgreSQL
  authority-process journey started IAM, Audit, PaaS, DevOps, all dispatchers,
  source fetcher, source observer, and check reporter and passed readiness
  failure/recovery plus exact user and system Audit facts.
- Full repository tests and vet pass with Go 1.26.3 on Windows. All affected
  contract, reporter, Gitea, PostgreSQL, migration, installation, topology,
  release-build, architecture, and authority-process packages pass race
  detection and twenty-run repetition.
- This is real control-plane and provider-protocol evidence, not the
  dedicated-host systemd/nftables/Docker/runsc, malicious-repository,
  restart-fencing, full source-to-check Gate B, or product UI Gate C evidence.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Run the dedicated-host Gate B on a real Linux/amd64 machine with PID 1
systemd, nftables, Docker `29.x`, the pinned offline toolchain, and pinned
`runsc`. Drive one real signed change through source fetch, isolated build,
normalized logs, and the implemented check reporter; prove no-egress
isolation, resource containment, malicious-repository handling, restart
recovery, readiness, no duplicate provider outcome, and secret-safe evidence.
Only after that boundary passes begin formal Matrix UI integration from the
accepted UX baseline.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
