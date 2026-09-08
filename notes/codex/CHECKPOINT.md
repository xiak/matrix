# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `7b0f66d`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `7b0f66d` completes source acquisition through the installed runtime:
  a forced-RLS archive-receipt table, table-blind source-fetcher role with
  exactly five functions, exclusive `FETCH` claims, fenced atomic receipt/run
  completion, heartbeat-gated readiness, and the selected-only
  `matrix-devops-source-fetcher` process and offline binary.
- The fresh DevOps and four-product PostgreSQL 18 journeys pass, including
  double apply, missing-receipt bypass rejection, failure/cancellation without
  receipts, fencing recovery, exact cross-schema denial, and two valid archive
  receipts. Full tests and vet pass on Go `1.26.8`; focused race and 20-run
  suites plus Linux/amd64 CGO-disabled full build pass.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the smallest independently testable Matrix Native
BuildExecutor vertical slice, consuming only the immutable source receipt and
the existing `VERIFY` fence. Follow the fixed dedicated-runner, offline
toolchain, gVisor, no-egress, resource, and sanitized-log boundaries already
owned by FEAT-007; do not couple it to PaaS execution or begin formal UI
integration before the real executor boundary passes. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
