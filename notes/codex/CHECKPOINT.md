# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `9e76f3d`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `9e76f3d` adds the provider-neutral BuildExecutor port and pure fenced
  `VERIFY` use case. Its closed command binds the current run, immutable
  PipelineRevision, stored source receipt, fixed profile/limits, and deadline;
  first claims execute while takeover fences only observe or cancel. A
  normalized digest-bound receipt sends both passed and verification-failed
  outcomes to the later reporter, while uncertainty preserves the intent.
- Full tests, vet, architecture tests, focused race and 20-run suites, and a
  Linux/amd64 CGO-disabled full build pass. This is a pure authority/workflow
  boundary: PostgreSQL persistence, the physical isolated runner, transport,
  sandbox, normalized logs, and reporter remain pending.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the smallest independently testable persistence and
process slice for the existing BuildExecutor use case: table-blind fenced
`VERIFY` claim/renew/complete functions, normalized build-receipt storage, and
an independent selected-only worker boundary. Do not claim repository code is
isolated until the dedicated runner, offline toolchain, gVisor, no-egress,
resource, and sanitized-log gates really pass; do not couple it to PaaS
execution or begin formal UI integration before that real boundary passes.
Preserve pragmatic DDD, replacement-first pre-v1 changes, optional-product
isolation, and repository-local Git identity `Xiak <Jellal@aliyun.com>`.
