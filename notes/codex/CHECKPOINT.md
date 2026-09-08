# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `caf8283`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `8ca8c97` replaces endpoint arrays with one exact `endpointOrigin`,
  adds closed source/binding health reasons and pure observed-status
  transitions, enforces two-minute source freshness at admission, and upgrades
  historical single-origin data while refusing ambiguous multi-origin data.
- Pushed `caf8283` adds the exact installation-owned
  `mx devops source-credential apply|retire-previous` surface. It authenticates
  the sealed installation journal, pinned trust root, committed signed release,
  and selected DevOps product while holding the installation lock; plaintext
  enters only through a protected regular input file and never output.
- DevOps installation now owns separate webhook/fetch/report roots. A
  purpose/tenant/reference-bound directory contains one strict canonical
  `material.json`; one durable file replacement atomically rotates or retires
  current/previous webhook values. The API resolver consumes this format and
  the superseded two-file resolver is deleted without an alias.
- Full tests and vet, focused race and 20-run repeated suites, Linux/amd64
  CGO-disabled builds, and the same focused filesystem suites in a disposable
  disconnected Debian container passed. The earlier PostgreSQL 18 source
  contract and data-bearing upgrade gates remain green in FEAT-007 evidence.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the smallest source-observer reconciliation slice:
observer-only database authority, lease/fence queue, exact Gitea read probes,
health commits/Audit transitions, heartbeat readiness, and only the three
purpose mounts that process requires. Do not begin executor/reporter effects or
formal UI integration until this source-readiness runtime boundary passes its
real PostgreSQL/provider gates. Preserve pragmatic DDD, replacement-first
pre-v1 changes, optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
