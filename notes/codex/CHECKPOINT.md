# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `1575d07`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `4e00ae2` adds the distinct Source Observer runtime, purpose-bound
  Gitea `1.27.3` read adapter, observer-only PostgreSQL identity, tenant-fair
  database queue, heartbeat/readiness boundary, health-transition Audit facts,
  and selected-only installation/release topology.
- Real PostgreSQL 18 gates prove double apply, exact four-function authority,
  heartbeat failure closure, cross-tenant fairness, monotonic fencing,
  stale-fence/resource rejection, equal-refresh behavior, sanitized Audit, and
  four-schema isolation. Full tests/vet, focused race and repeated suites, and
  Linux/amd64 CGO-disabled builds pass.
- Pushed `1575d07` adds and passes the opt-in protocol gate against the exact
  pinned rootless Gitea image digest, with a private repository and separate
  fetch/report tokens behind the required HTTPS boundary.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the smallest source-acquisition/FETCH slice: seal the
provider-neutral source archive contract, add the exact Gitea/Git effect behind
it, and connect it to the existing fenced PipelineRun task workflow with only
the fetch credential root. Prove exact commits, redirect/submodule/LFS/hook and
path rejection, cancellation, recovery, bounded storage, provider isolation,
and real PostgreSQL/Gitea behavior before beginning BuildExecutor, reporter, or
formal UI integration. Preserve pragmatic DDD, replacement-first pre-v1
changes, optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
