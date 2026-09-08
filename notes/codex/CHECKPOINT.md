# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `676d2cc`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `676d2cc` adds the fenced source-acquisition use case, deterministic
  provider-neutral gzip/tar codec, private atomic filesystem archive and
  canonical path-free receipt, and fixed pure-Go Gitea smart-HTTP fetcher.
  Execute claims may contact Gitea; recovered claims only rehash and parse an
  already-published archive. Commit, deadline, cancellation, lease-loss,
  redirect, SHA-1, path, mode, size, and tamper behavior is closed.
- The opt-in protocol gate passes against the exact pinned Gitea `1.27.3`
  digest by creating a real branch, commit, and pull request, fetching only its
  trusted base and pull-head refs, and reproducing the head tree without
  `.git`. Full repository tests pass on Go `1.26.8`; focused race and 20-run
  suites pass; `govulncheck v1.7.0` reports zero reachable vulnerabilities
  after upgrading `x/crypto` to `v0.56.0`.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 by connecting the completed acquisition boundary to one
tenant-leading forced-RLS archive-receipt table, an exact table-blind
source-fetcher role/function set, atomic `FETCHING -> VERIFYING` receipt
transaction, heartbeat-gated readiness, and the selected-only
`matrix-devops-source-fetcher` process/topology. Prove clean/double PostgreSQL
18 apply, fairness, fencing, bypass rejection, crash observation, private mount
authority, and offline binary inclusion before BuildExecutor, reporter, or
formal UI integration. Preserve pragmatic DDD, replacement-first pre-v1
changes, optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
