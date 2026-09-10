# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-10
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation and signed-runtime baseline: `5acf2a6`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Gate A and Gate B's specified automated and physical gates are complete.
  Pushed baseline `5acf2a6` includes the product-selected signed offline
  lifecycle, endpoint-scoped private-provider CA, purpose-separated source
  credentials, guarded Recheck, unified browser baseline, standalone runner
  export/enrollment/installation, and physical source-to-check processes.
- Signed release `matrix-v0.3.0-5acf2a6cbcc7` from exact commit `5acf2a6`
  passed a fresh disconnected install and verify, then exported, enrolled, and
  installed a one-slot D-backed WSL2/systemd runner with Docker `29.6.2`, pinned
  gVisor, the fixed Go toolchain image, and gateway-only UID egress.
- A private HTTPS Gitea `1.27.3` fixture, exact custom CA, three separate
  credentials, real APISIX administrator session, ready source/repository,
  active two-step Pipeline, signed PR webhook, source fetch, isolated execution,
  provider status, public sanitized logs, and correlated Audit completed as one
  `SUCCEEDED / REPORT / COMPLETED` run. Equal delivery replay remained one run;
  the full 106-record Audit chain verified; all DevOps processes had zero
  restarts and the runner left no container.
- Every disposable control host, provider, runner, network, worktree, bundle,
  signing file, image cache, and task directory from that acceptance was
  removed. Docker Desktop data remains D-scoped.
- One installed-runtime defect remains open: after a deliberately interrupted
  source run failed during `VERIFYING`, public bodyless manual Replay created
  its result but crash-looped the source-fetcher at `FETCH` before any provider
  request; guarded cancellation could not converge. This differs from equal
  provider-delivery replay and must be fixed and gated before final release.
- The complete browser role/state/accessibility and 360-pixel matrix remains
  pending and is owned by the separate UI workstream requested by the user.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

The DevOps implementation owner should reproduce the installed-runtime manual-
Replay crash, repair the replay/source-fetch invariant without a database
bypass or compatibility path, and add a real-runtime replay plus cancellation
recovery gate. The UI owner should complete the real-APISIX role/state/
accessibility and `360px` matrix without changing the accepted contracts.
After both land, rerun the common committed-worktree gates and one signed
offline local-provider release before claiming FEAT-007 complete.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.

On this Windows host, keep disposable build, test, download, and container data
on D-scoped storage and remove task-owned resources immediately after use.
