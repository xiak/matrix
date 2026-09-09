# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `4b63c1d`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Pushed `4b63c1d` completes the current signed control-plane installation
  milestone. Release images now retain both archive-configuration and source
  identities while running through deterministic signed local references, the
  DevOps migration process admits its exact five isolated database identities,
  and the executor gateway joins control plus edge so Docker can publish only
  the runner listener on `8444`.
- A signed release assembled from that commit completed a clean install on a
  disposable systemd Linux/amd64 host with Docker Engine `29.6.2` and its
  default containerd image store. All migrations and 16 services started;
  install, verify, status, and protected support-evidence operations returned
  `READY`; strict observation saw a healthy gateway with requested and active
  `0.0.0.0:8444` bindings.
- Full repository tests and vet pass on Windows. Affected topology,
  installation, platform-command, and release-build packages pass race
  detection and twenty-run repetition on Windows, plus twenty runs in the
  fixed disconnected Go 1.26.8 Linux/amd64 image with read-only source and
  module cache.
- This is real control-plane lifecycle evidence, not the dedicated-host
  systemd/nftables/Docker/runsc, malicious-repository, restart-fencing, or full
  source-to-check Gate B evidence.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Run the dedicated-host Gate B on a real Linux/amd64 machine with PID 1
systemd, nftables, Docker `29.x`, the pinned offline toolchain, and pinned
`runsc`. Prove no-egress isolation, resource containment, malicious-repository
handling, restart recovery, readiness, and log sanitization through an actual
repository execution. Then implement reporter effects and only after the
boundary passes begin formal Matrix UI integration.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
