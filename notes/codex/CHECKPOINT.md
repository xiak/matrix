# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `540d5d2`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Pushed `540d5d2` completes the authenticated Linux/amd64 dedicated
  runner-node installer slice. The closed `mx devops runner-node install`
  workflow validates the signed release, pinned-authority enrollment, CSR
  binding, exact payload inventory, and host preflight before publishing
  root-owned runtime material.
- The Linux adapter converges one isolated account and mutable root per slot,
  exact Docker `29.x` and pinned `runsc` state, UID-bound gateway-only nftables
  policy, the fixed offline toolchain image, systemd units, and loopback
  readiness. Firewall activation precedes Docker and runner processes; failed
  activation leaves runners stopped and disabled while retaining the
  fail-closed firewall. Equal replay is stable and foreign or changed state is
  rejected.
- Full repository tests and vet pass on Windows. The affected installer,
  runner-command, and CLI packages pass Windows race detection and twenty-run
  repetition, and twenty runs in the fixed disconnected Go 1.26.8 Linux/amd64
  image with read-only source and module cache. A separate disconnected Linux
  integration installs and re-verifies the actual current runner binary, the
  pinned official gVisor archive, and the real Docker-save toolchain archive.
- This is controlled-host installation and authentic-material evidence, not a
  real systemd/nftables/Docker/runsc host or repository-code execution gate.
  The full disconnected Linux repository run still reaches the pre-existing
  real-host/SSH probe in `app/adapter/infrastructure/localmachine`; do not claim
  it as a full Linux repository pass.

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
