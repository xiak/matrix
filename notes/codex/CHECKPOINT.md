# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `006f11c`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Pushed `006f11c` adds the opt-in real Linux execution integration. On a
  disposable systemd Linux/amd64 node, a canonical source archive crosses
  separate TLS 1.3 mTLS admin and runner listeners through the production
  gateway clients, handlers, spool, journal, workspace, and runner workflow,
  then runs both fixed Go steps in Docker `29.6.2` with the pinned `runsc`.
- The passing journey proves normalized logs, the exact terminal receipt,
  acknowledged journal, and zero residual containers. Repository-style probes
  prove no sensitive environment, Docker socket, privileged device, writable
  source/root filesystem, non-loopback interface, or reserved-address egress.
- The real runtime exposed and the implementation fixed two closed-profile
  defects: Docker 29's exact non-TTY multiplexed log media type and explicit
  UID/GID ownership of the private cache tmpfs for runner UID `65532`.
- The real gate passed in 73.76 seconds. Full repository tests and vet, affected
  Windows race and twenty-run suites, both affected Linux package suites, and
  the existing Docker preflight pass.
- The earlier physical check-reporter, fixed Gitea adapter, PostgreSQL
  authority journey, dedicated-node installer, authentic runner material, and
  selected-product topology remain present. This milestone proves a real
  Docker/runsc sandbox side effect, not yet a full standalone-process or
  source-to-provider Gate B journey, and not product UI Gate C.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Complete the dedicated-host Gate B as one physical process journey: drive a
real signed Gitea change through PostgreSQL, source fetch, standalone gateway,
build worker and runner processes, isolated build, normalized logs, and the
check reporter. Add restart recovery, resource-abuse and oversized-log cases,
readiness/fencing, and no-duplicate provider-outcome evidence. Only after that
boundary passes begin formal Matrix UI integration from the accepted UX
baseline.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
