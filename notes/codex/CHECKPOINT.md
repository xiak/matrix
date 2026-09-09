# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-10
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `c7af0ee`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Pushed `c7af0ee` completes Gate B. The real Gitea source journey now uses the
  physical IAM and Audit services and reuses the physical mTLS gateway,
  build-worker, and runsc-runner recovery path; no in-memory IAM/Audit sink or
  passing executor bridge remains.
- The joined gate proves fenced recovery after source publication, gateway
  submission, a running sandbox effect, provider-status creation, and a
  committed Audit event whose response is lost. It retains one immutable run,
  one provider outcome, one build/check receipt pair, exact physical Audit
  records, and no residual business or probe container.
- The joined journey passed in 45.78 seconds and the independent physical
  executor journey in 43.35 seconds. Affected Linux package tests and vet plus
  full Windows repository tests and vet passed on the same implementation.
- FEAT-007 records that the disposable WSL, Docker, provider, database, cache,
  download, and proxy resources were removed after the gate.
- Gate C product UI and offline-release completion have not begun.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Begin Gate C from FEAT-007's accepted product experience: integrate DevOps into
the real platform shell and deliver the smallest independently testable UI
slice without changing the Application PaaS product boundary. Keep UI authority
on the public DevOps and IAM contracts; do not expose provider-native payloads,
credentials, executor internals, host paths, or unavailable Artifact/Delivery
capabilities.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
