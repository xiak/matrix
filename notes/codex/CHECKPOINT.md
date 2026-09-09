# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-10
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `46a524b`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Pushed `c7af0ee` completes Gate B, including the physical IAM, Audit, Gitea,
  fetcher, executor, reporter, and recovery journey.
- Pushed `46a524b` begins Gate C with the public source-recheck command slice.
  Bodyless, idempotent, strong-ETag-guarded connection and binding commands use
  distinct administrator-only IAM actions and normalized Audit facts. They
  schedule only the delivery-owned observation task and cannot submit or alter
  health state.
- Windows full repository tests, vet, generation, and architecture gates pass.
  Clean PostgreSQL `18.6` journeys pass for DevOps double-apply, unchanged
  resource snapshots, due scheduling, in-flight lease preservation,
  observer-only state transition, and shared IAM/Audit action catalogs.
- The disposable D-drive WSL and PostgreSQL resources and export archive were
  removed after the gate. D-drive Go caches remain only while Gate C UI work is
  active and must be removed when that work ends.
- Gate C platform-shell UI and offline-release completion remain pending.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue Gate C from FEAT-007's accepted product experience: integrate DevOps
into the real platform shell and deliver the smallest independently testable UI
slice without changing the Application PaaS product boundary. Use the guarded
public recheck commands rather than synthesizing health state. Keep UI authority
on the public DevOps and IAM contracts; do not expose provider-native payloads,
credentials, executor internals, host paths, or unavailable Artifact/Delivery
capabilities.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
