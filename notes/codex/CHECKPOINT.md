# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `2d43660`

## Goal

Evolve Matrix from the accepted private Application PaaS into a private-cloud
foundation with independently selectable products, then deliver the DevOps
product through the repository's design, UX, architecture, FEAT, code, test,
and acceptance sequence.

## Current milestone

- FEAT-007 owns the current DevOps implementation work and remains
  `In progress`. Its fixed source-provider, executor, egress, limit, retention,
  IAM, and Audit baseline is complete.
- Gate A now has strict provider-neutral configuration contracts and pure
  `delivery` rules for projects, SourceConnections, RepositoryBindings,
  Pipeline drafts, and immutable activation. The pushed `9ca97c8` slice adds
  strict public HTTP reads/readiness, action-bound IAM and Audit HTTP adapters,
  durable Audit outbox dispatch with leases/fences/dead letters, and separate
  DevOps API and Audit-dispatcher processes.
- A signed release manifest is now the sole optional-product authority.
  Selecting DevOps derives its service identity and credentials, enrolls it
  through the IAM migration boundary, includes the DevOps release image and
  binaries, composes the two DevOps processes and APISIX route, and exposes
  authenticated product discovery. PaaS-only releases contain none of those
  DevOps resources.
- Full repository tests and vet passed after the slice. Race and repeated
  package tests passed for the affected authorities; PostgreSQL 18 integration
  proved idempotent Platform/DevOps enrollment, strict role confinement,
  outbox claiming/completion, and readiness behavior.
- The pushed `2d43660` authority-process gate builds and starts IAM, Audit,
  Application PaaS, DevOps, and all three Audit dispatchers against PostgreSQL
  18. It proves the authenticated configuration journey, exact replay,
  read-only viewer access, immutable nested revision reads, IAM-outage
  readiness, cross-schema confinement, five correlated DevOps Audit facts,
  and unchanged PaaS behavior.
- Gate A is not complete. SourceEvent, PipelineRun, logs,
  replay/cancellation, execution leases/fences, reconciliation, quotas, and
  pagination remain pending. Read FEAT-007 and its owning code/tests before
  continuing.
- FEAT-008 remains `In progress`. Its real DevOps second-product transition is
  now represented in release, installation, topology, readiness, and discovery;
  authenticated-browser and accessibility acceptance still remain open.

## Adoption boundary

- Prow is fixed at source commit
  `1a000594c40919068dd43a5704f279f273135d18` and is a reference/selective
  adaptation donor, never a Matrix build or runtime dependency.
- CODING is a product-experience reference. Matrix owns the unified code,
  trigger, pipeline, artifact, and deployment experience while execution
  remains adapter-based and can later target native cloud execution or
  Jenkins.

## Continuation

Resume from FEAT-007 and Git state. The project/Pipeline configuration vertical
is closed through its real network/process gate; expand next into the immutable
SourceEvent and PipelineRun admission slice without starting executor effects.
Preserve pragmatic DDD, the modular-monolith boundary, replacement-first pre-v1
changes, fixed-donor classification, and the exact repository-local Git
identity `Xiak <Jellal@aliyun.com>`.
