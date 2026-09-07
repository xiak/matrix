# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-07
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `3e77593`

## Goal

Evolve Matrix from the accepted private Application PaaS into a private-cloud
foundation with independently selectable products, then deliver the DevOps
product through the repository's design, UX, architecture, FEAT, code, test,
and acceptance sequence.

## Current milestone

- FEAT-007 owns the current DevOps implementation work and remains
  `In progress`. Its fixed source-provider, executor, egress, limit, retention,
  IAM, and Audit baseline is complete.
- The first Gate A slice now provides the strict provider-neutral
  `api/devops/v1` Go/OpenAPI contract and pure `delivery` rules for DevOps
  project creation, Pipeline draft creation/replacement, and immutable revision
  activation. Activation seals the fixed toolchain digest, isolation profile,
  ordered verification steps, egress, limits, actor, tenant, and deterministic
  identity. Full tests, vet, race, repeated tests, fuzzing, Linux/amd64
  cross-build, schema drift, architecture, and diff checks passed before
  `3e77593` was pushed.
- Gate A is not complete. Persistence/RLS, use cases, HTTP, IAM/Audit
  integration, SourceConnection, RepositoryBinding, SourceEvent, PipelineRun,
  logs, replay/cancellation, leases/fences, reconciliation, quotas, and
  pagination remain pending. Read FEAT-007 and its owning code/tests before
  continuing.
- FEAT-008 also remains `In progress`. Its product foundation and productless
  lifecycle paths are verified, but its real second-product transition and
  authenticated-browser/accessibility gates remain open; the real DevOps
  product should close the second-product gate instead of a long-lived fake.

## Adoption boundary

- Prow is fixed at source commit
  `1a000594c40919068dd43a5704f279f273135d18` and is a reference/selective
  adaptation donor, never a Matrix build or runtime dependency.
- CODING is a product-experience reference. Matrix owns the unified code,
  trigger, pipeline, artifact, and deployment experience while execution
  remains adapter-based and can later target native cloud execution or
  Jenkins.

## Continuation

Resume from FEAT-007 and Git state. Complete the current project/Pipeline
activation vertical slice through delivery-owned PostgreSQL/RLS, use cases,
HTTP, and IAM/Audit boundaries before expanding the contract to change events
and runs. Use the real DevOps product later to close FEAT-008's second-product
transition. Preserve pragmatic DDD, the modular-monolith boundary,
replacement-first pre-v1 changes, fixed-donor classification, and the exact
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
