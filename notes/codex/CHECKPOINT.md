# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `bbb0137`

## Goal

Evolve Matrix from the accepted private Application PaaS into a private-cloud
foundation with independently selectable products, then deliver the DevOps
product through the repository's design, UX, architecture, FEAT, code, test,
and acceptance sequence.

## Current milestone

- FEAT-007 owns the current DevOps implementation work and remains
  `In progress`. Its fixed source-provider, executor, egress, limit, retention,
  IAM, and Audit baseline is complete.
- Gate A now has strict provider-neutral contracts and pure `delivery` rules
  for projects, SourceConnections, RepositoryBindings, Pipeline drafts, and
  immutable activation. The pushed `bbb0137` slice adds action-bound IAM
  authorization values, durable equal/conflicting command replay, exact result
  snapshots, Audit outbox facts, and a delivery-owned PostgreSQL 18 schema with
  owner/migrator/API/worker roles, forced tenant RLS, composite ownership links,
  immutable binding snapshots, and immutable PipelineRevisions.
- Full tests, vet, race, repeated tests, Linux/amd64 cross-build, and real
  PostgreSQL 18 tests passed. The database migration applied twice both alone
  and with IAM, Audit, and PaaS; real API/worker credentials proved cross-schema
  confinement, function-only API writes, a table-blind worker, tenant
  isolation, exact replay snapshots, and Audit correlation.
- Gate A is not complete. HTTP, IAM/Audit adapters and outbox dispatch,
  DevOps credential enrollment, SourceEvent, PipelineRun, logs,
  replay/cancellation, leases/fences, reconciliation, quotas, and pagination
  remain pending. Read FEAT-007 and its owning code/tests before continuing.
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
activation vertical through IAM/Audit HTTP adapters, Audit outbox dispatch,
the DevOps HTTP service, and real process-boundary tests before expanding the
contract to change events and runs. Use the real DevOps product later to close
FEAT-008's second-product transition. Preserve pragmatic DDD, the
modular-monolith boundary, replacement-first pre-v1 changes, fixed-donor
classification, and the exact repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
