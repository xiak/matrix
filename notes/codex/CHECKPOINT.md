# Codex working checkpoint

> Non-authoritative agent memory. Validate every statement against the current
> Git worktree, executable tests, and the owning FEAT before acting. Formal
> product documentation lives under `docs/`.

- Updated: 2026-08-25
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/placement-policy`
- Active release: Private Application PaaS v0.1, Docker/Compose first

Local checkout paths are machine-specific and must never be relied upon.

## Durable working constraints

- Use Pragmatic DDD; abstractions must protect a real rule, boundary, side
  effect, variation, or current complexity.
- Design the target first, inspect donors only at fixed commits, then classify
  slices as `REUSE`, `ADAPT`, `REFERENCE`, or `REJECT`.
- IAM, Audit, and minimal Operation semantics are reusable authorities or
  mechanisms. The legacy universal ServiceRuntime is not the target product
  model.
- Application hosting uses Application, immutable ApplicationRevision, and
  Deployment. Compose is the first domain-local DeploymentExecutor;
  Kubernetes may conform later without becoming a universal runtime API.
- Formal docs use single ownership: one FEAT owns requirement through
  acceptance; ADRs own cross-FEAT boundaries; adoption records own provenance;
  runbooks own verified procedures.

## Portable branch state

- FEAT-001 and FEAT-002 mechanisms exist; FEAT-003 deterministic placement
  Gate A evidence exists.
- The product-boundary correction is recorded: the target model is
  Application, immutable ApplicationRevision, Deployment,
  ExecutionPool/ExecutionTarget, and a domain-local DeploymentExecutor.
- A Gate B foundation now exists: tactical DDD package boundaries, a
  transaction-owned create-placement use case, tenant-neutral capacity claims
  with tenant-owned reservation links, a pgx repository, and a forced-RLS
  PostgreSQL migration/verifier. Gate B is not accepted yet.
- For this checkpoint, unit, vet, race, ten-run, placement fuzz, architecture,
  `git diff --check`, and PostgreSQL 18 migration apply-twice/verify gates
  passed. Real repository, concurrency, RLS-behavior, and fault-injection
  integration tests remain absent.
- The current public draft still uses WorkloadRelease, RuntimeTarget, and
  technology-shaped isolation values and must be corrected before Gate B.

## Next concrete work

1. Correct the apphosting ApplicationRevision/Deployment and
   ExecutionPool/ExecutionTarget model without compatibility aliases.
2. Migrate the Gate B schema/repository/use case to that corrected model and
   add real PostgreSQL concurrency, tenant-isolation, replay, and atomicity
   integration tests.
3. Accept Gate B, then build the real Compose vertical slice and offline
   installation/upgrade/rollback release gate.

## Fixed donor baselines

- Legacy PaaS: `69336e51f94fa98f6aa278fa4c62382e224dbeaf`
- Senatria IAM/Audit foundation:
  `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d`

Replace this file at milestones or task handoff. Do not append command logs,
chat transcripts, secrets, raw provider payloads, or historical diaries.

For a cross-machine handoff: finish a coherent slice, run its stated gates,
replace this checkpoint, commit both the slice and checkpoint, and push the
same feature branch. On the next machine, pull the branch, confirm a clean
worktree, read this file once, and validate its claims before continuing.
