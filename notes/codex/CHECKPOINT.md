# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-08-25
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/placement-policy`
- Active release: Private Application PaaS v0.1, Docker/Compose first

## Durable constraints

- Use Pragmatic DDD and one current implementation. Git preserves replaced
  pre-v1 drafts; source, tests, and docs do not retain aliases, compatibility
  layers, or historical copies without evidence of a real consumer.
- Design each FEAT target before donor inspection. Review only fixed donor
  commits and record every relevant slice as `REUSE`, `ADAPT`, `REFERENCE`, or
  `REJECT`; donors never become build or runtime dependencies.
- Modify the current owner before adding an artifact. Tests prove current
  contracts, invariants, security boundaries, or supported runtime behavior;
  they do not snapshot SQL text, file layout, incidental order, or stale
  features.
- The Go module is `github.com/xiak/matrix`. The public API group is
  `paas.matrix.xiak.com/v1`; it is an identifier, not a customer DNS lookup.

## Portable branch state

- The branch contains commit `001d889` and uses the fixed donor baselines
  listed below.
- FEAT-001, FEAT-002, and FEAT-003 Gate A/Gate B are Accepted. The public model
  is Application, immutable ApplicationRevision, Deployment,
  ExecutionPool/ExecutionTarget, provider-neutral PlacementPolicy, and an
  apphosting-owned DeploymentExecutor boundary.
- Configuration is a default PaaS capability. Phase 1 binds immutable
  ConfigurationRevision values to ENV injection and exact secret versions to
  read-only FILE injection. Dynamic refresh, structured files, Nacos, and
  Consul are deferred behind the same provider-neutral binding seam.
- PostgreSQL placement uses tenant-leading forced-RLS resources,
  tenant-neutral capacity claims, tenant-owned reservation links, bounded
  serializable retries, exact replay, and one security-definer reservation
  transition boundary.
- FEAT-004 Gate A is Accepted. Deployment and placement bind an exact positive
  generation; versioned internal-visible executor schemas carry the immutable
  generation, exact ApplicationRevision and ConfigurationRevision documents,
  scheduled PlacementDecision, and normalized observation without secret
  bytes or provider-native controls.
- The Compose compiler deterministically admits only verified local image
  digests, WORKLOAD isolation, resource limits, ordinary ENV configuration,
  derived read-only secret grants, and the project default network. Its model
  has no caller-controlled build, pull, command, host port/path, privileged, or
  host-network capability.
- The same worktree passed generation drift, unit, vet, race, ten-run, schema,
  architecture, placement fuzz, four OS/architecture builds, Markdown-link,
  and diff gates. A disposable PostgreSQL 18 test applied the migration twice,
  ran the verifier, raced capacity, attacked RLS, injected rollback failure,
  and exercised activate/release/expiry under the race detector.
- No effecting Compose DeploymentExecutor, durable application Operation,
  northbound application workflow, offline distribution, verified
  install/operations path, or platform upgrade/rollback E2E exists yet. The
  Phase 1 goal is therefore active.

## Next concrete work

1. Implement FEAT-004 Gate B: authoritative application, configuration,
   immutable Deployment generation and Operation persistence; minimal
   northbound mutations; lease/fencing worker; apply/observe/stop/rollback
   state transitions and fault/replay/RLS verification on real PostgreSQL 18.
2. Implement and accept Gate C with real Docker Compose behavior, including
   exact secret-file resolution, reconciliation, update, rollback, network
   probe, and stop cleanup without registry or Internet access.
3. Package digest-pinned offline installation and prove clean-host install,
   verification, operations, platform upgrade, rollback, and application
   rollback without registry or Internet access.

## Fixed donor baselines

- Legacy PaaS: `69336e51f94fa98f6aa278fa4c62382e224dbeaf`
- Senatria IAM/Audit foundation:
  `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d`

Replace this file only at a committed-and-pushed milestone or handoff. Do not
append command logs, chat transcripts, secrets, raw provider payloads, or
machine-local paths.
