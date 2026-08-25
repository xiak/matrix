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

- The branch contains commit `001d889`; FEAT-004 Gate C is accepted and pushed
  in `2b7e398`, and FEAT-005 Gate A is accepted and pushed in `83502b0`. The
  fixed donor baselines remain those listed below.
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
- FEAT-004 Gate B is Accepted. The minimal standard-library HTTP surface
  creates and reads Application, Configuration, immutable revisions,
  Deployment generations, and Operations. It admits tenant and subject only
  from the IAM-facing Authorizer; tenant headers and caller-supplied
  `requestedBy` are never authority.
- PostgreSQL atomically accepts each resource or Deployment mutation together
  with its durable Operation and fixed sanitized Audit outbox event through
  API-only security-definer boundaries. The application use case enforces
  exact replay, changed-payload conflict, optimistic concurrency,
  configuration ownership, rollback snapshot validity, and bounded
  serializable retry.
- The Audit dispatcher uses stable event IDs, at-least-once ingestion, bounded
  retry/dead-letter behavior, database-time lease recovery, and
  fencing-protected completion. Credentials, request bodies, configuration
  values, secret bytes, arbitrary attributes, and native delivery errors are
  absent from its stored event contract. IAM token machinery and Audit
  retention/query remain outside apphosting behind `Authorizer` and
  `AuditIngestor` ports.
- A non-bypass worker login claims due Operations with a database lease,
  monotonically increasing fencing token, and attempt count. The explicit
  Operation state machine rejects stale workers and supports released retry,
  unknown-outcome reconciliation, and terminal lease cleanup.
- The Deployment worker now owns the complete durable reconciliation path:
  fenced placement, intent-before-effect commands, hashed receipts,
  observations, status transitions, and atomic Operation/capacity
  finalization. Update and rollback keep old capacity active until the new
  generation is observed READY; stop reuses the current target without a new
  claim; manual intervention conservatively retains capacity for an uncertain
  effect.
- FEAT-004 Gate C is Accepted. The effecting Go Compose executor confines
  state below one protected binding root, rejects links and reparse points,
  applies atomic durable writes and an OS file lock, resolves exact secret
  versions with a 1 MiB limit, forms only fixed non-interactive Docker Compose
  commands, and retains sealed sanitized receipts.
- A purpose-built static Linux fixture is imported directly into Docker with
  no Dockerfile, registry, pull, build, or Internet dependency. Real Compose
  coverage proves ENV and read-only secret injection, project-network access,
  no host port, update, unknown-outcome observation before retry, rollback,
  stop cleanup, and absence of secret/native/path leakage.
- FEAT-005 target design and fixed-donor adoption review are complete. Gate A
  now owns a canonical Ed25519 release/trust contract, exact streaming
  regular-file payload verification, a compact replay-safe installation state
  machine, the alias-free Cobra/pflag `mx platform` surface, and a complete
  content-hashed fixed Compose topology compiler. Linux no-follow, symlink,
  and executable-mode behavior passed in a network-disabled local container;
  generation drift, unit, vet, race, ten-run, architecture, placement fuzz,
  four-target build, documentation, dependency, authority, and diff gates
  passed on that Gate A worktree.
- The FEAT-004 accepted worktree passed its schema and real-runtime gates.
  Clean PostgreSQL 18 runs applied the migration twice, ran the verifier, used
  non-bypass API/worker logins, attacked RLS and cross-role privileges,
  injected transaction, delivery, and unknown-effect failures, and connected
  the real Compose executor through the durable worker and capacity workflow.
- No assembled offline release, durable installation journal/provider runner,
  real IAM/Audit/APISIX/UI service composition, or verified clean-host
  install/upgrade/rollback/recovery E2E exists yet. The Phase 1 goal is
  therefore active.

## Next concrete work

1. Implement FEAT-005 Gate B from the accepted contracts: protected durable
   journal/lock, host and Docker providers, bundle image load/inspect,
   generated configuration/secrets, migrations, backup, and real IAM, Audit,
   APISIX, PostgreSQL, PaaS API/worker/dispatcher, and UI composition.
2. Assemble releases A/B and prove clean-host install, verification,
   operations, upgrade failure, explicit platform/application rollback,
   recovery, and sanitized support evidence without registry or Internet.

## Fixed donor baselines

- Legacy PaaS: `69336e51f94fa98f6aa278fa4c62382e224dbeaf`
- Senatria IAM/Audit foundation:
  `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d`
- PaaS design: `338d9b5fcb820120c32265e380c55e5f171cdb75`

Replace this file only at a committed-and-pushed milestone or handoff. Do not
append command logs, chat transcripts, secrets, raw provider payloads, or
machine-local paths.
