# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-08-26
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
- The Go module is `github.com/xiak/matrix`. Public API groups use
  `*.matrix.xiak.com/v1`; they are identifiers, not customer DNS lookups.

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
- FEAT-005 Gate B has started. Commit `9a31558` adds the real installation
  journal boundary: a restrictive root, cross-process OS lock, random local
  HMAC key, canonical sealed state, monotonic writes, atomic durability, and
  link/reparse, ownership, permission, interruption, and tamper rejection.
  Native Windows and network-disabled Linux tests pass; provider effects and
  platform services are not wired yet.
- FEAT-006 target and fixed-donor adoption are pushed in `506f6d7` and
  `932252e`. Strict generated IAM/Audit Go and OpenAPI 3.1 contracts are pushed
  in `9f50b6c`; they reject authority selectors, ambiguous JSON, enum/union
  drift, arbitrary Audit payloads, and accidental credential serialization.
  Pure authority behavior is pushed in `0437fbf`: fixed-profile Argon2id,
  lookup and binding-scoped opaque credential digests, database-time session
  checks, fixed RBAC and bootstrap replay; plus authenticated-source canonical
  Audit facts, exact replay/conflict, per-tenant sequence/hash chains,
  indefinite retention, and tenant/filter-bound HMAC cursors. FEAT-006 Gate A
  is Accepted and pushed in `9a82568`. Separate IAM/Audit PostgreSQL owners,
  migrators, and runtime roles apply both clean schemas twice; the real PG18
  gate proves forced RLS, API-only writes, cross-schema denial, canonical
  closed events, immutable Audit rows, Go/SQL hash agreement, database event,
  session, and lease time, lease recovery, and stale-fence rejection. Full
  generation, unit, architecture, vet, race, ten-run, and PG18 race gates pass.
  The pre-Gate-B identity correction is pushed in `1beb2d0`: bootstrap owns
  five independent IAM, PaaS, Audit, APISIX, and verifier credentials, and
  `GET /v1/service-identity` returns only the organization, principal, and
  purpose bound to the current service Bearer. It accepts no selector, so
  Audit can derive a closed producer source without shared credentials,
  caller headers, or cross-schema reads. Generation, full unit/vet/race and
  ten-run gates, four-target builds, documentation/dependency checks, and a
  fresh real PostgreSQL 18 race gate all pass after the correction.
  The first Gate B IAM runtime slice is pushed in `df24b2f`: production
  use-case, PostgreSQL, and strict standard-library HTTP adapters now execute
  bootstrap/status, readiness, current service identity, login, and
  authorization. Calling services are confined to their owned action family;
  IAM decisions and sanitized events commit atomically. A fresh PostgreSQL 18
  race-tested HTTP-to-database run proves credential binding, initial-password
  denial, digest-only secret storage, and the IAM Audit outbox fact. IAM
  management commands, the runnable process, Audit delivery/service, and PaaS
  clients remain pending, so Gate B is not accepted.
  IAM management is pushed in `7073479`: all current OpenAPI commands now use
  the same session/RBAC/use-case/PostgreSQL/HTTP path for logout, password
  change, user creation, role binding, and binding/session revocation. A fresh
  PostgreSQL 18 race run proves old-password rejection, first-password gating,
  immediate role/session revocation, audited role denial, cross-tenant
  rejection, digest-only storage, and exact decision/outbox cardinality. IAM
  still lacks its runnable process and Audit dispatcher, and Audit/PaaS remain
  unwired, so Gate B is not accepted.
  The Audit core runtime is pushed in `9c69954`: production use-case,
  PostgreSQL, and strict standard-library HTTP adapters now derive producer
  source from the IAM service-identity port, bind query/verification tenant
  and actor to IAM decisions, enforce exact replay and tenant sequencing, and
  append local read/verification access facts in the same Audit transaction.
  Runtime SQL exposes only readiness, event locking/lookup, append, bounded
  filtered query, checkpoint, and chain reads; the replaced `lookup_event`
  surface is removed. A fresh PostgreSQL 18 HTTP-to-database race run proves
  equal/changed replay, independent tenant chains, tenant-bound cursors,
  time/action/actor filtering, access recording, integrity verification,
  direct-table/internal-function denial, and credential/native-error
  non-leakage. The vertical test still uses a controlled IAM port; real IAM
  HTTP integration, standalone processes, outbox dispatchers, and PaaS clients
  remain pending, so Gate B is not accepted.
- The FEAT-004 accepted worktree passed its schema and real-runtime gates.
  Clean PostgreSQL 18 runs applied the migration twice, ran the verifier, used
  non-bypass API/worker logins, attacked RLS and cross-role privileges,
  injected transaction, delivery, and unknown-effect failures, and connected
  the real Compose executor through the durable worker and capacity workflow.
- No assembled offline release, installation provider runner, real
  IAM/Audit/APISIX/UI service composition, or verified clean-host
  install/upgrade/rollback/recovery E2E exists yet. The Phase 1 goal is
  therefore active.

## Next concrete work

1. Continue FEAT-006 Gate B with the real IAM HTTP client, independently
   running IAM/Audit services, IAM and PaaS outbox dispatchers, and real PaaS
   clients; then prove bootstrap/login/RBAC/revocation, outage retry, exact
   Audit replay/query/verification, and cross-boundary security attacks.
2. Resume FEAT-005 Gate B provider effects and fixed platform composition,
   then assemble releases A/B and prove the network-disabled Compose install,
   verification, operations, upgrade, rollback, recovery, and support-evidence
   E2E required by both FEATs.

## Fixed donor baselines

- Legacy PaaS: `69336e51f94fa98f6aa278fa4c62382e224dbeaf`
- Senatria IAM/Audit foundation:
  `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d`
- PaaS design: `338d9b5fcb820120c32265e380c55e5f171cdb75`

Replace this file only at a committed-and-pushed milestone or handoff. Do not
append command logs, chat transcripts, secrets, raw provider payloads, or
machine-local paths.
