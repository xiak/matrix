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
  in `2b7e398`, FEAT-005 Gate A is accepted and pushed in `83502b0`, and the
  current durable implementation head is `0c305a0`. The fixed donor baselines
  remain those listed below.
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
- FEAT-005 Gate B is in progress. Commit `9a31558` adds the real installation
  journal boundary: a restrictive root, cross-process OS lock, random local
  HMAC key, canonical sealed state, monotonic writes, atomic durability, and
  link/reparse, ownership, permission, interruption, and tamper rejection.
  Commit `11ec1f4` replaces the stale draft topology with exact IAM, Audit,
  both Audit dispatchers, PaaS API, and a newly runnable PaaS Operation worker.
  The worker composes the accepted lease/fencing, placement, reconciliation,
  and real Compose executor path; a canonical local artifact catalog maps only
  admitted content digests to reverified Docker image IDs, while exact Secret
  versions are consumed from a non-mutating read-only tree. Workers and
  dispatchers now expose normalized internal readiness, and the fixed topology
  uses their actual environment/file contracts, least-privilege DSNs, real
  executable entrypoints, and the Go `matrix-health` probe. Full generation,
  unit, vet, race, repeated, architecture, four-target build, fresh PG18
  process, real Compose executor, and fresh PG18-to-Compose worker gates pass.
  Commit `8d6bed4` adds the production install workflow backend and the first
  local-machine effects without exposing the incomplete provider through
  `mx`. Release trust and exact content digests are pinned into the sealed
  journal; effect intent precedes each phase; unknown outcomes resume under
  the durable command; definitive failures persist rollback intent first.
  Authenticated release content is resumably staged, image archives stream to
  fixed `docker image load` stdin and are reverified by exact local identity,
  and restrictive IAM/database credentials plus deterministic
  Compose/APISIX/catalog files are generated. The versioned catalog now
  contains only the signed verification WORKLOAD image, never platform
  images. Full unit/vet and Linux/amd64 plus Darwin/arm64 build gates pass.
  Commit `97d1c2d` adds installation-owned execution of the IAM, Audit, and
  PaaS Go migration binaries, observation-before-retry through each owning
  verifier, and restrictive migration files; clean PostgreSQL 18 apply-twice
  verification passes for all three schemas. Commit `3323741` replaces a
  static placement seed with a continuously refreshed default local execution
  profile. The containerized worker observes the Docker Engine host rather
  than itself, atomically reconciles one fixed ExecutionPool, ExecutionTarget,
  tenant PlacementPolicy, and allocation through a worker-only PostgreSQL
  function, fails closed on identity/profile/freshness drift, and advertises
  no isolation while degraded. Its exact committed worktree passed generation
  drift, full unit/vet/race, ten-run repetition, placement fuzz, four-target
  builds, clean PostgreSQL 18, and a real network-disabled Docker Engine-host
  probe. Commit `0a0ba1f` adds ownership-safe observation and convergence of
  the fixed Compose project, exact runtime/isolation/resource checks, a pinned
  local Docker/Compose environment, offline-only start, replay, recoverable
  config-drift convergence, and unknown-outcome classification. Its exact
  worktree passed generation, full unit/vet/race, ten-run repetition,
  network-disabled Linux/amd64 start behavior ten times, real Docker
  normalization probes, and four-target builds. Commit `40cc917` adds
  ownership-safe failed-install cleanup: it proves exact platform and
  migration identities before deletion, removes containers before networks,
  reobserves uncertain effects, preserves installation data and diagnostics,
  and keeps dependency-unavailable rollback replayable. Its exact worktree
  passed generation, full unit/vet/race, relevant ten-run repetition,
  network-disabled Linux/amd64 start and cleanup behavior ten times, and
  four-target builds. Commit `13ce031` binds the signed verification WORKLOAD
  digest and running installation/release identity into the PaaS process and
  exposes only the fixed no-secret application probe through dedicated APISIX
  routes. Commit `aef5ee5` adds the installation-side loopback APISIX client:
  it reads only the protected verifier credential, polls the exact PaaS
  release-bound Deployment/Operation, then polls Audit for that delivered fact
  and bounded chain proof with strict response and leakage bounds. The concrete
  local-machine Effects compose the existing journaled phases, and the real
  `mx` process now wires install, signal handling, normalized streams, and
  stable exits. Commit `6825876` adds a real independent Go-served PaaS UI for
  IAM login and immutable ENV configuration revisions, plus the real signed
  verification workload that validates its installation/release bindings.
  The closed topology owns both exact executable entries. Release and topology
  packages are the single installation build boundary; no internal/public
  alias was retained. Commit `28d1448` adds the repository-owned offline
  release assembler and fixed network-disabled image builds, while `5489bcf`
  signs portable image identities. Commits `127beb7`, `bab7416`, `12ccc02`,
  `1490a93`, and `c2bcd73` close the PostgreSQL 18 contract and bind-ownership
  boundaries, converge the fixed runtimes, expose only the APISIX edge
  listener, and support the declared minimum Compose v2.33.0 runtime.
- Commit `cb7da45` adds authenticated immediate-successor upgrade with a
  verified pre-upgrade backup, target staging/loading/configuration/migration,
  exact source-or-target Compose ownership classification, atomic
  release-derived configuration replacement, and automatic restoration of the
  authenticated source release after a definitive candidate failure. Commit
  `0c305a0` corrects the release-verification Deployment update so it preserves
  the stored name without submitting a forbidden rename input.
- FEAT-006 Gate A and Gate B are Accepted. Target design and fixed-donor
  adoption remain `506f6d7` and `932252e`; the accepted authority contracts,
  pure behavior, and separate IAM/Audit PostgreSQL owners, migrators, runtime
  roles, RLS, immutable records, database-time sessions/leases, and stale-fence
  rejection remain authoritative in the FEAT and its owning tests.
  Commit `51790b7` runs IAM, Audit, and the IAM Audit dispatcher independently.
  Commit `255b790` adds the real PaaS IAM/Audit clients, independently runnable
  PaaS and PaaS Audit dispatcher, formal PaaS readiness, terminal delivery
  classification, exact Deployment stop authorization, and the complete
  cross-service process gate. A fresh PG18 race run starts five binaries and
  proves exact bootstrap replay/conflict, weak login, expiry/revocation,
  wrong-role/service and cross-tenant denial, IAM fail-closed behavior, exact
  IAM tenant/subject/decision propagation, atomic outboxes, outage/restart,
  duplicate/conflicting replay, dead letters, tenant-only Audit query/verify,
  access records, cross-schema denial, and secret/native-error non-leakage.
  Full generation, unit, architecture, vet, race, repeated, four-target build,
  dependency/diff, and independent clean PG18 database gates pass. FEAT-006
  commit `3fe0615` adds the sole fixed verifier-as-subject IAM decision: only
  the bootstrap installation verifier may request `installation.verify`, and
  IAM reloads its current credential, role, organization, and bootstrap receipt
  on every call. Commit `13ce031` composes that decision into deterministic
  PaaS Application/Configuration revisions and one probe Deployment without
  caller-controlled artifacts, configuration, Secrets, placement, or provider
  controls. Audit resolves the exact delivered PaaS Operation fact, verifies
  the bounded hash-chain segment ending at it, and records one sanitized
  verifier access fact; producer leases and fencing remain producer-owned.
  Fresh PostgreSQL 18 race gates pass the Audit migration/HTTP slice and a
  five-process IAM/PaaS/Audit plus both-dispatcher flow from PaaS `PENDING` to
  Audit `VERIFIED`. FEAT-006 Gate C remains pending until FEAT-005 consumes
  these services in the real external-network-disabled release lifecycle.
- The FEAT-004 accepted worktree passed its schema and real-runtime gates.
  Clean PostgreSQL 18 runs applied the migration twice, ran the verifier, used
  non-bypass API/worker logins, attacked RLS and cross-role privileges,
  injected transaction, delivery, and unknown-effect failures, and connected
  the real Compose executor through the durable worker and capacity workflow.
- Release A `matrix-v0.1.0-c2bcd738a753` was assembled from exact clean commit
  `c2bcd73` as build `phase1-a-20260826-07`. A brand-new privileged DinD with
  outer network mode `none`, Docker 27.5.1, Compose v2.33.0, and no inner
  containers, images, or volumes loaded all seven signed images and completed
  `mx platform install` as `READY`. APISIX was healthy on its real loopback
  listener; the signed no-pull verification workload reached Deployment
  `READY` and Operation `SUCCEEDED`; its Audit outbox was delivered; and the
  fixed PaaS and Audit APIs returned `READY` and `VERIFIED` for the same fact
  and bounded chain. Explicit rollback/recovery behavior and complete lifecycle
  E2E remain pending, so the Phase 1 goal is active.
- Commit `fa303a4` adds durable `status` and `verify`: status cannot create or
  write installation state; verify reauthenticates the sealed current release,
  exact images and owned healthy topology, runs only migration verification,
  then repeats the fixed PaaS/Audit probe. Exact `fa303a4` passed generation
  drift, full unit/vet/race, focused ten-run, four-target build, and diff gates.
  Its Linux/amd64 `mx` ran in the existing network-disabled A7 namespace: two
  status calls returned `READY` with an unchanged journal, verify returned
  `READY` without changing the release pointer, and an outer DinD restart
  preserved the journal while all nine signed Compose services recovered
  healthy before post-restart status and verify.
- Commit `fbfe4bf` adds durable protected backup and sanitized support
  evidence. Backup binds a generated identity into the sealed command,
  reauthenticates the current release and topology, verifies all three owning
  schemas, streams and verifies a bounded PostgreSQL custom dump, archives only
  immutable workload Secret versions, and seals exact artifact commitments
  with an installation-private HMAC key. Support binds only an output-path
  digest into the journal and emits normalized release, component, image, and
  schema evidence without paths, logs, configuration, database rows, or
  Secrets. Exact `fbfe4bf` passed generation drift, full unit/vet/race,
  focused ten-run Linux and host repetition, four-target builds, and diff
  gates. Its exact Linux/amd64 `mx` created a protected backup and `0600`
  support evidence in the external-network-disabled A7 namespace; value-level
  scans against every installed Secret and the installation path passed, and
  subsequent status/verify remained `READY` with all nine services healthy.
- Exact commit `0c305a0` passed generation drift, full unit/vet/race,
  release-verification ten-run repetition, architecture, four-target build,
  and repository-diff gates. Signed Release B
  `matrix-v0.2.0-0c305a03e725` upgraded the existing external-network-disabled
  Release A namespace to `READY` through the authenticated immediate-predecessor
  and protected-backup path. All nine platform services ran the B identities;
  the verification Deployment advanced from generation 1 to generation 2 and
  remained `READY`; both DEPLOY and UPDATE Audit outbox facts were delivered;
  immutable A and B revisions remained present; repeated status and verify
  succeeded; and the PostgreSQL data directory identity was unchanged. Before
  the correction, exact signed candidate `matrix-v0.2.0-cb7da457d2ad` reached
  the VERIFYING phase, failed definitively, automatically restored all nine A
  services, kept the A pointer and existing workload identity, and left
  status/verify `READY` without changing the PostgreSQL data directory identity.

## Next concrete work

1. Implement explicit N-1 rollback from B to A without discarding expanded
   data, followed by protected backup recovery.
2. Run the complete external-network-disabled Compose install, repeated
   operations, upgrade, automatic and explicit rollback, recovery, and support
   E2E required for FEAT-005 Gate B/C and FEAT-006 Gate C.

## Fixed donor baselines

- Legacy PaaS: `69336e51f94fa98f6aa278fa4c62382e224dbeaf`
- Senatria IAM/Audit foundation:
  `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d`
- PaaS design: `338d9b5fcb820120c32265e380c55e5f171cdb75`

Replace this file only at a committed-and-pushed milestone or handoff. Do not
append command logs, chat transcripts, secrets, raw provider payloads, or
machine-local paths.
