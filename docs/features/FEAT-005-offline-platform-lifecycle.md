# FEAT-005: Offline platform distribution and lifecycle

- Status: Accepted
- Target release: Private Application PaaS v0.1
- Target design date: 2026-08-25
- Release contract version: `v1`

## Outcome

Deliver Matrix as an authenticated, content-addressed offline bundle that an
operator can install, verify, operate, upgrade, roll back, and recover with the
single `mx` CLI. A clean supported host with Docker Engine and Docker Compose
already installed must reach the accepted Application PaaS vertical slice
without a registry or Internet connection.

This target is fixed before FEAT-005 donor inspection. Donor code may change
implementation tactics only through a recorded adoption decision.

## Supported Phase 1 profile

1. The installed platform target is Linux/amd64 on one Docker Engine. The
   release builder and acceptance driver may run on another operating system.
   Multi-node control planes, remote Docker, Kubernetes, and installation of
   the Docker daemon itself are outside v0.1.
2. The customer supplies a supported Docker Engine and Compose plugin. Matrix
   performs read-only preflight and never changes daemon configuration,
   firewall policy, system package repositories, or unrelated Docker objects.
3. One validated absolute installation root owns releases, generated platform
   configuration, exact secret files, backups, journals, and sanitized support
   evidence. Matrix rejects a volume root, links or reparse points, unsafe
   permissions, traversal, and objects it does not own.
4. Product lifecycle orchestration is Go. Fixed Docker/Compose and PostgreSQL
   backup calls are external provider effects; Python, shell orchestration,
   mutable hooks, and bundle-supplied commands are not product dependencies.
5. Phase 1 supports a fresh install and rollback to exactly the previous
   accepted platform release. Skipping releases, arbitrary downgrade, and
   uninstall are not admitted.

## Release inventory and ownership

An accepted bundle contains the exact immutable payloads required by
[`ADR-0002`](../architecture/ADR-0002-product-boundary.md):

- the `mx` Linux/amd64 executable and internal Matrix service executables;
- independently runnable IAM and Audit authorities;
- the PaaS HTTP control plane, Operation worker, Audit dispatcher, and Compose
  DeploymentExecutor;
- APISIX as the northbound gateway and an independent PaaS UI;
- PostgreSQL and every other approved third-party runtime image;
- generated-at-install Compose input owned by Matrix, migration assets, and
  non-secret verification metadata.

This FEAT owns distribution and lifecycle integration, not the internal IAM,
Audit, apphosting, gateway, or UI business models. Their owning contracts must
be accepted before a release can consume them. A health-only placeholder,
test-only authority, caller-trusted tenant header, in-process Audit sink, or
mock image cannot satisfy the release inventory.

Only `mx` is user-facing. Internal service entry points may be separate
executables or fixed modes of one immutable image, but IAM and Audit remain
independently deployable authorities and PaaS reaches them through their
accepted ports.

## Authenticated bundle contract

The bundle is a regular-file-only directory or archive with one canonical
manifest and detached Ed25519 signature. The manifest contains:

- schema version, release ID, semantic version, build identity, creation time,
  supported host profile, and signer key ID;
- every payload's relative path, media type, byte length, and SHA-256 digest;
- every platform image's logical component, immutable Docker image ID or OCI
  digest, archive payload, architecture, and required health contract;
- migration compatibility, previous-release constraint, minimum free space,
  and required Docker/Compose capabilities;
- the digest of the closed platform topology description from which Matrix
  generates Compose input.

Paths are normalized UTF-8 slash paths with no absolute form, empty component,
dot segment, duplicate, link, device, or case-fold collision. The manifest
cannot name itself, its signature, arbitrary hooks, environment files,
credentials, or caller-provided Compose/YAML.

The invoking bootstrap `mx` executable and public trust root are obtained and
verified through an authenticated out-of-band channel. `mx` verifies the
bundle signature before first installation, then pins the trusted key identity
in the installation journal. Upgrade cannot replace that trust root. Key
rotation requires a separately accepted contract and is deferred.

File digests, lengths, executable identity, image archive digest, loaded image
identity, and topology digest are all checked before an effect. Tags, archive
filenames, Docker load output, and directory presence are never authority.
Secrets, private signing keys, credentials, database contents, and absolute
host paths are absent from the bundle manifest.

## Installation state machine

`mx` holds one cross-process installation lock and persists an atomic,
fsynced, sealed journal before and after every external effect. The explicit
states are preflight, staging, image loading, configuration, database
migration, platform start, verification, commit, rollback, recovery, and
manual intervention. Equal command replay resumes or returns the stored
result; a changed bundle under the same command identity conflicts.

Install performs:

1. offline manifest/signature/content verification and host preflight;
2. collision checks against the installation root, ports, project name,
   platform networks, volumes, and already-loaded image identities;
3. restrictive generation of installation identity, database credentials,
   service credentials, and bootstrap IAM material without printing secrets;
4. exact image loading and post-load identity verification;
5. database initialization and forward migration through the owning Go
   migration boundary;
6. generation of a closed Compose document with immutable images,
   `pull_policy: never`, no build, bounded resources, internal control/web
   networks, one fixed APISIX-only edge network as the sole non-internal
   network, read-only exact secret files, exact installation-root mounts, the
   fixed Docker Engine socket needed by the worker, and one validated
   northbound listener;
7. detached non-interactive start, component health verification, IAM-backed
   authorization, Audit ingestion, and an Application PaaS smoke Deployment;
8. atomic commit of the current release only after every verification passes.

An uncertain Docker or database effect is observed before retry. A failed
fresh install removes only objects proved to belong to its uncommitted
installation identity and retains a sanitized journal for diagnosis.

## Operations, upgrade, rollback, and recovery

The stable command tree is:

- `mx platform install --bundle <path> --root <path> --trust-key <path>`;
- `mx platform verify --root <path>`;
- `mx platform status --root <path>`;
- `mx platform backup --root <path>`;
- `mx platform upgrade --bundle <path> --root <path>`;
- `mx platform rollback --root <path>`;
- `mx platform recover --root <path> --backup <id>`;
- `mx platform support --root <path> --output <path>`.

Commands use Cobra/pflag, injected streams, context cancellation, stable exit
classes, and `--format human|json`. Subcommands return errors and never call
`os.Exit`. JSON output is versioned and contains normalized failures rather
than native Docker, PostgreSQL, IAM, or Audit payloads.

The machine-output API is `cli.matrix.xiak.com/v1`. Success uses
`PlatformCommandResult`; failure uses `PlatformCommandFailure` with only a
normalized class, code, and class-owned message. The process exit contract is:

| Exit | Class |
| ---: | --- |
| `0` | Success |
| `2` | Invalid command input |
| `3` | Lifecycle precondition failed |
| `4` | Stored state or command conflict |
| `5` | Verification failed |
| `6` | Required dependency unavailable |
| `70` | Internal failure |
| `130` | Context interruption |

Every upgrade first verifies the new bundle, proves its declared immediate
predecessor equals the current release, creates and verifies a protected
backup, and stages new images/configuration without changing the current
pointer. Phase 1 database changes are expand/contract and must remain readable
by both current and previous binaries. Only after migration, start, health,
authorization, Audit, data, and application-execution verification succeed is
the new release committed.

Failed upgrade automatically restores the previous Compose release and leaves
the current pointer unchanged. Explicit rollback returns to that immediate
previous release without discarding data written after upgrade; the previous
binary must pass verification against the expanded schema. Recovery is the
separate destructive path that restores a selected verified backup after an
operator request. The recovery engine comes from an authenticated, supported
operator bundle compatible with the installation profile; the selected backup
alone determines the authenticated target release. A historical target binary
does not own the restore algorithm. Backups remain installation-owned,
restrictive, sealed, and excluded from support evidence.

`verify` rechecks journal seals, current bundle content, loaded image identity,
Compose project membership, service health, schema compatibility, IAM
authorization, Audit ingestion/deduplication, and one no-secret application
probe. `status` is read-only. `support` emits only release IDs, component
health, normalized state, image/content digests, migration version, bounded
timestamps, and correlation IDs; it excludes secrets, tokens, configuration
values, database rows, native errors, arbitrary logs, and absolute paths.

## Incremental acceptance

### Gate A: release and CLI contract

1. Canonical manifest/signature verification rejects byte, path, metadata,
   signer, architecture, duplicate, case-fold, and image-identity tampering.
2. The installation state machine, exact replay/conflict rules, stable JSON
   output, exit classes, and `mx platform` command surface pass unit and
   architecture tests.
3. The platform topology compiler admits only the fixed release inventory and
   cannot express pull, build, bundle-supplied command, a path outside the
   validated installation root and fixed Docker socket, plaintext secret,
   privileged mode, or an unrelated Docker object.

### Gate B: real lifecycle behavior

1. A real bundle installs from an empty root using only bundle image archives;
   apply-twice, verify, status, backup, interrupted-effect recovery, and
   ownership-conflict tests pass.
2. The installed gateway, IAM, Audit, PostgreSQL, PaaS API/worker, UI, and
   Compose executor satisfy their real health and cross-service contracts.
3. Upgrade to a distinct release preserves identity, Audit history,
   application desired/observed state, secrets, and data. Injected upgrade
   failure returns to the previous healthy release without committing it.
4. Explicit N-1 rollback keeps post-upgrade compatible data; verified backup
   recovery restores the selected snapshot and cannot target another
   installation.

### Gate C: clean offline release E2E

1. Acceptance starts with an empty installation root and a disposable Docker
   namespace containing none of the release images or Matrix objects, then
   disables external network access for installation and lifecycle commands.
2. Release A installs without registry, pull, build, package manager, or
   Internet access. Through APISIX and real IAM, the test creates immutable
   configuration/application revisions, deploys a digest fixture, verifies
   ENV/secret/network behavior and Audit, changes configuration, and observes
   the new generation.
3. Release B upgrades from A and preserves the running application and durable
   history. A failed candidate proves automatic rollback; explicit platform
   rollback returns to A; application rollback restores its earlier
   configuration; stop removes its project and releases capacity.
4. Backup recovery, repeated verify/status, restart, bounded support evidence,
   and zero secret/native/path leakage pass before cleanup.

Common generation-drift, unit, vet, race, repeated, schema, architecture,
real-PostgreSQL, real-Compose, cross-platform build, Markdown-link, stale-term,
donor-dependency, tenant-authority, and `git diff --check` gates must pass on
the same committed worktree. Tests assert behavior and security invariants,
not archive layout, Compose text, SQL text, command call order, or line counts.

## Implementation evidence

- Gate A's accepted implementation authenticates a strict canonical Ed25519
  manifest and every regular-file payload, pins signer and content identity in
  a sealed replay-safe journal, exposes only the alias-free `mx platform`
  command tree, and compiles a content-hashed closed topology that cannot
  express online pulls, builds, arbitrary commands, plaintext secrets,
  unrelated Docker objects, or paths outside the installation boundary.
- Gate B's accepted implementation packages the real PostgreSQL, APISIX, IAM,
  Audit, IAM Audit dispatcher, PaaS API, PaaS Audit dispatcher, Operation
  worker, UI, and signed verification workload. Go owns install, migration,
  readiness, verification, backup, support, upgrade, rollback, recovery, and
  unknown-outcome observation. The worker composes PostgreSQL lease/fencing,
  placement, immutable artifact/Secret resolution, and the real Compose
  executor without a legacy, Python, shell-orchestration, or donor dependency.
- Exact accepted runtime source
  `c88a84f379afcf94431e2aca7332fe6ec3136dc7` assembled compatible signed
  Release A `matrix-v0.1.0-c88a84f379af` and Release B
  `matrix-v0.2.0-c88a84f379af`. Their six Matrix-built image identities are
  distinct while the fixed PostgreSQL identity remains immutable, and B names
  A as its immediate predecessor.
- Gate C ran those exact releases in a fresh privileged Docker-in-Docker host
  whose outer network mode was `none`. Inner Docker 27.5.1 and Compose v2.33.0
  began with zero containers, images, and volumes, loaded all seven signed
  images from the bundles, and installed A from an empty root without a
  registry, pull, build, package manager, or Internet access.
- Through the real APISIX edge, IAM authenticated and authorized a user,
  immutable application/configuration revisions produced generations 1 and 2,
  the signed workload proved ENV, read-only Secret, and network behavior, and
  both IAM and PaaS facts reached the queryable integrity-verified Audit
  authority. A deliberately failed B candidate automatically restored A; a
  successful B upgrade preserved state; explicit platform rollback returned to
  A; protected-backup recovery restored the selected coherent snapshot;
  application rollback produced generation 3; and stop produced generation 4,
  removed the workload project, and released capacity.
- Repeated status/verify, restrictive backup and support artifacts, and
  value-level Secret plus native-error, path, and backup leakage scans passed.
  Restarting the entire outer Docker-in-Docker container preserved the sealed
  installation and recovered all nine platform services healthy; post-restart
  status/verify completed the offline lifecycle.
- The exact source passed deterministic generation with no tracked drift,
  `go mod verify`, full unit/vet/race suites, architecture tests, ten-run
  critical-package repetition, placement fuzzing, clean PostgreSQL 18
  migration/IAM/Audit/PaaS/authority-process race gates, real Compose adapter
  and PostgreSQL-to-Compose worker gates, CGO-disabled Windows/amd64,
  Linux/amd64, Linux/arm64, and Darwin/arm64 builds, Markdown links,
  stale-brand and machine-path scans, donor-dependency and tenant-authority
  checks, and `git diff --check`. The fixed donor commits and every adoption
  decision remain owned by the FEAT-005 adoption record.

## Deferred

Docker installation, multi-node control plane, high availability, remote
Docker, Kubernetes, online registry installation, air-gap media splitting,
delta bundles, arbitrary downgrade, trust-root rotation, automatic uninstall,
stateful tenant volumes, and more than one previous platform rollback remain
outside Phase 1.

Relevant costly boundaries are owned by
[`ADR-0001`](../architecture/ADR-0001-repository-layout.md),
[`ADR-0002`](../architecture/ADR-0002-product-boundary.md), and
[`ADR-0003`](../architecture/ADR-0003-command-line.md). Fixed donor decisions
are owned by the
[`FEAT-005 adoption review`](../adoption/FEAT-005-offline-platform-lifecycle.md).
