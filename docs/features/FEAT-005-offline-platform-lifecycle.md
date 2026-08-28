# FEAT-005: Offline platform distribution and lifecycle

- Status: Accepted
- Target release: Private Application PaaS v0.1
- Target design date: 2026-08-25
- Release contract: accepted foundation `v1`; multi-tenant extension `v2` in progress

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
operator request. Backups remain installation-owned, restrictive, sealed, and
excluded from support evidence.

`verify` rechecks journal seals, current bundle content, loaded image identity,
Compose project membership, service health, schema compatibility, IAM
authorization, Audit ingestion/deduplication, and one no-secret application
probe. `status` is read-only. `support` emits only release IDs, component
health, normalized state, image/content digests, migration version, bounded
timestamps, and correlation IDs; it excludes secrets, tokens, configuration
values, database rows, native errors, arbitrary logs, and absolute paths.

## Incremental acceptance

### Multi-tenant authority-profile extension

The isolated IAM branch replaces the single migration number for new releases
with the signed manifest v2 database profile. Its code-owned composition is
IAM schema 3, Audit schema 2, PaaS schema 1, and `contractRevision=3`. This
revision adds credential-generation-bound sessions and the current-session
password-change policy to the tenant lifecycle/original-primary recovery and
exact seven-column IAM claim contract. It is not a request/configuration
selector. Real service readiness and the owning function/dispatcher gates must
prove the composition, rather than comparing three version numbers alone.
The revision-3 populated signed lifecycle is still pending; the earlier
revision-2 evidence below cannot accept the new session behavior.
The current code passes the full repository race/vet gates and the native Linux
backup/recovery boundary tests. The actual published installer still rejects
the new format, and both directions between the previous `2/2/1` revision 2
and current profile fail before journal or provider effects.

Upgrade and data-preserving rollback require exact equality of the complete
profile before journal advancement or provider effects. A larger number is
not compatibility: neither the previous `2/2/1` revision 2 nor a Phase 3
composition with PaaS schema 2 is compatible with this branch's `3/2/1`
revision 3. Building an old IAM executable and retaining its database during
a SQL migration proves that migration's failure-closed behavior, not a
supported cross-profile release upgrade or data-preserving rollback. Backup and
recovery bind their selected snapshot to its authenticated release's complete
profile. Recovery also requires current and target profiles to be identical,
in both the command boundary and each adapter phase before journal advancement,
service changes or data restoration. No force/override bypass is provided;
support reports the same non-secret profile.

The published v1 manifest and backup canonical bytes and signatures/seals stay
readable. This does not certify that an old executable can run new schemas,
that an old topology remains executable, or that a cross-profile upgrade is
supported. The existing gates must prove published-format preservation and
unsafe transition rejection, followed by real signed A/B releases with this
same complete profile, retained tenant/credential/resource/Audit state,
data-preserving rollback and selected-backup recovery. These new gates remain
separate from the accepted foundation evidence below and from FEAT-008's host
work.

The profile contract gates pass on this branch on 2026-08-27: unit/race and
architecture checks, native Linux backup/seal and all recovery-phase refusal
checks, and the actual published `c88a84f` installer rejecting the new signed
format before effects. The negative recovery test first demonstrates that an
authenticated old snapshot alone admitted a different current profile; both
command and adapter boundaries now reject that transition without changing
the journal, services, credentials, backup or data. The published v1 seal and
canonical bytes still round-trip unchanged. In new task-owned PostgreSQL 18
databases, the actual old IAM executable retained-account upgrade passes,
followed by the independent five-process race gate checking real runtime
logins, the `2/2/1` readiness tuple, the seven-column IAM claim contract and
the existing tenant/lifecycle/outbox matrices. These checks do not replace the
signed populated A/B offline lifecycle acceptance above.
Fixed implementation `b3a6f81450988d9759ce25163071338e89ed18c4` passes all
three [independent Verification jobs](https://github.com/xiak/matrix/actions/runs/33068851630).

The populated gate uses the existing `phase1e2e` owner. Before backup it opens
two tenants through IAM, changes each original primary's and same-named
child's initial password, and creates same-ID applications/configurations and
independent quota with their original child actor/Operation/Audit identities.
One child loses its role and session; the other is disabled, its tenant is
paused, and only that tenant's original primary credential is recovered.
Failed upgrade, successful A/B upgrade, rollback, selected-backup recovery and
engine restart must preserve those states, values and pre-backup Audit hashes.
A resource written after upgrade must survive rollback but disappear on
restoring the earlier snapshot. Only explicit tenant/member resume may restore
access; the recovered original primary must replace its password, old sessions
must remain invalid and platform permissions must remain absent. Each installed
stage must match its signed profile in real readiness/verification and support
evidence.

The revision-3 gate also carries a valid session explicitly retained by an
ordinary password change across signed upgrade, rollback, selected-backup
recovery and process restart. Other initial-password sessions remain denied
after forced replacement, including when false was submitted. Tenant pause
must revoke even an otherwise retained valid session. These sessions are
generated through the actual installed IAM HTTP API, not inserted fixtures.

These populated gates pass on 2026-08-27 using signed Release A
`matrix-v0.1.0-b3a6f8145098` and Release B `matrix-v0.2.0-b3a6f8145098`, both
assembled from fixed implementation `b3a6f81450988d9759ce25163071338e89ed18c4`
with the exact `2/2/1` revision 2 profile. A new task-owned Linux Docker 27.5.1
host, limited to two CPUs and 4 GiB with external networking disabled, starts
with no inner images, containers or volumes. The 340.83-second real gate
installs PostgreSQL 18 and all nine platform services, completes the populated
tenant baseline and both tenant/installation Audit delivery, verifies two real
application generations, failed-candidate rollback, successful B upgrade,
data-preserving rollback, selected-backup recovery, application rollback/stop,
capacity release and bounded support evidence. The post-upgrade tenant resource
and Operation survive rollback and are absent after restoring the earlier
snapshot. No revoked role/session or disabled user/tenant is revived.

Restarting the entire owned Docker engine then passes the 20.01-second second
gate. The original primary recovery is still bound to its original tenant and
USER; explicit tenant resume and the required password change restore its
tenant administration without platform permission. The child remains disabled
until explicitly enabled, retains its changed password, and cannot reuse its
old session. Tenant and platform Audit hashes/chains, configuration values,
quota and original resource/Operation ownership survive. Actual installed
readiness and repeated migration/function verification match the signed
profile, including the seven-column IAM claim; support reports that same
profile without credentials or configuration values.

The releases have distinct release/image identities but share fixed production
source. This proves the complete same-profile lifecycle, not a cross-profile
or historical-binary N-1 runtime transition. Those unsupported transitions
continue to fail closed. Browser acceptance of the installed release remains
owned by FEAT-007. The gate's negative HTTP client also checks the proper
`application/problem+json` contract, so expected authentication and access
denials are not mistaken for malformed success responses.

The installed-browser follow-up also assembles signed Release C
`matrix-v0.3.0-464910f0df23` from fixed source
`464910f0df23d79264fb59b35324a915a8a21335`, declaring A as its predecessor and
the same complete `2/2/1` revision 2 profile. Signed Release D
`matrix-v0.4.0-a36cf9817f52`, fixed source
`a36cf9817f522549b995ea9c1f0d873499b4fe62`, declares C as its predecessor with
that same complete profile. An actual protected backup, A-to-C and C-to-D
upgrades, and subsequent `mx platform verify` succeed on the populated owned
installation. These source changes are confined to console rendering/tests,
embedded assets and evidence; they are not evidence for an arbitrary
schema-changing or cross-profile N-1 upgrade. FEAT-007 owns the installed
browser and preserved workload observations. The browser's task-owned
loopback network is attached only after the network-disabled offline gates;
it is not presented as part of their offline-network proof.

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
