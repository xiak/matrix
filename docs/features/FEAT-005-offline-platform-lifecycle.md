# FEAT-005: Offline platform distribution and lifecycle

- Status: Phase 1 accepted; Phase 3 authentication recovery extension accepted for the exact signed A/B test pair
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
does not own the restore algorithm. Phase 1 recovery may target the current
release or its exact signed immediate predecessor. A cross-profile recovery is
admitted only for the explicitly supported predecessor-to-current upgrade
profile pair; it never admits a skipped or arbitrary downgrade, while direct
rollback remains equal-profile only. Backups remain installation-owned,
restrictive, sealed, and excluded from support evidence.

`verify` rechecks journal seals, current bundle content, loaded image identity,
Compose project membership, service health, schema compatibility, IAM
authorization, Audit ingestion/deduplication, and one no-secret application
probe. `status` is read-only. `support` emits only release IDs, component
health, normalized state, image/content digests, migration version, bounded
timestamps, and correlation IDs; it excludes secrets, tokens, configuration
values, database rows, native errors, arbitrary logs, and absolute paths.

## Phase 3 enterprise authentication recovery extension

Phase 3 adds installation custody for IAM TOTP wrapping keys without changing
the accepted Phase 1 lifecycle boundary. Installation generates a distinct
installation-scoped keyring once, binds it to the sealed bootstrap identity,
and mounts the exact read-only file only into IAM. The keyring, TOTP seeds,
password material and recovery capabilities never enter a signed release,
Audit event, support bundle, command output or ordinary backup manifest field.
An immutable per-key commitment may cross the boundary; a complete keyset
digest is inventory evidence only and cannot prove which keys a database
snapshot needs.

MFA is enabled through two exact signed releases. The preparation release owns
the key custody, database registry and runtime guards while leaving MFA
creation disabled. Its readiness, login, credential validation and Session
use paths all fail closed if they encounter MFA state they cannot enforce; a
health probe alone is not the security boundary. The enabling release is
admitted only from that exact predecessor and only after the predecessor's
database/function behavior has been verified. A schema number, equal version
tuple, manifest capability string or caller override cannot substitute for
that behavior. If a rollback binary cannot enforce existing MFA state, it
must remain unable to serve authentication rather than silently issue a weak
Session.

Each protected backup obtains TOTP custody and the PostgreSQL dump from one
read-only repeatable snapshot. A purpose-only IAM entry, reached through a
dedicated no-table-access identity, exports the snapshot, returns the bounded
sorted set of immutable key commitments required by every factor state that
still needs decryption, and holds that snapshot while the fixed lifecycle
invokes `pg_dump --snapshot`. Unknown key references or factor states fail the
backup. The sealed backup records only the non-secret required commitments
and their custody digest. Restore verifies that the current installation
keyring is a superset before changing the database, and IAM readiness verifies
the restored database needs again before authentication can start. The active
key alone, an independently timed query, or the current keyset digest is not
same-snapshot proof.

Destructive restore closes authentication before the first database effect.
The durable closed record binds the exact installation, command, backup and
custody digest plus the authenticated source and target signed release
manifests. It has no caller-selectable tenant or user and confers no permission
to reopen authentication. Reopening requires a separate purpose-limited IAM
transaction that matches that exact closed intent, advances the recovery
epoch, revokes restored Sessions, fences credential and TOTP replay state,
writes one immutable completion and succeeds exactly once. Changed or missing
evidence, an unknown outcome, a second command, a restored pre-completion
receipt, or a release/profile mismatch remains closed. Recovery never grants
a role, enables a tenant, transfers root ownership or exposes a wrapping key.

This extension is accepted only after the same committed source proves all of
the following in an externally disconnected, task-owned runtime:

1. a populated preparation release upgrades to the enabling release without
   changing installation identity, key commitments, tenants, roles or Audit
   history, while skipped and mismatched release pairs fail before effects;
2. real password, TOTP enrollment/challenge, Session and readiness paths fail
   closed under unknown keys, unknown factor states, missing custody and an
   attempted rollback that cannot enforce MFA;
3. a backup taken during concurrent factor creation/rotation either contains
   the exact same-snapshot requirement set or fails, and restore cannot begin
   with a missing or changed required key;
4. crash/resume around snapshot export, dump completion, closure, restore and
   reopen has one observable result and cannot authenticate from restored old
   Sessions or replay state; and
5. successful restore preserves usable authorized identities and factors,
   writes the closed Audit evidence, passes restart plus signed
   upgrade/rollback gates, and leaves Phase 2 and every remote host untouched.

The task-local signed preparation source `26dcb50b` publishes IAM 36, Audit
19, PaaS 6 and contract revision 14. Its sealed target has TOTP custody but
cannot create MFA; it rejects retained factors across all tenants before
reopening. Signed enabling source `ec701f54` publishes IAM 40, Audit 24, PaaS
6 and revision 15. Its exact predecessor is the preparation release, and it
owns the notification worker, purpose-only database login, mandatory
installation-owned email keyring and protected SMTP channel. A recovered
predecessor journal does not retain the successor-only mail commitment;
same-release recovery preserves it. Both sources passed local full Go tests,
vet and focused PostgreSQL 18 authentication-recovery integration gates,
including a restored snapshot whose epoch predates the authenticated closure
by more than one generation. The enabling source also passed independent
[Verification 35998187356](https://github.com/xiak/matrix/actions/runs/35998187356)
with successful Go, UI, authority-process and Linux node-process jobs.

The exact signed pair `matrix-v0.3.0-26dcb50bc7f5` →
`matrix-v0.4.0-ec701f54f1ce` passed a fresh, externally disconnected,
task-owned Docker 27.5.1 / PostgreSQL 18 lifecycle in 453.98 seconds, then
passed the post-engine-restart gate in 15.10 seconds. The run covered
populated A installation, real applications and Audit history, original
platform-credential recovery without runtime restart, failure-injected
cross-profile upgrade with authenticated recovery, retained-data B upgrade,
delivered TLS mail and first TOTP enrollment, B backup/recovery with old
Session denial and factor retention, direct rollback refusal, recovery of
the earliest A backup after multiple recovery epochs, A-owned status/verify,
application rollback/stop, capacity release and bounded support output. The
isolated engine had no external network and used two CPU, four GiB memory and
task-owned data, Docker and release volumes; its container and volumes were
deleted after the restart gate. The signatures use a task-local test signer,
not a published production release key.

This sequential signed lifecycle alone does not prove concurrent factor
creation/rotation or every crash/resume point. The focused and interrupted
runtime gates below provide the additional evidence used in the final
acceptance reconciliation.

A focused PostgreSQL 18 process gate now holds an actual restricted backup
snapshot while an IAM HTTP enrollment creates a pending TOTP factor after
verified contact. The imported old dump has no factor references; the next
lease and imported dump require its original wrapping key. With that real
factor retained, a second held snapshot spans a real IAM process keyset
rotation; the old dump remains at revision 1 and the next snapshot requires
both old and new keys at revision 2. Additional revoked and pending reference
rows are opaque storage fixtures used only to test retention and closure
failures, not completed enrollment. This proves the concurrent creation and
rotation snapshot boundary, but not signed restore or every crash/resume
point above.

The Linux backup adapter gate also injects a partially written PostgreSQL
dump failure after snapshot export. It verifies the lease is aborted, no
partial or published backup remains, and retry with the same backup ID takes
a new snapshot and publishes an authenticated backup. This is a bounded
provider-failure/resume check, not a signed process-kill or restore-stage
crash claim.

The same task-local signed A/B pair passed a fresh disconnected lifecycle in
489.96 seconds. Before installing A, the actual signed B executable rejected
an attempted initial B installation with `INSTALL_RELEASE_HAS_PREDECESSOR`;
the installation root and Docker state remained empty. Five real installer
process kills then passed. The IAM helper's exported
PostgreSQL snapshot frame and the real `pg_dump --snapshot` process exit were
each withheld at a separate `BACKING_UP` intent. Replay kept each backup and
correlation ID, took a fresh snapshot lease, removed the unpublished partial
and published an authenticated backup. During same-release recovery, the
purpose-only IAM close and reopen containers each exited successfully while
their result was withheld from `mx`. Killing it after close left the original
`RECOVERING` command without a local closure file and denied the old bearer.
Between close and reopen, the real SQL restore consumer received its first six
statements; PostgreSQL reported an open, idle transaction after the four
schema operations. Killing `mx` ended that transaction without losing the
original IAM authorization decisions, and replay retained the command ID and
completed the restored archive. Killing it after reopen left the command in
`STARTING` with its closure file; replay completed without reviving the old
Session. First MFA enrollment, application data, Audit history and
cross-profile rollback refusal remained intact. After restarting only the
isolated local Docker engine and observing its daemon ready, the post-restart
gate passed on its first attempt in 14.50 seconds. The test-owned container,
volumes and transient test executable were deleted.
[Verification 36016699660](https://github.com/xiak/matrix/actions/runs/36016699660)
passed Go, UI, authority-process and node-process on the combined test source.
An earlier run of the preceding source failed the node-process generic
plaintext-storage assertion without identifying the matching input or table;
the subsequent test reports only a safe input index and table name if that
assertion recurs. Its cause is not established by the successful rerun. These
checks prove the exact signed negative install and five injected crash
boundaries; they are not a substitute for the concurrent-snapshot gate.

The same signed A/B pair then passed another fresh disconnected lifecycle on
source `c68a88475c298f58d5315c75fe6e0f9bb08a5f8b` in 481.60 seconds.
After a populated B backup, the test replaced only the isolated
installation's protected TOTP keyring with two individually valid keyrings:
one missing the backup-required key ID and one retaining that ID with changed
key material. Each real `mx recover` failed with
`RECOVERY_SOURCE_VERIFICATION_FAILED` before changing the sealed journal;
the original keyring was restored and the platform remained healthy. The
subsequent authenticated recovery, MFA login, five process-kill replay gates,
and post-engine-restart check (15.41 seconds) passed. Only the task-owned
local Docker engine was restarted; the exact test container, volumes and
transient executable were deleted afterward. This proves a signed restore
pre-effect denial for unavailable custody, not acceptance of arbitrary
keyring rotation or a historical N-1 release profile.
[Verification 36020911215](https://github.com/xiak/matrix/actions/runs/36020911215)
completed successfully for the exact source, with Go, UI,
authority-process and node-process jobs all passing.

On test source `c6a9563d624fb3c3d2c3771d9d004c44916313a5`, the same signed
A/B pair passed another fresh disconnected lifecycle in 486.82 seconds and
the post-engine-restart gate in 14.63 seconds. After the real B backup was
restored, the public installation-scoped Audit API returned exactly the
closed, reconciled and reopened IAM recovery facts for the original command:
SYSTEM actor, installation target, request/correlation identity, no tenant or
IAM decision. The platform integrity endpoint verified their complete chain.
This adds signed cross-service evidence to the earlier PostgreSQL outbox
checks.
The labeled local test container, its two volumes and the transient test
binary were deleted afterward.
[Verification 36024686653](https://github.com/xiak/matrix/actions/runs/36024686653)
completed successfully for the exact test source; Go, UI, authority-process
and node-process jobs all passed.

The same signed A/B pair passed a further disconnected lifecycle on test
source `201779db220b2150f1940c0441cfce261cd7ae7c` in 516.49 seconds and
the local-engine restart gate in 15.02 seconds. Two additional validly signed
successor packages kept B's source/profile/topology but declared either a
skipped v0.2 predecessor (`matrix-v0.2.0-000000000000`, manifest SHA-256
`3e2f1c51892de7659764c0dd7f269a7b11dbbcfed9edd6f5cf7bcecc3706aee0`)
or a different v0.3 predecessor (`matrix-v0.3.0-111111111111`, manifest
SHA-256 `c5f04a39368cd6eec65b84b4936dfdf0760bfdcdfdeb642f43784775ad6e1b0b`).
On a populated A installation, the real B `mx upgrade` rejected each package
with `UPGRADE_PREDECESSOR_MISMATCH`. The sealed journal, backup and release
directories, and Docker container/image/volume/network inventories were
unchanged; A's workload remained usable. The genuine signed B then upgraded
successfully and the rest of the MFA, recovery, Audit and application gates
passed. Only the task-owned local DIND container was restarted. Its container,
two volumes, transient binary and temporary source worktree were deleted.
The signatures are task-local test signatures, not a production trust root.
[Verification 36028868894](https://github.com/xiak/matrix/actions/runs/36028868894)
completed successfully for the exact test source; Go, UI, authority-process
and node-process jobs all passed.

On the same committed source (`201779db220b2150f1940c0441cfce261cd7ae7c`),
the focused PostgreSQL 18 process and custody gates were also run inside a
task-owned Docker network namespace with no external network. The real IAM
process, restricted backup helper, `pg_dump --snapshot` and imported dumps
proved that enrollment after a held snapshot is absent from that dump but
present with its key in the next lease; a rotation during another held
snapshot leaves the old dump at revision 1 while the next requires both keys
at revision 2. A separate real-database gate exercised password login,
existing Session, readiness, conflicting key registrations and retained
factor fail-closed behavior. Both focused tests passed. Their temporary
PostgreSQL container, database volume and combined Go/PostgreSQL test image
were removed after the run; no shared or remote resource was touched. The
actual-login/Session custody fence also passed with external networking
disabled for missing material, mismatched scope/revision/key/commitment,
unsupported factors and database unavailability.

Acceptance reconciliation: item 1 is proved by the populated signed A to B
upgrade and both signed wrong-predecessor pre-effect denials; item 2 by the
signed MFA and rollback paths together with the disconnected custody process,
database and login/Session gates; item 3 by the disconnected held-snapshot
creation/rotation test and signed missing/changed-key restore denials; item 4
by the five signed process-kill/replay points; and item 5 by signed recovery,
Audit integrity, engine restart and workload retention. The production code
under these test additions is byte-for-byte the fixed signed A/B pair. This
accepts the Phase 3 authentication recovery extension for that exact pair and
its task-local test signer only. It does not publish a production trust root,
admit an arbitrary predecessor or complete the separate IAM/PaaS release work.

## Phase 3 integrated release closure

The accepted host self-enrollment in [FEAT-008](FEAT-008-linux-host-management.md)
and the exact A/B authentication recovery extension above do not, separately,
prove one publishable release composition. The integrated gate remains open.
Its input must be a fixed, independently verified IAM/Audit source adapted to
the current PaaS and host owners, one exact database/function profile and
predecessor, and signed platform and node packages verified before effects.
Importing another branch's PaaS schema or accepting a matching version tuple
without function-shape proof is not a substitute.

The existing full offline gate now selects the current host-local enrollment
path only for an explicit private control-plane fixture and an adjacent signed
current node release pair; it preserves the legacy predecessor path only for
its original fixture. Focused and package-wide race tests prove selection and
wrong-pair rejection. The independent [Verification run 36037002499](https://github.com/xiak/matrix/actions/runs/36037002499)
completed successfully for exact `10a754f10b95c0b130b61fee0234826d7c1a52f6`
across go, UI, node-process and authority-process. This is test entry and
diagnostic coverage, not a two-host runtime pass.

Mutable Account security settings and factor replacement add a recovery fence.
Each new protected backup must seal a separate, non-secret authentication and
authorization state digest from the same PostgreSQL snapshot as `pg_dump`;
the TOTP key-custody commitment cannot stand in for that digest. It covers
durable Account/USER qualification, policy and role authority, factor lineage
and credential revocation, but not Session, one-time-code consumption or
notification delivery state that recovery fences separately. The source close
transaction compares its current projection with the selected backup's sealed
digest. A known mismatch rejects before authentication is closed or any
destructive provider/database effect; it cannot strand an otherwise running
installation behind a predictably incompatible older backup.
An earlier backup format without this commitment is not an empty matching
state: the integrated successor refuses its automatic identity restore before
effects. Historical decoding remains available for verification, but a
separate explicit migration/recovery path would need its own proof.
The predecessor may remain an admitted in-place upgrade source without being
an admitted automatic recovery source; the release recovery-profile function
must not infer restore permission from upgrade compatibility.

The close transaction reprojects the complete durable authentication and
authorization state, including Account status/root ownership/settings,
USER qualification and credential/factor lineage, role/policy authority and
platform-recovery eligibility. Its digest must equal the selected backup's
independent state commitment. It also captures one immutable, bounded snapshot
of the non-rollbackable MFA replay floor: the complete sorted Account/USER
identity set and each USER's factor identity, last consumed step and explicit
failure windows. Closure binds both digests and the snapshot count. The
installation durably seals the exact snapshot bytes outside the database
backup's rollback range before destructive restore. A lost close response can
retrieve only the original committed snapshot for the same intent, not sample
later state. The bounded replay snapshot is not a substitute for the full
state digest or a source of policy, role or platform-recovery authority.

The installation consumer at `4b3920fb` carries the sealed backup's state
digest into the recovery intent, validates the close envelope against the
locally sealed bootstrap scope, durably stores and rereads the exact replay
snapshot before publishing closure, and validates a read-only snapshot mount
before reconcile or reopen. Task-local Linux race tests prove retry after a
lost close result and reject missing, changed, truncated, oversized or
wrong-scope snapshots before launching the recovery container. Losing a
completed snapshot also blocks the next recovery epoch. This does not
establish the IAM producer transaction, enable v5 for
the current database profile, or complete the signed runtime gate.
[Verification 36049571005](https://github.com/xiak/matrix/actions/runs/36049571005)
passed Go, UI, authority-process and node-process for the exact supplemental
snapshot failure-gate source `8028738c`.

After restore, missing, changed or weaker evidence stays CLOSED. In
particular, an older backup's `requiredForUsers=false` or superseded TOTP
factor cannot silently replace a current requirement or factor. The first
slice is a fail-closed fence, not permission to rewrite old rows or mark a
principal `RECOVERY_REQUIRED` without a supported proof and re-enrollment
path; positive recovery requires its own verified policy. The earlier MFA
custody/closure ABI lacks this proof, so a schema/profile increment alone
cannot authorize the new signed recovery path.

The integrated recovery gate must prove these cases with real PostgreSQL and
the signed installation path, not only pure contract tests:

1. A backup at T0 followed by a stronger Account requirement, factor
   replacement or authorization revocation at T1 is rejected before journal,
   provider, database, credential or closure effects. Missing legacy state
   commitment has the same pre-effect refusal.
2. A matching committed backup restores the intended data while preserving
   current authentication qualification, OTP replay bounds, Audit history and
   the explicit closed/reconciled/reopened chain; old Sessions do not return.
   Four failed password attempts after the selected backup must still leave
   only the fifth attempt in the original window after restore; a second
   restore must not refund that budget or reset its sequence.
3. A lost close result replays the exact original receipt and snapshot. Missing,
   changed, truncated, oversized or incomplete protected snapshot material
   cannot advance restore or reopen, including after process interruption.
4. Capacity and transaction-time limits fail before a partial backup or a
   successful close is published; tests cover the accepted boundary and its
   first rejected successor without silently omitting Account or USER rows.

On that exact composition, a fresh task-owned offline run must use the
host-local one-time registration command on two independent test hosts while
exercising the platform-credential and MFA recovery paths, real workloads,
Operation and Audit delivery, retained host identity and resource samples,
upgrade/rollback and protected recovery. The authenticated browser ceremony
and independent CI remain separate required evidence; a process-only fixture
does not prove the console. Before and after each run, record the exact
pre-existing host Docker/systemd inventory and delete only resources proved
to belong to that run. Do not reboot a remote host or its Docker daemon, use
the 172.30.1.3 ZFS host, or touch Phase 2. A task-local signature proves the
offline mechanics but is not a production trust-root publication.

The native gate's one-time join transfer now attempts bounded, exact-path
secret cleanup even when the install context was canceled, and reports a
failed remote deletion for explicit follow-up. The Linux fake-SSH race gate
and [Verification 36053002247](https://github.com/xiak/matrix/actions/runs/36053002247)
passed for `397d5952`; this is test-resource safety evidence, not the final
combined signed release gate.

The authority-process fixture at `d078d456` serializes the actual copied
PostgreSQL host, port and database into each restricted runtime DSN, removing
query selectors that could silently route a restore test back to its source.
[Verification 36055308970](https://github.com/xiak/matrix/actions/runs/36055308970)
passed Go, UI, authority-process and node-process for that exact source. This
fixes test targeting; only the forthcoming populated v5 restore can prove the
new recovery behavior.

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
