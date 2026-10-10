# FEAT-005: Offline platform distribution and lifecycle

- Status: Accepted foundation; current source profile is IAM/Audit/PaaS `82/37/3+r30`. This slice has locally verified the signed additional-product Profile transport and isolated migration mount; the full current-profile offline lifecycle and exact-source independent CI remain required
- Target release: Private Application PaaS v0.1
- Target design date: 2026-08-25
- Release contract: accepted foundation `v1`; current candidates use manifest `v2` and are admitted only when the complete authority tuple and contract revision match. The current source is exactly `82/37/3` revision 30; earlier accepted slices remain historical evidence, not an alternate current profile

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
  non-secret verification metadata;
- the canonical IAM additional-product Profile catalog consumed only by the
  one-shot IAM migration boundary.

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

The current manifest also requires one fixed
`config/iam/authorization-profiles.json` payload. The release builder validates
and canonicalizes the repository-owned additional-product catalog before any
image build, then signs its exact path, media type, length and digest with the
rest of the bundle. Installation re-verifies the staged bundle and mounts this
file read-only only into the one-shot IAM migration process; no resident API,
worker, verifier or other authority receives it. The catalog cannot replace a
Matrix built-in product, invent built-in history, register a service identity,
attach a Policy or grant Account access. The release builder rejects
non-canonical or unsupported content before build effects; installation rejects
a missing or changed signed payload before provider effects; the one-shot
migration revalidates catalog semantics before database effects. The IAM FEAT
owns declaration/evolution semantics; this FEAT owns signed transport and
installation isolation.

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

The current recovery contract closes authentication before a destructive
database restore and does not reopen it merely because PostgreSQL is healthy.
Backup creation obtains one purpose-only IAM repeatable-read lease and binds
the database dump to its exact TOTP-custody commitment and complete
authentication-state digest. Recovery preflights the exact protected intent
before journal advancement or provider effects, persists its source closure
and security snapshot outside the restored database, restores and migrates
while authentication remains closed, then reconciles and reopens only that
same snapshot. Missing, changed or uncertain evidence fails closed.

The installation journal carries a monotonic authentication-recovery epoch.
Only the exact successful terminal recovery transition may advance it;
ordinary journal writes, failed recovery, replay variants and response loss
cannot do so. Equal replay observes the original completion. This epoch is the
installation-owned non-rollback signal consumed by IAM access analysis after
a supported restore; it is not a substitute for the IAM closure, a caller
selector, a cross-profile compatibility permit or protection against a local
root rolling back every installation disk and key together.

`verify` rechecks journal seals, current bundle content, loaded image identity,
Compose project membership, service health, schema compatibility, IAM
authorization, Audit ingestion/deduplication, and one no-secret application
probe. `status` is read-only. `support` emits only release IDs, component
health, normalized state, image/content digests, migration version, bounded
timestamps, and correlation IDs; it excludes secrets, tokens, configuration
values, database rows, native errors, arbitrary logs, and absolute paths.

## Incremental acceptance

### Current IAM policy-completion lifecycle candidate

The fixed production source `8abbea36da422fdb758233b68221ad8139b00904`
assembled signed A=`matrix-v0.1.0-iam-r13.1-8abbea36da42` and immediate
B=`matrix-v0.1.0-iam-r13.2-8abbea36da42`. Both carry the identical IAM schema
66, Audit schema 35, PaaS schema 3 and `contractRevision=13`; the IAM
authorization Profile revision is 14. This candidate includes the immutable
policy-attachment completion/read contract used to resolve an uncertain write
response without repeating a different mutation.

The release builder now distinguishes two image identities that Docker exposes
for different purposes. A base dependency is admitted only when inspection
contains the exact expected repository manifest digest, and every generated
Dockerfile uses the digest-qualified reference. The bundle archive and release
manifest continue to authenticate the actual portable config image ID returned
by save/load. A local `.Id` can no longer be compared with a registry manifest
digest, a mutable tag cannot substitute for the pinned reference, and the
PostgreSQL archive records its inspected config identity rather than a constant
named after the registry digest. Missing, malformed, foreign-repository or
wrong-digest metadata fails before build effects. Focused race/vet,
architecture and an opt-in real Docker 27.5.1 inspection gate passed before
the signed releases were assembled.

A fresh task-owned Docker 27.5.1 classic-image-store engine began with zero
inner images, containers and volumes. Its outer network mode was `none`; the
outer container had no default route, was limited to 2 CPUs, 4 GiB and 768
PIDs, and no host, shared engine or remote service was restarted. The private
SMTP input was created with the production codec and was not included in either
bundle. Its task-only Postfix 3.10.13 fixture first passed certificate-name
verification, authenticated STARTTLS/SASL submission, real Maildir receipt,
bad-credential rejection and external-relay rejection. The fixture archive is
exactly
`sha256:61d6532dfba0e1ab7f8ef6a1122f41696f1a93f4e3258bad179af3b1e84ff924`
and its classic portable config image identity is
`sha256:ddaa1e5a8ebc3363614646a452761593a7418c22a795ebd21a3bc82332867eb9`.
It proves only this isolated local SMTP/Maildir path, not Internet delivery or
recipient reading.

The effectful `TestOfflinePhase1Lifecycle` gate passed in 609.38 seconds. It
installed A from the empty namespace, verified status/readiness and restricted
database identities, exercised IAM through APISIX, retained two accounts and
their primary/member revocation state, verified the notification contact,
bound TOTP and completed a fresh MFA login with a real security notice, applied
an explicit access-analyzer disposition, created two application generations,
verified tenant and installation Audit chains, created a protected backup,
proved failed-candidate automatic rollback, upgraded to B, explicitly rolled
back to A, restored the selected backup with session reissuance, rolled back
and stopped the application with capacity release, and produced bounded
zero-secret support evidence.

After that gate, the operator-private SMTP input was removed from the runtime
state. Only the exact task-owned outer engine was stopped and started; its
identity, persistent Docker volume, installation state volume, `network=none`
boundary and Docker 27.5.1 daemon were rechecked. The read-only after-restart
gate then passed in 68.40 seconds: a fresh MFA login succeeded, both accounts'
primary/recovery/revocation state remained exact, status/verify succeeded and
the complete offline lifecycle marker was present. This is local signed-runtime
evidence for the exact source and profile. The independent CI for that source
must still complete successfully before this candidate is recorded as the
accepted current combination; it does not admit another profile, Docker image
store, arbitrary N-1 binary or cross-profile recovery.

The Linux-created delivery archives were then re-extracted in the same
network-disabled engine and compared by complete path set, per-file SHA-256 and
Unix mode; directories are `0700`, `bin/mx` is `0700`, every other payload is
`0600`, and no link is present. The copies streamed back to the workspace have
the same engine-side hashes:

- A `matrix-v0.1.0-iam-r13.1-8abbea36da42-linux-amd64.tar.gz`:
  `e186ad906cf087ff7f109916221f82bb530f1d65d81384fc03ba7fd71734662b`;
- B `matrix-v0.1.0-iam-r13.2-8abbea36da42-linux-amd64.tar.gz`:
  `f7de52d6d9ea93996f7bbe10ff3ccfb4ad9c9ecf40a412da2df84800920afca9`;
- public `release-trust.json`:
  `af23e4b4ecf998169e28d5c4b43a58d4127fc68aa5f4068b80a3162ae8b44a6a`.

The archives contain only the signed release directory. The public trust file
is separate; the signing key, SMTP configuration, fixture private material and
installation state are absent.

### Current IAM authentication-recovery lifecycle candidate

The source candidate uses IAM schema 64, Audit schema 34, PaaS schema 3 and
`contractRevision=11`. Revision 11 identifies the exact backup wire v3,
purpose-only backup-custody and authentication-recovery entry points,
protected closure/security-snapshot files, complete recovery intent and
monotonic installation epoch. It does not admit an earlier backup wire,
another authority tuple or another revision for recovery. Historical v1/v2
backup metadata remains bounded and decodable for diagnosis, but current
recovery rejects it before destructive effects.

The exact product source `ddac6992c60ea267e8b2992b05de4487c14314f5`
assembled signed A=`matrix-v0.1.0-iam-r11.1-ddac6992c60e` and immediate
B=`matrix-v0.1.0-iam-r11.2-ddac6992c60e`, both with the identical
`64/34/3+r11` profile and topology digest. A task-owned, network-none Docker
27.5.1 engine limited to 2 CPUs, 4 GiB and 768 PIDs completed the 553.71-second
pre-restart lifecycle: fresh A installation, actual restricted PostgreSQL
roles, IAM and tenant paths through APISIX, TOTP and real SMTP/Maildir receipt,
access analysis, two application generations, Audit chain verification,
protected backup, failed-candidate automatic rollback, B upgrade, explicit
platform rollback and selected-backup recovery. Recovery restored the
backup-owned application, IAM, Audit and security state; removed post-backup
state; advanced the installation recovery epoch; and required fresh password
or TOTP authentication because every pre-recovery USER/Role Session was
revoked. Normal same-profile upgrade and data-preserving rollback continued to
retain valid sessions. The gate did not infer either behavior from service
health or database timestamps.

Only that task-owned nested engine was stopped and started. Its persistent
Docker, installation and runtime volumes then completed the 68.84-second
post-restart gate, including fresh MFA login, retained tenant primary recovery
and revocation state, status/verify/support and the complete offline lifecycle.
No shared engine, remote host or another Phase resource was restarted. The
SMTP fixture was a task-only archive with SHA-256
`e90419f560f9b484dd5125961e097b54ec98adb48e8660a5f7c5fd516e88abb6`
and portable image ID
`sha256:2976d5e49e940f05f720969403d1cf6531892b4816c0be4ccca403b554f50732`;
it proves the configured local delivery path, not an external provider SLA or
recipient reading the message.

This is accepted signed-runtime evidence for the exact production source and
test contract. The assertion and runtime-gate correction is fixed at
`ed2835db362de0a4a1ef3ca9145ee56801ae2436`; its
[Verification 37144670484](https://github.com/xiak/matrix/actions/runs/37144670484)
completed successfully with all 15 jobs, including both recovery-storage and
recovery-window lanes, the complete authority-runtime lane and the final
authority-process summary. Revision 11 is therefore accepted for this exact
IAM authentication-recovery lifecycle slice. It does not admit revision 10,
another authority profile, an earlier backup wire, arbitrary host-level
snapshot rollback, or imply acceptance of the entire IAM release and LIVE UI.

The first assertion-only follow-up `08600d4faecf4244c3c6fcfe183e32dc3eca4fad`
did not pass [Verification 37139124479](https://github.com/xiak/matrix/actions/runs/37139124479):
the Ubuntu installation unit gate still modelled the pre-v3 backup fake and
therefore omitted the real purpose-only custody/recovery subprocess contract.
That failure does not invalidate the signed-runtime execution above, but it
does prevent accepting the follow-up commit. The current correction keeps the
production contract unchanged, makes the existing Linux local-machine owner
verify the exact isolated container arguments, private mounts, canonical
lease/release frame, closure/snapshot consumption and one-shot recovery
receipt, and proves an equal backup replay neither streams PostgreSQL nor
acquires custody a second time. The focused Linux Go 1.26.5 container gate
(`network=none`, 2 CPUs, 2 GiB, 256 PIDs) passed installation/release vet and
race; the full Windows-host repository vet and race suites also passed. The
same correction is contained in the independently successful `ed2835db`
verification above; the failed `08600d4f` run remains a failed historical
attempt and is not backfilled.

### Signed IAM security-report precursor

The fixed security-report candidate used IAM schema 61, Audit schema 31, PaaS
schema 3, and `contractRevision=6`. Revision 6 identifies the
exact AccountSecurityReport API, storage, Audit action and installed consumer
shape at that fixed source; it is not a caller option or an
ordering claim over another branch's profile. A bundle with any different
authority tuple or revision remains incompatible and must be rejected before
journal advancement, service changes, backup creation or another provider
effect.

The existing `phase1e2e` owner requires Release A to generate, read and
download one unexpired AccountSecurityReport and to observe both its created
and download-started Audit facts before the protected backup. An exact receipt
replay, immutable JSON document and byte-identical CSV must survive the
same-profile Release B upgrade and data-preserving rollback. A second report
created on B must also survive rollback, while selected-backup recovery must
restore the first report and its receipt/Audit history and remove the
post-backup report.

The fixed source `67a2a19cf42f76cff7c24abddc830dd7bc093039` produced signed
Release A `matrix-v0.1.0-iam-report.5-67a2a19cf42f` and its immediate Release B
`matrix-v0.1.0-iam-report.6-67a2a19cf42f`, both with the exact `61/31/3`
revision 6 profile. The isolated, network-none Linux runtime passed install,
status/verify, the IAM user path through APISIX, tenant primary/member
revocation, two application generations, Audit query/chain integrity,
protected backup, failed-candidate automatic rollback, B upgrade, explicit
platform rollback, selected-backup recovery, support redaction and the
required task-owned engine restart. The post-restart status/verify and complete
offline lifecycle gate passed in 89.43 seconds. This is accepted local signed
runtime evidence; the candidate remains unaccepted as a release combination
until the exact source's independent Verification run completes successfully.

The earlier IAM 60 to 61 retained-data SQL gate proves only the rolling
development predecessor and does not authorize a signed `4/3/1` revision 4
installation to upgrade to this profile. No cross-profile upgrade, rollback or
backup recovery is admitted.

### Current IAM security-mail topology candidate

The current source profile is IAM schema 61, Audit schema 31, PaaS schema 3,
and `contractRevision=7`. Revision 7 owns the signed runtime topology and
credential ABI that add the purpose-only IAM notification dispatcher, its
independent database login, the installation-bound email-verification keyring
and SMTP channel, and a separate non-internal `mail-egress` network. Only the
notification dispatcher joins that network or receives the SMTP channel;
IAM API receives the email-verification keyring but not the channel, and no
Audit, PaaS, UI, verifier or ordinary worker receives either capability.

Install and upgrade take one operator-private canonical security-mail file.
The lifecycle journal stores only its digest. Installation derives the stored
channel scope from the sealed installation ID and canonical IAM bootstrap
digest, creates the keyring once, writes the keyring, channel and notification
database DSN as protected files, and rejects a changed digest, installation
scope or bootstrap scope. Equal replay preserves the exact stored bytes.
The signed IAM image remains a `scratch` runtime; its fixed multi-stage recipe
copies only the system CA bundle from the pinned Alpine base so a channel may
validate public roots without adding a shell or package manager to the runtime.
An explicitly configured private CA remains bound inside the protected channel.

Revision 6 is not an upgrade, rollback or recovery predecessor for revision 7.
The existing complete-profile admission rejects both directions before journal
advancement or lifecycle effects, and a revision-6 topology digest is not a
revision-7 release. Focused contract, lifecycle, journal, local-machine,
topology and release-build tests pass, including configuration substitution and
cross-installation attacks.

The exact signed product source `823a665e8d24b21c180134ab7893dc189d55599d`
assembled fresh revision-7 A/B releases and passed the full lifecycle in a new
network-none Docker 27.5.1 classic-image-store engine limited to 2 CPUs, 4 GiB
memory and 768 PIDs. The final 362.63-second gate proved real restricted PostgreSQL
process identities, install/status/verify, the APISIX IAM path, tenant primary
and member revocation, a purpose-only notification dispatcher, and the real
security-mail flow: start contact verification, authenticated STARTTLS/SASL
submission to a task-owned Postfix fixture, Maildir-only retrieval of the
eight-digit code, HTTP confirmation, and a second security notice that did not
contain the code or other protected values. It then passed two application
generations, Audit query/chain integrity, protected backup, failed-candidate
automatic rollback, B upgrade, explicit platform rollback, selected-backup
recovery, workload rollback/stop/capacity release and bounded support scans.
The verified notification contact's exact account, user, address, state,
resource version and verification time were re-read after the failed upgrade
rollback, B upgrade, explicit rollback and selected-backup recovery; the
private retained-state fixture was not written until that contact had been
verified. Missing or malformed retained contact state fails closed.
The fixture container and image were removed by the gate. Restarting only that
task-owned outer engine followed by the read-only retained-state/status/verify/
support gate re-read the same contact and passed in 16.88 seconds.

The current `phase1e2e` candidate reused those exact authenticated A/B bits and
extended the same owner with a real MFA consumer rather than changing the
release profile. A normal User verified its own notification address, bound a
TOTP factor from one-time provisioning, observed the old Session rejected,
waited for a fresh 30-second step, completed password plus TOTP login, and
received a separate `AUTHENTICATOR_BOUND` message through the restricted
dispatcher and Postfix/Maildir fixture. The 350.46-second lifecycle retained
the exact User, contact, factor state and MFA Session across failed-upgrade
rollback, B upgrade, explicit rollback and selected-backup recovery. After
restarting only the exact task-owned outer engine, a new password plus fresh
TOTP login and logout passed together with the retained-state/status/verify/
support checks in 16.53 seconds. Test-only seed and Session material remained
in a mode-0600 fixture outside both the signed bundle and installation backup,
were included in the support leakage deny-list, and were not printed. This is
local candidate evidence until its exact source passes independent CI; it does
not admit a new release profile, cross-profile transition or production SMTP
provider.

The fixture archive was authenticated as
`sha256:68960426f3d59e6a8732485cd13521b6618bc81b1abf46a6a057e1e4b6b29612`
and loaded to the classic Docker image identity
`sha256:c4a3d9c41ba180cb8748865badc712c909ffb6f4e2b09a4efde7c6aed76bd028`.
An earlier run correctly exposed a missing SASL runtime module in the fixture;
another exposed that successful `postfix status` writes to stderr and therefore
must be silenced inside the fixture rather than weakening the gate's global
no-stderr rule. Neither failure is counted as a pass.

Docker 29.6.2 with the containerd image store exposes the loaded OCI manifest
identity rather than the classic portable config identity authenticated by the
current signed release contract. The same bundles therefore fail closed at
image verification. This is an explicit unsupported runtime/store combination,
not a reason to loosen image identity or claim Docker 29 support. Independent
CI for the final evidence commit is still required before this revision-7
combination can be accepted.

### Historical multi-tenant authority-profile evidence

The earlier isolated IAM branch replaced the single migration number for new releases
with the signed manifest v2 database profile. Its code-owned composition is
IAM schema 3, Audit schema 2, PaaS schema 1, and `contractRevision=3`. This
revision adds credential-generation-bound sessions and the current-session
password-change policy to the tenant lifecycle/original-primary recovery and
exact seven-column IAM claim contract. It is not a request/configuration
selector. Real service readiness and the owning function/dispatcher gates must
prove the composition, rather than comparing three version numbers alone.
The revision-3 populated signed lifecycle passes from fixed implementation
`5721b7b1a985f25c9730ddb9229a51f7f6c3b63a`; earlier revision-2 evidence is not
used to accept the new session behavior. The same code passes full-repository
race/vet and native Linux backup/recovery boundary gates. The actual published
installer rejects the new format, and both directions between the previous
`2/2/1` revision 2 and current profile fail before journal or provider effects.

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
supported. The existing gates prove published-format preservation and unsafe
transition rejection, followed by real signed A/B releases with this same
complete profile, retained tenant/credential/resource/Audit state,
data-preserving rollback and selected-backup recovery. These gates remain
separate from the accepted foundation evidence below and from FEAT-008's host
work.

The profile contract gates pass on this branch on 2026-08-28: unit/race and
architecture checks, native Linux backup/seal and every recovery-phase
refusal, and the actual published `c88a84f` installer rejecting the new signed
format before effects. Command and adapter boundaries reject a different
current/target profile even with an authenticated target backup, without
changing the journal, services, credentials, backup or data. The published v1
seal and canonical bytes round-trip unchanged. FEAT-006 owns the actual old
IAM binary retained-data migrations and independent restricted-login process
gates; they are not cross-profile release compatibility evidence. Current
implementation `5721b7b1a985f25c9730ddb9229a51f7f6c3b63a` passes all three
[independent Verification jobs](https://github.com/xiak/matrix/actions/runs/33138242923).

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

These populated gates pass on 2026-08-28 using signed Release A
`matrix-v0.1.0-5721b7b1a985` and Release B `matrix-v0.2.0-5721b7b1a985`, both
assembled from fixed implementation `5721b7b1a985f25c9730ddb9229a51f7f6c3b63a`
with the exact `3/2/1` revision 3 profile. A new task-owned local Linux Docker
27.5.1 engine, limited to two CPUs, 4 GiB and 768 PIDs with external networking
disabled, starts with no inner images, containers or volumes. The
315.69-second real gate installs PostgreSQL 18 and all nine platform services,
completes the populated
tenant baseline and both tenant/installation Audit delivery, verifies two real
application generations, failed-candidate rollback, successful B upgrade,
data-preserving rollback, selected-backup recovery, application rollback/stop,
capacity release and bounded support evidence. The post-upgrade tenant resource
and Operation survive rollback and are absent after restoring the earlier
snapshot. No revoked role/session or disabled user/tenant is revived.

After restarting only this owned local engine and observing its services
return to READY, the second gate passes in 14.55 seconds. No remote machine,
host Docker daemon or shared service is restarted. The explicitly retained
valid session remains usable; revoked and old temporary sessions remain
denied. The original primary recovery is still bound to its original tenant
and USER; explicit tenant resume and required password replacement restore
tenant administration without platform permission. The child remains disabled
until explicitly enabled, retains its changed password, and cannot reuse its
old session. Tenant and platform Audit hashes/chains, configuration values,
quota and original resource/Operation ownership survive. Actual installed
readiness and repeated migration/function verification match the signed
profile, including the seven-column IAM claim and generation-bound password
function; support reports the same profile without credentials or
configuration values. Engine availability alone is not platform readiness.

The releases have distinct release/image identities but share fixed production
source. This proves the complete same-profile lifecycle, not a cross-profile
or historical-binary N-1 runtime transition. Those unsupported transitions
continue to fail closed. Browser acceptance of the installed release remains
owned by FEAT-007. The gate's negative HTTP client also checks the proper
`application/problem+json` contract, so expected authentication and access
denials are not mistaken for malformed success responses.

The real browser subsequently consumes this installed revision-3 release,
not a development server. FEAT-007 owns that journey and its preserved
database observations. Its task-owned loopback network is attached only after
the network-disabled lifecycle and restart gates; browser connectivity is not
presented as part of their offline-network proof.

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
