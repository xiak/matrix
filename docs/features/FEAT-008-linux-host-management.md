# FEAT-008: existing Linux hosts and remote application delivery

- Status: P3-2 accepted; P3-3 implementation in progress
- Target: Matrix PaaS Phase 3
- Design date: 2026-08-27
- Branch: `feat/linux-host-management`
- Fixed integration baseline: `f5ce412ff795abdaf5ba8e5fe112378f1cd1af41`

## Outcome and scope

Enroll existing Linux hosts and continuously observe health and resource
usage. Deploy, update, stop and roll back applications through the existing
IAM-authorized, audited workflow. Provide live resource views and access to
the actual running application container. Prove signed offline installation,
operations, upgrade, rollback and recovery across independent hosts.

The long-term private-cloud direction, optional Kubernetes provider and domain
boundaries belong to [ADR-0002](../architecture/ADR-0002-product-boundary.md).
Phase 3 supports Linux/amd64 with Docker Engine and Compose already installed.
It does not provision VMs, install an OS/Docker, change customer firewalls,
implement Kubernetes, or deliver public-cloud billing/HA.

Development, artifacts and disposable runtime objects are isolated from
Phase 2. Never reset, edit, merge into, redeploy or stop its branch, worktree
or environment. UI additions happen only on this Phase 3 branch; existing
console and managed PostgreSQL behavior remain regression requirements.
Never reboot a remote machine, including a remote experiment VM. Reboot
acceptance uses only task-owned local guests; the shared host, Docker Desktop,
other engines and other tasks' services must remain running unchanged.

## Iterative roadmap

Proceed in order. Each increment must run and prove its behavior before
acceptance; compiling interfaces or passing mocks is insufficient. Security,
offline operation and recovery are built into each slice. The final release
exercise combines these capabilities rather than introducing them late.

| Iteration | Usable outcome | Required evidence | State |
| --- | --- | --- | --- |
| P3-0: design and adoption | Fixed scope, isolated branch and donor decisions | Target committed before fixed-source review; no donor dependency | Complete for the initial node slice |
| P3-1: one managed host | Secure resident agent enrollment, identity, heartbeat and continuously refreshed basic CPU/memory/filesystem status through the control plane | Real authenticated Linux node; wrong identity denied; stale/disconnected state; restart and signed offline startup | Complete |
| P3-2: remote application loop | Deploy, observe, update, stop and roll back a real application on that host | IAM/Audit/Operation/accounting integration; exact routing; ENV/Secret behavior; replay and lost-response recovery | Complete |
| P3-3: interactive operations | Live host/container UI and terminal in the selected running instance | Successive measurements without reload; real terminal I/O, resize, expiry, disconnect, authorization and audit | In progress |
| P3-4: multiple hosts | Pool placement, drain, unavailable-node handling and safe removal across two independent hosts | No cross-host/local fallback; identity collision, tenant isolation and concurrent capacity checks | Pending |
| P3-5: offline release | Platform and nodes install, operate, upgrade, roll back and recover without external access | Complete Gates A-E on exact committed source and signed releases | Pending |

Start P3-1 after P3-0's donor review. Its basic measurements do not replace
P3-3's full observability scope. Historical queries, interactive sessions and
multi-host policy are implemented when their iteration is reached.
No iteration alone completes the Phase 3 goal.

## Ownership and node design

| Concern | Owner |
| --- | --- |
| Admission, pool membership, drain and scheduling intent | Existing apphosting ExecutionTarget/ExecutionPool; no duplicate Machine model |
| Placement, generations, Operations, reservations and audit outbox | Existing apphosting use cases and PostgreSQL transactions |
| Host facts and remote application execution | InfrastructureAdapter and DeploymentExecutor, adapted through versioned node protocol data |
| Resident process and local effects | Node agent; reuse existing Compose compiler/runtime/locks/receipts |
| Endpoints, node certificates, credentials, Secret roots and releases | Protected installation configuration and lifecycle |
| Container access sessions | Separately authorized apphosting use case and provider adapter |
| Resource measurements/history | Pinned existing collector plus bounded Docker observation, separate from the privileged executor |

The first node transport is bounded mTLS HTTPS on a private management
listener. Nodes have exact installation/target identities, no control-plane
database credentials and no scheduling or IAM authority. Installation owns
certificate provisioning, renewal and revocation. SSH may bootstrap or rescue
a node; it is not the steady-state workload protocol.

The signed-platform connection increment uses `mx platform configure-nodes`
with a protected, installation-bound controller configuration and the expected
current configuration digest. Installation owns the private input, an atomic
configuration replacement and a resumable journal; only the owned PaaS API is
recreated to load an appended binding inventory. Existing target/binding/pin
tuples cannot be removed or rebound by this command. Certificate replacement
may not change controller identity. An empty initial configuration admits no
nodes. The runtime receives no CA signing key, node key, host path selector or
SSH/database credential through this input. A private management egress
network and a read-only private configuration directory belong to the signed
topology; no host network or Docker socket is added to the API. Configuring a
connection grants no platform role, registers no target and creates no tenant
resource. Existing platform-authorized admission owns those decisions.

This increment consumes operator-provisioned controller credentials; it does
not yet provide an automatic certificate issuer. Its acceptance requires
closed/secret-safe input, wrong installation/identity/expected digest rejection,
append-only inventory, crash/resume and current credential replacement,
exact API-only effects, unchanged other services/workloads, signed topology
and real platform/node observations. Evidence and remaining release gates are
recorded below. The previous platform bundle has no node connection mount and
cannot be described as integrated merely because the native process gate passed.
This changes the signed topology digest, not the database profile; transition
from the previous topology is not admitted or claimed by this increment.

PostgreSQL owns desired state/accounting; nodes own effects/observations.
Disconnection preserves accepted workloads. Restart/reconnect uses durable
receipts and actual runtime observations. Unknown outcomes require observation
on the same target before retry; a node never relocates work or invents a new
generation while offline.

## Required behavior

### Admission and execution

- Pool creation and target registration are platform-authorized use cases.
  A registration selects an opaque, installation-owned node binding, never a
  caller-provided endpoint, certificate or host path. The configured
  installation, target and identity pin must agree with the real node probe.
  Extend the existing Operation/outbox owner with an explicit installation
  authority partition; do not represent platform resources as a fake tenant.
- Resolve bindings server-side and probe outside transactions; atomically
  commit accepted identity, pool/target, Operation and audit event. Exact
  idempotency replay succeeds; changed input, identity collisions and binding
  conflicts fail. Updates use optimistic concurrency.
- Refresh cannot overwrite operator intent. Stale, unavailable, changed-identity
  or unsupported targets reject new placement without stopping healthy nodes.
  Drain retains existing work; removal rejects live/reserved/unresolved work.
  Neither touches unrelated host files or Docker objects.
- Persisted placement selects the exact executor for apply/observe/stop/rollback.
  No other-host or control-plane fallback. Preserve RLS, least privilege,
  worker fencing and capacity conservation.
- Accept closed versioned operations with one action-specific payload. Reject
  unknown/duplicate fields, trailing data, excessive size/depth, identity
  mismatch, stale generations and expired requests before effects. Verify
  trust, certificate validity and exact peer identity; no insecure TLS.
  Bound streaming, concurrency and deadlines.
- Deployment input has no shell, provider YAML, host paths, credentials or
  arbitrary Docker options. Use verified preloaded image digests and exact
  Secret references; missing material fails before effects. No pull/build/tag
  fallback. Errors/receipts exclude raw output, config values, secrets and paths.

### Live resources

Observe the OS visible to the node, not an unseen VM hypervisor. Required
measurements are CPU count/utilization/load/I/O-wait; memory total/available/
used and swap; filesystem capacity/usage/available bytes and inodes; disk
read/write bytes, operations and duration where supported; network bytes/
errors/drops; container CPU/memory and separately attributed image, writable
layer and volume storage. Shared image layers are not exclusive container usage.

Collection continues without an open UI. Authenticated current/history queries
and live subscriptions carry units, timestamps, interval and freshness.
Fast CPU/memory/network samples target five-second updates; expensive storage
accounting has its own bounded, displayed cadence. Reconnect obtains current
state; missing/stale/unsupported values are explicit, never false zero.
Bound labels/history and enforce operator/tenant visibility.

Capacity, allocatable capacity, reservations and actual usage remain distinct.
Idle CPU or metrics failure never releases reservations. Resource pressure
may prevent new placement. Full APM, arbitrary log search, BMC/SMART and a
custom alerting language are outside this release.

P3-1 uses a pinned [node_exporter v1.12.1](https://github.com/prometheus/node_exporter/releases/tag/v1.12.1)
process under a separate unprivileged UID, without Docker access. The node
scrapes only a loopback mTLS listener with distinct collector/node certificate
roles. CPU rates need two samples and exclude I/O wait from busy time; guest
time is not counted twice. Memory used is total minus available. Filesystem
used is total minus free, not total minus space available to non-root users.
Unreported inode capacity is explicitly unsupported or unavailable. Source
timestamps/expiry survive reads; failure never becomes a fabricated zero.

P3-3 starts with a platform-operator host inventory and current-resource view.
The public collection is bounded by the installation's admitted-target limit
and returns normalized `ExecutionTarget` documents only; it exposes no binding,
endpoint, certificate, host path or provider credential and accepts no tenant or
target selector. Reads use the already persisted background observations and
must not synchronously probe a node, renew a source timestamp or advance a
resource version. The console performs one authenticated fetch at a time on a
five-second cadence, cancels it on navigation or logout, retains the last proved
sample across a transient failure and shows source time, expiry and measurement
state. A stale or unavailable value remains visibly stale or unavailable.

This first increment provides successive CPU, memory and filesystem samples
without a page reload; it is not yet the final live-subscription, history,
container-attribution or terminal acceptance. Those remain P3-3 work. Host
inventory is platform-scoped, while later container observations and terminal
sessions resolve tenant ownership from a Deployment and never grant a tenant
user general host visibility.

### Interactive container access

UI selection resolves server-side to the authorized tenant, exact Deployment
generation, placed target and running instance. Do not accept arbitrary host
addresses/container IDs or expose node credentials/Docker sockets to browsers.
A separate IAM action admits a short-lived, single-use session bound to user
and instance; the node verifies workload ownership again.

Support bounded bidirectional I/O and resize with origin checks, idle/absolute
expiry, concurrency/backpressure, revocation and disconnect cleanup.
Replacement ends the old session; reconnect cannot silently switch generation
or replica. Use the container's configured user without privileged execution,
added mounts, host namespaces or environment injection. No-shell images report
unsupported; no unapproved debug image is injected.

A terminal is write-capable and may expose its workload's own secrets; it is
not read-only. Interactive edits do not create desired generations. Audit
actor, resource/session, decision, start/end and outcome; do not retain raw
I/O by default or include it in support. Sessions, metric samples and deployment
Operations have distinct lifecycles.

### Offline lifecycle

The signed release manifest names IAM, Audit and PaaS schema versions
individually. New bundles use manifest v2 and the closed authority profile;
the current source requires IAM 4, Audit 3 and PaaS 2. A separate contract
revision binds the compatible function/wire boundary: changing a return-column
shape without changing schema numbers still changes this profile. Revision 4
includes purpose-only local credential recovery and its closed SYSTEM Audit
fact, retaining the seven-column IAM Audit claim and credential-generation/
password-session contracts owned by [FEAT-006](FEAT-006-platform-authorities.md),
event-bound producer proof and host admission. Readiness and retained-
data gates verify the exact function shapes. Equal revisions
with different authority schema tuples still cannot admit a transition.
The published Phase 1 v1 manifest and
sealed backup formats remain verifiable without changing their bytes; this is
not admission of an older platform topology or implicit platform permissions.
Their former single schema number is not evidence that a newer authority can
run after rollback. Upgrade and data-preserving rollback initially admit only
identical complete database profiles; a different profile is rejected before
backup, migration, process replacement or journal advancement. Recovery also
requires the current release, target release and authenticated backup to have
the same complete profile, including at resumed recovery/start/verification
boundaries. Selecting an older backup is not permission to cross profiles. Admitting a
future cross-profile transition requires its retained-data and actual N-1
runtime gates, not an increasing version number. Backup/recovery and sanitized
support carry the same complete profile. This admission rule does not by itself
prove an offline release compatible or accepted.

Authenticate signed executable/collector/image payloads and protocol
compatibility before effects. Stage, verify images/ownership, start supervised
processes, verify real behavior, then commit the release. Replay/restart
preserves ownership, secrets and accepted receipts.

The existing installed-platform gate admits a verified, immediate predecessor
with a distinct source commit only within the same complete profile and
topology. It must also write an application and Operation through the successor,
read that exact terminal Operation and its Audit history through the predecessor
after data-preserving rollback, and prove that only explicit restoration of the
earlier backup removes those later records. Same-source A/B remains a lifecycle
fixture, not proof of a separately built predecessor.

Its optional native companion uses two independently booted, empty workload
engines in the same externally disconnected experiment. Pinned loopback SSH
forwards are fixture preparation only, never a runtime adapter or a source of
fabricated host facts. Signed enrollment and platform admission must bind the
actual machine/engine identities, CPU, memory and filesystem observations;
background refresh is checked without an HTTP reader. Admission Operations,
Audit hashes, latest trust and real database fixture data must survive the
combined platform/node lifecycle and automatic native boot. These database
fixtures do not count as P3-2 remote application delivery. After boot, the
machine/engine identities must still match, while capacity quantities are
compared with the current OS facts rather than treated as immutable identity.

The first node distribution is a distinct, closed `OfflineNodeRelease` in
the existing signed release owner, containing `mx`, the node executable and
the pinned collector, not platform images or a fictitious database profile.
The existing lifecycle/journal owner seals its installation, target and
credential/configuration commitment; node phases cannot run platform database
or backup effects. `mx node` owns enrollment/start/status/verification while
the existing local-machine adapter owns native process effects. Protected
installation input supplies only the node and collector certificates, never
a controller private key. The node's own identity can query a bounded
self-readiness endpoint, but cannot invoke the controller observation or
execution surface. Readiness requires fresh host and collector observations.

Native execution uses installation-owned transient systemd services, with a
dynamically allocated collector UID, read-only payload/credential access and
no Docker socket for that collector. A narrowly owned persistent startup unit
invokes the staged `mx node start`, authenticates the retained release,
configuration and credentials, then reconciles the same node and collector.
It cannot bypass node-payload verification or create a new enrollment authority.

The startup unit is derived from the sealed installation/target binding. Its
source stays below the protected installation root; only exact, non-forced
registration links may be created. Existing masks, foreign units, drop-ins or
changed policies fail before runtime replacement. Readiness includes the
verified persistent registration. Replay must recover an interrupted, already
configured node installation using its original command and staged release;
missing or conflicting state is not permission to create another installation.
Failed-install rollback removes only its own registration while retaining
receipts and workloads; release rollback retains the registration. No customer
package or firewall is changed. Full local guest boot,
tamper rejection, interruption/replay and unchanged retained state are required
before accepting this slice.

Native installation roots must be clean absolute POSIX paths without whitespace,
control characters, quotes, backslashes, colons, dollar signs or percent signs.
The minimum systemd's transient bind serialization does not quote source paths;
unsupported roots are rejected before creating installation state, not accepted
until a later manager reload changes their meaning. The signed node runtime
contract binds this restriction. External enrollment input files are copied
into the protected root and are not native mount sources.

Node credential rotation is an installation command, not a writable node API.
`mx node rotate-credentials` consumes protected enrollment input and the expected
current configuration digest. It may change only the node/collector certificate,
key and management trust bytes; installation/target, controller, binding, host
fingerprint, addresses, reserve policy, storage and signed release stay fixed.
The existing journal seals the old and candidate commitments before activation.
Both sets are staged in protected installation-owned storage so an interrupted
replacement can resume the same command without the original input files.
Only the exact node and collector processes are reconciled; executor receipts,
Docker workloads and boot ownership are retained. Expiry of the old certificates
does not prevent an authorized rotation of their still-authenticated sealed bytes.
After the new commitment is durable, remove only its two authenticated temporary
credential snapshots. Cleanup is replayable; failure retains the new commitment
and blocks staging another rotation, rather than accumulating old private keys.

The default rotation replaces the complete management trust set and both private
keys. Node and collector keys must be distinct, and no old key may be retained
by moving it to the other role. It rejects retained old trust keys, including
reissued CA certificates with the same key, and is the first revocation primitive;
ordinary same-trust certificate renewal requires explicit `--revoke-previous=false`.
Revocation is not automatically rolled back after activation failure. The sealed
candidate remains the recovery intent, failed verification stays unaccepted, and
restart must not silently restore the old credential set. This is a bounded local
trust-domain replacement, not CRL/OCSP, automatic CA issuance or zero-gap CA overlap.
The control plane reloads protected credential references at each new node TLS
connection, without changing the admitted node mapping or falling back to cached
credentials on invalid input. Completing the trust switch requires updating that
installation-owned control-plane input as well; local node readiness alone is not
proof that every consumer has revoked the previous node credential.

The existing TLS, lifecycle, native-effect and process gates must prove successful
renewal, old-peer rejection after the complete trust switch, exact replay and stale
digest conflict, wrong identity/address/key rejection before effects, interruption
at replacement boundaries, retained workload/receipt state and restart with only
the committed credentials. The signed node runtime revision changes for this
capability; it does not change the platform authority database profile or admit an
unverified older node release.

`mx node upgrade` stages an authenticated immediate successor before accepting
its activation intent. The candidate must remain available in protected local
storage if the original media disappears. `--resume` and the persistent startup
entry use only that sealed source/destination pair and original command.
`mx node rollback` selects only the retained, signed predecessor. Neither command
accepts new enrollment, credentials, reserves, host paths or a platform database
profile. The latest credential commitment survives both directions.

The node running contract must also admit the upgrade/rollback journal and boot
entry, not merely the observation protocol. This slice introduces runtime
revision 3: revision-2 installers reject those journal actions and cannot be
treated as compatible rollback readers. Cross-runtime-profile transitions remain
unsupported before effects; old nodes keep their current installation. Prove a
real signed predecessor/successor pair within the supported contract before
claiming N-1. Same-source A/B alone remains insufficient for that claim.

Activation authenticates both exact native service owners and the closed old/new
startup definitions before changing either. Replace the protected boot source
atomically without removing its registration links; admit only those two known
loaded definitions while reconciling a lost reload reply. Reconcile only the node
and collector, retaining every Docker workload, executor receipt and credential.
Failed candidate verification restores and verifies the source release; an
uncertain effect retains the same intent instead of issuing another upgrade.
Conflicting ownership or failed recovery is explicit and never permits force,
unknown-file overwrite or a host/engine restart. Existing lifecycle, native
effect and signed-process owners must prove these boundaries, including removal
of original media, interruption/replay, latest-key retention and unchanged
workload identity/data. Certificate renewal/revocation remains independent.

Retain platform backup/recovery/status/support. `mx node support` writes a
bounded, closed diagnostic snapshot only under the installation's private
support directory. It authenticates the installed release, enrollment and
native ownership, but never reconciles a process, changes the lifecycle journal
or cleans credentials. An active lifecycle command conflicts; diagnosis does
not replace its recovery intent. A repeated output name may return only its
validated stored snapshot for the same journal/credential commitment,
with original observation times; a changed installation requires a new file.

The snapshot contains normalized identity, release/runtime revision, supervision
and readiness states, configured reserve, bounded collector CPU/memory/filesystem
quantities and lifecycle correlations. It reuses the existing authenticated
collector with at most two samples and no background task or controller key.
Missing observations remain unavailable, not zero. Raw logs, host/device paths,
endpoints, environment, certificates, keys and provider output are excluded.
Support file creation adds no journal action or node-wire field, so it does not
alter the runtime-revision-3 rollback reader contract. Existing CLI, workflow,
filesystem and signed-native gates must prove redaction, write-once/private
output, outage diagnosis and unchanged journal/services/workloads. Destructive
recovery remains an explicit operator action.

### Local platform credential recovery

`mx platform recover-credentials` is a distinct installation operation, not
backup restoration or bootstrap replay. Its first slice invokes only IAM's
purpose-limited recovery transaction for the sealed original installation
primary. The account, binding, session, concurrency and Audit invariants are
owned by [FEAT-006](FEAT-006-platform-authorities.md). It does not grant or
restore platform authority, transfer ownership, enable an account or tenant,
or recover service credentials. Development-history first authorization and
revoked-role reinstatement are unsupported product intents.

The existing installation lock and authenticated journal own the command.
Before recording a new intent or invoking recovery, authenticate the installed
release, complete supported authority profile, protected bootstrap provenance
and local capability. Do not accept caller-selected users, tenants, database
addresses or executables. Invoke only the signed IAM entrypoint with its
restricted local recovery capability; existing online users, runtime services
and the installation verifier gain no such capability. Migration and direct
table writes are not the recovery interface. Recovery neither changes release
pointers nor restarts the platform, engine, node or workloads.

Read secret input through a bounded protected-file boundary, never a password
argument or environment value. Ordinary journal records, command output,
errors, Audit and support evidence contain no password, password hash or raw
recovery material. Keep only the authenticated protected material needed to
resume an interrupted command. Its exact identity remains stable across
response loss and process restart; replay after a later credential change or
role revocation cannot perform another reset. Once the IAM completion receipt
and local completion are durable, remove only that command's authenticated
temporary material. Failed cleanup is resumable and cannot authorize another
recovery or a rollback of credentials.

Extend the existing CLI, lifecycle, filesystem and installed-runtime gates.
Prove wrong-root/provenance/profile and changed-input rejection before effects,
bounded secret input and sanitized output, lost-response and crash replay,
one-way credential replacement, exact temporary-material cleanup, and unchanged
service/workload identities and data. IAM's transaction and delayed-Audit gates
remain in their current owner. SQL migration evidence alone does not admit a
cross-profile release transition or accept the combined offline slice.

### Supported release and authority migration boundary

Matrix supports upgrade, rollback and recovery only between explicitly signed
releases admitted by an exact source, database profile, contract revision and
topology transition. The fixed `c88a84f` executable is a development-history
and retained-data fixture, not a supported customer predecessor for platform
authority. Its bootstrap records do not identify the executing source or role
catalog. Consequently, an absent platform binding or empty grant history is
never evidence from which the product may grant `PLATFORM_OPERATOR`.

Fresh supported installations establish their sealed installation owner and
initial platform authority through the current bootstrap ceremony. Credential
loss for an owner that still has an unrevoked platform binding uses the separate
purpose-only recovery operation above. A revoked binding remains revoked, and
unknown or incomplete provenance fails closed.

If a future published release requires a new highest privilege, that release
must define a dedicated, version-scoped transition with authenticated source
and target manifests, explicit operator intent, one-time non-rollback
consumption evidence and a closed Audit fact. Database migration, startup
reconciliation, bootstrap replay and absence checks are not substitutes. This
pre-v1 replacement-first boundary removes development-history first
authorization from P3-1 while retaining the real `c88a84f` regression that
proves migration and replay never grant absent authority. The supported
compatibility baseline begins with the first accepted Phase 3 signed release.

## Acceptance gates

| Gate | Required evidence |
| --- | --- |
| A: contracts/security | Real mTLS rejection and identity binding; strict bounded protocol; deadlines/concurrency; replay/conflict/restart; existing architecture rules |
| B: durable authority | Clean PostgreSQL apply-twice and schema/privilege checks; IAM/Audit/RLS; host mutations and reservation concurrency; stale-fence/lost-response recovery; session denial/replay prevention; Phase 1/2 regressions |
| C: real runtime/UI | Independent engines run application lifecycle with actual ENV/Secrets/limits/networks; samples respond to controlled CPU/file activity; browser receives successive/stale/recovered samples and opens the exact container with real I/O/resize/expiry/disconnect; specified negative paths |
| D: clean offline lifecycle | Empty control-plane engine and two empty workload engines with external egress disabled throughout; signed A install/enrollment and Gate C; tamper rejection, failed-candidate rollback, compatible B upgrade and N-1 rollback; backup/recovery, certificate lifecycle, restart, verify/status/support; Phase 2 untouched |
| E: release closure | Exact committed source: generation drift, module verification, unit/vet/race/repeated tests, architecture, real database/adapters, cross-platform builds, links, donor/secret/path scans and diff checks; applicable independent GitHub gates and signed artifacts; no donor dependency |

Tests extend their current owners and prove current behavior, contracts or
security boundaries. Add a suite only for a new boundary or unowned gate.
No SQL-text/file-layout/line-count/incidental-order snapshots, duplicate
per-iteration harnesses or tests for removed drafts. This FEAT alone owns
roadmap/status/evidence; adoption owns donor decisions; runbooks contain only
executed commands; one checkpoint contains portable resume pointers.

## Implementation evidence

The target/roadmap were fixed in `fbdb250` before the initial fixed-source
review. P3-1 now has a versioned observation protocol, mTLS client/listener,
resident host probe and bounded collector adapter. Background capacity/health
and actual CPU/memory/filesystem samples preserve the configured identity pin.
Allocatable capacity excludes installation reserve, not measured free memory;
a collector outage leaves infrastructure capacity intact and usage unavailable.

The [protocol/security tests](../../app/service/nodeagent/internal/service/nethttp/handler_test.go)
verify actual TLS admission, exact peers and correlations, malformed/bounded
requests, freshness, concurrency, collector roles and sanitized errors. The
[collector tests](../../app/adapter/infrastructure/nodeexporter/collector_test.go)
cover real HTTP parsing, counter resets/gaps, missing/duplicate/nonfinite
measurements, inode support and bounded failures. The
[process gate](../../app/service/nodeagent/internal/service/nethttp/runtime_test.go)
passed twice with built executables in an egress-disabled Linux Docker-in-Docker
fixture: separate collector UID, no-reader refresh, controlled CPU/file activity,
collector failure/recovery, disconnection, persisted identity and node restart.
It also passed twice on an authorized native Ubuntu/ZFS host, with all test
files below the operator-selected experiment directory. The transient service
was verified active with a one-CPU quota, 512 MiB memory ceiling, private
network/devices and protected home directories. Existing containers and their
collector were not changed. Storage assertions follow the experiment's actual
mount and verify reserve policy against each current capacity sample; shared
pool capacity is not assumed constant between observations.
The transient native services and their remote artifacts were removed afterward.
The default Go suite, architecture, vet, module verification, generation drift,
this slice's race checks and ten repeated runs passed locally. Opt-in database
and full Phase 1/2/3 release exercises were not implied by that default run.

[Independent CI](https://github.com/xiak/matrix/actions/runs/33044131708) passed
on `540dc10`, including the full Linux Go/race and real node/collector process
gates in the existing [verification workflow](../../.github/workflows/verification.yml).
No implementation iteration or complete Phase 3 gate is accepted.
The node observation chain alone is not the completed observability product.
The prerequisite installation-scoped IAM and Audit boundaries and their
verification are owned by
[FEAT-006](FEAT-006-platform-authorities.md).

Control-plane pool creation, target registration and current-state queries now
use the existing apphosting authority. A protected installation file selects
the node's endpoint, mTLS controller credentials and exact identity pin;
northbound input contains only its opaque binding reference. Admission probes
outside the transaction, then atomically stores the pool/target, identity,
terminal installation Operation and Audit outbox fact. Current IAM permission
is required even for exact replay; a committed replay does not need a reachable
node or rewrite the original decision. Tenant and installation Operation/outbox
partitions remain distinct even when their authority IDs have identical text.

The PaaS process refreshes admitted hosts from a five-second background loop
without UI readers, with at most two concurrent probes and 128 configured
targets. This bounds work; it is not a multi-host latency guarantee. Refresh
preserves scheduling intent, labels, accepted identity and reservations.
Metric-only samples do not advance the placement resource version; changed
health/capacity does. Lost connectivity retains last capacity and source times,
marks the target unavailable and lets usage expire. Reconnection restores fresh
observations without re-enrollment. GET does not renew source measurements.

The existing [PostgreSQL gate](../../app/service/paas/internal/apphosting/data/postgres/execution_admission_integration_test.go)
passed with concurrent admission/replay, identity collisions, forced RLS,
cross-partition rejection, atomic rollback, refresh and outbox fencing. The
[five-process gate](../../test/authorityprocess/process_e2e_test.go) now obtains
host facts through real IAM-authorized PaaS HTTP mutations and its dispatcher,
not a hand-made host Audit event. It passed background no-reader sampling,
wrong node identity, outage/recovery, exact Operation/Audit correlation and
next-request denial after platform revocation and IAM restart. Its node peer is
a closed wire fixture reached by the production mTLS client. Runtime database
login evidence uses the corrected gate owned by
[FEAT-006](FEAT-006-platform-authorities.md), not the earlier DSN assumption.

The [Linux variant of that same gate](../../test/authorityprocess/node_runtime_linux_test.go)
connects the real node and pinned collector to all five authority processes.
Native Ubuntu/ZFS runs received the actual machine fingerprint, OS CPU/memory,
filesystem measurements and reserve policy through the PaaS API. The same
admission, no-reader refresh, wrong-identity rejection, outage/restart,
Operation and Audit assertions run against those processes. Shared filesystem
capacity may change between samples; the resource version must remain monotonic,
while the controlled wire peer still proves metric-only version stability.
The native gate ran with one CPU, a 1 GiB ceiling, protected system/home paths
and loopback-only network access. The collector ran as UID/GID 65534 without
Docker access. Its separate PostgreSQL 18 fixture had no network or published
port and used only a fixture-owned local socket. Executables and the
pinned collector were hash-checked before the run. Existing host services and
containers were not changed. The transient processes, test database/image,
socket and native experiment files were removed afterward. This proves real observation
through the control plane, not remote application execution or signed node
installation.
The combined node gate passed on source `1ff7f16` in the existing
[independent CI node-process job](https://github.com/xiak/matrix/actions/runs/33063053971).

The [retained-data upgrade gate](../../app/service/paas/internal/apphosting/data/postgres/upgrade_integration_test.go)
executes the fixed `3916644` PaaS schema 1 and seeds tenant work through its
transaction functions. Applying the new schema twice preserved Operations,
immutable generations, Audit documents and in-flight leases; retained work and
Audit completion continued afterward. Legacy execution pools were not silently
enrolled. PaaS API/worker readiness now requires schema 2 and rejects schema 1.
Fresh PostgreSQL and upgrade tests, the five-process gate, full Go race/vet,
stable generation, module verification, ten repeated focused runs and Linux
builds passed locally. Source `3e208ea` passed
[independent CI](https://github.com/xiak/matrix/actions/runs/33056029691),
including all existing Go/race, PostgreSQL/authority-process and real
node/collector process jobs.

The fixed account, historical-proof and lifecycle/session integration has passed
this branch's host admission regression; its authority evidence is owned by
[FEAT-006](FEAT-006-platform-authorities.md).

The release builder now emits the explicit authority profile and contract
revision. Existing [lifecycle gates](../../app/service/installation/internal/platformcommand/backend_test.go)
prove rejection of an unproved profile before any effect or journal change,
including equal schema numbers with a different contract revision and an
incompatible predecessor already present in sealed state. An actual `mx` built
from the published `c88a84f` source authenticated the v1 format and rejected v2
before effects in an egress-disabled Linux fixture. This does not demonstrate
that the older executable can run the current platform topology.
The existing [backup/recovery gates](../../app/service/installation/internal/localmachine/localmachine_test.go)
proved unchanged v1 canonical seals, no rewrite on replay, complete profile
binding, rejection of substituted profiles and zero/null legacy selectors,
and retained sanitized support behavior. The real PostgreSQL 18 five-process
gate checks each authority's HTTP schema version against the release profile,
alongside the existing host, tenant-isolation and runtime-login assertions.
The process fixture ran on its own internal bridge without published ports;
its process and database containers each had a verified one-CPU ceiling and
bounded memory/PIDs. Release, lifecycle and local-machine tests passed ten
repetitions in network-disabled Linux containers. Full Go race/vet, Linux
builds/vet, module verification and stable generation passed. Source `c29f9e3`
passed all three existing jobs in
[independent CI](https://github.com/xiak/matrix/actions/runs/33065856592).
These tests
establish admission and format boundaries, not a signed offline release or
runnable cross-profile N-1 compatibility.

The existing process gate consumes a release-builder-produced signed
`OfflineNodeRelease` and executes its bundled `mx`, without a second test-only
release implementation. Clean source `bd08f5d` assembled the runtime-revision-2
bundle with the pinned collector, licenses and two native executables. Gate
`9c49d55` passed its full native exercise in 417.07 seconds on a task-owned
local Ubuntu 22.04 guest with systemd 249, Docker 27.5.1 and Compose 2.33.0.
The software-emulated guest had two virtual CPUs and 2 GiB memory inside a
two-CPU, 3 GiB wrapper with no external network, published port, privileged
mode or shared Docker socket. The gate had its own one-CPU, 768 MiB limit.
It covered exact install replay, no-reader sampling, staged-payload and effective
service-policy tamper rejection, manager reload, collector outage/reconciliation
and supervised crash restart. Restoring an altered unit source without reloading
does not hide a loaded privileged execution flag. Unsupported native roots fail
before creating installation state. Partial boot registration is repaired without
replacing healthy processes.

The same gate's boot preparation passed in 180.73 seconds, retaining an
interrupted real installer command. Only that local guest kernel was rebooted;
the changed boot ID was verified. The persistent startup unit automatically
completed the original in-flight command, with no service retry or manual start. Both
resident processes were running before the first manual `mx` status query.
The retained installation/target, release, command ID, configuration, certificate/key bytes
and executor marker were unchanged. The read-only boot phase passed in
8.20 seconds; it separately bounds the wait for fresh observations after boot
load instead of equating a running process with a current sample. This boot
case does not combine kernel reboot with credential rotation or prove that a
deployed application/database workload survives reboot. No remote machine,
shared engine or other task's service was restarted. Its task-owned runtime
and transferred fixture files were removed after verification.

The collector runs under a distinct non-root UID without access to the node
private key or Docker socket. Systemd owns and removes its private runtime
directory when the service stops. Real stop/restart and cleanup assertions prove
that no mount placeholder remains; a pre-existing directory is not adopted by
name. Local effect gates retain executor files and credentials during rollback;
failed-install rollback authenticates every service before removing its exact
boot links.

Enrollment/security regressions cover closed input, overlapping IP aliases,
exact certificate roles, mutual trust, expiry and certificate address binding.
The node's self credential cannot enter the controller command surface.
The existing journal/lifecycle gates preserve the node's sealed identity and
prevent platform database/backup phases or cross-purpose directory reuse.
Linux local-machine tests cover retained executor files, credentials and backup
bytes, including recovery rejection at every effect boundary when the current,
target and authenticated backup profiles differ. Node lifecycle does not change
the platform database profile. The integrated authority composition is specified
above; the existing lifecycle gate explicitly rejects transitions in either
direction with the preceding
IAM 2 / Audit 2 / PaaS 2, revision 1 profile before journal or provider effects.

The native exercise consumes an extracted Linux bundle; declared executable
modes were restored after the Windows-origin transfer before verification.
It does not prove a portable archive format or a compatible signed
platform/node release pair.

The verified runtime-revision-2 slice supports sealed credential rotation and protected
control-plane credential reload. The existing lifecycle/filesystem gates prove
old/candidate commitments, immutable target/configuration/release, rejected
foreign services and unknown file contents, mixed-file recovery, exact replay,
and one-way recovery intent. Committed snapshot cleanup can resume after an
unlink; failure preserves the new credentials and blocks another rotation.
Native service ownership binds immutable enrollment and signed release, while
the journal separately authenticates credential bytes. Rotation retains the
exact persistent startup source and verifies ownership before stopping services.

The existing real-TLS gates prove exact roles, expired sealed predecessors,
rejection of shared or cross-role reused private keys and reissued old CA keys,
and refusal of both retired peers. The same control-plane client reads replaced
protected credential references; missing/invalid input and changed node mappings
fail before HTTP without falling back to cached credentials.

The extended signed native gate exercises explicit same-trust renewal,
default complete trust replacement, killing the real installer, removal of all
external rotation inputs, resumption from sealed snapshots, old-controller/node
TLS refusal, resident-process restart, and replay retaining the original command.
A separate preloaded PostgreSQL 18 fixture had no network or published port,
a half-CPU quota and a 384 MiB memory ceiling. Its container ID, startup time,
restart count and SQL marker remained unchanged throughout. An executor-state
marker and boot/configuration bytes were retained, and completed rotation snapshots were
removed. Its initialization has a bounded fixture wait independent of node
readiness deadlines. This case passed within the full minimum-systemd exercise
above and in independent CI; it is not evidence of PaaS remote application
placement.

Full Go tests/vet, affected-package race checks, ten focused repetitions,
architecture, stable generation, module verification and Linux builds passed.
The production rotation slice `a7ad849` and the gate-only fixture correction
`9c49d55` each passed all three jobs in
[production CI](https://github.com/xiak/matrix/actions/runs/33144098456) and
[gate CI](https://github.com/xiak/matrix/actions/runs/33146237962), including the
signed native package, real-authority node variant and retained-data/
least-privilege regressions. The gate correction also passed the local default
Go suite, vet, module verification and Linux test build.
No authority database profile changed, and no remote machine or shared engine
was restarted. These per-node checks alone do not prove a combined offline
platform/node lifecycle.

The local original-primary credential recovery consumer now uses the signed
IAM one-shot executable, protected intent files and the existing installation
journal. Public CLI/backend tests cover exact retry, unknown outcomes,
definitive rejection and one-way completion; local-effect tests reject
substituted process ownership, preserve in-flight recovery and authenticate
temporary-file cleanup. The authority transaction/process evidence is owned by
[FEAT-006](FEAT-006-platform-authorities.md). Control-network resolution retains
the complete provider identity; ownership checks do not accept a truncated
prefix. Audit observation retries only explicitly unavailable responses within
a fixed bound; authorization errors, malformed pages and missing historical
hashes still fail.

The existing installed-runtime gate's combined phase (`a060715`) consumed
signed platform A from `91b8ba5` and B from `7910622`, both with the complete
4/3/2 revision-4 profile and the same protected-node-connection topology.
Signed node A used `cd271c5`; B used `6697292`, both at runtime revision 3.
Both pairs contain distinct source revisions. The lifecycle phase passed in
1076.69 seconds with a new empty control-plane engine and two independently
booted, empty workload engines, with external egress disabled throughout.

The task-owned Docker 27.5.1 wrapper had four CPUs, an 8 GiB ceiling and a
768-task limit. It was privileged for nested Docker, without a host socket,
host bind mount or published port. Two local Ubuntu 22.04/systemd 249 guests
each had two virtual CPUs, 2 GiB RAM and an ext4 disk. Their private management
forwards served only this experiment. No remote machine was accessed.

The gate killed the real installer after IAM committed but before the provider returned,
removed the operator input and resumed the same sealed intent through its
exact receipt. Old sessions and the retired password were rejected; forced
change, completed replay, unchanged service/workload identities, private-file
cleanup and the single SYSTEM fact with a complete platform chain passed.
Application generations, failed-candidate automatic rollback, successful B
upgrade, data-preserving rollback, selected-backup recovery, retained Audit
hashes, capacity release and sanitized support also passed.

Both signed nodes were admitted through the real platform authority. The gate
checked actual machine/engine identities and CPU/memory/filesystem quantities,
background refresh without HTTP readers, isolated node outage and replay of
the original admission Operation. Complete trust/key replacement rejected the
old controller. Updating controller credentials recreated only the owned
PaaS API, preserving every other running service and workload at that boundary.
Node A-to-B upgrade and B-to-A rollback retained the latest credentials.
The original host Operations, Audit hashes, node bindings and two independent
PostgreSQL 18 container identities, start times and SQL markers survived the
combined platform/node lifecycle, including selected-backup recovery.

The exercised manifest SHA-256 values were platform A
`76938c05d17633b003c78a6ea4bfa04def0afeecf5683b3a9743779c08fc447a`
and B `a42e56940667bb4334ff4e3239cca894489688f993b0bbce67e2485ccbb97b04`,
node A `5b19cd9f1f9daafb8ea620f62a73b32d52342ff1c3dc511b97065d2a7f40cfff`
and B `32d66e02d67ecc1d7ef6491103639c048dfe393cee93e350a9ad8901be5cc9d9`.

A new application, terminal Operation and associated Audit fact were committed
through B after the backup. Actual A read the same Operation and retained
Audit hashes after rollback; only explicit recovery of the earlier backup
removed those later records. The status consumer retains the existing
configuration digest and still rejects unknown fields. The populated controller
inventory retained its latest credential commitment through rollback and
recovery, rather than restoring the older trust from the backup.

Only the two local guests and their task-owned engine were shut down and
started again. All nine platform container identities became healthy
automatically. The boot phase (`dc8dd3a`) passed in 71.02 seconds, proving new
kernel boot IDs with the original machine/engine identities, automatic sealed
node startup without a test start command, latest credentials, fresh platform
observations, retained host Operations/Audit hashes and the same database
containers and SQL data. Their new start times reflected the actual boot.
Current OS capacity was compared exactly with the new platform sample; one
guest's usable RAM changed by 4096 bytes without changing its identity.

No remote machine, shared engine or other task's service was restarted.
The temporary engines, guest disks and test volumes were removed afterward;
fixed source and signed inputs were retained. This accepts the exercised
observation-only lifecycle and exact predecessor pairs, not arbitrary
historical N-1, cross-profile transitions, development-history upgrade
compatibility or the complete Phase 3 release. The database fixtures are not remote PaaS
application placement or interactive-container acceptance.
The exercised input was an extracted signed directory with declared file modes
restored after Windows-origin copying, not a portable-archive acceptance.
Local checks passed affected-package race, architecture, vet and fixed Linux
builds. The existing five-process gate also passed in 30.90 seconds with a
separate PostgreSQL 18 database limited to one CPU, 768 MiB and 192 tasks;
that local variant uses the controlled node wire peer. Its platform Audit
observer retries only the closed `audit.unavailable` response, at most five
times. Denials, malformed responses, persistent unavailability and invalid
page/chain data remain failures; mutation and negative-access assertions do
not acquire retry behavior. The default behavior regression covers these cases.
All three jobs on the final code checkpoint `524a982` passed in
[independent CI](https://github.com/xiak/matrix/actions/runs/33190459118), including
full Go/race/vet, module/generation checks, retained authority upgrades,
least-privilege processes and the real Linux node variant. CI does not run
the optional two-guest combined exercise and is not a substitute for it.

The protected platform/node connection increment `91b8ba5` passed repository
tests/vet, affected-package race, architecture, stable generation and Linux
native installation regressions. Its closed private contract, append-only
inventory, interrupted-effect/resume and exact API-only provider boundaries
are covered in the existing owners. All three jobs passed in
[independent CI](https://github.com/xiak/matrix/actions/runs/33165337635).

Signed platform and node bundles from that exact source were then installed
on two operator-provided Debian/ext4 VMs. Real IAM-authorized admission,
platform-only Operations, exact historical Audit/content commitments and a
complete platform chain passed. CPU, memory, filesystem and inode samples
advanced through the signed platform. Stopping only the owned node service
produced unavailable/stale state with retained capacity and source times;
committed admission replay and reconnection kept the original target and facts.
Wrong-installation connection input changed neither journal nor runtime.

The same installation replaced the node/collector keys and complete management
trust set. Current-controller TLS succeeded before and after retired-controller
and anonymous rejection. The old platform connection remained unavailable until
its protected controller credentials were replaced, then fresh samples resumed.
Both configuration commands recreated only the PaaS API: the other eight
platform container IDs, start times and restart counts were unchanged. Completed
configuration replay and authenticated pending-file cleanup passed. Node verify
and platform status ended ready. No remote machine, engine or Kubernetes service
was restarted. This observation fixture reserved every workload slot and placed
no application. Its VM network was not externally disconnected, so it is not
Gate D, a signed platform/node upgrade pair, or remote application acceptance.

The signed node release-transition implementation `cd271c5` introduces runtime
revision 3 without changing the platform database profile. The diagnostic
increment `6697292` retains that journal/wire/runtime contract. Existing
lifecycle, journal, CLI and native-effect gates cover closed source/target
ownership, interrupted activation and manager reload, unavailable original
media, source recovery, completed replay and retention of credentials rotated
after upgrade. Diagnostic gates cover private write-once output, redaction,
conflicting metadata/content, unavailable measurements and canceled collection.
Full Go tests/vet, affected-package race, architecture, stable generation,
module verification and Linux builds passed. All three jobs passed on the
exact successor commit in
[independent CI](https://github.com/xiak/matrix/actions/runs/33174882532), whose
native gate now builds its actual predecessor from fixed `cd271c5`.

That gate also passed in 124.59 seconds on a task-owned Debian/ext4 VM with
systemd 257.7 and Docker 28.5.1. Signed A used `cd271c5`; B used `6697292`,
not another label on A's source. The one-CPU, 768 MiB, 128-task helper denied
non-loopback IP traffic; the preloaded PostgreSQL 18 fixture had no network,
port or image pull. Actual installer interruption, resume after media removal,
B boot-entry execution, complete credential replacement on B, interrupted
rollback and failed-candidate automatic source recovery passed. The old A
installer read B's journal and operated again after rollback. Workload
identity/start time/restart count/SQL data, executor marker and latest credential
commitments were retained.

The signed B diagnostic command read both B and rolled-back A, returned real
bounded CPU/memory/filesystem quantities, and reported collector outage without
zero-valued substitutes. Repeating a destination retained its original bytes
and source times; diagnostic creation/replay left journal, keys, native process
identities and workload unchanged. The gate removed only its temporary services
and workload. The VM boot ID and pre-existing node/collector PIDs and start
times were unchanged, with no blocked D-state tasks afterwards. Declared
executable modes were restored after Windows-origin archive transfer. The VM
itself was not externally disconnected. This admits the tested runtime-3
predecessor/successor pair, not arbitrary historical N-1, runtime-2 admission,
a portable archive format or the combined offline platform/node release.

P3-2 is accepted for its remote application loop. The production slice fixed at
`54a5591` routes every persisted placement to its exact target-bound executor.
An update or rollback is an in-place replacement on the Deployment's current
target: only that Deployment's exact active capacity claim is excluded while
checking replacement capacity, and every other target fails closed. Relocation
remains a future explicit operation, not an implicit response to a busy host.
Unit and real PostgreSQL 18 gates cover invalid caller-supplied bindings,
digest binding, a one-slot target with the old generation still active,
concurrent accounting and release after terminal success.

A signed platform release from exact source `54a5591` used manifest SHA-256
`d40d292b7f176045a145fe07d616ae85e8f037c5c3230afd3396703693306947`
and transport SHA-256
`76a87b96bf9da545030f9c5701e8c0e99017e59b7489e9237d89195078791cda`.
It upgraded the task-owned control plane and used the separately installed
managed node without an external image pull. A real application with bounded
resources, configuration environment values and a protected file Secret
reached READY at generation 1. Update generation 2 and rollback generation 3
remained on the same managed host; generation 4 stopped it, cleared placement
and released every claim. The control-plane host had no container for this
Deployment. Exact PaaS decisions and APPLY/APPLY/ROLLBACK/STOP commands all
named the managed target and reached terminal success; the tenant and platform
Audit chains verified. Successive host samples advanced independently of reads
and reported real CPU, memory and filesystem values throughout the lifecycle.

The first real run exposed the former implicit rescheduling defect instead of
masking it: generation 2 had moved to the control-plane host while generation 1
remained on the managed node. The accepted slice replaces that behavior. The
two test Deployments ended STOPPED with released claims and zero remaining
containers; only the exact orphaned test container and its network were removed,
while its authenticated project state was retained. Both remote machine boot
identities remained unchanged and neither machine nor Docker Engine was
restarted.

The signed product source's first independent run exposed a stale test fixture
that still invoked the removed six-argument execution-profile function. The
test-only successor `640ff2d` uses the installation-scoped seven-argument
contract. Full local Go tests/vet, the affected race gate, a dedicated real
PostgreSQL 18 authority-process run and the real Linux node-process variant
passed. All three jobs then passed in
[independent CI](https://github.com/xiak/matrix/actions/runs/33262466613).

P3-2 does not accept interactive access, multi-host scheduling policy or the
complete offline release. Next in P3-3: add successive live host/container
views and a separately authorized, short-lived terminal bound to the selected
running instance. Gate D as a whole remains open, and no untested predecessor
or cross-profile admission is inferred from the fixed pairs exercised here.

## Adoption

- [FEAT-008 fixed-source review](../adoption/FEAT-008-linux-host-management.md)
