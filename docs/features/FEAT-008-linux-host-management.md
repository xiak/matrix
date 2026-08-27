# FEAT-008: existing Linux hosts and remote application delivery

- Status: Target and initial donor review complete; P3-1 implementation in progress
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

## Iterative roadmap

Proceed in order. Each increment must run and prove its behavior before
acceptance; compiling interfaces or passing mocks is insufficient. Security,
offline operation and recovery are built into each slice. The final release
exercise combines these capabilities rather than introducing them late.

| Iteration | Usable outcome | Required evidence | State |
| --- | --- | --- | --- |
| P3-0: design and adoption | Fixed scope, isolated branch and donor decisions | Target committed before fixed-source review; no donor dependency | Complete for the initial node slice |
| P3-1: one managed host | Secure resident agent enrollment, identity, heartbeat and continuously refreshed basic CPU/memory/filesystem status through the control plane | Real authenticated Linux node; wrong identity denied; stale/disconnected state; restart and signed offline startup | In progress |
| P3-2: remote application loop | Deploy, observe, update, stop and roll back a real application on that host | IAM/Audit/Operation/accounting integration; exact routing; ENV/Secret behavior; replay and lost-response recovery | Pending |
| P3-3: interactive operations | Live host/container UI and terminal in the selected running instance | Successive measurements without reload; real terminal I/O, resize, expiry, disconnect, authorization and audit | Pending |
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

Authenticate signed executable/collector/image payloads and protocol
compatibility before effects. Stage, verify images/ownership, start supervised
processes, verify real behavior, then commit the release. Replay/restart
preserves ownership, secrets and accepted receipts.

Stage compatible upgrades without disrupting workloads. Failed verification
restores the previous executable/configuration; explicit N-1 rollback retains
compatible data. Both versions read retained receipts and communicate with the
supported control plane. Reconcile interrupted activation from sealed state,
not directory presence. Verify certificate renewal/revocation independently.

Retain platform backup/recovery/status/support. Node support exposes bounded
normalized identities, release/health/capacity and correlations, not raw logs,
paths or secrets. Destructive recovery is an explicit operator action.

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
Next in P3-1: control-plane admission/refresh and signed offline node startup.
The node observation chain alone is not the completed observability product.
The prerequisite installation-scoped IAM and Audit boundaries and their
verification are owned by
[FEAT-006](FEAT-006-platform-authorities.md).
Platform host mutations, their Operation/Audit integration and explicit
authorization when upgrading an older installation remain unaccepted.
Retained-data schema migration alone does not establish runnable N-1
compatibility; the release's schema profile and rollback admission still need
the complete offline lifecycle gate.

## Adoption

- [FEAT-008 fixed-source review](../adoption/FEAT-008-linux-host-management.md)
