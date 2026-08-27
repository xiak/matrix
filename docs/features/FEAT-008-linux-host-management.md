# FEAT-008: existing Linux hosts and remote application delivery

- Status: Target design fixed; implementation and acceptance pending
- Target: Matrix PaaS Phase 3
- Target design date: 2026-08-27
- Development branch: `feat/linux-host-management`
- Fixed integration baseline: `f5ce412ff795abdaf5ba8e5fe112378f1cd1af41`

## Outcome and isolation

An operator enrolls existing Linux hosts, observes their identity, health and
resource usage, enables or drains their scheduling capacity, and delivers
applications to them through the current IAM-authorized, audited Deployment
workflow. A resident node agent executes Docker/Compose locally and retains
durable effect receipts. Signed offline installation, operations, upgrade,
rollback and recovery cover the platform and its enrolled nodes.

Phase 3 has its own branch, worktree, artifact names and disposable runtime
environment. The fixed integration baseline includes Phase 2 code; this work
does not modify, reset, merge into, redeploy or stop the progressing Phase 2
branch or environment. Its console and managed PostgreSQL behavior remain
regression requirements. Host administration initially uses the operator CLI
and API, without changing the Phase 2 UI.

This target is fixed before opening donor implementation slices. This FEAT
owns Phase 3 requirements, design, status and acceptance. Existing FEATs keep
their already accepted contracts; prior local execution evidence does not
prove remote delivery or Phase 3 acceptance.

## Supported profile

1. One control-plane installation manages at least two independent existing
   Linux/amd64 workload hosts. Supported Docker Engine and Compose are host
   prerequisites. Provisioning virtual machines, installing an OS or Docker,
   changing customer firewalls or daemon configuration, and control-plane HA
   are outside this release.
2. The application profile remains digest-addressed OCI artifacts, exact
   configuration and Secret versions, workload isolation, resource limits,
   network-local endpoints and immutable Deployment generations. The platform
   never accepts tenant shell, Compose YAML, Docker options or host paths.
3. A resident Go node agent runs under a supervisor. The first transport is
   bounded, mutually authenticated HTTPS over the private management network.
   The control plane calls a closed node protocol; there is no general remote
   command, terminal, port-forwarding or filesystem API. The management
   listener must not be exposed as a public or tenant-facing endpoint.
4. Nodes have an installation identity and an exact ExecutionTarget identity.
   They receive no control-plane database credentials, IAM signing authority,
   scheduling authority or credentials for another node. Installation owns
   certificate provisioning, trust, renewal/revocation and release selection.
5. Network disconnection preserves already accepted workloads. Durable local
   receipts and runtime observations allow reconnection and restart recovery;
   a timeout is never proof that a submitted effect did not happen. A node
   does not relocate work or invent a new desired generation while offline.
6. Neither platform nor nodes need a registry, package repository, Internet
   access, donor checkout, Python or mutable orchestration scripts to install,
   execute applications or perform supported lifecycle operations.

## Ownership and extension boundaries

| Concern | Owner |
| --- | --- |
| Target identity, admission, pool membership, scheduling intent and drain | Existing `apphosting` ExecutionTarget/ExecutionPool; no duplicate Machine resource |
| Placement, reservations, immutable generations and durable Operations | Existing apphosting use cases and PostgreSQL transactions |
| Local machine facts | InfrastructureAdapter and platform-normalized observations |
| Remote execution transport | DeploymentExecutor adapter over versioned `api/adapter/node/v1` data |
| Node process, bounded request handling and effect recovery | `nodeagent`; a real host-side failure/security boundary |
| Compose generation, project identity, secret handling, locks and receipts | Existing Compose adapter, constructed only at the node composition root |
| Addresses, certificates, trust, executable paths and secret roots | Protected installation configuration, never public resource attributes |
| Release staging, node install, verification, upgrade and rollback | `installation`, separate from tenant execution |
| Historical host/container metrics and queries | Observability integration using a pinned existing collector, not a second scheduler |
| Authorization and business audit | Existing IAM and transactional Audit outbox |

The source-of-truth boundary is deliberately asymmetric: PostgreSQL owns
desired state and accounting; nodes own only effects and their observed state.
Telemetry is not a second source of scheduling reservations or audit evidence.
New ports protect actual transport, credentials or transaction boundaries.
No universal runtime, workflow engine, provider registry or second Compose
implementation is introduced. A later executor can implement the existing
application port without becoming a node-agent command extension.

## Host admission and scheduling

1. An operator supplies a protected node connection binding. The service
   resolves it server-side, probes outside the transaction, then commits the
   accepted machine fingerprint, target, pool association, Operation and
   sanitized audit event atomically. Tenant input cannot select an endpoint,
   certificate, executable or root directory.
2. Enrollment supports exact idempotency replay; changed input conflicts.
   Updates require optimistic concurrency. Duplicate machine identity under
   another target and conflicting binding ownership are rejected.
3. Refresh changes observed health/capacity/freshness, never operator intent.
   Unexpected machine identity, unavailable runtime, stale observation or an
   unsupported isolation guarantee prevent new placement. One unreachable
   node must not stop work on healthy nodes.
4. Drain prevents new reservations but preserves existing workloads and their
   stop/recovery routing. Removal is rejected while active/pending capacity,
   a live Deployment or an unresolved effect still requires the target.
   Drain/removal do not reboot hosts or remove unrelated Docker objects.
5. Every command and observation is bound to its persisted placed target.
   Retries, application rollback and stop cannot silently fall back to the
   control-plane engine or another host. Uncertain effects prohibit implicit
   cross-host relocation.
6. Operator-defined pools/policies use existing placement and tenant rules.
   Forced RLS, least-privilege roles, fencing, immutable snapshots and capacity
   conservation remain mandatory.

## Closed node protocol and runtime safety

Versioned requests admit only capabilities, target inspection/observation,
deployment validation, apply, observation, stop and application rollback.
Exactly one action-specific payload is permitted. Unknown fields, versions,
actions, duplicate JSON keys, trailing documents, excessive length/depth and
mismatched request/result identities fail closed.

mTLS authenticates the installation controller and exact node. Trust roots,
certificate identity and validity are verified; an arbitrary CA-signed client
is not automatically a controller. Authentication, target/binding identity,
deadline and generation validation precede effects. No insecure TLS option is
supported. Requests and responses are bounded while streaming, concurrency
and deadlines are bounded, and raw provider failures are never returned.

The node reuses the existing Compose compiler, restrictive filesystem writes,
project locks and command receipts. Equal replay returns the same receipt;
conflicting digests or stale desired generations fail. A lost response after
dispatch becomes an uncertain outcome; the worker observes the same target
before another effect and rejects stale lease results.

Image digests resolve only to verified, already-loaded images on that host.
Pull/build and tag fallback are forbidden. Exact Secret versions are supplied
through installation-owned protected files or the existing resolver boundary;
they are not added to remote request resources. Missing image/Secret material
fails before an effect. Configuration values and secret material are absent
from logs, errors, receipts, Operations, audit and support output.

## Host observability and resource accounting

Observability explicitly includes the machine, not just application logs or
traces. The accepted scope is the operating system visible to the agent: a
guest VM's measurements do not claim to describe its physical hypervisor.

| Category | Required observations |
| --- | --- |
| Identity/inventory | Stable target/fingerprint, OS/architecture, logical CPU count, memory and managed filesystem capacity |
| CPU | Utilization, load and I/O-wait with an explicit sampling interval |
| Memory | Total, available, used and swap usage |
| Filesystems | Capacity, used/available bytes and inode usage per admitted filesystem |
| Disk I/O | Read/write bytes, operations and duration/rate where the host supports them |
| Network | Interface receive/transmit bytes, errors and dropped packets |
| Docker | Container CPU/memory and separately attributed image, writable-layer and volume storage usage |

Reuse a pinned mature collector for host telemetry; runtime-specific facts
come through a bounded Docker observation adapter. An authenticated query
surface exposes current samples and bounded historical ranges with units,
timestamps, interval and freshness. Missing, stale or unsupported measurements
remain explicit, never fabricated as zero. Collection avoids unbounded labels,
process arguments, secret values or unredacted paths in tenant responses.
Shared image layers are not summed as exclusive per-container disk ownership.

Capacity, allocatable capacity, durable reservations and instantaneous usage
are different facts. Scheduling deducts accepted reservations from allocatable
capacity; a temporarily idle CPU does not release its reservation. Disk or
memory pressure can make a target ineligible for new work, but a metrics
backend outage cannot erase reservations or imply workload termination.

Collectors and the high-privilege execution agent have independent process
and permission boundaries, although one offline distribution installs both.
Queries enforce operator/tenant visibility. A complete APM, arbitrary log
search, hardware BMC/SMART integration and custom alerting language are not
required by this release.

## Offline installation, operations and recovery

The signed distribution includes exact node executable/collector versions,
approved images and protocol compatibility metadata. Installation authenticates
and stages payloads, verifies loaded image identities, binds node/installation
identity, starts supervised processes, verifies real authenticated execution
and observation, then commits the active release. Restart/replay must not
overwrite ownership or unrelated files and Docker objects.

Upgrade stages a compatible candidate without rewriting accepted receipts or
Secrets. Failed verification restores the previous executable/configuration
selection; explicit N-1 rollback retains compatible data and running workloads.
Both versions must read retained receipts and communicate with the supported
control-plane version. Interrupted activation is reconciled from sealed
lifecycle state, not directory presence. Certificate renewal and revocation
are verified independently of an application generation change.

Existing platform backup, recovery, status and support remain required.
Node support contains bounded normalized identities, release/health/capacity
facts and correlations, not credentials, configuration, raw logs or host
paths. Destructive backup recovery remains an explicit operator action.
Only executed operational commands enter a verified runbook.

## Acceptance gates

### A: contracts and node security

- Closed request/response validation, correlation and adapter conformance.
- Real mTLS rejects unknown/expired/wrong-node certificates and wrong
  controller identity before any effect; enrollment identity cannot drift.
- Streaming size/depth limits, deadlines/cancellation, bounded concurrency,
  redaction, target/binding mismatch, replay/conflict and restart tests.
- Existing domain, service, adapter and installation dependency gates.

### B: durable host and application workflow

- Clean real PostgreSQL migration apply-twice and structural privilege checks;
  IAM authorization, RLS/role denial, audit correlation and deduplication.
- Enrollment replay/conflict/collision, refresh freshness, enable/drain/remove
  safety and concurrent updates/reservations.
- Exact multi-target dispatch, lost-response reconciliation, stale-fence
  rejection and no cross-host/local fallback.
- Existing Phase 1 and Phase 2 contracts pass regression tests on this branch.

### C: real host resources and remote execution

- Two independent Linux Docker Engines and resident agents execute validate,
  apply, update, observe, application rollback and stop through the worker.
- Digest fixtures verify ENV/Secret behavior, limits, project networks, no
  published application ports, placement isolation and accounting.
- Real CPU/memory/filesystem/I/O/network/container samples are queryable;
  controlled CPU activity and a known-size file change affect the appropriate
  measurements. Stale data, collector restart, access denial and unavailable
  metrics never become false zero usage or released reservations.
- Wrong node identity, unavailable host, missing image/Secret, lost response,
  duplicate command, host restart and competing workers are exercised.

### D: complete clean offline multi-host lifecycle

- A clean control-plane engine and two clean workload engines start without
  release images, Matrix containers, volumes or installation state. External
  egress stays disabled throughout acceptance; only their private network is
  available. Two containers sharing one engine are not multi-host evidence.
- Signed Release A installs the actual platform and both nodes, enrolls them,
  and completes authenticated/audited generations and all Gate C behavior.
- Tampered bundles and a failed candidate are rejected/rolled back. Compatible
  Release B upgrades platform and nodes while preserving identity, receipts,
  Secrets, workloads, resource observations and audit history; explicit N-1
  rollback returns to A without discarding compatible data.
- Drain/unavailability, protected backup/recovery, certificate lifecycle,
  node/control-plane restart, repeated verify/status and sanitized support
  pass. Phase 2 files, branches and runtime objects remain untouched.

### E: evidence and release closure

- The exact committed source passes generation drift, module verification,
  unit, vet, race, repeated critical tests, architecture, real PostgreSQL and
  security tests, adapter tests, cross-platform builds, links, donor dependency
  and secret/path scans, plus `git diff --check`.
- Fixed donor decisions are complete; no donor is a build/runtime dependency.
- GitHub independently runs applicable gates and tracks substantive Phase 3
  work/artifacts without changing Phase 2 delivery state.
- This FEAT records exact source/release identities and requirement-matched
  evidence. All gates, including the real offline multi-host E2E, are required
  for Phase 3 completion.

## Implementation evidence

Target design only. No Phase 3 acceptance gate has passed.

## Adoption

- [FEAT-008 fixed-source adoption](../adoption/FEAT-008-linux-host-management.md)
