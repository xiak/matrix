# FEAT-002: LocalMachine infrastructure adapter

- Status: Accepted
- Target release: Private Application PaaS v0.1
- Adapter contract version: `v1`
- Target design date: 2026-08-25

## Outcome

Admit an explicitly configured local or remote machine as a normalized
`ExecutionTarget` without creating infrastructure and without exposing machine
access material to a public API. The adapter discovers stable machine identity,
capacity, health, labels, and supported isolation guarantees. Placement and
DeploymentExecutor features consume only the normalized observation.

This target design is fixed before the FEAT-002 donor implementation review.
Donor code can change implementation tactics only through a recorded
amendment.

## Incremental release gates

### Gate A: local machine

Gate A is the first usable backend increment and is sufficient to begin
FEAT-003 and FEAT-004 development:

1. A platform-installation binding named `local` selects the current machine.
2. A real cross-platform host probe returns a stable identity fingerprint,
   logical CPU, memory, storage, architecture, and observation time.
3. Docker Engine and Compose availability are probed through fixed commands;
   callers cannot submit a command, executable, argument, or host path.
4. Registration and refresh produce the same target identity for the same
   machine and fail on an unexpected identity change.
5. Unit tests use injected probes; a local integration test inspects the real
   host without requiring Docker to be healthy.

Docker unavailability may make a target `DEGRADED` or `UNAVAILABLE` for
Compose, but it must not falsify host capacity or silently advertise Compose
isolation.

Gate A observes the adapter process host and is immediately usable for a
host-native control-plane/worker. A containerized worker must not present its
container identity as the physical host. Release composition must explicitly
select the completed pinned-SSH probe or a separately accepted Docker-engine
or host-agent probe. The injected `HostProbe` boundary allows that replacement
without changing `ExecutionTarget` or placement contracts.

### Gate B: pinned remote Linux machine

Gate B completes FEAT-002:

1. A platform-installation SSH binding contains an endpoint, credential reference,
   expected host-key SHA-256 fingerprint, labels, and isolation allowlist.
2. The credential reference is resolved inside the composition root or an
   injected secret resolver. Private keys and passwords are never fields of a
   PaaS API resource, Operation, Evidence, or adapter observation.
3. Host-key pinning is mandatory. `InsecureIgnoreHostKey` and trust-on-first-use
   are forbidden.
4. The SSH executor accepts a closed probe identifier, not arbitrary command
   text. Each identifier maps to an adapter-owned command with a deadline and
   bounded stdout/stderr.
5. Remote tests use an ephemeral SSH server and prove host-key rejection,
   output limits, timeout normalization, and that unrecognized probes never
   reach the transport.

Remote Windows support and machine provisioning remain deferred. A remote
binding registers an existing Linux machine only.

## Ownership and trust boundaries

`LocalMachine` is an infrastructure adapter. It can observe an explicitly
bound machine; it cannot:

- create, destroy, reboot, patch, or resize a machine;
- choose a tenant or placement;
- authorize a caller;
- deploy or stop a workload;
- grant a stronger or weaker isolation guarantee than service policy permits;
- accept arbitrary SSH options, scripts, environment variables, or paths.

The service owns `ExecutionTarget` identity and desired state. Platform
installation configuration owns connection bindings. IAM owns authorization. The adapter
returns facts and normalized failures only.

## Binding model

A `MachineBinding` is server-side configuration, not a northbound resource.
Its minimum shape is:

| Field | Local | SSH | Rule |
| --- | --- | --- | --- |
| `id` | Required | Required | Opaque lookup identity placed in the adapter command envelope. |
| `kind` | `LOCAL` | `SSH` | Closed enum. |
| `endpoint` | Forbidden | Required | Parsed host and port; never returned in an observation. |
| `credentialRef` | Forbidden | Required | Opaque reference resolved internally. |
| `hostKeySHA256` | Forbidden | Required | Exact pinned server key fingerprint. |
| `expectedMachineFingerprint` | Optional | Optional | Once enrolled, identity changes fail closed. |
| `labels` | Optional | Optional | Operator-owned scheduling facts; bounded and sanitized. |
| `allowedIsolationGuarantees` | Required | Required | May contain only adapter-supported guarantees. |
| `storagePath` | Optional | Optional | Installation-owned capacity probe root; never tenant supplied. |

Binding validation occurs before network or process activity. Unknown fields,
duplicate labels/isolation guarantees, relative storage roots, missing pins, and
mixed local/SSH fields are rejected.

## Versioned adapter data

Concrete adapters live outside the PaaS service `internal/` tree. Therefore
all method parameter and result data they must compile against lives in the
versioned `api/paas/v1` adapter contract:

- `InspectExecutionTargetRequest` and `ObserveExecutionTargetRequest` carry only the common
  `AdapterCommandEnvelope`;
- `ExecutionTargetObservation` carries fingerprint, normalized labels,
  capacity, allocatable capacity, health, supported isolation guarantees, and timestamp;
- service-owned interfaces remain under
  `app/service/paas/internal/apphosting/port` and refer only to versioned data.

Endpoints, usernames, private keys, raw probe output, and native operating
system structs are not members of these types. This is a refinement of the
FEAT-001 Go package boundary, not a public northbound API addition.

Target inspection commands use `ResourceScope{kind: PLATFORM}`. Tenant scope is
invalid for machine registration, so the adapter never needs a fabricated
tenant ID.

## Identity and observation rules

1. The adapter derives a machine identity from a platform-stable machine ID,
   operating-system family, and architecture.
2. It returns only
   `sha256(canonical-version || machine-id || os || architecture)`; the raw
   machine ID is never returned or logged.
3. Canonical fields use length-prefix encoding so concatenation cannot create
   collisions.
4. The same facts always produce the same fingerprint across refreshes.
5. A missing stable machine ID is a terminal validation failure; hostname
   alone is not sufficient identity.
6. CPU is logical CPU multiplied by 1000 millicores. Memory and storage are
   bytes. Negative, overflowing, or impossible values are rejected.
7. Allocatable capacity is policy-derived and cannot exceed capacity.
8. Adapter and observation timestamps are UTC with microsecond precision.
9. Labels from the binding and safe discovered labels are merged with
   operator labels taking precedence; reserved authority labels cannot be
   overwritten by discovery.

## Health and isolation

The observation health is deterministic:

| Host probe | Docker Engine | Compose plugin | Health | Advertised guarantee |
| --- | --- | --- | --- | --- |
| Fails | Any | Any | `UNAVAILABLE` | None |
| Passes | Fails | Any | `DEGRADED` | None |
| Passes | Passes | Fails | `DEGRADED` | None |
| Passes | Passes | Passes | `READY` | Policy intersection |

FEAT-002 advertises only `WORKLOAD`, and only when the binding allowlist and
discovered Compose capability both contain it. `TENANT` and `HOST` are never
inferred from a machine probe.

`ObserveExecutionTarget` does not mutate target desired state or placement. It
returns a new observation; the service decides whether and how to persist it.

## Failure normalization

| Condition | Class | Stable code | Retryable |
| --- | --- | --- | --- |
| Invalid or mixed binding | `VALIDATION` | `INVALID_ARGUMENT` | No |
| Binding not found | `NOT_FOUND` | `NOT_FOUND` | No |
| Machine fingerprint changed | `CONFLICT` | `CONFLICT` | No |
| SSH host key mismatch | `PERMISSION_DENIED` | `ADAPTER_REJECTED` | No |
| Credential reference unavailable | `PERMISSION_DENIED` | `PERMISSION_DENIED` | No |
| Probe deadline | `TIMEOUT` | `DEADLINE_EXCEEDED` | Yes within operation budget |
| Transport unavailable | `UNAVAILABLE` | `EXECUTION_TARGET_UNAVAILABLE` | Yes |
| Malformed/oversized probe output | `VALIDATION` | `ADAPTER_REJECTED` | No |
| Unexpected adapter defect | `INTERNAL` | `INTERNAL` | No |

Returned messages contain the binding ID, probe identifier, and normalized
reason only. They cannot contain endpoints, usernames, command text, raw
stderr, credentials, or native driver errors.

All external label, failure-message, and safe discovered text rejects ASCII
control characters and known raw-secret markers before entering an
observation or Evidence. Remote output limits are applied while reading, not
after unbounded output has already been buffered.

## FEAT-002 acceptance evidence

### Gate A

1. `app/adapter/infrastructure/localmachine` implements the versioned
   `InfrastructureAdapter` method set without importing a service `internal/`
   package.
2. Local binding validation, identity canonicalization, capacity validation,
   capability intersection, health mapping, and failure normalization have
   exhaustive tests.
3. A real local-host integration test proves a non-empty stable fingerprint,
   positive CPU/memory/storage, bounded labels, and sanitized results.
4. Repeated inspection returns the same identity and does not create a side
   effect.
5. Tests prove public/versioned adapter data has no credential, SSH endpoint,
   arbitrary command, script, or host-path fields.

#### Gate A evidence

Accepted on 2026-08-25. Unit tests cover binding, identity, capacity,
capability intersection, health, scope, and normalized errors. A real local
inspection test exercises the host probe without requiring Docker readiness.

### Gate B

1. A pinned ephemeral SSH integration test completes all fixed remote probes.
2. Wrong pins and unknown probe identifiers fail before any probe is executed.
3. Deadline, output-size, and malformed-output failures map exactly to the
   normalized table.
4. A remote observation is byte-for-byte equivalent in normalized shape to a
   local observation with the same safe facts.

#### Gate B evidence

Accepted on 2026-08-25. A loopback ephemeral SSH server exercises every fixed
probe, mandatory host-key pinning, rejected credentials, deadline and
cancellation behavior, bounded stdout/stderr, malformed output, and redacted
failures. Unknown probe identifiers are rejected before transport execution.

The implementation adds `golang.org/x/crypto/ssh` as the only new direct
runtime dependency. Neither donor repository is linked, copied, or required
at build or runtime.

### Common gates

- Donor decisions record fixed commits and `REUSE`, `ADAPT`, `REFERENCE`, or
  `REJECT` per reviewed slice.
- `go test ./...`, `go vet ./...`, `go test -race ./...`, architecture tests,
  schema tests, and `git diff --check` pass.
- No donor repository is a build or runtime dependency.

## Deferred

Persisting ExecutionTarget and bindings, tenant placement, worker leases,
Compose effects, IAM/Audit integration, northbound registration endpoints,
cloud provisioning, Kubernetes discovery, remote Windows, and UI are owned by
later features.

## Donor-informed amendments

The fixed-commit review retained the target architecture and added two stricter
implementation details:

1. Reuse the legacy PaaS external-text rule: control characters and recognizable
   raw secret material fail closed even in fields otherwise considered safe.
2. Improve on the Senatria OpenSSH helper by enforcing output limits during
   the read itself. Its configuration and quoting tests are useful, but its
   optional insecure host checking, raw environment private key, arbitrary
   script API, and post-buffer size check are not admitted.

The complete comparison is recorded in
[`docs/adoption/FEAT-002-localmachine-adapter.md`](../adoption/FEAT-002-localmachine-adapter.md).
