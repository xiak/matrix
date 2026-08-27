# ADR-0002: private Application PaaS product boundary

- Status: Accepted
- Date: 2026-08-25

## Context

`xiak` is an invented brand word inspired by the Chinese word “侠客”, with
`xiak.com` as its domain. Matrix is the umbrella product and may contain
multiple independently bounded subproducts. Phase 1 delivers its ToB private
Application PaaS subproduct. That subproduct must install and operate without
Internet access, use customer-provided machines, and support application
deployment, operations, upgrade, rollback, recovery, identity, and audit.
Docker Engine is the default v0.1 substrate; Docker Compose is the first
application executor. Kubernetes may be added later.

Matrix's long-term product direction is an independently deployable private
cloud platform that can later evolve toward public-cloud operation.
Application PaaS is one product domain within it. The product evolves through
accepted vertical slices, not a one-step implementation of every cloud
capability. That direction must not turn the current PaaS into a universal API
spanning containers, virtual machines, functions and managed services.

## Decision

### Product boundary

The Phase 1 boundary is the privately delivered **Matrix Application PaaS**
subproduct. Its distribution contains IAM, Audit, APISIX, the PaaS control
plane and worker, the independent PaaS UI, approved adapters, PostgreSQL, and
an offline-capable Compose deployment. Customer business code, schemas, and
product-specific UIs remain external workloads.

APISIX protects northbound APIs and may implement application routing, but the
two roles use separate internal bindings and credentials. Its Admin API is
never exposed to browsers or tenants.

### Bounded contexts

```text
offline bundle -> installation
                       |
       IAM -------- Operation -------- Audit
                       |
                application hosting
                       |
              DeploymentExecutor
                 /          \
          Compose v0.1    Kubernetes later
```

| Context | Source of truth |
| --- | --- |
| `apphosting` | Application, immutable ApplicationRevision, Deployment, ExecutionPool, ExecutionTarget, placement, capacity reservation, and application lifecycle. |
| `installation` | Bootstrap journal, installation identity, platform release preflight/apply/verification, backup, rollback, and recovery. |
| `operation` | Durable command identity, idempotency, attempts, leases, unknown-outcome reconciliation, and generic asynchronous execution state. |
| `iam` | Tenant, principal, role, session, and authorization decision. |
| `audit` | Unified audit record, integrity, retention, and audit query. |

These are logical boundaries, not mandatory microservices. Phase 1 stays a
modular monolith except that IAM and Audit remain independently deployable
authorities. Operation is a shared mechanism; product contexts retain their
own state machines.

### Application and runtime boundary

The application-hosting model is:

```text
Application -> immutable ApplicationRevision -> Deployment
                                               -> PlacementDecision
                                               -> ExecutionTarget
```

One revision can be deployed more than once. Deployment owns configuration,
placement, readiness, health, current Operation, and rollback to a prior
accepted snapshot. ExecutionPool and ExecutionTarget describe provider-neutral
capacity; the apphosting context owns the DeploymentExecutor boundary.

The executor contract is portable only inside the bounded Matrix application
profile: digest-pinned OCI artifacts, components, endpoints, resource limits,
replicas, configuration/secret references, health expectations, and an exact
placement. It never accepts caller-provided shell, Compose YAML, Kubernetes
manifests, host paths, privileged mode, credentials, or provider-native blobs.

Compose owns rendering and project/network identity. Kubernetes may later
implement the same profile after passing its conformance suite. Native
Kubernetes, VM, serverless, or managed-data products receive separate domains
and APIs rather than entering `Runtime.Deploy(anySpec)`.

Kubernetes is an optional provider, not Matrix's resource authority,
installation prerequisite or mandatory UI vocabulary. Matrix owns identity,
authorization, desired state and product lifecycle. Shared application
experiences can use provider-specific execution, observation and access
adapters, with explicit capabilities where providers differ. An interactive
workload access session is separately authorized; it is not an arbitrary
command field in the Deployment contract.

Placement remains apphosting policy. Tenant-facing isolation describes a
guarantee, not Compose projects, Docker daemons, Kubernetes namespaces, or
other implementation mechanisms. The technology-shaped draft isolation
values are replaced before FEAT-003 Gate B. Unsupported guarantees remain
unschedulable and can never be silently downgraded.

### Private delivery and future evolution

Platform self-installation and upgrade are separate from tenant application
execution even when both use Docker. The first accepted release must prove a
clean network-disabled install plus platform backup, upgrade verification,
rollback/recovery, and sanitized support evidence. Exact bundle contents and
commands belong to the release FEAT and verified runbook, not this ADR.

Application PaaS remains one product domain as Matrix evolves. IAM, Audit,
Operation, policy, quota, metering, resource references and provider
connections may become shared foundation only after multiple real products
consume them. Product domains do not share a `UniversalWorkload`.

Each iteration delivers an independently runnable and verifiable product
slice. Its current security and offline-recovery obligations are implemented
with that slice, not postponed to a final hardening phase. Feature sequencing,
scope and release gates belong to the owning FEAT. Future capability alone
does not justify an empty provider framework or extra service boundary.

Public-cloud operation requires its own acceptance of untrusted-tenant
isolation, availability/failure domains, metering and abuse protection. A
private deployment or Compose workload isolation does not by itself prove
that readiness. Public exposure is not a deployment-mode shortcut around
those boundaries.

### Pragmatic DDD

Business rules stay in their owning context; use cases own workflow and
transactions; persistence and external systems are adapters. Add an
abstraction only when it protects a real invariant or boundary, isolates a
real side effect/variation, or contains current complexity. A domain noun by
itself does not justify a class, interface, repository, package, or layer.

Normative source dependencies live in
[`DEPENDENCY-RULES.md`](DEPENDENCY-RULES.md). Donor choices and fixed commits
remain in the existing FEAT adoption records.

## Consequences

- Application, Deployment, placement, and executor contracts use one
  provider-neutral vocabulary across Compose v0.1 and later executors.
- Compose is the shortest path to a usable private PaaS without becoming a
  tenant-facing product concept.
- Offline delivery and platform rollback are release gates, not later
  packaging work.
- Source repositories remain donors, never build or runtime dependencies.
