# ADR-0002: private Application PaaS product boundary

- Status: Accepted
- Date: 2026-08-25

## Context

Matrix is first a ToB PaaS delivered into a customer's private environment.
It must install and operate without Internet access, use customer-provided
machines, and support application deployment, operations, upgrade, rollback,
recovery, identity, and audit. Docker Engine is the default v0.1 substrate;
Docker Compose is the first application executor. Kubernetes may be added
later.

Matrix may eventually grow into a cloud platform. That future must not make
the current product a universal API spanning containers, virtual machines,
functions, Kubernetes-native resources, and managed services.

## Decision

### Product boundary

Matrix is a privately delivered **Application PaaS**. Its distribution
contains IAM, Audit, APISIX, the PaaS control plane and worker, the independent
PaaS UI, approved adapters, PostgreSQL, and an offline-capable Compose
deployment. Customer business code, schemas, and product-specific UIs remain
external workloads.

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

If Matrix later becomes a cloud platform, Application PaaS remains one product
domain. IAM, Audit, Operation, policy, quota, metering, resource references,
and provider connections may become shared foundation only after multiple
real products consume them. Product domains do not share a
`UniversalWorkload`.

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
