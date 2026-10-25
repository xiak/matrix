# ADR-0002: private-cloud foundation and product boundary

- Status: Accepted
- Date: 2026-09-07

## Context

`xiak` is an invented brand word inspired by the Chinese word “侠客”, with
`xiak.com` as its domain. Matrix began with a privately delivered Application
PaaS, but the accepted product direction is now a private-cloud platform with
independently bounded products. Application PaaS remains one product; DevOps
becomes a second optional product. More products may follow.

Matrix's long-term product direction is an independently deployable private
cloud platform that can later evolve toward public-cloud operation.
Application PaaS is one product domain within it. The product evolves through
accepted vertical slices, not a one-step implementation of every cloud
capability. That direction must not turn the current PaaS into a universal API
spanning containers, virtual machines, functions and managed services.

## Decision

### Platform and product map

Matrix is split into a private-cloud foundation and optional products:

```text
Matrix private-cloud platform
├── Foundation
│   ├── installation and release lifecycle
│   ├── IAM
│   ├── Audit
│   ├── northbound gateway
│   └── signed product discovery and readiness
├── Application PaaS product
│   └── application hosting and deployment
└── DevOps product
    └── source-triggered verification, build, artifact, and delivery workflow
```

Foundation is a shared control foundation, not an IaaS product and not a
generic workflow engine. A capability belongs in Foundation only when at least
two real products require one authority and one compatibility contract.
Otherwise it remains inside its owning product.

Application PaaS and DevOps are separately selectable products. Installation
may package both in one signed offline release, but the signed release manifest
declares which products are installed and healthy. A navigation tile, route,
permission, or API cannot claim an unavailable product. Separate commercial
packages or independent release trains are deferred until licensing, ownership,
scaling, failure isolation, or customer lifecycle creates a real boundary.

### Authority and dependency direction

| Authority | Owner |
| --- | --- |
| Installation identity, release inventory, installed-product discovery, upgrade, rollback, backup, and recovery | `installation` foundation context |
| Organization, principal, session, role, service identity, and authorization decision | `iam` foundation authority |
| Immutable security and product facts | `audit` foundation authority |
| Durable command identity, attempt, lease, fencing, receipt, and unknown-outcome mechanism | The `operation` mechanism composed by each owning context |
| Application, immutable ApplicationRevision, Deployment, placement, runtime observation, and application rollback | `apphosting` product context |
| Source connection, repository binding, normalized source event, immutable pipeline revision, build run, check result, artifact evidence, and delivery handoff | `delivery` DevOps product context |

The allowed product dependency is:

```text
DevOps ──versioned public API──> Application PaaS
   │                                  │
   └──────────> Foundation <──────────┘
```

Application PaaS never imports DevOps contracts, reads DevOps storage, waits
for a DevOps run, or needs DevOps to accept a deployment. DevOps submits an
exact verified artifact through the ordinary PaaS API using a narrowly
authorized service identity. The resulting Operation, Deployment generation,
placement, rollout, observation, and rollback remain PaaS truth. Direct
executor or database calls across that boundary are forbidden.

The physical PostgreSQL server may be shared in the first release, but product
and foundation contexts use separate schemas, owners, migration identities,
runtime roles, credentials, and connection pools. They receive no
cross-schema table grants. Integration uses versioned contracts and durable
identities even when code is composed into one process.

### Product APIs and unified UI

Public contracts stay product-scoped:

- `api/paas/v1` owns Application PaaS contracts;
- `api/devops/v1` owns DevOps contracts;
- Foundation authorities own their existing versioned contracts.

The Matrix UI has one platform shell for authentication, organization/project
context, product discovery, navigation, global operation correlation, and
safe readiness. Each product owns its information architecture, routes,
permissions, empty/error states, and resource views behind that shell. The
shell consumes public APIs only; it does not join product databases or import
service internals.

A single deployable UI and shared design system are the Phase 1 default.
Micro-frontends, runtime-loaded JavaScript, and a general plugin marketplace
are not required to prove product independence. The installed-product manifest
is signed release data, not mutable browser configuration.

### Product-specific execution boundaries

Application PaaS owns a `DeploymentExecutor` for a bounded Matrix application
profile: digest-pinned OCI artifacts, components, endpoints, resource limits,
replicas, configuration/secret references, health expectations, and exact
placement. It never accepts caller-provided shell, Compose YAML, Kubernetes
manifests, host paths, privileged mode, credentials, or provider-native blobs.

DevOps owns a separate `BuildExecutor` for untrusted source verification and
image construction. Its credentials, network, isolation, quotas, evidence,
failure modes, and conformance suite are distinct from application execution.
Build code cannot receive source-provider, registry-publisher, IAM, Audit,
PaaS, host, or runner-control credentials.

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

### DevOps provider boundary

Matrix Native is the default DevOps authority. It admits source events, selects
an immutable pipeline revision, coordinates isolated execution, records
normalized results, and verifies artifact evidence.

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

These are logical boundaries, not mandatory microservices. Phase 1 stays a
modular monolith except where an already accepted authority or runtime
isolation requires an independent process. A context is split physically only
for a real scaling, release, ownership, failure-isolation, security, data, or
commercial boundary.

Business rules remain in their owning context; use cases own workflow and
transactions; persistence and external systems are adapters. An abstraction is
added only when it protects a current invariant or boundary, isolates a real
side effect or variation, or contains existing complexity.

Normative source dependencies live in
[`DEPENDENCY-RULES.md`](DEPENDENCY-RULES.md). Detailed requirements and
acceptance evidence remain in the owning FEAT. Fixed donor commits and
`REUSE`/`ADAPT`/`REFERENCE`/`REJECT` decisions remain in adoption
records.

## Consequences

- Matrix can present one private-cloud experience while products retain
  separate authority, vocabulary, APIs, storage, and lifecycle.
- Customers may install Application PaaS without DevOps, or add DevOps without
  replacing PaaS deployment truth.
- DevOps can offer native and connected execution profiles without exposing
  provider-native systems as Matrix contracts.
- The first release avoids premature service, database, UI, and packaging
  fragmentation while preserving seams that can later be split for evidence-
  based reasons.
- New products integrate through Foundation contracts and their own APIs; they
  do not enlarge PaaS or DevOps into universal domains.
