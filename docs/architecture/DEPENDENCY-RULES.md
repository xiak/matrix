# Dependency rules

These rules are normative and will become architecture-test inputs when code
is admitted.

## Allowed direction

```text
app/ui/platform ────┐
app/service/* ──────┼──> api/*
app/adapter/* ──────┘

app/service/*/cmd/* ──> owning service + allowlisted app/adapter/*
deploy/* assembles released artifacts; application code never imports it.
```

The arrows describe source dependencies. Runtime calls may point outward
through service-owned ports without reversing the source dependency rules.

Inside a Matrix bounded context such as `apphosting`, `delivery`,
`installation`, or `operation`:

```text
service/<transport> -> usecase/<command> -> domain
data/<technology> -> usecase-owned repository contract + domain
cmd/<binary> -> service/usecase + concrete adapters
```

## Rules

1. `api/` contains data and transport contracts only. It imports no service,
   adapter, infrastructure, or deployment implementation.
2. Each service owns its `internal/` tree. No other service, UI, or adapter may
   import it.
3. Services own product policy. Adapters cannot select placement, authorize
   requests, redefine workload identity, or become an audit authority.
4. Adapters implement stable ports or contracts and normalize external-system
   payloads before they reach service domain models.
5. Only composition roots under `app/service/*/cmd/` may construct concrete
   adapters. Domain and application code depend on interfaces.
6. Cross-process adapter contracts, when required, live under a versioned
   `api/adapter/` boundary. Service-local ports stay with their owning service.
7. UI depends only on generated or hand-maintained public client contracts. It
   never imports service implementation or APISIX Admin types.
8. `deploy/` is a composition boundary, never a reusable code library.
9. Cross-service database reads and writes are forbidden. Integration uses
   versioned APIs, events, and workload identities.
10. New shared code starts in its owning service. After at least two real
    consumers and a compatibility contract exist, an ADR may introduce a
    specifically named SDK or foundation instead of a generic `platform/`.
11. Every FEAT names its bounded context, invariant/source-of-truth owner,
    application use case, transaction boundary, and currently required ports
    before implementation.
12. Domain code cannot import usecase, data, transport, adapter, deployment,
    generated transport, provider SDK, or database-row packages.
13. Use cases own workflow and transaction coordination. Repositories and
    adapters cannot own domain decisions.
14. Business packages and exported business types cannot use ambiguous
    `Manager`, `Helper`, `Logic`, `DAO`, `Model`, or `DTO` names.
15. Deployment-executor interfaces are owned by one product domain. A Compose,
    Kubernetes, VM, function, or cloud-provider schema cannot become a shared
    universal workload contract.
16. Platform installation and upgrade code cannot use the tenant application
    executor as its source of truth or privileged control path.
17. Provider technology names cannot appear in tenant-facing isolation
    guarantees. Adapters must produce evidence showing how a product guarantee
    was fulfilled.
18. Offline distribution artifacts are assembled under `deploy/`; product
    lifecycle policy remains in the `installation` context and is exercised
    through explicit ports.
19. Foundation contains only authorities or mechanisms with at least two real
    product consumers and one compatibility contract. It cannot become a
    catch-all product-services package.
20. Product-to-product integration uses the provider product's versioned public
    API and a narrowly authorized service identity. Application PaaS cannot
    depend on DevOps; DevOps cannot read or write apphosting storage.
21. The DevOps `BuildExecutor` and Application PaaS
    `DeploymentExecutor` remain separately owned contracts. They cannot share
    a universal executor, credential, provider payload, or conformance suite.
22. The platform UI shell may compose product UI modules in one deployable, but
    shell and modules consume public APIs only. Installed-product navigation
    comes from the installation-owned signed release inventory and readiness,
    not from hard-coded availability or a mutable browser plugin manifest.

These rules refine the product boundary in
[ADR-0002](ADR-0002-product-boundary.md). Architecture tests, rather than
duplicated prose in each FEAT, enforce them during normal implementation.
