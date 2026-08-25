# Dependency rules

These rules are normative and will become architecture-test inputs when code
is admitted.

## Allowed direction

```text
app/ui/paas ────────┐
app/service/* ──────┼──> api/*
app/adapter/* ──────┘

app/service/*/cmd/* ──> owning service + allowlisted app/adapter/*
deploy/* assembles released artifacts; application code never imports it.
```

The arrows describe source dependencies. Runtime calls may point outward
through service-owned ports without reversing the source dependency rules.

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
