# Dependency rules

These rules are normative and will become architecture-test inputs when code
is admitted.

## Allowed direction

```text
api  <── platform
 │          │
 ├──────────┼──── app/service/*
 ├──────────┼──── app/ui/paas
 └──────────┴──── providers/*

deploy/* and infra/* assemble released artifacts; application code never
imports them.
```

The diagram indicates dependencies pointing toward `api` and `platform`.

## Rules

1. `api/` contains data and transport contracts only. It imports no service,
   provider, infrastructure, or deployment implementation.
2. `platform/` may depend on versioned `api/` contracts. It contains no PaaS,
   IAM, Audit, Compose, APISIX, Kubernetes, or cloud-vendor product semantics.
3. Each service owns its `internal/` tree. No other service, UI, or top-level
   provider may import it.
4. Public provider contracts live under a versioned `api/provider/` boundary,
   not under `app/service/paas/internal/`.
5. `app/service/paas/internal/provider/` may own registry, orchestration, and
   policy logic, but not the public adapter contract.
6. Providers depend on public contracts and SDKs. The control plane discovers
   them through explicit registration; it does not import vendor payloads into
   domain models.
7. UI depends only on generated or hand-maintained public client contracts. It
   never imports service implementation or APISIX Admin types.
8. `infra/` and `deploy/` are composition boundaries, never reusable code
   libraries.
9. Cross-service database reads and writes are forbidden. Integration uses
   versioned APIs, events, and workload identities.
10. New shared code starts in its owning service. It moves to `platform/` only
    after at least two real consumers and a compatibility contract exist.
