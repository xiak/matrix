# PaaS service

This service owns the control-plane and worker processes.

The service is a modular monolith. Phase 1 has three deliberate PaaS contexts:

- `apphosting` owns customer application hosting and placement;
- `operation` owns durable asynchronous execution mechanics;
- `installation` owns private platform bootstrap, upgrade, rollback, and
  recovery.

Each bounded context under `internal/` uses tactical layers only when the
current implementation needs them:

```text
internal/
  <context>/
    domain/      # aggregate behavior, values, and pure rules
    usecase/     # application commands and transaction coordination
    port/        # context-owned external-effect interfaces
    data/        # persistence implementations and boundary mapping
```

Composition roots and transport layers are added only when their executable
use cases exist.

No empty layers or speculative interfaces are created. Package and type names
must reveal their DDD role; ambiguous `Manager`, `Helper`, `Logic`, `DAO`,
`Model`, and `DTO` business names are rejected.

The apphosting context owns Application, ApplicationRevision, Deployment,
ExecutionTarget, PlacementPolicy, and PlacementDecision. Operation remains a
separate shared mechanism. The service delegates identity to IAM, unified
audit to Audit, and external effects to allowlisted adapters.

Cross-process adapter contracts, when required, are versioned under
`api/adapter/`. Service-local ports remain owned by this service.
