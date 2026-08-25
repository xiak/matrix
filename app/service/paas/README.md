# PaaS service

This service owns the control-plane and worker processes.

FEAT-001 has admitted the following service-owned packages:

```text
internal/
  port/          # interfaces required by the service
  runtime/       # lifecycle and external command identity
```

FEAT-002 through FEAT-006 add the `cmd/` composition roots and the
infrastructure, placement, operation persistence, and transport use cases only
when their acceptance slices are executable.

The control plane owns RuntimeTarget, PlacementPolicy, PlacementDecision,
WorkloadRelease, and Operation. It delegates identity to IAM, unified audit to
Audit, and external effects to allowlisted adapters.

Cross-process adapter contracts, when required, are versioned under
`api/adapter/`. Service-local ports remain owned by this service.
