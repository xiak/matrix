# PaaS service

This service will own the control-plane and worker processes.

Planned internal layout:

```text
cmd/
  control-plane/
  worker/
internal/
  api/
  operation/
  placement/
  port/          # interfaces required by the service
  runtime/
```

The control plane owns RuntimeTarget, PlacementPolicy, PlacementDecision,
WorkloadRelease, and Operation. It delegates identity to IAM, unified audit to
Audit, and external effects to allowlisted adapters.

Cross-process adapter contracts, when required, are versioned under
`api/adapter/`. Service-local ports remain owned by this service.
