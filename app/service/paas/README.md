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
  provider/      # registry, policy, and orchestration only
  runtime/
```

The control plane owns RuntimeTarget, PlacementPolicy, PlacementDecision,
WorkloadRelease, and Operation. It delegates identity to IAM, unified audit to
Audit, and external effects to allowlisted providers.

Public provider contracts are versioned under `api/provider/`; they are not
defined in this service's `internal/` tree.
