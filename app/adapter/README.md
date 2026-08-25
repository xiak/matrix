# Adapters

Adapters translate stable PaaS contracts into external-system operations.
They do not own product semantics and cannot accept arbitrary shell commands,
script paths, SSH parameters, or raw credentials from public APIs.

Adapter classes:

- infrastructure adapters inventory compute and capacity;
- runtime adapters apply and observe workloads;
- gateway adapters manage workload ingress.

Public cross-process adapter contracts live under versioned `api/adapter/`
packages. Adapter implementations must not import any service's `internal/`
packages or own placement, authorization, or audit policy.
