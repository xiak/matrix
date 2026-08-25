# Providers

Providers translate stable PaaS contracts into external-system operations.
They do not own product semantics and cannot accept arbitrary shell commands,
script paths, SSH parameters, or raw credentials from public APIs.

Provider classes:

- infrastructure providers inventory compute and capacity;
- runtime providers apply and observe workloads;
- gateway providers manage workload ingress.

Public provider contracts live under versioned `api/provider/` packages.
Provider implementations must not import any service's `internal/` packages.
