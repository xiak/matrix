# API contracts

This directory owns the public, versioned contracts of Matrix PaaS.

Contract groups:

- `iam/v1` and `audit/v1` integration contracts;
- [`paas/v1`](paas/v1/) control-plane resources and adapter envelopes;
- runtime target, placement, workload release, and operation schemas;
- adapter contracts and audit event envelopes.

Contracts must remain independent from APISIX, Compose, Kubernetes, and cloud
vendor payloads. Adapter-native responses must not become public API types.
