# ADR-0001: Repository layout

- Status: Accepted
- Date: 2026-08-25

## Context

The Kubernetes repository demonstrates useful control-plane engineering
principles: versioned API ownership, separate command binaries, explicit test
and build areas, and strong component boundaries. Its current repository also
contains `cluster`, `hack`, `pkg`, `plugin`, `staging`, and `vendor` structures
that support Kubernetes' exceptional scale and publication workflow.

In particular, Kubernetes documents `staging/` as the source area from which
many separate `k8s.io/*` repositories are published. Matrix PaaS does not have
that release topology in P0.

## Decision

Matrix PaaS will borrow principles, not directory names wholesale:

1. Public contracts live in a versioned top-level `api/` boundary.
2. Independently runnable products live under `app/service/` and `app/ui/`.
3. Each Go service owns `cmd/` binaries and `internal/` implementation.
4. Providers are explicit top-level adapters grouped by capability class.
5. PaaS-owned ingress and deployment assets live in `infra/` and `deploy/`.
6. Cross-component verification lives in `test/`.
7. Repository tooling lives in `tools/`; a broad `hack/` directory is not
   introduced.
8. `staging/`, vendored dependencies, a root catch-all `pkg/`, and generated
   publication machinery are deferred until an evidenced need exists.

## Consequences

- IAM, Audit, control plane, worker, UI, and providers can release separately
  while remaining in one product repository.
- Public API stability is visible and enforceable.
- Early development avoids Kubernetes-scale repository machinery.
- A future package can move to a dedicated repository without requiring a
  Kubernetes-style staging publisher today.

## References

- https://github.com/kubernetes/kubernetes
- https://github.com/kubernetes/kubernetes/blob/master/staging/README.md
