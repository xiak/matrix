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
4. Replaceable integrations live under `app/adapter/`, grouped by
   infrastructure, application-hosting, and gateway capability.
5. PaaS-owned deployment and ingress configuration lives under `deploy/`.
6. Shared code stays with its owning service until multiple concrete consumers
   justify a specifically named SDK or foundation; no generic top-level
   `platform/` directory is pre-created.
7. Cross-component verification lives in `test/`.
8. Repository tooling lives in `tools/`; a broad `hack/` directory is not
   introduced.
9. `staging/`, vendored dependencies, a root catch-all `pkg/`, and generated
   publication machinery are deferred until an evidenced need exists.

## Consequences

- IAM, Audit, control plane, and UI retain explicit release boundaries, while
  adapters remain independently replaceable and testable.
- Public API stability is visible and enforceable.
- Early development avoids Kubernetes-scale repository machinery.
- A future package can move to a dedicated repository without requiring a
  Kubernetes-style staging publisher today.

## References

- https://github.com/kubernetes/kubernetes
- https://github.com/kubernetes/kubernetes/blob/master/staging/README.md
