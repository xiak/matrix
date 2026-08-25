# Matrix PaaS

Matrix PaaS is an independent platform product. It provides identity, audit,
control-plane, placement, runtime-provider, and user-experience capabilities
without embedding customer business applications.

## Product boundary

The product distribution includes:

- APISIX as the default northbound gateway;
- IAM as the identity and authorization authority;
- Audit as the unified audit authority;
- the PaaS control plane and worker;
- the independent PaaS UI;
- infrastructure, runtime, and gateway providers;
- a minimal Compose-based local distribution.

Backend, building, analysis, SenatriaAI, agent business features, and other
customer workloads do not belong in this repository. They may be managed by
Matrix PaaS through versioned APIs and providers.

## Repository layout

| Path | Responsibility |
| --- | --- |
| `api/` | Versioned public API, event, and schema contracts. |
| `app/service/` | Independently runnable IAM, Audit, and PaaS services. |
| `app/ui/paas/` | Independent Next.js/React PaaS console. |
| `platform/` | Shared, intentionally public foundations and SDKs. |
| `providers/` | Replaceable infrastructure, runtime, and gateway adapters. |
| `infra/` | Infrastructure owned by the PaaS distribution itself. |
| `deploy/` | Local and release deployment composition. |
| `docs/` | Architecture decisions, adoption records, and product design. |
| `test/` | Cross-component contract, integration, and end-to-end tests. |
| `tools/` | Repository-owned development and release tooling. |

Each Go service owns its binaries under `cmd/` and non-public implementation
under `internal/`. A root-level catch-all `pkg/` is deliberately avoided.

## Current phase

The repository is in P0: product-boundary and repository-baseline formation.
No runtime capability is considered implemented until it is present here,
tested here, and released from this repository.

See [the architecture index](docs/architecture/README.md) and
[the adoption policy](docs/adoption/README.md).
