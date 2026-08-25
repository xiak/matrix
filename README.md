# Matrix PaaS

Matrix PaaS is an independent platform product. It provides identity, audit,
control-plane, placement, runtime execution, and user-experience capabilities
without embedding customer business applications.

## Product boundary

The product distribution includes:

- APISIX as the default northbound gateway;
- IAM as the identity and authorization authority;
- Audit as the unified audit authority;
- the PaaS control plane and worker;
- the independent PaaS UI;
- infrastructure, runtime, and gateway adapters;
- a minimal Compose-based local distribution.

Backend, building, analysis, SenatriaAI, agent business features, and other
customer workloads do not belong in this repository. They may be managed by
Matrix PaaS through versioned APIs and adapters.

## Repository layout

| Path | Responsibility |
| --- | --- |
| `api/` | Versioned public API, event, and schema contracts. |
| `app/service/` | Independently runnable IAM, Audit, and PaaS services. |
| `app/adapter/` | Replaceable infrastructure, runtime, and gateway integrations. |
| `app/ui/paas/` | Independent Next.js/React PaaS console. |
| `deploy/` | Local and release deployment composition. |
| `docs/` | Architecture decisions, adoption records, and product design. |
| `test/` | Cross-component contract, integration, and end-to-end tests. |
| `tools/` | Repository-owned development and release tooling. |

Each Go service owns its binaries under `cmd/` and non-public implementation
under `internal/`. Shared code remains with its owning service until multiple
real consumers justify a specifically named SDK or foundation. Root-level
catch-all `pkg/`, `platform/`, and `infra/` directories are deliberately
avoided.

## Current phase

The repository is in P0: product-boundary and repository-baseline formation.
No runtime capability is considered implemented until it is present here,
tested here, and released from this repository.

See [the architecture index](docs/architecture/README.md) and
[the adoption policy](docs/adoption/README.md).
