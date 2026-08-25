# Matrix PaaS

Matrix PaaS is a Docker-first enterprise Application PaaS for private
delivery. It provides identity, audit, durable operations, application
hosting, placement, execution, offline installation/upgrade, and
user-experience capabilities without embedding customer business
applications.

## Product boundary

The product distribution includes:

- APISIX as the default northbound gateway;
- IAM as the identity and authorization authority;
- Audit as the unified audit authority;
- the PaaS control plane and worker;
- the independent PaaS UI;
- infrastructure, application-executor, and gateway adapters;
- a digest-pinned, offline-capable Compose-based private distribution.

Backend, building, analysis, SenatriaAI, agent business features, and other
customer workloads do not belong in this repository. They may be managed by
Matrix PaaS through versioned APIs and adapters.

## Repository layout

| Path | Responsibility |
| --- | --- |
| `api/` | Versioned public API, event, and schema contracts. |
| `app/service/` | Independently runnable IAM, Audit, and PaaS services. |
| `app/adapter/` | Replaceable infrastructure, application-executor, and gateway integrations. |
| `app/ui/paas/` | Independent Next.js/React PaaS console. |
| `deploy/` | Local and release deployment composition. |
| `docs/` | Formal architecture, FEAT, adoption, and verified runbook documents. |
| `notes/codex/` | Non-authoritative, Git-portable Codex task checkpoint. |
| `test/` | Cross-component contract, integration, and end-to-end tests. |
| `tools/` | Repository-owned development and release tooling. |

Each Go service owns its binaries under `cmd/` and non-public implementation
under `internal/`. Shared code remains with its owning service until multiple
real consumers justify a specifically named SDK or foundation. Root-level
catch-all `pkg/`, `platform/`, and `infra/` directories are deliberately
avoided.

## Development

The owning FEAT document is the only source for its requirements, design,
implementation status, acceptance criteria, and evidence. Start from the
[feature links](docs/features/README.md). Read an
[architecture decision](docs/architecture/README.md) only for a cross-FEAT
boundary change.
