<div align="center">

<img src="app/ui/paas/_frontend/public/brand/matrix-horizontal-cyan.svg" alt="Matrix Cloud" width="420" />

### Your cloud. In control. Every possibility. Connected.

Private-cloud control plane for infrastructure, application delivery, managed services, identity, and operations.

[Feature contracts](docs/features/README.md) ·
[Install Matrix](docs/runbooks/platform-installation.md) ·
[Architecture](docs/architecture/README.md) ·
[API contracts](#api-contracts)

[![Verification](https://github.com/xiak/matrix/actions/workflows/verification.yml/badge.svg?branch=main)](https://github.com/xiak/matrix/actions/workflows/verification.yml)

</div>

![Matrix Cloud control-plane overview](.github/assets/readme/control-plane-overview.png)

## One control plane for the private cloud

Matrix brings infrastructure, applications, cloud services, delivery workflows,
identity, and day-two operations into one account-aware console. The product is
implemented as a modular monolith with explicit bounded contexts and versioned
contracts, so a private deployment can start small without closing the path to
larger cloud operations.

Capabilities ship as independently accepted vertical slices. A screenshot,
route, or MOCK journey does not by itself prove runtime availability; the
linked feature contracts own current scope and acceptance evidence.

## Product surfaces

| | |
| --- | --- |
| **Unified cloud console**<br />Move between products, regions, resources, operations, and messages without losing account context. [Explore the product shell](docs/features/FEAT-010-product-foundation-shell.md). | **Application delivery**<br />Model applications, deploy Compose workloads, and evolve toward continuous delivery through explicit contracts. [Explore application hosting](docs/features/FEAT-001-apphosting-contracts.md). |
| **Tenant-aware IAM and audit**<br />Separate account ownership, users, groups, roles, policies, sessions, service identities, and audit evidence. [Explore platform authorities](docs/features/FEAT-006-platform-authorities.md). | **Managed cloud services**<br />Use a public-cloud-style product flow for service discovery, tenant activation, quotas, instances, and connection endpoints. [Explore managed-service activation](docs/features/FEAT-007-control-plane-console.md). |
| **Connected infrastructure**<br />Place workloads across private-cloud regions and existing Linux hosts without turning infrastructure identity into tenant authority. [Explore host management](docs/features/FEAT-008-linux-host-management.md). | **Delivery you can verify**<br />Keep repository, runtime, installation, authority, and browser gates attached to the contracts they protect. [Explore repository validation](docs/features/FEAT-009-repository-delivery.md). |

## Product tour

### Identity is part of the cloud account model

The IAM workspace keeps account ownership visible while presenting users,
access methods, policy sources, status, and bulk actions in one operational
view.

![Matrix IAM user management](.github/assets/readme/iam-users.png)

### Cloud services start with an explicit tenant activation

Managed products use a shared activation experience: the tenant reviews the
service boundary, accepts the activation statement, and then manages quotas and
instances without receiving implicit resource permissions.

![Matrix PostgreSQL service activation](.github/assets/readme/managed-postgresql.png)

## Explore without touching real infrastructure

The control-plane console includes a browser-local **MOCK** workspace for
reviewing cloud, PaaS, DevOps, observability, IAM, and managed-service journeys.
Preview state stays in the browser experience and does not write to a real IAM
or infrastructure backend. The owning contract and browser evidence live in
[FEAT-007](docs/features/FEAT-007-control-plane-console.md).

## Get started

- **Platform operators:** follow the verified
  [installation runbook](docs/runbooks/platform-installation.md).
- **Product engineers:** start with the
  [feature contracts](docs/features/README.md), then read only the directly
  relevant [architecture decisions](docs/architecture/README.md).
- **Contributors and coding agents:** follow the repository
  [engineering instructions](AGENTS.md) and
  [dependency rules](docs/architecture/DEPENDENCY-RULES.md).
- **Donor inspection:** use the fixed-source
  [adoption records](docs/adoption/README.md); legacy repositories never become
  runtime or build dependencies.

## API contracts

- [IAM v1](api/iam/v1/README.md)
- [Audit v1](api/audit/v1/README.md)
- [PaaS v1](api/paas/v1/README.md)
- [Managed service v1](api/managedservice/v1/README.md)
- [DevOps v1](api/devops/v1/README.md)
- [Installation v1](api/installation/v1/README.md)

## Repository map

- [`app/`](app/) — product applications and bounded-context implementations
- [`api/`](api/) — versioned external contracts
- [`deploy/`](deploy/) — deployment and installation assets
- [`test/`](test/) — cross-context acceptance and real-runtime gates
- [`.github/`](.github/) — repository automation and verification workflows
