# ADR-0002: Independent PaaS product boundary

- Status: Accepted
- Date: 2026-08-25

## Context

Earlier plans placed PaaS inside a Senatria business monorepo and treated its
existing DevOps implementation as a permanent execution engine. The product
direction now requires an independently deliverable PaaS that can manage
Senatria and other customer workloads without compiling their business code.

## Decision

The Matrix PaaS product includes IAM, Audit, APISIX, the PaaS control plane and
worker, the PaaS UI, adapters, and its own minimal delivery chain.

IAM and Audit remain independently deployed bounded services:

- IAM is the sole identity and authorization authority.
- Audit is the sole unified audit authority.
- PaaS owns runtime resources, placement, operations, and local execution
  evidence.

APISIX has two distinct roles:

- `deploy/compose/apisix` protects the PaaS product's northbound APIs and UI;
- `app/adapter/gateway/apisix` manages workload routes through an internal
  adapter contract.

Customer business services, business schemas, and product-specific UIs are
excluded. They can be onboarded later through Catalog, WorkloadRelease, and
adapter contracts.

## Consequences

- Source repositories are donors, not runtime or build dependencies.
- Every adopted slice records a fixed source commit and passes local gates.
- The PaaS Compose distribution contains platform services only.
- Senatria becomes a candidate customer workload rather than part of the PaaS
  kernel.
