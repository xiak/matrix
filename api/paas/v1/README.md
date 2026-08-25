# PaaS v1 contracts

This directory is the source of truth for the
`matrix.paas.io/paas/v1` control-plane contract.

- `openapi.json` defines the machine-readable resource, problem, concurrency,
  and internal adapter-envelope schemas.
- Go types and validators provide the first server-side executable contract.
- `examples/` contains strictly decoded, validation-tested wire examples.
- `contract_test.go` prevents enum drift, isolation downgrade, secret-bearing
  evidence, and adapter-native names in public properties.

Northbound resource paths are intentionally absent from the FEAT-001 schema.
FEAT-006 adds those paths only after service use cases, authorization, and
durable operations have executable behavior.

Design and provenance:

- [`FEAT-001 runtime contracts`](../../../docs/features/FEAT-001-runtime-contracts.md)
- [`FEAT-001 donor review`](../../../docs/adoption/FEAT-001-runtime-contracts.md)
