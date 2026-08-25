# Feature specifications

| Feature | Status | Outcome |
| --- | --- | --- |
| [FEAT-001](FEAT-001-runtime-contracts.md) | Accepted | Vendor-neutral Runtime v1 resource, state-machine, error, idempotency, and adapter contracts. |
| [FEAT-002](FEAT-002-localmachine-adapter.md) | Accepted | Explicit local and pinned-SSH remote Linux machines produce normalized, fail-closed target observations. |
| [FEAT-003](FEAT-003-placement-isolation.md) | Gate A accepted | Deterministic tenant placement is executable; transactional reservations and tenant-safe persistence remain Gate B. |

A feature specification fixes the target design and acceptance evidence before
donor code is reviewed. Adoption decisions are recorded separately under
`docs/adoption/`.
