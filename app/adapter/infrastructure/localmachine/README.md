# LocalMachine infrastructure adapter

This adapter represents explicitly configured machines as normalized
`RuntimeTarget` observations. It reports a one-way identity fingerprint,
bounded labels, CPU/memory/storage capacity, health, and the exact Compose
isolation classes currently available. It never deploys a workload.

Current release gate:

- local Windows, Linux, and macOS host metrics;
- stable platform machine identity with no raw machine ID in observations;
- fixed Docker Engine and Compose capability probes;
- `READY` only when both Docker Engine and Compose are available;
- server-owned binding allowlists and optional expected-identity pin;
- normalized, sanitized adapter failures.

Pinned remote Linux SSH is the second FEAT-002 gate and is not yet advertised
by the adapter. An SSH binding therefore returns `CAPABILITY_UNSUPPORTED`
without attempting a connection.

The adapter imports only [`api/paas/v1`](../../../../api/paas/v1/) data
contracts. It does not import PaaS service internals. See the
[`FEAT-002 design`](../../../../docs/features/FEAT-002-localmachine-adapter.md)
and [`adoption review`](../../../../docs/adoption/FEAT-002-localmachine-adapter.md).
