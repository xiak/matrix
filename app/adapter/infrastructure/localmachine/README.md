# LocalMachine infrastructure adapter

This adapter represents explicitly configured machines as normalized
`RuntimeTarget` observations. It reports a one-way identity fingerprint,
bounded labels, CPU/memory/storage capacity, health, and the exact Compose
isolation classes currently available. It never deploys a workload.

Accepted FEAT-002 capabilities:

- local Windows, Linux, and macOS host metrics;
- stable platform machine identity with no raw machine ID in observations;
- fixed Docker Engine and Compose capability probes;
- `READY` only when both Docker Engine and Compose are available;
- server-owned binding allowlists and optional expected-identity pin;
- pinned remote Linux SSH with an opaque credential resolver;
- public-key authentication only, with mandatory SHA-256 host-key pinning;
- a closed eight-probe command set with per-probe deadlines and bounded output;
- normalized, sanitized adapter failures.

Remote probing is enabled only when the composition root supplies an
`SSHHostProbe`. Without it, an SSH binding still fails closed with
`CAPABILITY_UNSUPPORTED` and no connection attempt. Credentials, endpoints,
usernames, host paths, commands, and raw probe output never enter the
versioned observation contract.

The adapter imports only [`api/paas/v1`](../../../../api/paas/v1/) data
contracts. It does not import PaaS service internals. See the
[`FEAT-002 design`](../../../../docs/features/FEAT-002-localmachine-adapter.md)
and [`adoption review`](../../../../docs/adoption/FEAT-002-localmachine-adapter.md).
