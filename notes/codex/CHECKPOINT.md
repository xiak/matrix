# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `3f9322f`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `c9acd5f` adds the outbound-only production runner client and its
  independent private journal behind the strict TLS 1.3 gateway. Canonical
  assignment metadata and a complete-request digest bind staging before archive
  consumption; verified source is atomically published before an effect marker,
  then immutable generations preserve renewal, cancellation, recovery fencing,
  normalized terminal receipt, and acknowledgement. Certificate-derived runner
  identity, OS-exclusive directory ownership, strict file shape, and archive,
  request, state-chain, identity, symlink, and restart checks fail closed. A real
  mTLS journey persists claim through acknowledgement and recovers it after
  restart without giving the journal any network, database, product, provider,
  Docker, or process-execution authority.
- Pushed `83bde3c` composes the physical table-blind build-worker command from
  its PostgreSQL repository, read-only archive store, strict mTLS admin client,
  independent heartbeat, and readiness endpoint. A shared protected client-
  certificate loader binds exact SPIFFE identity and pinned server roots, while
  architecture tests deny provider, runner, Docker, IAM, Audit, and PaaS
  authority. Its focused suites pass race/repetition and fixed disconnected
  Linux/amd64 tests with read-only source/module cache and lookup disabled.
- Pushed `3cd0607` adds the runner's closed Docker Engine API `v1.46`
  boundary over a protected root-owned Unix socket. Preflight fails before
  claim unless Docker `29.x`, Linux/amd64, `runsc`, resource-limit support,
  node capacity, installation-owned free storage, the pinned image ID/digest,
  and a trusted negative-isolation probe all pass. Host-side inspection binds
  the probe's image, command, environment, runtime, no-network/no-IPC,
  read-only root, empty authority, resource limits, terminal state, and network
  attachment; outcome ambiguity is cleaned by randomized controlled name. The
  same adapter derives immutable `go test`/`go vet` container requests with
  exact user, environment, read-only source mount, and bounded tmpfs, but does
  not execute them yet. Unit, race, repetition, fixed disconnected Linux Unix-
  socket, and real read-only Docker `29.6.2` evidence pass; the current Docker
  Desktop host correctly fails closed because `runsc` is absent, which is not
  gVisor-isolation evidence.
- Pushed `b796b51` adds the OS-exclusive, runner-bound workspace store between
  the journal archive and sandbox request. The shared archive codec now visits
  bounded regular-file members without surrendering gzip/tar validation; the
  workspace independently rehashes compressed input, atomically publishes
  fsynced `0444`/`0555` content beneath `os.Root`, and seals a canonical full-
  request/execution/archive/tree manifest. Equal reuse and restart rescan every
  file and require archive, manifest, globally sorted content/mode digest, and
  exact parent-directory set to agree. Foreign identity, changed request or
  input, link, special/extra/writable entries, file-directory collision,
  cancellation, unsafe roots, abandoned staging, and close ambiguity fail
  closed. Windows race/repetition and fixed disconnected Linux/amd64 suites
  pass, including the Linux handoff of only this source root to both immutable
  Docker step plans; no repository code executes yet.
- Pushed `32b8035` adds the runner-owned, run-shared native-output boundary.
  A strict Docker multiplex decoder reconstructs split stdout/stderr lines and
  emits monotonic UTF-8 chunks while independently bounding native and
  normalized bytes to 8 MiB, lines to 16 KiB, and chunks to 64 KiB. Unsafe
  lines are replaced in full for invalid UTF-8, control/ANSI bytes, credential-
  shaped assignments and token formats, URL user information, absolute Unix,
  drive, or UNC paths, and overlong content. Malformed, truncated, empty, or
  over-budget streams poison the shared budget so a partial parse cannot be
  resumed. Full tests/vet, Windows race and twenty-run repetition, a 547,883-
  execution fuzz campaign, and twenty runs in the fixed disconnected Go 1.26.8
  Linux/amd64 image pass. This is parser/sanitizer evidence only: no container
  response is wired to it and no normalized log is persisted yet.
- Pushed `3f9322f` replaces the private journal state with a schema-v2 ordered
  step chain. The exact two request steps progress only through durable
  `PENDING`, `STARTED`, and one closed conclusion; step two cannot start before
  fsynced step-one success. Archive-free same-runner recovery preserves this
  chain and may continue the next pending step, while an already-started step
  must be observed. Cancellation is now representable both before any sandbox
  effect and during a started step. A terminal receipt must exactly match the
  stored conclusions, and semantic validation rejects changed/out-of-order
  replay and recomputed step-chain rollback. The production mTLS round-trip now
  persists both step conclusions before terminal completion. Full tests/vet,
  Windows race and twenty-run repetition, and twenty fixed disconnected Linux/
  amd64 runs pass. No container is created by this slice.
- Full tests and vet, architecture tests, focused race and 20-run suites, and
  the same focused suites run twenty times in the fixed disconnected Go 1.26.8
  Linux/amd64 image with read-only source and no module lookup. The physical
  dedicated runner process, sandbox lifecycle/cancellation, real response
  hookup, normalized-log persistence, real cross-process journey, reporter,
  UI, and offline release remain pending.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the smallest independently testable physical-execution
slice behind the accepted BuildExecutor port: add the Docker Engine lifecycle
for the already-closed step plans with create/attach/start/wait/inspect/kill/
delete recovery, fixed step/run deadlines, cancellation, feed the already-
bounded normalized-output decoder, and verify host-side postconditions; then
compose the dedicated runner process around gateway client, journal, workspace,
and sandbox. Do not claim
repository-code isolation until a dedicated `runsc` node passes the malicious-
repository and real-runtime gates.
Keep runner authority away from
PostgreSQL, source/report credentials, IAM, Audit, PaaS, and admin operations.
Do not claim repository
code is isolated until the dedicated Linux/amd64 runner, pinned offline
toolchain, gVisor, no-egress, resource, malicious-repository, restart, and
sanitized-log gates really pass; do not couple it to PaaS execution or begin
formal UI integration before that real boundary passes. Preserve pragmatic
DDD, replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
