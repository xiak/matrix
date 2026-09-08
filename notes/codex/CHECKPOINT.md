# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `5c2ff67`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing. Earlier accepted slices are
  preserved in Git and summarized there rather than repeated here.
- Pushed `5c2ff67` closes the port-driven durable runner workflow over the
  already accepted runner client, private journal, immutable workspace, and
  closed Docker sandbox. Claim commit precedes effects; lease renewal precedes
  workspace work; recovery observes before create; cancellation, fixed
  deadlines, log-cursor handoff, cleanup, local terminal replay, and gateway
  acknowledgement retain one fenced truth. Concrete authorities remain behind
  delivery ports.
- Evidence on that worktree: full `go test ./...`, full `go vet ./...`, focused
  Windows race detection with twenty repetitions, and twenty focused runs in
  the fixed disconnected Go 1.26.8 Linux/amd64 image with read-only source and
  module cache all pass.
- This proves orchestration against controlled boundaries, not a physical
  runner process. Production normalized-log persistence, process composition,
  selected release topology, and real repository execution remain pending.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the tenant-leading normalized-log persistence boundary:
make sequence replay idempotent, changed replay conflicting, access
tenant-derived, and retention bounded across the gateway/control-plane split.
Then compose the dedicated runner process and selected release topology around
the already pushed workflow.

Do not claim repository-code isolation until a dedicated Linux/amd64 runner
with the pinned offline toolchain and `runsc` passes the real no-egress,
resource, malicious-repository, restart, and log-sanitization gates. Keep runner
authority away from PostgreSQL, source/report credentials, IAM, Audit, PaaS,
and executor-admin operations. Do not begin formal UI integration before that
real boundary passes. Preserve pragmatic DDD, replacement-first pre-v1 changes,
optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
