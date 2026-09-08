# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `c8f0f16`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing. Earlier accepted slices are
  preserved in Git and summarized there rather than repeated here.
- Pushed `c8f0f16` closes authenticated standalone runner distribution and CSR
  enrollment. A DevOps-selected release carries an exact signed Linux/amd64
  subset with `mx`, the runner, the fixed offline Go toolchain image, and the
  fixed gVisor archive/checksum; PaaS-only releases reject that payload.
  Installation export reports the current server/runner CA fingerprints, every
  one-to-four-slot CSR binds those operator-trusted pins, and each private key
  remains under its distinct node-local root. Enrollment stores public records
  only and rejects foreign installs, changed requests, or self-consistent
  responses that introduce an unpinned authority.
- Full repository tests and vet, focused Windows race detection and twenty
  repetitions, and twenty focused runs in the fixed disconnected Go 1.26.8
  Linux/amd64 image with read-only source and module cache pass on `c8f0f16`.
  Production integration also stages the authentic pinned gVisor `.tar.zstd`
  and saves/re-inspects the authentic pinned toolchain OCI image through a full
  signed-release assembly.
- This proves distribution and enrollment, not dedicated-node installation,
  reporter effects, or real repository execution under gVisor.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with dedicated Linux/amd64 runner-node installation. Consume
only the authenticated exported subset and a signed enrollment matching the
node's canonical CSR and pre-pinned authorities; install the fixed gVisor
binaries without network/package-manager side effects, load and re-inspect the
fixed toolchain image, configure only the fixed `runsc` Docker runtime, enforce
the single gateway egress boundary, and compose one system-managed runner
process per independently credentialed slot with disjoint mutable roots.
Installation and equal replay must be atomic and fail closed on changed host,
payload, PKI, runtime, image, firewall, or service state. Reporter effects
remain a separate subsequent slice.

Do not claim repository-code isolation until a dedicated Linux/amd64 runner
with the pinned offline toolchain and `runsc` passes the real no-egress,
resource, malicious-repository, restart, and log-sanitization gates. Keep runner
authority away from PostgreSQL, source/report credentials, IAM, Audit, PaaS,
and executor-admin operations. Do not begin formal UI integration before that
real boundary passes. Preserve pragmatic DDD, replacement-first pre-v1 changes,
optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
