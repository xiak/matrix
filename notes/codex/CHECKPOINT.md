# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `569eeaa`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing. Earlier accepted slices are
  preserved in Git and summarized there rather than repeated here.
- Pushed `569eeaa` closes the selected DevOps control-plane installation slice.
  The signed DevOps inventory now carries the build-worker and executor-gateway
  binaries, composes both without Docker authority, publishes only the
  runner-role mTLS port, and stages a private spool plus installation-bound,
  purpose-separated server/admin/runner PKI. PaaS-only installation owns none
  of those resources. Authority keys remain outside runtime containers.
- Full repository tests and vet, focused Windows race detection and twenty
  repetitions, and twenty focused runs in the fixed disconnected Go 1.26.8
  Linux/amd64 image with read-only source and module cache pass on `569eeaa`.
- This proves the selected control-plane topology, not a standalone runner-node
  release, runner enrollment, reporter effect, or real repository execution
  under gVisor.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with an independently installable runner-node artifact and
enrollment contract. It must consume authenticated offline runner, pinned
toolchain, and gVisor artifacts, issue a node/slot identity only below the
installation runner namespace, and never place Docker authority or the runner
on the Foundation/PaaS host. Preserve the four-slot maximum as distinct
credentials and roots. Reporter effects remain a separate subsequent slice.

Do not claim repository-code isolation until a dedicated Linux/amd64 runner
with the pinned offline toolchain and `runsc` passes the real no-egress,
resource, malicious-repository, restart, and log-sanitization gates. Keep runner
authority away from PostgreSQL, source/report credentials, IAM, Audit, PaaS,
and executor-admin operations. Do not begin formal UI integration before that
real boundary passes. Preserve pragmatic DDD, replacement-first pre-v1 changes,
optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
