# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `88bec23`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing. Earlier accepted slices are
  preserved in Git and summarized there rather than repeated here.
- Pushed `8679c2f` closes the Docker Engine lifecycle for one immutable runner
  step. The adapter creates and proves a deterministic stopped container,
  starts only that fixed ID, follows bounded multiplexed output, waits and
  re-inspects the same ID, closes ordinary and OOM exits, cancels created or
  running work, and deletes only proved non-running work. Same-name replacement,
  configuration/state drift, malformed or incomplete responses, and mutating
  transport ambiguity fail closed without native error disclosure. Fixed
  blocking `local` log rotation bounds daemon storage, failure cleanup has a
  ten-second deadline, and post-delete absence is observed.
- The same pushed slice replaces the pre-v1 journal step record with a
  digest-bound canonical first-start time. It is fsynced with `STARTED`, remains
  unchanged on replay/restart, is bounded by the request/lease, and prevents a
  recovered or later step from renewing or moving the ordered step clock
  backwards.
- Pushed `88bec23` makes the whole-run 8 MiB native/normalized log budget
  recovery-stable. A pure validated cursor carries only both cumulative byte
  counts and the last sequence; the sandbox restores it, while journal schema
  v3 advances it only atomically with a started step's conclusion. Backwards,
  partial, changed-replay, pending-cancellation, poisoned, and recomputed-chain
  cursor states fail closed; native output is not journaled.
- Evidence on that worktree: full `go test ./...`, full `go vet ./...`, focused
  Windows race detection with twenty repetitions, and twenty focused runs in
  the fixed disconnected Go 1.26.8 Linux/amd64 image with read-only source and
  module cache all pass. The shared output decoder additionally passed a
  1,241,687-execution fuzz campaign.
- This proves the sandbox adapter boundary, not physical execution. No runner
  process yet composes gateway polling, journal recovery, workspace publication,
  step deadlines, sandbox lifecycle, normalized-log delivery, and receipt
  completion; repository code therefore still does not execute.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the smallest physical-runner vertical slice: compose the
outbound runner client, private journal, verified workspace, and closed Docker
sandbox around fixed lease/step/run deadlines and cancellation. Preserve
observe-before-effect recovery and do not duplicate an already-started step.
Then add the tenant-leading normalized-log handoff required by that composition.

Do not claim repository-code isolation until a dedicated Linux/amd64 runner
with the pinned offline toolchain and `runsc` passes the real no-egress,
resource, malicious-repository, restart, and log-sanitization gates. Keep runner
authority away from PostgreSQL, source/report credentials, IAM, Audit, PaaS,
and executor-admin operations. Do not begin formal UI integration before that
real boundary passes. Preserve pragmatic DDD, replacement-first pre-v1 changes,
optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
