# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-08-26
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/placement-policy`
- Release: Private Application PaaS v0.1
- Phase 1 state: Accepted

## Durable constraints

- Follow pragmatic DDD and replacement-first pre-v1 changes. Git preserves
  superseded drafts; the worktree does not retain aliases, compatibility
  layers, stale tests, duplicate documents, or rollback copies without a real
  consumer.
- Each FEAT fixes its enterprise target before donor inspection. Donors are
  reviewed only at the recorded commits, every relevant slice is classified as
  `REUSE`, `ADAPT`, `REFERENCE`, or `REJECT`, and no donor is a build or
  runtime dependency.
- Product branding is xiak / Matrix, the CLI is `mx`, the Go module is
  `github.com/xiak/matrix`, and public API groups use
  `*.matrix.xiak.com/v1`. API groups are identifiers, not customer DNS
  dependencies.
- Configuration is a default PaaS capability. Phase 1 supports immutable ENV
  configuration and exact read-only FILE Secret injection; dynamic refresh,
  structured files, Nacos, and Consul remain future providers behind the
  current binding boundary.
- Repository documentation and generated artifacts contain no machine-local
  checkout, home, release-artifact, or container-host paths.

## Accepted branch state

- The branch contains `001d889`. FEAT-001 through FEAT-006 are Accepted;
  FEAT-005 Gates A/B/C and FEAT-006 Gate C are closed.
- Exact accepted runtime source is
  `c88a84f379afcf94431e2aca7332fe6ec3136dc7`. Compatible signed releases are
  `matrix-v0.1.0-c88a84f379af` (build `phase1-a13-a-c88a84f`) and
  `matrix-v0.2.0-c88a84f379af` (build `phase1-a13-b-c88a84f`).
- A fresh Docker-in-Docker engine with outer network mode `none`, Docker
  27.5.1, Compose v2.33.0, and no initial inner containers, images, or volumes
  completed the signed offline lifecycle. It installed A, exercised real
  APISIX/IAM/Audit application generations, proved failed-candidate automatic
  rollback, upgraded to B, explicitly rolled the platform back to A, recovered
  a protected A backup, rolled the application back, stopped it and released
  capacity, produced bounded support evidence, restarted the entire engine,
  and passed final status/verify with all nine platform services healthy.
- The exact source passed generation drift, module verification, full unit,
  vet and race suites, architecture gates, ten-run critical-package coverage,
  placement fuzzing, clean PostgreSQL 18 migration/IAM/Audit/PaaS/authority
  process gates, real Compose adapter and PostgreSQL-to-Compose worker gates,
  CGO-disabled Windows/Linux/Darwin builds, Markdown links, stale-term and
  machine-path scans, donor-dependency and tenant-authority checks, and
  `git diff --check`.

## Phase 1 execution roadmap

| Slice | Deliverable | State |
| --- | --- | --- |
| A1 | Phase boundary, target design, ADRs, and fixed-donor decisions | Accepted |
| A2 | Application, configuration, deployment, and placement model | Accepted |
| A3 | PaaS API, Operations, IAM authorization, and Audit boundary | Accepted |
| A4 | Fenced worker and real Compose workload executor | Accepted |
| A5 | Signed offline release contract and `mx platform` CLI | Accepted |
| A6 | Journaled install, migration, start, verify, and cleanup effects | Accepted |
| A7 | Clean network-disabled Release A install | Accepted |
| A8 | Status, verify, and restart behavior | Accepted |
| A9 | Protected backup and bounded support evidence | Accepted |
| A10 | Authenticated upgrade and automatic rollback | Accepted |
| A11 | Explicit N-1 platform rollback | Accepted |
| A12 | Protected backup recovery | Accepted |
| A13 | Complete clean external-network-disabled lifecycle E2E | Accepted |
| A14 | Final common gates, documentation convergence, and Phase 1 acceptance | Accepted |

## Continuation

Phase 1 has no unfinished implementation slice. Any later capability must begin
with its owning FEAT and target design rather than extending this checkpoint or
reviving a superseded Phase 1 draft.

## Fixed donor baselines

- Legacy PaaS: `69336e51f94fa98f6aa278fa4c62382e224dbeaf`
- IAM/Audit foundation donor:
  `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d`
- PaaS design: `338d9b5fcb820120c32265e380c55e5f171cdb75`

Replace this file only at a committed-and-pushed milestone or handoff. Do not
append command logs, chat transcripts, secrets, raw provider payloads, or
machine-local paths.
