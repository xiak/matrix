# FEAT-008 adoption review: existing Linux hosts

- Status: Initial node slice review complete
- Target: [FEAT-008](../features/FEAT-008-linux-host-management.md)
- Target design date: 2026-08-27
- Direct donor dependency allowed: No

## Fixed baselines

| Donor | Commit | Inspection rule |
| --- | --- | --- |
| Legacy PaaS | `69336e51f94fa98f6aa278fa4c62382e224dbeaf` | Git objects only; never the donor worktree |
| IAM/Audit and delivery foundation | `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d` | Git objects only; narrow execution/observability/lifecycle slices |
| PaaS design | `338d9b5fcb820120c32265e380c55e5f171cdb75` | Git objects only; rationale, not runtime evidence |

Source identities are owned by [the fixed-source entry](sources.yaml).
The target and iterative roadmap were pushed in `fbdb250` before these Git
objects were opened. No donor worktree or moving branch was inspected.

## Selected decisions

Paths below are relative to the named donor. Decisions apply to the named
sections, not an unreviewed transitive implementation closure.

| Fixed donor slice | Decision | Result |
| --- | --- | --- |
| Legacy `app/service/paas/internal/kernel/providerregistry/domain/provider_binding.go`: binding fields, constructor and authority/credential validation | `ADAPT` | Keep opaque credential references, scope agreement and validation before use. Do not import its activation, policy/quota/evidence graph or shared-kernel types. |
| Legacy `app/service/paas/internal/runtime/domain/values.go`: ProjectionWindow, timestamp and external-text validation | `ADAPT` | Preserve explicit observation freshness, stale-at-expiry behavior, UTC precision and sensitive-text rejection. Use the existing Matrix validation owner rather than another scalar-type framework. |
| Legacy `app/service/paas/internal/provider/contract/envelope.go` | `REFERENCE` | Correlate invocations and normalize unknown outcomes. Existing Matrix command envelopes already own these semantics; no duplicate envelope authority. |
| Legacy provider/runtime aggregate dependencies referenced by those sections | `REJECT` | Importing them would introduce a different resource hierarchy without implementing a resident node or resource sampler. |
| Foundation `platform/go/foundation/server/tlsconfig/server.go` | `ADAPT` | Separate policy validation from loading keys/trust. Require mTLS and exact installation/node peer identity, bounded protected-file reads and sanitized errors; do not retain disabled/optional-auth modes or raw path/native errors. |
| Foundation `devops/infrastructure/remoteexecution/ssh.py` | `REJECT` as the node runtime | Arbitrary script input, inline private keys, optional insecure checking and post-buffer output bounds do not meet the resident-node boundary. Existing accepted pinned SSH remains available for scoped bootstrap work. |
| Foundation `devops/infrastructure/inspection/compose_runtime_source.py` | `REFERENCE` | Fixed observations, locked state and strict record validation are useful. Do not import shell orchestration, donor environment files, Audit-specific paths or operational payloads. |
| Foundation `deploy/compose/middleware/observability/victoriametrics/promscrape.yaml` | `REFERENCE` | Periodic collection and trusted scrape identities inform the integration. Its application scrape jobs are not host measurements or proof of current host-observability acceptance. |
| Design `docs/paas/adoption-manifest.yaml`: staged adoption and dependency boundaries | `REFERENCE` | Preserve independently verifiable slices and explicit unknown/stale state. |
| Same design manifest: GitLab/current-DevOps execution authority and release inventory | `REJECT` | Matrix owns its independent host runtime and offline lifecycle; donor CI/product topology is not a runtime prerequisite. |

No source file is copied and no donor is a build/runtime dependency. Existing
accepted Matrix adapters, validators, journals and tests retain their owners.
Any additional source needed by a later iteration is reviewed here at its
fixed commit before use, rather than opening the whole donor in advance.
