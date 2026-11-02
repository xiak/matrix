# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-02
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/product-onboarding-release`
- Committed and pushed Logstash platform implementation: `bd74051e19a58f97f1fe89bcdd9c592d36ee3b9e`.
- Active goal: finish ELK product onboarding and release closure, then reuse the same contract for Redis.
- PRs #11, #12 and #13 are merged. [PR #14](https://github.com/xiak/matrix/pull/14) remains draft; verify the current head and CI before accepting it.

Follow `AGENTS.md` and repository-local Git identity. Read only the relevant owner:

- [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#产品团队接入契约) owns product contracts, Logstash candidate status and runtime evidence.
- [Product-team guide](../../docs/product-guide/managed-service-onboarding.md) and [executed onboarding commands](../../docs/runbooks/managed-service-onboarding.md).
- [FEAT-IAM-008](../../docs/features/iam/FEAT-IAM-008-product-enforcement.md) for authorization and product dependencies.
- [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md) and [installation runbook](../../docs/runbooks/platform-installation.md) for signed lifecycle.

Logstash now has a real adapter, default catalog and worker registration, UI routes, signed artifact inventory and production-process tests. Database offering/shape/version constraints derive from the compiled catalog instead of a second SQL product list. The UI registration supplies discovery, navigation and routes. The fixed older MySQL entrypoint and authenticated four-product installed manifests remain supported as real predecessors.

Local five-product production processes passed in 428.32 seconds, including native protocol/data, IAM, quotas, tenant rejection, revocation, Audit, termination and the existing MySQL two-tenant isolation gate. Real PostgreSQL catalog constraints and retained-state predecessor migration passed. UI embedded export matched 337 files. Full installation/platformcommand/localmachine/release/topology/releasebuild/architecture checks passed on Linux. The expanded-product upgrade retains its active phase after start/verification failure rather than automatically returning to an authority unable to manage new resources; explicit incompatible product rollback fails before effects.

The implementation commit's Verification 41408406255 exposed two stale frontend projection assertions that assumed four products; it is not accepted. The Product onboarding run is 41408406276. Check the latest head after the focused assertion correction; do not treat earlier CI or local S2 as final release acceptance. The previous adapter milestone d31f981a had all 19 Verification jobs and Product onboarding green.

Next acceptance boundary: signed Logstash candidate upgrade, actual browser/screenshots, compatible-version rollback and platform recovery with retained product data; synchronize existing user guide, runbook and FEAT evidence after execution. Keep P2 pending until verified. Then implement Kibana's typed same-tenant READY Elasticsearch dependency, current dependency-use authorization and delete/create race protection, persistent dependency-owned credentials/keys, and isolated network routing; the current Kibana sample has only trusted fixture dependency assumptions. Redis follows accepted ELK. Shared-host Docker isolation is not physical isolation.

Secrets, account credentials, absolute checkout paths and uncommitted machine-local runtime state are excluded.
