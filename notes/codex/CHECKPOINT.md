# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-10
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `5cca59e`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Pushed `c7af0ee` completes Gate B, including the physical IAM, Audit, Gitea,
  fetcher, executor, reporter, and recovery journey.
- Pushed `46a524b` begins Gate C with the public source-recheck command slice.
  Bodyless, idempotent, strong-ETag-guarded connection and binding commands use
  distinct administrator-only IAM actions and normalized Audit facts. They
  schedule only the delivery-owned observation task and cannot submit or alter
  health state.
- Pushed `ae86a55` adds the Gate C unified DevOps browser-client baseline to
  the existing platform shell. Product-local `Code`, `Pipelines`, and `Runs`
  routes exercise the public project, source, immutable-revision, exact-run,
  normalized-log, Recheck, cancellation, and replay contracts. Mutation
  admission follows signed product readiness; guarded commands are bodyless;
  source health cannot be supplied by the browser; and session/journey state
  remains in page memory.
- Content-addressed embedded assets and UI contract tests cover the exact
  product information architecture, public-only route inventory, no
  secret-value/file inputs, no browser persistence or raw problem reflection,
  and digest drift. Full Windows repository tests, vet, architecture, JavaScript
  syntax, DOM identity, desktop browser journeys, and exact `360px` no-overflow
  checks pass with no browser console warning or error.
- Pushed `39fd910` integrates the first DevOps-selected Gate C boundary into
  the existing signed offline lifecycle. Both A and B must select DevOps. The
  executable gate creates the project/source/binding/Pipeline/revision graph
  and schedules guarded Rechecks through APISIX, proves a public-IAM-created
  Viewer can read but not mutate, and uses an immediately cleaned
  second-organization identity to prove tenant-scoped `404`. It reads the graph
  after failed upgrade rollback, upgrade, rollback, and recovery, then checks
  the persisted reference chain after host restart without retaining a user
  password. Application PaaS and protected Audit/backup assertions remain in
  the same lifecycle. Full Windows tests and vet plus the affected race and
  twenty-run suites pass.
- Pushed `5cca59e` adds the release-carried source-credential lifecycle to that
  harness. The operator applies all three purpose-separated references, rotates
  the webhook value, proves equal apply and repeated retirement, and schedules
  a post-rotation guarded Recheck. Each private input file and its fresh empty
  directory are removed and proved absent immediately after use. The physical
  observer must advance the source to `PROVIDER_UNAVAILABLE`, rather than
  `SECRET_UNAVAILABLE`, before and after rotation, advance the binding to
  `CONNECTION_NOT_READY`, and deliver both health-transition Audit facts. Strict
  result and exact non-recursive cleanup tests join full Windows tests/vet and
  the affected race/twenty-run gates.
- `5cca59e` is acceptance-harness implementation, not real signed-release
  execution evidence. Private-provider CA trust, the local-provider
  source-to-check journey, real APISIX-backed browser acceptance, the complete
  UI state/accessibility matrix, and the exact signed offline run remain Gate C
  work.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue Gate C in the existing offline lifecycle. Design the smallest
installation-owned private-provider CA trust boundary without disabling TLS or
turning a tenant connection into host trust, then run the local-provider
source-to-check journey without putting a secret in browser/API/argv/environment/
evidence. Execute the exact signed A/B lifecycle on a clean external-network-
disabled Linux host. Exercise the committed platform-shell client through that
real APISIX edge with authorized, Viewer, and foreign-tenant identities; cover
success, failure, cancellation, unavailable, stale, denied-log, empty/loading,
keyboard, focus, contrast, reduced-motion, text-expansion, and `360px` states
without weakening the guarded public commands or changing the Application PaaS
product boundary.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
