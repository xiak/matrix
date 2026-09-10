# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-10
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `ae86a55`

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
- Every disposable browser fixture, WSL/database artifact, export, Go cache,
  and temporary directory used by these Gate C slices has been removed. Docker
  Desktop and both registered WSL distributions are stopped.
- Real APISIX authorized/viewer/foreign-tenant browser acceptance, the complete
  designed UI state/accessibility matrix, and signed offline-release completion
  remain Gate C work.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue Gate C from FEAT-007's real-edge acceptance boundary. Exercise the
committed platform-shell client through APISIX with authorized, viewer, and
foreign-tenant identities; cover success, failure, cancellation, unavailable,
stale, denied-log, empty/loading, keyboard, focus, contrast, reduced-motion,
text-expansion, and `360px` states without weakening the guarded public
commands. Then carry the accepted DevOps topology and UI into the signed
offline release, recovery, upgrade, rollback, and support-evidence gates without
changing the Application PaaS product boundary.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
