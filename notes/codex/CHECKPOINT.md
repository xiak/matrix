# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `e9ad554`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Pushed `e9ad554` extends the opt-in source-process journey against a clean
  PostgreSQL 18 database and fixed Gitea `1.27.3`. It starts the actual DevOps
  API, source-observer, two source-fetchers, three successive check-reporter
  processes, and DevOps Audit-dispatcher binary. The API validates its IAM
  service identity through a narrow HTTP test boundary.
- The physical DevOps webhook returns 401 for a forged signature, 204 for one
  valid pull-request event and its equal replay, and 409 for changed-byte
  replay. The valid HTTP request identity correlates the one source event, one
  run, and two Audit outbox facts.
- The first fetcher performs exactly one Gitea `upload-pack` and atomically
  publishes the source archive, then is killed before PostgreSQL acknowledgement.
  Its replacement claims fence two, observes the immutable archive without a
  second provider fetch, stores one receipt, completes FETCH, and advances the
  same run to `VERIFYING`. Archive, database, and process evidence contains no
  credential or private path.
- A narrow in-test passing executor bridges the production VERIFY use case to
  the separately proved isolated-executor gate. After a bootstrap reporter
  establishes readiness, the first recovery reporter claims REPORT fence one
  and creates exactly one Gitea success status. It is killed after the provider
  effect completes but before PostgreSQL can store the receipt. The database
  retains an open fence-one REPORT intent and no receipt; after bounded lease
  expiry, a replacement claims fence two, performs one provider read and no
  second create, stores the sole receipt, and makes the unchanged run
  `SUCCEEDED / COMPLETED`.
- The actual DevOps Audit dispatcher authenticates to a narrow validating HTTP
  boundary and delivers every accumulated outbox fact once. Source admission
  and run creation retain the webhook request correlation; the terminal fact
  targets/correlates the same run and uses the system run-worker actor. The
  separate authority-process gate remains physical IAM/Audit-service evidence.
- The joined process journey passed in 3.42 seconds under disconnected Go
  `1.26.8`; Linux package vet and current full-repository Windows tests and vet
  pass. It still does not join the physical executor, IAM service, and Audit
  service in one journey or close malicious repository/resource abuse,
  oversized logs, all other external-effect restarts, full Gate B, or UI Gate
  C.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Join the existing physical IAM/Audit/executor evidence where that materially
protects the end-to-end boundary, without duplicating their already proved
isolated gates. Complete malicious repository/resource-abuse and oversized-log
cases plus remaining external-effect restarts with no duplicate provider
outcome. Only after complete Gate B passes begin formal Matrix UI integration
from the accepted UX baseline.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
