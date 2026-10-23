# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, the host goal and the owning FEAT.

## Pushed release-candidate milestone

- Repository `https://github.com/xiak/matrix.git`, branch
  `feat/iam-console-release-candidate`; repository-local Git identity is exactly
  `Xiak <Jellal@aliyun.com>`.
- Latest pushed integration source is `4b9080a33`. It composes the current IAM
  branch head `1da954e84` (production-code milestone `571692dd2`) with the
  verified console UX branch `ed001f9ef` (latest source fix `8b4cc05d1`).
- Ownership was kept explicit: IAM backend, IAM FEATs and authority-process
  tests remain from the IAM branch. The overlay is limited to the console
  frontend and embedded export, its web-server contract test, FEAT-007 and its
  adoption/research owners. Old UX backend, provisioner and process-test slices
  were not imported.
- Embedded console build is `matrix-83584a7392a45b794192`.

## Verified evidence at `4b9080a33`

- Frontend install and source gates passed: typecheck, lint, architecture,
  234 theme-contrast pairs, 80 test files / 2106 tests, and eight Node export
  tests.
- Static export and embed verification passed: 59 pages, 57 normalized routes,
  and 324 source/export/embed files byte-equivalent. PaaS UI Go test and vet
  passed.
- Full repository `go test -p 2 ./...` and `go vet -p 2 ./...` passed without
  creating another Docker/PostgreSQL fixture.
- In the built-in browser, the integrated MOCK console entered successfully,
  opened the User directory and a User detail, kept Delete disabled for an
  active User with an explanatory reason, navigated through Products & Services
  to Cloud MySQL, and rendered the common opt-in gate. The browser emitted no
  warning or error for this journey.
- The MOCK service opt-in gate states that enabling a service creates no
  resource permission and links IAM authorization separately. Its consent is
  explicit and its action stays disabled until accepted.

## Unaccepted boundaries

- This is a pushed integration candidate, not a signed final release. Read the
  exact remaining acceptance gates from FEAT-007, IAM/FEAT-IAM-010 and
  IAM/FEAT-IAM-011 rather than copying them into this checkpoint.
- Real User deletion NORMAL and RESPONSE_LOSS browser journeys remain
  unaccepted. The expired prior target was still disabled at version 3 with no
  tombstone, deletion fact, page POST, receipt or finish marker; RESPONSE_LOSS
  never started. A prior confirmation must not be transferred to another
  target.
- Cleanup remains policy-blocked. Read-only inspection found five owned
  containers and eleven related paths. The rejection happened before cleanup
  launched. Do not bypass it through another executor, split command,
  delegation, rename or parent deletion.
- `npm ci` reported the lockfile's current dependency audit findings (two
  moderate, ten high and one critical). Do not run an unscoped audit fix or
  claim the dependency gate resolved; give it an owning dependency slice.
- Previously accepted K1/K2/R1/R2 evidence and the signed installed-release
  baseline remain owned by the IAM FEATs. Do not rerun them merely to restate
  acceptance, and do not infer a new signed release from this integration
  branch.

## Continuation route

- Read `AGENTS.md`, then the directly owning FEAT document and code/tests.
  FEAT-007 owns console UX and export evidence; IAM/010 owns browser/runtime
  journeys; IAM/011 owns independent CI evidence.
- Validate branch/remote equality and the current host goal before acting.
  Keep the MOCK experience inspectable while closing remaining release gates.
- Preserve replacement-first changes and current ownership boundaries. Do not
  add compatibility copies, duplicate status documents or a second checkpoint.
