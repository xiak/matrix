# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, the host goal and the owning FEAT.

## Pushed release-candidate milestone

- Repository `https://github.com/xiak/matrix.git`, branch
  `feat/iam-console-release-candidate`; repository-local Git identity is exactly
  `Xiak <Jellal@aliyun.com>`.
- Latest verified candidate code source is `66e86549e`; it expands the shared
  table-filter workspace on top of permission-catalog milestone `4d7ea249c`
  and candidate source `3afe96248`, which follows the pushed console source
  `0b3f95d94`. Its integration base
  `4b9080a33` composes IAM branch head `1da954e84` (production-code milestone
  `571692dd2`) with console UX branch `ed001f9ef` (latest source fix
  `8b4cc05d1`). Dependency hardening is owned by `74fdc98da`; the latest source
  commit stops tracking Next's generated declaration, generates it before
  typecheck, and regenerates the owned static export. It does not import a
  second backend or IAM model.
- Ownership was kept explicit: IAM backend, IAM FEATs and authority-process
  tests remain from the IAM branch. The overlay is limited to the console
  frontend and embedded export, its web-server contract test, FEAT-007 and its
  adoption/research owners. Old UX backend, provisioner and process-test slices
  were not imported.
- Embedded console build is `matrix-8ea9c08c538fa18b7909`.

## Verified table-filter workspace at `66e86549e`

- The platform-only permission catalog now follows the same connected card
  hierarchy as the User directory: section identity and boundary, shared
  toolbar, table and shared footer align without the former nested inset.
- The product collection reuses the disclosed shared filter pattern for exact
  calling-service and authority-scope conditions. Active criteria remain
  removable, clearing restores all four MOCK declarations and focus returns to
  the stable trigger.
- Every consumer of the shared table toolbar now keeps search, disclosure and
  result status on the stable first row, then opens a bounded full-width filter
  workspace. Labelled large controls fill equal responsive columns, the clear
  action stays at the row edge, and applied criteria remain individually
  removable. The User directory and permission catalog were both inspected in
  the running DEV browser.
- The complete 80-file/2,107-case frontend suite, eight export tests,
  typecheck, lint, architecture, 234 theme-contrast pairs, 59-page export with
  57 normalized segment files, 322-file embedded equality and PaaS Go
  test/vet passed. The expanded controls, combined result, clear path and
  persistent removable criteria passed behavior and built-in-browser checks;
  the browser warning/error log remained empty.

## Verified evidence at `0b3f95d94`

- Frontend install and source gates passed: typecheck, lint, architecture,
  234 theme-contrast pairs, 80 test files / 2106 tests, and eight Node export
  tests.
- Static export and embed verification passed: 59 pages, 57 normalized routes,
  and 322 source/export/embed files byte-equivalent. PaaS UI `go test` and
  `go vet` passed. The broader repository Go gates had already passed on the
  dependency slice without creating another Docker/PostgreSQL fixture.
- Next and `eslint-config-next` are 16.4.2; compatible patched dependencies
  include Sharp 0.35.5, `source-map-js` 1.2.2, Vitest 4.1.12, Vite 8.3.5 and
  Undici 8.12.3. Supported Node 24.19.0/npm 11.6.4 reports zero production
  vulnerabilities. The full development audit still reports five high entries,
  all the same unpatched `braces@3.0.3` ESLint-only chain; do not conceal it
  with npm's incompatible Next-14 downgrade or an unfixed override.
- In the built-in browser, the upgraded MOCK console entered successfully on
  port 4318, rendered the User owner/table/actions hierarchy, and navigated via
  the real Products & Services directory to Cloud MySQL and back to IAM. Each
  accepted click projected the destination frame and H1 before dynamic content;
  Cloud MySQL rendered the common opt-in gate, and the browser emitted no
  warning or error for this journey.
- The MOCK service opt-in gate states that enabling a service creates no
  resource permission and links IAM authorization separately. Its consent is
  explicit and its action stays disabled until accepted.
- Exact-source GitHub Verification
  [#740](https://github.com/xiak/matrix/actions/runs/39885755013) completed with
  the console job failed only because Next 16.4.2 rewrote the tracked generated
  `next-env.d.ts` from a development type path to the production type path.
  All 80 frontend files / 2106 tests and all eight Node export tests passed;
  the authority aggregate was skipped after the console prerequisite failed.
  Source `0b3f95d94` fixes the ownership error instead of normalizing generated
  output after every build. Its exact-source Verification
  [run 39887832592](https://github.com/xiak/matrix/actions/runs/39887832592)
  completed `success`: all 19 jobs passed, including console, Go, Node-process,
  PostgreSQL HA installation, every authority shard and the authority-process
  aggregate. This closes the independent CI gate for that source; it does not
  pre-accept the remaining browser or signed-release gates.
- Documentation successor `2df38c8b8` has the same production and test tree as
  `3afe96248`. Its exact-source Verification
  [run 39895467786](https://github.com/xiak/matrix/actions/runs/39895467786)
  completed `success`: the run and all 19 jobs were independently confirmed
  `completed/success`. Only run/job metadata was checked, so this does not
  invent full-log details or replace the real browser evidence below.

## Verified User deletion evidence at `3afe96248`

- A fresh PostgreSQL 18.6 NORMAL fixture completed the real built-in-browser
  User deletion with exactly one POST. The immutable receipt matched login,
  stable User ID, request ID, deletion time and resource version 4; explicit
  finish then independently reread an empty ordinary-User directory. The
  authority-process root passed in 283.297 seconds.
- A separate fresh PostgreSQL 18.6 RESPONSE_LOSS fixture also issued exactly
  one POST. The server committed and dropped the response; the console kept
  the exact login, stable User ID, original request ID and submitted version
  as UNKNOWN through navigation, reload and same-owner relogin. It performed
  no retry and no completion query. The authority-process root passed in
  391.715 seconds.
- Both paths proved the exact tombstone, permanent
  password/Session/RoleSession/AccessKey denial, cleared Key secret, ended
  direct attachments, preserved tenant resources/Operations and Role trust
  history, unique User and Key-cascade Audit facts, and a complete tenant
  Audit chain. Both task-owned PostgreSQL containers were removed after exact
  ID and label verification.
- `3afe96248` adds the required explicit `permissionBoundary: null` to the
  deleted-login reservation probe so it reaches the expected 409 conflict
  instead of failing request-shape validation with 400. It changes no
  production contract. NORMAL and RESPONSE_LOSS are independently accepted.

## Verified daily password evidence at `3afe96248`

- Two fresh PostgreSQL 18.6 browser fixtures completed the normal daily
  self-password-change flow. The default `revokeOtherSessions=true` path
  passed in 82.26 seconds (84.624 seconds package time); the explicit
  `false` path passed in 67.03 seconds (68.973 seconds package time).
- Both paths advanced the exact User and credential epoch once, retained the
  calling Session, preserved the previously revoked Session, rejected the old
  password, accepted a fresh login with the new password, and emitted one
  self-authenticated fact in the verified tenant Audit chain. The true path
  revoked both other valid Sessions; the false path retained and upgraded
  both without reviving the prior logout.
- Each accepted fixture used an isolated task-labelled container and empty
  database. The containers had no mounts and were removed after exact ID and
  ownership verification. This accepts the two normal choices only; it does
  not accept a response-loss recovery journey.

## Unaccepted boundaries

- This is a pushed integration candidate, not a signed final release. Read the
  exact remaining acceptance gates from FEAT-007, IAM/FEAT-IAM-010 and
  IAM/FEAT-IAM-011 rather than copying them into this checkpoint.
- Real User deletion NORMAL and RESPONSE_LOSS are accepted at `3afe96248`;
  neither result is reused as evidence for another deletion path.
- Historical cleanup remains policy-blocked. The current NORMAL and
  RESPONSE_LOSS task-owned PGs were removed after verification; the four older
  denied containers remain out of scope. Do not bypass the earlier rejection
  through another executor, split command, delegation, rename or parent deletion.
- Production dependency audit is closed at zero. The five-entry development
  finding above remains an explicit upstream risk; do not run an unscoped
  audit fix, force a mismatched framework downgrade or claim the complete
  development tree is clean.
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
