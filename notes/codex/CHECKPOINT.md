# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, the host goal and the owning FEAT.

## Pushed release-candidate milestone

- Repository `https://github.com/xiak/matrix.git`, branch
  `feat/iam-console-release-candidate`; repository-local Git identity is exactly
  `Xiak <Jellal@aliyun.com>`.
- Latest pushed candidate source is `0b3f95d94`. Its integration base
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
- Embedded console build is `matrix-382e368f7e95398e5502`.

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
  is in progress; local evidence does not pre-accept that remote gate.

## Unaccepted boundaries

- This is a pushed integration candidate, not a signed final release. Read the
  exact remaining acceptance gates from FEAT-007, IAM/FEAT-IAM-010 and
  IAM/FEAT-IAM-011 rather than copying them into this checkpoint.
- Real User deletion NORMAL and RESPONSE_LOSS browser journeys remain
  unaccepted. The expired prior target was still disabled at version 3 with no
  tombstone, deletion fact, page POST, receipt or finish marker; RESPONSE_LOSS
  never started. It is no longer present in the current MOCK directory and no
  deletion dialog is open. A confirmation must not be transferred to another
  target.
- Daily self-password-change browser acceptance remains open for both the
  revoke-other-sessions and retain-other-sessions modes. Do not infer acceptance
  from a prepared form or a live fixture; the runtime assertions must finish.
- Cleanup remains policy-blocked. Read-only inspection found five owned
  containers and eleven related paths. The rejection happened before cleanup
  launched. Do not bypass it through another executor, split command,
  delegation, rename or parent deletion.
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
