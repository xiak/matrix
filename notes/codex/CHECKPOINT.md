# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`.
  The renewed IAM first-release goal remains ACTIVE and incomplete.
- Latest fixed production candidate:
  `9621bb6e66b1076576649d3f6b224725a60d6848`, IAM87/Audit39/PaaS7+r37.
  It selectively consumes UX fixed `82954bcefe2abcad4d3f1d9c2189e0d5e6408a66`
  and test-only `64311a0b14e9bb2fd5f9fe9ef21b412e89fe505c`: three existing
  source/test paths, preserving this branch's renderer tests and rebuilding
  its own embedded assets. USER attachment begin/submit/UNKNOWN inspect now
  require both the current owner and verified repo+Session before effects.
  The consuming branch observed two new tests fail on the unchanged old
  source, then pass with the correction. Two related files/267 tests passed;
  after the direct-context test addition, four focused cases passed, as did
  type/changed-path lint/architecture/234 contrast pairs, eight Node tests,
  two-worker deterministic unset/0 exports and 324 matching embedded files,
  Go UI/architecture race, UI vet and Linux amd64 UI build. Exact
  [Verification 39203431655](https://github.com/xiak/matrix/actions/runs/39203431655)
  attempt 1 is completed/success: all 19 jobs and all 57 authority roots were
  independently verified, including required processes/final storage scan,
  the real 40001 retry, the rolling predecessor and four real products.
  Console passed 77 files/1965 tests plus eight Node tests and 324 matching
  exports/embedded files; 33 existing act warnings remain. Seven dedicated
  Postfix subtests and 13 opt-in browser flags did not run. FEAT011 owns the
  closed CI evidence; do not fetch the same attempt logs again. No API/SQL/
  backend/Profile change. Its new signed combination is still not accepted.
- Rejected predecessor `101dc339f9ad368f293f95a3834b5613e5a6d669` /
  Verification 39199323432 attempt 1 is closed as completed/cancelled after
  the fixed-source owner-fence finding. Cancellation was intentional, not
  a newly proven backend assertion failure; its aggregate failed because
  lanes were cancelled. Do not reopen its full log audit or backfill it.
- Its fixed test predecessor `42c957aa4bd4614777513aff782b2071c67f2a9d`
  extends the existing attachment browser fixture to USER and ROLE, preserving
  default GROUP. RoleSession business permission remains separate from its
  source USER. Default compilation/race/architecture/vet passed; the new opt-in
  browser paths have not run and are not accepted.
- Latest accepted independent test correction:
  `38a2cda69ec547c9e8d9d557bf61a3bcd992335c` /
  [Verification 39196850326](https://github.com/xiak/matrix/actions/runs/39196850326),
  attempt 1, all 19 jobs completed/success. The test expert closed all required
  logs: all 57 top-level authority roots RUN/PASS, the deterministic real
  SQLSTATE40001 retry passed, and required processes plus final storage scan
  actually ran. Seven dedicated-Postfix skips and default opt-in browsers
  are not execution evidence. Do not repeat this closed log audit or backfill
  the older 28f CI failure. FEAT011 owns the evidence; FEAT009 owns the invariant.
- Test-only release-gate correction
  `5708545f54e15adeadca79d947ebb99802bac5ea` is committed and pushed.
  FEAT-005 owns the native-Linux first-run failure and focused reproduction:
  the unchanged Postfix fixture exited when its inherited descriptor limit
  exceeded the observed kernel ceiling; explicit `nofile=4096:4096` kept it
  running and strict original-CA/SAN STARTTLS passed. The existing fixture
  now supplies and inspects that finite limit, with ordinary negative unit
  coverage. Phase1e2e unit/race, architecture race, vet and Linux driver build
  passed. Exact Verification 39212113957 attempt 1 is running, assigned to
  the existing Test Expert's read-only monitor. Production bits and profile
  are unchanged: the signed source remains 9621, and its full fresh runtime
  and restart gates still need actual passing evidence. Do not backfill the
  failed 640.84-second first run or substitute the TLS diagnostic for SMTP.
- Accepted signed-release source remains
  `741dceb6f0092fbc33706842862980816fe72d15`,
  IAM87/Audit39/PaaS7+r37. Its exact CI and same-profile signed A/B lifecycle
  and restart verification passed. The new UI is not accepted as a signed
  combination. The single rolling predecessor remains
  `08e1dc4a6ce81386ea7223e62d03356f82aeee58`, IAM86/Audit39/PaaS7+r36.

## Reading route and remaining outcome

Read AGENTS, IAM/FEAT-IAM-010-console.md, IAM/FEAT-IAM-011-acceptance.md,
then the relevant existing test/authorityprocess/process_e2e_test.go owner.
FEAT010 owns individual UI paths and gaps; FEAT011 owns combined acceptance.
Read the current FEAT005 and verified runbook before signed lifecycle work.

Prior Group attachment CREATE/REVOKE response-loss and Group deletion effects
have real evidence. The new UI keeps visible immutable receipts and explicit
completion navigation; User/Role commands fence stale repository/Session
owners. Historical Account-settings receipts do not expire later Sessions.
These source/component facts do not close the remaining LIVE journeys.

The new Group browser run stopped before its final deletion without a finish
marker; the new REVOKE receipt rerun did not start. Neither is accepted.
Tool-mandated action-time human confirmation cannot be replaced by blanket
authorization or another tool/API. Do not repeatedly ask or start a long
waiting fixture without this prerequisite.

Continue the existing nonDeferred FEAT010 matrix, including final receipt
operations, daily password change, direct User/Role attachments and remaining
policy/security/resource paths. Do not repeat accepted gates without an
affected boundary. Deferred integrations are not silently added to this goal.
The final new-source signed combination and unused-task-resource cleanup
remain separate required outcomes.

## Coordination and delivery boundaries

- UX/UI engineer `01a07b21-9a0d-7fd0-b090-7827ce18262e` owns UI on its
  own branch. Consume fixed reviewed deltas only, preserve consumer tests and
  rebuild assets; no foreign WIP or inherited acceptance. Its 101dc/42c
  fixed review found the USER pending-identity blocker now corrected in 9621.
  Test Expert independently reviewed the fixed 829 production fence and
  closed the exact consuming 9621 CI. UX confirmed no outstanding production
  delta in its source subtree; current matrix gaps are real-page/combination
  evidence, not permission to invent another UI implementation. The obsolete
  security-settings wording gap was removed in pushed 183e91a0a.
- Test expert `01a12f7b-be04-7590-acb1-3ba4f0dab999` owns read-only
  independent CI/log review. It closed 9621/run39203431655/attempt1 after 38a
  and the cancelled 101dc; the existing monitor remains responsible for new
  fixed tuples only. Do not duplicate automations, repeat closed log audits,
  or delegate execution beyond its human-authorized read-only scope.
- Routine product development/testing is human-authorized without repetitive
  approval. Mandatory tool-specific handoff still binds. Do not reset shared
  Docker/WSL, restart remote machines/shared services or touch other resources.
- Use unique task-owned limited resources, GOMAXPROCS2 and bounded concurrency;
  serialize heavy real gates and remove unused task resources after evidence.
  A successful CI cleanup does not prove all historical local objects are gone.
- Markdown and existing owners; local Git identity Xiak <Jellal@aliyun.com>.
  Push only this feature branch.
