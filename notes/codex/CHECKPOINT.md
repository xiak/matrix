# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`.
  The IAM first-release goal remains ACTIVE and incomplete.
- Current fixed UI consumer:
  `2d853754ab0f1f0608355665fbb9011315b3779f`, parent
  `5e78e32c1dacb9ce095403155ee755b53d708524`.
  Selectively ADAPT UX `fd3cf32c70f608b4048749a5289750e473975825`,
  parent `9d0e3b9729eeb53cc07cbff54b651ff730afd648`.
  Seven production blobs match the fixed donor; both consumer test files'
  differences and original login interactions remain. Embedded assets were
  rebuilt here. No backend API, SQL or
  IAM87/Audit39/PaaS7+r37 change.
- The earlier f312 storage/read-back fixes remain, including four independent
  7.72s red / 8.37s unchanged green regressions. The new four page connections
  fail before fd3 and pass unchanged after it; the prior client-change case
  remains green. Three added consumer negatives prove rejected/wrong-owner
  reads stay locked with zero key writes and stale client callbacks cannot
  open a later identity's directory. Both complete renderer files pass 285/285
  in85.99s. Type/lint/architecture,234 contrast pairs,eight Node tests and
  dual two-worker export comparison (324 files) pass. Go UI/architecture/
  default authorityprocess race 7.277/2.342/3.910s, vet and Linux UI build pass.
  These are local gates, not LIVE or independent-CI acceptance.
- Issue https://github.com/xiak/matrix/issues/5 remains OPEN. Fixed consumer
  and remaining real-browser items are recorded at
  https://github.com/xiak/matrix/issues/5#issuecomment-6272714813 .
  FEAT010 owns exact-owner recovery across directory pages/failures,
  User policies/keys section navigation and one-time Secret leave protection.
  These three connections are implemented, not browser-accepted. No global
  key lookup or invented Access Analysis owner relationship.
- Earlier test-only fixed source
  `ef10d51bfbf120ec521e665bac9d54b14fa26c0d` keeps closed rollback error
  categories and original receipt assertions in the existing phase1e2e owner.
  Its opt-in prepared-B rollback diagnostic is not a second lifecycle suite.
  phase1e2e/platformcommand/CLI race 3.133/20.880/2.534s and vet pass.
- Sole unclosed CI tuple:
  2d853754 / Verification39288898228 / attempt1,
  https://github.com/xiak/matrix/actions/runs/39288898228 .
  Last independently observed in_progress; no terminal acceptance yet.
  Audit this exact tuple rather than restarting or retrieving closed runs.
- ef10d51 / Verification39284297226 / attempt1 is CLOSED FAILURE, not queued
  or cancelled: independent audit sealed19 logs,17success/2failure jobs,
  56PASS/1FAIL of57 roots. ManagedProductProviderProcesses39.94s failed when
  the worker exited1 before HTTP200 with
  PAAS_WORKER_EXECUTION_PROFILE_OBSERVE_TIMEOUT. The five-second Observe
  budget is unchanged; the underlying command/connection cause is unproven.
  Issue https://github.com/xiak/matrix/issues/6 owns diagnosis. No independent
  IAM contract/security assertion failure is evidenced. Never re-fetch this
  closed attempt or reinterpret two passing PG roots as four-product success.
- Prior production `e1a96db06142f62508a26870edd8ce36cdc32780` has closed
  Verification39258833606 / attempt1: all nineteen jobs and necessary logs
  independently verified success. 57 authority roots RUN1/PASS1, complete
  1973 Vitest+eight Node tests. Issue4 is CLOSED for that exact source-Session
  fix. Do not re-fetch those closed logs or treat them as f312 acceptance.
- Accepted signed production remains
  `9621bb6e66b1076576649d3f6b224725a60d6848`, IAM87/Audit39/PaaS7+r37.
  Sole rolling data predecessor:
  `08e1dc4a6ce81386ea7223e62d03356f82aeee58`, IAM86/Audit39/PaaS7+r36.
  FEAT005 owns exact A/B/trust, lifecycle2787.02s and own-engine restart
  261.79s with driver26deca2. Real SMTP/MFA, four products, protected backup,
  failed-upgrade rollback, B upgrade/rollback/recovery, retained identities/
  Audit and capacity release passed. This does not accept later consumers.
- Later e1 signed A .r37.7/B .r37.8 full lifecycle FAILED at
  platform-rollback after2000.90s. Original output was collapsed and not
  retained; precise original cause is unknown. A later authenticated B READY
  status did not convert failure to success.
- ef10's separate focused rollback of that retained signed B succeeded
  in373.84s on2026-10-20 Asia/Shanghai. It authenticated A/B, checked the
  installation, executed the original signed mx, and proved A/empty previous/
  changed, exact healthy A inventory, absence of B containers, repeated
  read-only status and verify/profile. Driver SHA256
  a94c0050c054cfcb1ff59a75c8cf3376e95a92ca63ae7db4810bf97842e0f13e.
  It did not reproduce the failure, prove its cause, or accept whole-release
  business/backup/restart behavior. A prior CR-suffixed timeout argument
  failed before test entry and had no rollback effect.
- After diagnosis, that task's engine, exclusive Docker volume and7.6GiB
  synthetic installation/credentials were removed. Signed inputs, public
  trust and driver remain. Native host boot and shared Docker start unchanged.
  No live e1 installation or process handle remains.
- Issue3 stays OPEN for repeated large-payload I/O and bounded runtime
  limitations. Do not interpret signed lifecycle results as a production SLO.

## Reading route and next outcome

Read AGENTS, IAM/FEAT-IAM-010-console.md and IAM/FEAT-IAM-011-acceptance.md,
then owning code/tests. Release work additionally reads FEAT005 and the
verified platform-installation runbook. Keep each fact in its existing owner.

Close the exact current CI and complete the three AccessKey page connections'
real-browser evidence. Preserve the original four consumer regressions and
no-secret/no-second-write boundaries. Real browser response-
loss, navigation, reauthentication and replay/read-back remain separate gates.
Use a clean fixed signed candidate for final release acceptance; do not rerun
the retired e1 full lifecycle merely to overwrite its earlier failure.

Remaining nonDeferred work: attachment CREATE receipts, Role page actions,
Policy default/boundary/error/conflict paths, both daily password options,
AccessKey lifecycle, restricted/forced MFA and recovery/step-up pages,
original Root recovery and product-termination UNKNOWN submissions.
FEAT010 pins the existing ROLE/REVOKE two-tab journey; backend re-assumption
and a finish marker alone are not page evidence.
IdP/WebAuthn/role chains/all-factor-loss protected Root recovery and
production fairness/installed database HA remain explicitly Deferred.
Keyboard专项 stays lower priority, not accepted.

## Runtime and tool boundaries

- Accepted9621 task engine remains STOPPED with its installation volume
  retained; proxy/tunnel are stopped, not an online integration endpoint.
  Do not reboot remote machines or restart shared Docker/services.
- Prior SET_DEFAULT and ROLE/REVOKE pages stopped before final submission
  under browser confirmation rules. Signed existing-factor login stopped
  before password/OTP submission. No PASS or finish marker; never reroute
  blocked actions through APIs, terminal or another agent.
  New credential entry/change requires the browser tool's human hand-off.
- Exact earlier Role-fence cleanup, four old UI ELF removals and a201MiB
  task-created temporary npm cache removal were tool-blocked. They were not
  deleted; do not retry equivalent deletion through another command/tool.
- Only own exact labeled objects, bounded CPU/memory/PIDs,
  GOMAXPROCS2/-p2 and serialized heavy gates. Do not touch other tasks or
  remote1.3/1.5/161. Keep accepted packages and genuinely reusable caches.
- Use process-local pinned Node22.22.2, not default PATH Node23.
  Vitest one worker/2GiB; production export two workers. No global nvm change.

## Coordination

- UX/UI engineer `01a07b21-9a0d-7fd0-b090-7827ce18262e` owns UI/browser
  work. Fixed objects only, never WIP or inherited acceptance. Current
  consumedfd3 and pending page acceptance are in FEAT010/Issue5; the donor's
  900618f documentation/checkpoint was not imported.
- Test Expert `01a12f7b-be04-7590-acb1-3ba4f0dab999` owns independent
  audit of the sole unclosed2d853/39288898228/attempt1 tuple.
  No duplicate monitor, new task or new subagent.
- User permits routine development/testing without repetitive approval;
  actual tool-specific restrictions remain.
- Commit only this branch as repository-local Xiak <Jellal@aliyun.com>.
  Markdown and existing documentation owners only.
