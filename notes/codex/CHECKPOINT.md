# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`.
  The IAM first-release goal remains ACTIVE and incomplete.
- Latest pushed production candidate:
  `e1a96db06142f62508a26870edd8ce36cdc32780`, parent
  `176097677b5f73b63f3d47c7b4f218585feb050a`.
  Selectively ADAPT UX fixed
  `ad8cd9c3cd846d8556d0c3974826ff49bc4fc32d`, parent
  `3ddbd9911eb144f36eeecb4bbf8596df286b8ed9`; both selected production
  new/parent blobs match. Original consumer regressions and main renderer
  interaction remain; embedded assets were rebuilt here, not imported.
  Backend API/SQL and IAM87/Audit39/PaaS7+r37 are unchanged.
- Issue https://github.com/xiak/matrix/issues/4 is CLOSED/completed,
  confirmed at 2026-10-19 13:52:57 UTC. Old pending CREATE -> same-User
  logout/login -> restored UNKNOWN -> old401 or oldsuccess previously erased
  the later Session's persisted original intent. Both original tests fail
  before the patch in 1.94s and pass unchanged after it in 1.81s. Requests
  now verify the live source Session predicate using frozen source credential
  and revision; success/failure/cleanup cannot alter a later owner's intent.
  No new Session model, persisted credential or automatic second write.
- Exact Verification39258833606 / attempt1 / e1a96db is independently CLOSED:
  https://github.com/xiak/matrix/actions/runs/39258833606 .
  Terminal completed/success at 2026-10-19 13:48:00 UTC; all nineteen jobs
  and complete necessary logs verified, 57 authority roots RUN1/PASS1,
  370 steps = 175 success + 195 matrix-design skips, no failure/cancellation.
  Console 77 files/1973 Vitest + eight Node, 234 contrast pairs and
  324 matching exports passed; target provider file48/48. Exact metrics,
  four-product evidence, capacity limits and1855s wall duration belong to011.
  Seven Postfix children and thirteen opt-in browser entries did not run.
  No signed release or missing browser journey is accepted by this CI.
  Test Expert sealed the tuple; do not repeat jobs/log retrieval.
- Local seven-file/282-test regression, type/lint/architecture,
  contrast, two-worker export consistency, Go UI/architecture/default
  authorityprocess race and vet passed. No original assertion was weakened.
- Parent1760976 fixes the browser relay: /api/paas/ reaches PaaS rather
  than UI fallback; original owner checks method, raw cursor/URI,
  bearer/status and no tenant injection. This is not browser acceptance.
- Previous5384/39252717070, ca7d35c/39245573647,
  41ef/39237503801 and26deca/39224178428 are closed; do not re-fetch.
  Replaced bb960/39243201762,8c60/39241486192 and rejected
  101dc339/39199323432 remain cancelled, not PASS.
- Accepted signed production remains
  `9621bb6e66b1076576649d3f6b224725a60d6848`, IAM87/Audit39/PaaS7+r37.
  Sole rolling data predecessor:
  `08e1dc4a6ce81386ea7223e62d03356f82aeee58`, IAM86/Audit39/PaaS7+r36.
  FEAT005 owns exact A/B/trust, native-Linux lifecycle2787.02s and
  own-engine restart261.79s using fixed test driver26deca2.
  Real SMTP/MFA, four products, protected backup, failed-upgrade rollback,
  B upgrade/rollback/recovery, retained identities/Audit and capacity release
  passed. This does not accept e1's new signed consumer.
- Current9621 browser evidence includes Group deletion699.49s,
  GROUP attachment REVOKE403.43s and USER REVOKE578.23s, visible receipts,
  navigation, next-request authorization, unique completion/outbox/Audit
  and complete chains. Older evidence retains its exact source.
- Issue https://github.com/xiak/matrix/issues/3 remains OPEN for repeated
  large payload I/O and bounded runtime limitations. Failed/deadline runs
  remain failures. Signed lifecycle acceptance is not a production SLO.

## Reading route and next outcome

Read AGENTS, IAM/FEAT-IAM-010-console.md and IAM/FEAT-IAM-011-acceptance.md,
then owning code/tests. Release work additionally reads FEAT005 and the
verified platform-installation runbook. Keep facts in existing owners.

e1 CI is closed. Prepare an exact clean fixed-source signed consumer while
remaining actual browser actions retain their separate execution limits.
FEAT010 at pushed4cf0ad7102f976cd3f462b51d0663635a64ce100 pins the existing
ROLE/REVOKE two-tab journey: ordinary source User explicitly assumes its Role
and reads applications; admin revokes its exact attachment and recovers the
original receipt; ordinary tab observes business401/BLOCKED, explicitly
revalidates source User, then receives source-only403. Only then create the
existing finish marker. Backend re-assumption is not page evidence.
UX fixed-source review confirms existing routes; MOCK is not acceptance.

Remaining nonDeferred work: attachment CREATE receipts, Role page actions,
Policy default/boundary/error/conflict paths, both daily password options,
AccessKey lifecycle, restricted/forced MFA and recovery/step-up pages,
original Root recovery and product-termination UNKNOWN submissions.
IdP/WebAuthn/role chains/all-factor-loss protected Root recovery and
production fairness/installed database HA remain explicitly Deferred.
Keyboard专项 stays lower priority, not accepted.

## Runtime and tool boundaries

- Accepted9621 task engine is normally STOPPED with its installation volume
  retained; proxy/tunnel are stopped, not an online integration endpoint.
  Never restart remote machines or shared Docker/services.
- Previous SET_DEFAULT and ROLE/REVOKE pages stopped before final submission
  under browser action-time confirmation rules. Their fixtures were stopped
  and disposable PG/network/volume cleaned; no finish marker or PASS.
- Signed existing-factor login stopped before password/OTP submission;
  precise confirmation remains unanswered. Do not retry blocked credential
  actions, generate/submit OTP, or route them through another tool/agent.
  New credential entry/change requires human hand-off under the browser tool.
- Exact native/local Role-fence cleanup and four old local UI ELF-binary
  removals were tool-blocked. Nothing was removed by those requests; do not
  retry equivalent deletion through another command/tool. No prune.
- Only own exact labeled objects, bounded CPU/memory/PIDs,
  GOMAXPROCS2/-p2 and serialized heavy gates. Do not touch other tasks or
  remote1.3/1.5/161. Preserve accepted packages and reusable caches.

## Coordination

- UX/UI engineer `01a07b21-9a0d-7fd0-b090-7827ce18262e` owns UI/browser
  work. Fixed objects only, never WIP; latest adopted ad8cd9c/parent3ddbd991
  above. Earlier3ddbd991125e... does not exist. UX acknowledged narrow Issue4
  closure; no new MOCK/full-suite rerun.
- Test Expert `01a12f7b-be04-7590-acb1-3ba4f0dab999` completed exact e1
  final read-only CI audit. No other unclosed tuple at handoff,
  no duplicate monitor or repeated closed logs.
- User permits routine development/testing without repetitive approval;
  actual tool-specific restrictions remain. No new user tasks/subagents.
- Commit only this branch as repository-local Xiak <Jellal@aliyun.com>.
  Markdown and existing owners only; do not inherit donor acceptance/profile.
