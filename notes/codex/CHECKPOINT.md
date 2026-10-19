# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`.
  The IAM first-release goal remains ACTIVE and incomplete.
- Latest production candidate:
  `5384e4421877069f9ad4bc4e47ca219d46be9798`, parent
  `477b766d3e3a55151b16d9d1cd80c95bf8a5ff6e`.
  It selectively consumes UX fixed
  `c5f858d64ddb7ea4355fec794d950401e85edb1d` plus required
  `3ddbd9911eb144f36eeecb4bbf8596df286b8ed9`.
  Nine existing frontend source/test/locale paths and locally regenerated
  assets changed; backend API/SQL and IAM87/Audit39/PaaS7+r37 are unchanged.
  Protected business/Audit 401 expires only the current effective identity.
  ROLE blocks until explicit source revalidation, without auto-assumption or
  silent USER fallback. Late responses must match repository, Session revision
  and actor ownership. Dedicated password/TOTP/step-up failures remain separate.
- Main reproduced both c5 regressions before taking 3dd: a replaced repository's
  late 401 logged out the unchanged User bearer; a captured USER expiry callback
  cleared the source after ROLE activation. Both unchanged regressions now pass.
  Seven related files/280 tests passed in 56.05s on Node22.22.2, one worker,
  2GiB heap. Full lint, type/architecture, 234 contrast pairs, eight Node tests,
  2-worker unset/0 exports and all 324 embedded bytes passed. Go UI/architecture
  race passed in 7.305/2.438s, with related vet. Donor MOCK observations and test
  counts are not inherited.
- Exact new Verification
  https://github.com/xiak/matrix/actions/runs/39252717070 /
  attempt 1 / `5384e4421877069f9ad4bc4e47ca219d46be9798`
  was confirmed in_progress via GitHub API and handed to Test Expert.
  No new signed or real browser acceptance is claimed for this candidate.
- Prior test-only `ca7d35c971f4325801d1357881928e4a3530cdd1` /
  Verification39245573647 / attempt1 is independently CLOSED success.
  All nineteen jobs, complete necessary logs and 57 authority roots passed;
  console 77 files/1965 Vitest + eight Node tests, 234 contrast pairs and
  324 matching exports passed. Seven Postfix child tests and thirteen opt-in
  browser entries did not run. FEAT011 owns the exact scope and 2002s duration.
  Do not refetch this closed tuple or 41ef/39237503801, 26deca/39224178428.
  Replaced bb960/39243201762, 8c60/39241486192 and rejected
  101dc339/39199323432 remain cancelled, not PASS.
- Accepted signed production remains
  `9621bb6e66b1076576649d3f6b224725a60d6848`, IAM87/Audit39/PaaS7+r37.
  Sole rolling data predecessor:
  `08e1dc4a6ce81386ea7223e62d03356f82aeee58`, IAM86/Audit39/PaaS7+r36.
  FEAT005 owns fixed A/B/trust identities and native-Linux full lifecycle
  2787.02s plus own-engine post-restart 261.79s, using test driver
  `26deca2ae9df57cf2913a4868bca47f9332dd7c4`.
  Real SMTP/MFA, four products, backups, failed-upgrade rollback, B upgrade,
  explicit rollback, recovery, retained identity/Audit and capacity release
  passed. This does not accept the new 5384 UI or unfinished page journeys.
- Current 9621 real-process browser passes include Group deletion699.49s,
  GROUP attachment REVOKE403.43s and USER attachment REVOKE578.23s, with visible
  immutable receipts/navigation, next-request authorization, unique completion/
  outbox/Audit and complete chains. Older User/Group/Account evidence retains
  its original fixed sources. No API-only postcondition is relabeled a page run.
- Issue https://github.com/xiak/matrix/issues/3 stays OPEN for repeated large
  payload I/O and bounded runtime limitations. Failed fixture/deadline runs
  remain failures. Signed lifecycle acceptance does not establish production SLO.

## Reading route and next outcome

Read AGENTS, IAM/FEAT-IAM-010-console.md, IAM/FEAT-IAM-011-acceptance.md,
then the directly owning code/tests. For release work read FEAT005 and the
verified platform-installation runbook. FEAT010 owns the remaining page matrix;
FEAT011 owns combined acceptance. Update existing owners, not new diaries.

Continue exact 5384 CI through Test Expert while preparing the remaining ROLE
journey with UX. The existing
`TestIAMPolicyAttachmentRecoveryConsoleBrowser` covers GROUP/USER/ROLE
CREATE/REVOKE; its ROLE re-assumption and business checks are backend fixture
postconditions, not browser source switching. Do not mistake that fixture
passing for actual ROLE -> protected business401 -> explicit source validation.
The UX owner has been asked for fixed-source-only review and minimum page/fixture
steps; no new real endpoint or credential window has been opened.

Remaining nonDeferred work includes attachment CREATE receipts, ROLE page
actions, Policy default/permission-boundary/error/conflict paths, both daily
password options, AccessKey lifecycle, forced/restricted MFA and relevant
recovery/step-up pages, original Root recovery and product termination UNKNOWN
final submissions. IdP/WebAuthn/role chains/all-factor-loss protected Root
recovery and production fairness/installed database HA remain explicitly
Deferred. Keyboard专项 remains lower priority, not accepted.

## Runtime and tool boundaries

- Signed 9621 task engine was normally STOPPED and its installation volume
  retained; proxy/tunnel were stopped. It is not an online integration endpoint.
  No remote machine or shared Docker was restarted. New UI tests/builds in this
  milestone created no containers, databases, tunnels or signing material.
- Previous SET_DEFAULT and ROLE/REVOKE page runs stopped before final submit
  because their executing browser tool required human action-time confirmation.
  No finish marker or successful operation was claimed; their disposable PG,
  volume and network were removed after zero external clients.
- Signed existing-factor login likewise stopped before password/OTP submission.
  The precise action-time confirmation remains unanswered; do not generate or
  submit credentials, use another tool/API/agent, or relabel broad authorization
  as satisfaction of a tool-specific requirement. Source-code review can proceed.
- Native/local Role-fence source/archive cleanup was explicitly tool-blocked.
  Those files were not removed; do not retry equivalent cleanup through another
  tool. Retain reusable caches and the accepted installation until no longer
  needed; no prune or broad deletion.
- Use unique labeled resources, bounded CPU/memory/PIDs, GOMAXPROCS2/-p2 and
  serialized heavy real gates. Only clean exact task-owned objects after evidence.
  Do not touch other tasks' environments or remote hosts 1.3/1.5/161.

## Coordination

- UX/UI engineer `01a07b21-9a0d-7fd0-b090-7827ce18262e` owns UI and
  browser work on its branch. Consume only fixed Git objects, never its WIP.
  Correct follow-up is 3ddbd9911eb144f36eeecb4bbf8596df286b8ed9;
  the earlier misreported 3ddbd991125e... object does not exist.
  Current request is fixed-code review only, not MOCK or live credential actions.
- Test Expert `01a12f7b-be04-7590-acb1-3ba4f0dab999` owns read-only
  independent CI/log review. Its existing monitor follows the exact new tuple;
  no duplicate monitor, repeat reads of closed logs, or runtime mutation.
- User permits routine product development/testing without repetitive approval;
  actual tool-specific restrictions still apply. No new user tasks/subagents.
- Commit only this feature branch, repository-local Xiak <Jellal@aliyun.com>.
  Markdown and existing owners only; do not merge other branches or inherit their
  profile/acceptance claims.
