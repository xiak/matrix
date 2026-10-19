# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`.
  The IAM first-release goal remains ACTIVE and incomplete.
- Latest pushed production candidate:
  `e1a96db06142f62508a26870edd8ce36cdc32780`, parent
  `176097677b5f73b63f3d47c7b4f218585feb050a`.
  It selectively consumes UX fixed
  `ad8cd9c3cd846d8556d0c3974826ff49bc4fc32d` on top of the earlier
  c5f858d + 3ddbd991 effective-credential boundary. Both selected production
  parent blobs match this branch; SessionProvider/ControlPlaneProvider now
  match the fixed donor, while original consumer tests and main renderer
  interaction remain. Assets are rebuilt here, not imported.
  Backend API/SQL and IAM87/Audit39/PaaS7+r37 are unchanged.
- Issue https://github.com/xiak/matrix/issues/4 remains OPEN pending exact new CI.
  Old pending CREATE -> same-User logout/login -> restored UNKNOWN -> old401
  or oldsuccess used to delete the later Session's persisted original intent.
  Both original regressions fail before the patch in 1.94s and pass unchanged
  after it in 1.81s. A component-local ref survives in the old Promise after a
  keyed subtree remount, so requests additionally verify the live source
  Session predicate with frozen source credential/revision. Success, failure
  and cleanup cannot delete a later owner's original intent or submit again.
  Do not close the issue from the earlier 5384 green CI.
- Seven related files/282 tests passed in 64.72s on Node22.22.2, one worker,
  2GiB heap. Type/lint/architecture, 234 contrast pairs, eight Node tests,
  2-worker unset/0 exports and all 324 embedded bytes passed. Go UI,
  architecture and default authorityprocess race passed in 7.303/2.398/3.941s,
  with related vet. No opted-in database/browser gate ran in this local check.
- Parent 1760976 fixes only the existing browser relay and its tests:
  `/api/paas/` now reaches PaaS instead of the UI fallback. The original owner
  proves the method, raw cursor/URI, synthetic bearer, status and absence of a
  caller-selected tenant header. Wrong UI200 is red, exact PaaS401 is green;
  default loopback routing is not real browser or PaaS authorization acceptance.
- Exact new Verification
  https://github.com/xiak/matrix/actions/runs/39258833606 /
  attempt 1 / `e1a96db06142f62508a26870edd8ce36cdc32780`
  was confirmed in_progress via GitHub API and handed to Test Expert.
  No new signed or real browser acceptance is claimed for this candidate.
- Previous production candidate `5384e4421877069f9ad4bc4e47ca219d46be9798` /
  Verification39252717070 / attempt1 is independently CLOSED success.
  Nineteen jobs and complete necessary logs, 57 authority roots, console
  77 files/1971 Vitest + eight Node, 234 contrast pairs and 324 matching
  exports passed. Seven Postfix child tests and thirteen opt-in browser entries
  did not run. FEAT011 owns the exact scope and 1754s wall duration.
  Do not refetch this closed tuple, ca7d35c/39245573647, 41ef/39237503801
  or 26deca/39224178428.
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

Continue exact e1a96db CI through Test Expert while preparing the remaining ROLE
journey with UX. The existing
`TestIAMPolicyAttachmentRecoveryConsoleBrowser` covers GROUP/USER/ROLE
CREATE/REVOKE; its ROLE re-assumption and business checks are backend fixture
postconditions, not browser source switching. Do not mistake that fixture
passing for actual ROLE -> protected business401 -> explicit source validation.
Fixed-source inspection confirms ROLE+REVOKE can use two browser tabs with
independent in-memory Sessions: ordinary `browser.attachment.recovery` explicitly
assumes its exact Role and reads applications; admin revokes the attachment and
recovers the original immutable receipt; ordinary tab observes 401/BLOCKED,
explicitly revalidates the source User, then gets source-only business403.
Create the existing finish marker only after the actual page journey; later
backend re-assumption cannot replace it. This sequence was sent to the UX owner
for fixed-source review. No new endpoint or credential window has been opened.

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
  Latest consumed follow-up is ad8cd9c3cd846d8556d0c3974826ff49bc4fc32d,
  parent 3ddbd9911eb144f36eeecb4bbf8596df286b8ed9. The earlier misreported
  3ddbd991125e... does not exist. Current request is fixed-code review only,
  not MOCK or live credential actions.
- Test Expert `01a12f7b-be04-7590-acb1-3ba4f0dab999` owns read-only
  independent CI/log review. Its existing monitor follows the exact new tuple;
  no duplicate monitor, repeat reads of closed logs, or runtime mutation.
- User permits routine product development/testing without repetitive approval;
  actual tool-specific restrictions still apply. No new user tasks/subagents.
- Commit only this feature branch, repository-local Xiak <Jellal@aliyun.com>.
  Markdown and existing owners only; do not merge other branches or inherit their
  profile/acceptance claims.
