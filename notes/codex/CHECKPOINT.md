# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Write only
  this task's independent worktree. Updated 2026-09-24.
- Full IAM goal remains ACTIVE/incomplete. Read AGENTS, IAM/011 for the
  development test window, IAM/009 for current MFA work, then owning code.
  IAM/012 owns mail; docs/adoption/FEAT-006-platform-authorities.md owns
  fixed sources. Markdown only.
- Latest implemented and pushed test source:
  **aefe4f786242d7d6816f253b6389d5c94c314a75**.
  Test-only reduction; no production API/SQL/schema/profile, installation
  or UI change. Actual source IAM42/Audit24/PaaS2, not a release profile.
- Exact https://github.com/xiak/matrix/actions/runs/35972120363 is pending.
  Verify precise SHA and every gate before calling CI accepted. Default
  skipped external tests are not real-runtime evidence.
- Verified/pushed rollback point09fac9135af99da3273d31c2f9b3e26d6aacfdc5
  corrected two Audit integration schema assertions and separated original
  retained Account/Session fields from new explicit security defaults.
  Its local real tests passed. Do not inherit an unfinished CI conclusion.

## Current development test window

User explicitly authorized a bounded pre-v1 window and companion review:
current version plus one fixed necessary predecessor, not schema1..N or one
old binary for every FEAT. Delete replaced test paths and their helpers/envs,
not permanent SKIP lists. Exceptions require a real published/non-atomically
migratable consumer, fixed source, reason and exit condition.

TestIAMRetainedPredecessorProcessUpgrade uses actual
0a237aae5c904e0e32e5766544e31c1cfed5a02a (IAM41) to current42.
MATRIX_IAM_PREDECESSOR_POSTGRES_TEST_DSN requires a uniquely named
matrix_iam_upgrade_predecessor_ database. Nine obsolete entry points removed;
CI seven predecessor paths became one, with six extra databases removed.
Published Audit bytes and installation effect-before-reject remain supported
contracts; numeric adjacency never grants upgrade/rollback compatibility.

Current test retains original bootstrap/outbox/proofs, two Accounts/same
username, revoked attachment, normal/ended/NULL-generation/forced Session,
shared budgets, original completion, pending mail and real MFA recovery.
A true late-DDL failure is reached (private nontransactional sequence proves
it) and leaves the original schema/data intact; underlying migration errors
remain sanitized. Apply twice, equal bootstrap, restart and original recovery
completion remain. Frozen product declaration/non-expansion, explicit default
selection and incompatible Deny behavior moved out of the obsolete IAM21
wrapper into this current-authority phase; no hypothetical schema matrix.

Local final evidence is in IAM/011:
- Actual predecessor gate37.13s/package40.525; independent IAM pair,
  PaaS/Audit/dispatchers143.49s/package146.678, both race-p1 serial.
- Actual restricted runtime logins, tenant/Operation/outbox boundaries,
  committed TCP-loss/restart/original replay, cross-replica single OTP,
  revoked identities and secret checks all retained.
- Full default race-p2 (including architecture), vet, gofmt/diff and workflow
  YAML/14 Bash blocks passed. No new SMTP/browser/signed-release acceptance.
- Go1.26.7/GOMAXPROCS2/GOMEMLIMIT512MiB. Owned PG18.6 used Windows Job
  hard2logicalCPU/1GiB/24processes,16connections,64MiB shared_buffers,
  4MiB work_mem/no parallel workers. Zero-client check then normal stop;
  all local test/PG handles terminal. Data retained. No shared/remote restart.
  Never retry policy-denied temporary cleanup.

## Current MFA production boundary

Fixed339d37474f2cfbee11479a497514d8dcb4d38b0f adds immutable purpose in
original authentication_challenges: LOGIN for password-proved login and its
verified password-change successor, RECOVERY for consumed original saved-code
rebinding. Private lookup requires purpose; usecase reservations/seed access,
final locks and deferred completion all check it. No ENROLLMENT SQL issuance.
Missing/damaged current purpose fails closed, never guessed on equal replay.
Its earlier CI actually ran but failed on the two test-contract issues fixed
by09fac; do not report339 as independently accepted.

Fixed0a237aae supplies only public first-ENROLLMENT contracts. Restricted
PASSWORD_CHANGE/ENROLLMENT is not a Session, cannot expose later state before
required password change, and requires verified original contact before factor
creation. No current first-enrollment HTTP/SQL capability may be inferred.

Fixed018fbd75 supplies read-only GET /v1/account/security-settings:
current USER LOGIN_SESSION plus exact iam.security-settings.read on its
ACCOUNT; no selector or Role/Key/Service substitute. New existing-account
fields initially1/false/originalcreatedAt. Current immutable SQL guard forbids
writes. Product Profile6 archives5; existing policies/attachments gain no right.
Root/admin can legitimately receive403.

Next S2c target remains real forced initial password/contact/TOTP completion,
settings PUT CAS with exact operation StepUp/current authority, monotonic
Session/Role qualification and supported-restore nonrollback requirements.
Already bound MFA is not a session authentication fact. Settingstrue→false,
protected binding revoke/regrant and restore must not revive old authority.
Do not assume a new qualification representation has been implemented/frozen.

Fixedb7a70bfa9e53f0a5f16619c60523c84613cb7b0b supplies current Session-held
step-up/regeneration: only RECOVERY_CODES_REGENERATE,120s absolute,max3 live,
nonforced PASSWORD_TOTP Session and exact Account/USER/Session/generation/
factor/revision/batch/intent. APPLIED returns ten codes once; equal replay and
same-USER completion lookup return metadata only, never change later Session.
OTP math uses pquerna/otp1.5.0, not a duplicate HMAC implementation.

Private recovery donor a4cbd18598099751eb1bd3eac896e191db474524 was ADAPTed
into existing executable/role/codec and000014 CLOSED/reconcile/reopen fences.
Keep login_session_contract_ready. Current fixed consumers retain service
lookup5, Audit claim7 and original canonical semantics. No release profile
permission follows from development source versions.

## Coordination and remaining boundaries

Installation task01a04149-5dbb-7300-9e4c-31d9e85c8ada owns protected keys,
signed consumers/journal/profile and actual restore. Asked to review its own
obsolete tests and identify any fixed real consumer exception to the rolling
window; no pause/foreign environment change requested. No final reply yet.
Its S2c prerequisite remains durable complete current Account security
requirements outside DB rollback before destructive restore; missing/unknown
current state cannot restore oldfalse. Snapshot/closure ABI not yet frozen.
No new recovery codec or release revision allocated here. Real SMTP worker,
keyring/channel and signed consumer acceptance remain its own evidence.

UI task01a07b21-9a0d-7fd0-b090-7827ce18262e, feat/cloud-console-ux,
exclusively owns UI. It reviewed current slice tests: supported MOCK remains;
no deletion purely for count. Preserve cross-Session late-reply/secret gates,
LIVE/MOCK separation, exact unknown-intent retry and409-not-proof.
Latest reported fixedcd0be0bc/docs cf80c414 are not imported or independently
accepted here. Owner proceeds with005 CUSTOMER/TENANT version publication;
publication is not default selection or grant. No invented compile-preview API.
Current stable backend errors have no field-path array:400 iam.json.invalid,
422 iam.argument.invalid,413 iam.body.toolarge,415 media/encoding.unsupported,
401 authentication.failed,403 authorization.denied,409 state.conflict,
503 iam.unavailable (iam. prefix). Public Problem is type/title/status/code/
requestId; never expose raw validator, response or secret input.

009/012 own remaining first enrollment/replacement/removal/settings/session
barrier/password governance, real mail/browser and signed recovery. Whole
IAM also still lacks final product/service/federation/capacity/HA acceptance.
No full goal completion from this test cleanup or a green local subset.

Local Git identity Xiak <Jellal@aliyun.com>. No new agents/tasks, foreign
worktree writes, remote1.3/.160/.161 or withdrawn GitLab/1.5 operations,
global config/sharedDocker/WSL restart/prune, personal mailbox tests or
cleanup-policy bypass. Each companion keeps its own branch and resources.
