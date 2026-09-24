# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam; write only
  this task's independent worktree. Updated 2026-09-24.
- Full IAM goal remains ACTIVE/incomplete. Read AGENTS and IAM/009 for MFA,
  IAM/012 for mail, then owners. Adoption belongs to
  docs/adoption/FEAT-006-platform-authorities.md.
- Latest implemented/pushed fixed candidate:
  **0a237aae5c904e0e32e5766544e31c1cfed5a02a**, parent6e105658.
  This is restricted first-enrollment contracts/issuer defense, not the
  ENROLLMENT HTTP/SQL runtime or settings write. Runtime read baseline below
  remains **018fbd7505ae16d59dcfe857df7fbbe870bf1a13**.
  Source IAM41/Audit24/PaaS2. No release profile allocated or changed.
- Exact https://github.com/xiak/matrix/actions/runs/35961451647 is
  completed/failure; seven jobs runner_id=0/steps=0. go annotation explicitly
  says payment/spending limit prevented execution. Independent CI NOT passed.
  Prior018/35959220825, d570/35955820844 and b7/35953732463 had the same zero-execution
  outcome. Do not alter billing or repeatedly rerun unchanged blockage.

## Current settings read

GET /v1/account/security-settings requires current USER LOGIN_SESSION plus
explicit iam.security-settings.read on its actual ACCOUNT instance.
No Account/tenant/body/cursor selector; RoleSession, AccessKey and Service
cannot substitute. Product Profile6 archives5 unchanged; immutable system
policies and existing attachments gain no rights. CurrentIdentity capabilities
are unchanged. Root/admin can legitimately receive403.

Existing accounts owns security_settings_version, mfa_required_for_users,
security_settings_updated_at. Initial pre-settings migration records
1/false/original Account.created_at; creation does so in its transaction.
No read-time defaults. CHECK/ALWAYS guard reject any settings mutation in
this slice. Missing authority fails closed; exact shape/ACL checked by
readiness/verify. read_account_security_settings(text,text,text) consumes
the current transaction's actual allowed decision.

No PUT/history route, update action or settings StepUp. Six strict types
originated at d570673ba87c113f7474fdab79b5e22a83c2b323. IAM/009 S3 owns
design/evidence. Next writes must include forced enrollment, Session/Role
qualification barrier and supported restore's non-rollback Account MFA
requirement. Existing backup configuration alone cannot prove current
requirements; installation coordination remains open. Do not stop goal here.

## Local evidence at018fbd75

Go1.26.7/GOMAXPROCS2/GOMEMLIMIT512MiB; real gates serial race-p1.
Owned Windows PG18.6: Windows Job hard2logicalCPU/1GiB/24processes,
16connections/64MiB shared_buffers/4MiB work_mem/no parallel workers.
Zero-client check and normal shutdown completed; no live task test/PG handle.
No shared or remote restart. Never retry policy-denied temp cleanup.

- Policy storage full142.48s; final settings flow+parent18.60s/package22.017.
  Two Accounts/same username, grant/Deny/Boundary/revocation/isolation,
  actual session/current_user login, five SQL denial cases,11 schema/ACL
  drift cases, immutable read timestamp and replay.
- Actual fixedf5cec0e132ad18900d9a5a5629eae04fda4817f1 IAM37 executable
  retained upgrade23.41s/package26.768: original Account/identity/credential/
  attachment/Session/receipt/canonical/profile bytes preserved; head6 and
  initial settings only. Original MFA/recovery/restart retained, not release
  profile compatibility.
- Independent IAM pair/Audit/PaaS/dispatchers127.29s/package130.724:
  runtime logins, replica reads/revocation/restart, actual Role/Key rejection,
  historical read-decision producer/outbox delivery after revocation.
  Original tenant business/MFA/lost-TCP/recovery/regeneration gates retained.
  Role policy-history test checks its exact target/request/actor once across
  pages, not the incidental count of all tenant policies.
- Audit storage5.45s/package8.346; HTTP1.30s/package4.279 passed.
- Full default race/architecture, vet, modules, Linuxamd64 all-package build,
 122-file repeat generation and gofmt/diff passed. External default skips
  are not real-runtime evidence. No UI/browser or SMTP acceptance imported.

## Restricted first-enrollment preparation at0a237aae

AuthenticationChallenge now has the distinct ENROLLMENT purpose with only
PASSWORD_CHANGE or ENROLLMENT steps; LoginResponse can describe it but still
never includes Session/bearer/mustChangePassword in that branch. Existing
LOGIN issuer explicitly rejects another purpose or initial PASSWORD_CHANGE.

Four strict requests use challengeCredential only: inspect, start TOTP,
start first notification-contact verification, confirm first contact.
EnrollmentChallengeState exposes no later state before required password
change; pending factor requires revision1/VERIFIED contact before creation
and the challenge's exact original expiry. TOTPEnrollment permits positive
remaining duration up to5minutes; original normal-Session SQL still requires
exact5minutes. No new HTTP/SQL, action, StepUp operation or recovery ABI.
Current contract owners: api/iam/v1 types/encoding/validation/security_mail,
contractgen and original tests; 009 and012 own requirements, adoption updated.

Local full default race/vet/modules/Linux build/generation passed; final
affected API/usecase/HTTP/architecture race passed after last validation
change. Single-worker15s request fuzz72241 executions passed. No PG, SMTP or
browser started; all test handles terminal. Next implement real restricted
challenge issuance/initial password/contact/binding with shared budgets and
locked authority, then settings CAS/proof/Session-Role barrier and supported
restore evidence. Do not treat contract presence as capability or goal done.

## Existing runtime / remaining work

Fixedb7a70bfa9e53f0a5f16619c60523c84613cb7b0b supplies five Session-held
step-up/regeneration routes. Only RECOVERY_CODES_REGENERATE:120s absolute,
max3 live, original nonforced PASSWORD_TOTP Session, exact Account/USER/
Session/generation/factor/revision/batch/intent. No new bearer or PDP permit.
APPLIED ten codes once; EQUAL_REPLAY and reauthenticated same-USER lookup
metadata only. Historical completion never upgrades/logs out a later Session.
OTP math remains pquerna/otp1.5.0, not a second HMAC implementation.

000012 proof24cols/completion11cols; service lookup5, claim7, Session outputs24,
record9/contract4/evidence5/mailclaim18 and canonical unchanged by018fbd75.
Fixeda4cbd18598099751eb1bd3eac896e191db474524 private recovery donor was
ADAPTed: local executable/role/codec and000014 CLOSED/reconcile/reopen fences.
Keep login_session_contract_ready; donor-base removal was rejected.
No installation CLI/profile/PaaS/UI/foreign acceptance imported.

Remaining009 S2/S3/S4 and012 stay authoritative: forced initial enrollment,
legal replacement/removal, settings writes/proof/barrier, password rules/
expiry/governance, real mail/UI and signed recovery. Docker Linux engine
pipe was unavailable at final read-only probe; no service/WSL restart.
New regeneration real Postfix delivery remains unproved; older mail evidence
and synthetic process contact fixtures cannot substitute.

## Coordination

Installation task01a04149-5dbb-7300-9e4c-31d9e85c8ada owns protected keys,
signed consumer/journal/profile/actual restore. It received018fbd75 and exact
local/CI boundaries. IAM41 is not permission to change its release profile;
no new recovery codec/window allocated. Never read its WIP.
S2c concrete requirement sent: capture complete current Account settings and
qualification before destructive restore, commit outside DB rollback, refuse
missing/unknown state instead of restoring oldfalse. Bounded snapshot/closure
ABI and installation persistence still need joint freeze. Installation owner
identified missing SMTP worker/email keyring/channel in its enabling bundle;
it owns that correction without weakening verified-contact prerequisites.

UI task01a07b21-9a0d-7fd0-b090-7827ce18262e, feat/cloud-console-ux,
exclusively owns UI. It received018fbd75 as fixed source for GET/read/403
only; settings write remains separate MOCK. No capability guessed from role.

Bounded fixeda2ff4f6ff1fc56fa9a43ab56499962e03ac05733 review matched b7's
five routes/120s/generic verify401/EQUAL metadata. Found unguarded delayed
renderer setCodes across Session changes. UI owner acknowledged and supplied
fixed3b9544020c347eff88a44a30aeb9b1bdb9a0afff (docs a5eece91). Bounded
fixed-source review now confirms provider Session/generation return guard,
renderer remount/intent check and retained-promise A/B tests; no tests or
browser acceptance inherited. Fixedc62e794970442e39bfe13222bd3f8aaca175d2c7
adds LIVE read-only settings: reviewed exact Account/explicitbool/shape,
local403, no404/mock fallback, generation-bound401 and late-client guard.
Not imported and not browser-accepted here. It received cumulative018 product
directory/policy/version/attachment boundaries; SSO/IdP remains012 Deferred,
no invented LIVE routes. Give fixed0a as contract-only, not runtime permission.
Prior Role f0455570c3f5ae9f18bd266dffd5eb386e473c4e and navigation intent
c5ec1f945cdcd7af61941aafed8da4d7e68f839c received scoped reviews only.

Local Git identity Xiak <Jellal@aliyun.com>. Markdown only. No extra agents/
tasks, foreign worktree writes, remote1.3/.160/.161 or withdrawn GitLab/1.5,
global settings, sharedDocker/WSL restart or prune. Unique bounded fixtures,
no personal mailboxes, no cleanup-policy bypass.
