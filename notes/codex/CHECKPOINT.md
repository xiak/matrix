# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam; write only
  this task's independent worktree. Updated 2026-09-24.
- Full IAM goal remains ACTIVE/incomplete. Read AGENTS and IAM/009 for MFA,
  IAM/012 for mail, then owners. Adoption belongs to
  docs/adoption/FEAT-006-platform-authorities.md.
- Latest implemented/pushed fixed candidate:
  **339d37474f2cfbee11479a497514d8dcb4d38b0f**, parentcfbc5a1d.
  This adds actual immutable challenge purposes and runtime guards to the
  existing LOGIN/RECOVERY ceremonies. First ENROLLMENT issuance/HTTP/SQL and
  Account settings writes are NOT implemented. Public contract preparation
  is0a237aae; settings read baseline is018fbd75.
  Source IAM42/Audit24/PaaS2. No release profile allocated or changed.
- Exact https://github.com/xiak/matrix/actions/runs/35967101589 is live:
  GitHub API verified339d3747, actual runners and node-process success;
  go/storage were running, remaining serial lanes pending. Do not call
  independent CI passed until the whole precise run and its gates finish.
  Earlier0a/35961451647 was zero-execution failure for payment/spending limit;
  that historical blockage does not describe the new actually running run.

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

## Immutable challenge runtime at339d3747

000012 retains purpose in the original row: LOGIN for password-proved login
and its verified password-change successor, RECOVERY for a consumed original
saved code's rebinding successor. ENROLLMENT is not yet issued by SQL.
Purpose is immutable, nonnull, without a default; private lookup JSON must
include it. Use cases reject a different purpose before attempt reservations
or seed reads; final locks and deferred Session/recovery proofs recheck it.
The private snapshot is not an API/worker permission. Old binaries cannot
consume the changed strict lookup JSON by guessing schema compatibility.

Actual pre-purpose rows are classified only by their closed original
lineage. Run original deferred completion constraints under each actual
Account RLS context before ALTER; never disable those proofs. A damaged
current authority missing purpose fails equal migration, not reclassification.
No ServiceIdentity/lookup_service/claim/Session output/canonical changes.

Local final production evidence, Go1.26.7/2/512MiB, real race-p1 serial on
owned native PG18.6 with Job hard2CPU/1GiB/24processes,16connections,
64MiB shared_buffers/4MiB work_mem/no parallel workers:

- TOTP binding/recovery/password plus schema/ACL attacks106.06s. Missing,
  nullable/default purpose, missing relation constraint and API snapshot
  grant are not READY; migration failure rollback preserves original READY.
- Actual fixedf5cec0e1 IAM37 LOGIN→42 passed38.19s.
- Actual fixed0a237aae IAM41→42 passed41.90s: TWO Accounts, same username,
  each original HTTP bound/consumed saved code before migration; new binary
  finishes original pending recovery. Original receipt/canonical/factors/
  attempt history/credentials preserved through replay and restart.
- Independent IAM pair/Audit/PaaS/dispatchers135.70s/package139.319 passed,
  real runtime identities, committed TCP-loss/restart/replay and disabled
  USER historical proofs. Final secret scan passed after evidence-backed
  correction: an actual six-digit code coincided with a requestDigest's
  SHA256 substring in the preserved failed DB. Scan decoded JSON; only a
  contract-valid Audit requestDigest treats six-digit coincidences as such.
  18 negative/default cases retain actual/escaped/numeric/nested/key leaks,
  invalid digests, other fields, literal LIKE characters and malformed JSON.
- Full default race/architecture, vet, modules, Linuxamd64 all packages,
  122-file repeat generation and gofmt/diff passed. Seven purpose negatives
  use real valid fixture challenge credentials; missing authority fails closed.
- SMTP explicitly SKIP; no browser or signed release acceptance. PG was
  stopped normally only after zero other clients; launcher terminal0.
  All local handles terminal; no shared/remote restart or data deletion.

Next actual target remains restricted first enrollment/password/contact/
factor completion, Account settings CAS/proof and monotonic Session/Role
qualification, with supported-restore nonrollback requirement evidence.
Do not substitute this foundation slice for the full S2c or IAM goal.

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
signed consumer/journal/profile/actual restore. It received339d3747 and exact
local/CI boundaries. IAM42 is not permission to change its release profile;
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

Latest UI owner reports policy read-only detail2c3dc421 and version directory/
exact read a4f2a0b7 (docs a86dc4cf); not imported or independently tested here.
It is proceeding with005 version writes, without an ActionCapability guess.
Confirmed unchanged backend contract: original requestId/resourceVersion/body
on equal retry;409 after an unknown result is not success/failure proof.
Current default/content/404 is only current state, not proof of that intent.
New intent requires explicit fresh review; current TENANT/CUSTOMER/ACTIVE
only establishes applicability, not authority. Root label never means Allow.

Local Git identity Xiak <Jellal@aliyun.com>. Markdown only. No extra agents/
tasks, foreign worktree writes, remote1.3/.160/.161 or withdrawn GitLab/1.5,
global settings, sharedDocker/WSL restart or prune. Unique bounded fixtures,
no personal mailboxes, no cleanup-policy bypass.
