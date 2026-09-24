# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Write only
  this task's independent worktree. Updated 2026-09-24.
- Full IAM goal remains ACTIVE/incomplete. Read AGENTS, IAM/009 for MFA or
  IAM/012 for mail, then owning code/tests. Fixed adoption belongs to
  docs/adoption/FEAT-006-platform-authorities.md, not this checkpoint.
- Latest implemented and pushed fixed candidate:
  **d570673ba87c113f7474fdab79b5e22a83c2b323**, parent86e68f3b.
  S2c pure Account security-settings contracts only; no new runtime routes,
  StepUp operation, actions, SQL, schema or release profile. Runtime still
  uses fixedb7a70bfa9e53f0a5f16619c60523c84613cb7b0b's Session-held
  step-up/regeneration and recovery fences, IAM40/Audit24/PaaS2.
- Exact https://github.com/xiak/matrix/actions/runs/35955820844 for d570
  and35953732463 for b7 are completed/failure. All seven jobs each have
  runner_id=0/steps=0; go annotations explicitly say account payment/spending
  limit prevented execution.
  Independent CI is NOT accepted. Do not change billing or repeatedly
  rerun the unchanged blockage. Older zero-execution runs remain separate
  from 5e185e95's actual Audit runtime-probe failure.
- This fixed candidate is not a signed release or complete MFA acceptance.
  New regeneration SMTP, real UI/browser, independent CI and release
  recovery remain open, as do remaining009 S2/S3/S4 requirements.

## Current pure settings contract

IAM/009 S3 owns the exact six new nonsecret types and their design. Explicit
MFA false/true is required; missing/null, selectors and arbitrary payloads
fail. Versioned intent leaves space for expected+1. Immutable change refers
to the original request and snapshot; callerSessionEnded describes only the
original caller, never an instruction to log out a later reader's Session.
No settings route or operation is LIVE. Current StepUp rejects it.

All API/architecture race, APIvet,122-file repeat generation and IAM/Audit
default tests passed. New single-worker15s fuzz221734executions passed.
Defaults' external DB skips are NOT real runtime evidence. Current fixed
adoption is b7; no UI/installation/profile state was imported. Next implement
the full009 S2c transaction/permissions/forced enrollment/Session-Role barrier,
not merely the types; coordinate actual ABI before allocating versions.

## Current runtime contract

The five routes are now implemented, not merely the prior303 pure types:
POST /v1/auth/step-up, GET /v1/auth/step-up/by-request/{requestId},
POST /v1/auth/step-up/{id}:verify,
POST /v1/auth/recovery-codes:regenerate and
GET /v1/auth/recovery-codes/regenerations/by-request/{requestId}.

Only RECOVERY_CODES_REGENERATE is supported. A StepUp is held by the
original current nonforced PASSWORD_TOTP USER Session; it is not a new
bearer, login challenge, PDP Allow or cached generic permit. It binds
actual Account/USER/Session/generation, factor/revision, old batch, original
intent and Account/USER versions. PENDING/PROVED/CONSUMED retain the original
120-second absolute deadline; reading or proving does not extend it.
At most three live proofs; shared durable password/OTP budgets remain.

Unknown creation/verification is queried by original request ID, without
replaying password/OTP or inferring rollback from NOT_FOUND. APPLIED returns
ten codes once; EQUAL_REPLAY and completion lookup contain only metadata.
Another login Session cannot consume the old proof, but a normally
reauthenticated same USER can read the old regeneration completion.

Regeneration atomically consumes the exact proof, terminates the exact old
batch, commits new one-way verifiers/completion/outbox/notification.
Factor revision, password, Session facts and roles remain unchanged.
Only iam.recovery-codes.regenerated and RECOVERY_CODES_REGENERATED mail
were added for this online mutation; original binding event remains.

New step_up files stay under existing HTTP/usecase/PostgreSQL owners.
000012 owns proof24cols/completion11cols plus precise constraints/RLS/ACL.
ServiceIdentity, lookup_service5, claim7, lookup_session24, revoke_session6,
record9/contract4/evidence5, mailclaim18 and old canonical bytes stay intact.
Standard OTP math remains pquerna/otp1.5.0; no second HMAC/OTP algorithm.

## Fixed recovery integration and ownership

ADAPT donor a4cbd18598099751eb1bd3eac896e191db474524 only: private
installation codec, dedicated local executable/role/use case,000014
CLOSED/reconcile/reopen and immutable fences. Existing
iam.login_session_contract_ready() remains; donor-base removal was rejected.
No installation CLI/profile/PaaS/UI source or foreign acceptance imported.

Ordinary identity transactions hold OPEN shared authority; CLOSED excludes
new authentication mutations. Exact historical local-password recovery
receipts retain their purpose-limited transaction path. Reopen generation
and immutable fences prevent old Session/proof/batch revival. The new
process is not a generic online recovery/grant/backup endpoint.

Installation task01a04149-5dbb-7300-9e4c-31d9e85c8ada owns signed
consumer, journal, keys/mounts, release/profile and actual restore. It has
received fixedb7 plus exact local evidence/gaps. Its consumer05b23417 is
not imported. Old preparation35/18+r13 cannot serve as a target lacking
the purpose executable/SQL. A new preparation A and enabling B require
actual signed B-to-A restore and exact ABI/profile evidence. Proposed
numbers are not allocated here; do not import installation PaaS6/profile.

## Current local evidence at fixedb7

Go1.26.7/GOMAXPROCS2/GOMEMLIMIT512MiB; real gates serial race-p1.
Owned Windows portable PG18.6 had Windows Job hard2logicalCPU/1GiB/24
processes,16connections/64MiB shared_buffers/4MiB work_mem/no parallel workers.
It was normally stopped after zero-client verification. No Docker/shared
or remote service restart. Do not retry any policy-denied temp cleanup.

- TestIAMStepUpPostgres395.18s/package398.640:56 real schema/permission
  damage cases,9online scenarios. Two independent PROVED on same old batch
  race58.61s:one APPLIED10codes,one401,one completion/fact/notice/livebatch;
  losing proof not consumed. Original120s lock-expiry121.23s, sameproof
  duplicate, budgets, anotherSession,logout/change/reset/disable/enable,
  terminal rollback and real new-code recovery all retained.
  historical-regeneration-mail explicitly SKIP, not SMTP evidence.
- TestIndependentIAMAuditAndPaaSProcesses143.01s/package146.381:
  actual restricted logins,twoIAM/Audit/PaaS/dispatchers,create/prove/
  regenerate each actual commit then lost TCP response, restarts, original
  metadata and explicit replacement, disabled USER history/replay/chain.
  New step-up USER is independently created/bound/logged in to avoid
  sharing the original login-race USER's real budget; no window changes.
  Synthetic contact-code custody fixture is NOT SMTP/browser evidence.
- Actual fixedf5cec0e132ad18900d9a5a5629eae04fda4817f1 IAM37 executable
  retained MFA to40:43.21s/package46.723. Double migrations/bootstrap/
  restarts preserve original factor,consumption,batch,Session/challenge,
  receipt/canonical/proof; original savedcode still completes recovery.
  Completed state then survives another replay/restart without revival.
  Whole-row JSON snapshot wrongly counted new NULL provenance as mutation;
  replaced with explicit original facts and separate no-invented-authority
  assertions, not a production relaxation or release compatibility claim.
- TestIAMAuthenticationRecoveryPostgres86.74s/package90.279:two separately
  prepared source/restored DBs,current PROVED beforeclose,CLOSED denial,
  old/newSession cannot consume prior proof afterreopen,newproof cannot
  use fenced batch,migration no revival. NOT actual pg_dump or signed CLI.
- Final Audit storage5.64s,oldtenant chain0.35s/package9.134;HTTP isolation/
  concurrency1.27s/package3.844. Initial stale IAM39 readiness expectations
  failed; two exact expected numbers corrected to40 and fresh DBs passed,
  all original shape/privilege/immutable-history assertions retained.
- TestStepUpStopsAtUnknownAdmissionOrChangedCaller10cases6.80s:
  uncertain password/OTP reservation or rejection commit,stage-to-stage
  Session revoke/generation change,denial/no extra seed/proof/free attempt
  and workslot release. Control-flow evidence only; PG proves durability.
- Final full default race/architecture and vet passed, including terminal
  full-session5899. Modules verified,122API tracked file set/hash stable
  aftergeneration,all packages Linuxamd64 build,gofmt,diff passed.
  Latest Audit edit also realrace/vet passed; default externalSKIPs not
  substituted for any runtime result.
- CI YAML and14Bash blocks parse. Four DB lanes remain max-parallel1;
  storage/runtime/step-up each20m, natural-window30m.17 compiled IAM
  fixtures mapped once:general6,Role1,runtime8,step-up1,window1.
  Moving new6.5min gate avoids spending an existing lane's deadline;
  original test deadlines, production windows/costs remain unchanged.

Prior fixed48e56cbb online recovery and80a6e6d1 ten-code natural-window
exhaustion remain scoped evidence in009. Prior real Postfix recovery mail
does not prove the new regeneration template/delivery. Actual pg_dump
custody proof remains with its original gate, not the doubleDB substitute.

## Next delivery work

Read009/012 owners first. Complete the existing step-up historical mail
branch with a dedicated bounded actual Postfix and worker; Docker was
unavailable at last probe, do not start/restart shared services or use a
personal mailbox. No fake SMTP can close that gate.

Do not stop overall goal at this candidate. Remaining009 includes forced
first enrollment,legal factor replacement/removal,security-settings CAS/
two approved tenant actions and Session/Role barrier,S3 rules/expiry,
S4 governance; exact FEAT scope and cross-owner prerequisites remain
authoritative. New shared surface must be aligned, not silently expanded.
UI/real browser and signed release recovery remain separate owner gates.

## UI coordination

All UI task01a07b21-9a0d-7fd0-b090-7827ce18262e, branch
feat/cloud-console-ux. Fixed objects only; never read/copy its WIP.
It received b7 and d570; only b7's five runtime routes are LIVE development
contracts, settings remains MOCK. It finished fixed
f0455570c3f5ae9f18bd266dffd5eb386e473c4e Role creation and is now consuming
the b7 recovery-code routes. Its first long SHA was incorrect; the actual
object was resolved from fixed docs9dc2fc090bbdeb5b44aa606e39a387b2976eb4f7
and confirmed by the owner. Read-only shared contract review matched the
six create fields/current Account/USERtrust/duration and exact unknown retry.
Requested same-Account USER/Session change and delayed-result isolation
regression in its existing UI tests; did not claim full UI/browser acceptance.
Do not replace or parallel-implement UI here.

Fixedc5ec1f945cdcd7af61941aafed8da4d7e68f839c read-only focused review
passed navigation intent P1:AccountAccessProvider survives keyed view
remount and owns the revocation intent; Session identity binds visibility,
async update checks original request ID. No local UI import/build/browser
claim. Nonblocking test strengthening requested:capture the actual A
callback/promise, create B's own intent before A settles, prove it unchanged.

Earlier fixedd7d6333d's recovery unknown-result/loginName isolation and
enrollment intent ownership reviewed; product-onboarding5114dda3 remains
MOCK/preview only. No online Profile publishing API promised from catalog
metadata. Consumer evidence never transfers into this branch's acceptance.

Git local identity Xiak <Jellal@aliyun.com>. Markdown only. No extra agents/
tasks,foreign worktree writes,remote1.3/.160/.161 or withdrawn GitLab/1.5,
global settings,sharedDocker/WSL/system restart or prune. Unique bounded
fixtures; no personal mailboxes; no cleanup-policy bypass.
