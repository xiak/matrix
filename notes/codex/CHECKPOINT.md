# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Write only
  this task's independent worktree. Updated 2026-09-24.
- Full IAM goal remains ACTIVE/incomplete. Read AGENTS, IAM/009 for current
  MFA work, IAM/011 for the test window, then owning code. IAM/012 owns mail;
  docs/adoption/FEAT-006-platform-authorities.md owns fixed sources.
  Markdown only. UI exclusively belongs to its own task.
- Latest locally verified and pushed **source candidate**:
  **847fc85307f8f50992a04f67b71caecf7581683d**.
  IAM43/Audit25/PaaS2; not a release profile or full MFA acceptance.
- Exact https://github.com/xiak/matrix/actions/runs/35997837317 was checked
  through GitHub API. Node-process completed/success; go and authority-storage
  were genuinely running with assigned runners; other lanes queued.
  Final independent CI is UNCONFIRMED. Follow this exact run, not an earlier
  green commit. Queued run-level status did not mean all jobs stopped.
- Parent6f057456 contains test cleanup aefe4f786242d7d6816f253b6389d5c94c314a75,
  whose own Verification35972120363 seven jobs succeeded. Do not inherit that
  result. Earlier verified/pushed rollback09fac913 remains in Git.

## Fixed S2c candidate

Original owners implement settings update with exact operation-bound StepUp,
current USER Session/PDP, Account-first locks and CAS. The transaction consumes
proof and records immutable completion, tenant Audit fact and
SECURITY_SETTINGS_CHANGED mail intent to the original operator's verified
contact. No arbitrary recipient/SMTP selector or new queue. IAM product
Profile7 archives6; existing policies are never auto-expanded.

First required enrollment uses purpose ENROLLMENT, not a Session or recovery
capability: PASSWORD_CHANGE if needed, normal reauthentication, first verified
contact, TOTP confirmation with one-time saved codes, then normal login.
PASSWORD_CHANGE cannot expose later state. OTP uses pquerna/otp1.5.0. Private
storage times normalize to UTC before public validation.

Session and LOGIN/RECOVERY/ENROLLMENT issuance pin Account settings version.
Historical NULL stays NULL and fails closed. Every real settings change,
including true-to-false, invalidates old USER/derived Role qualification.
Actual INSTALLATION USER attachment grant/revoke ends old Sessions and pending
challenges; equal replay does not repeat. No Account-wide Session UPDATE loop.
ServiceIdentity, lookup_service5, claim7 and old canonical/hash stay unchanged.

PUT /v1/account/security-settings binds original requestId, expected version,
target value and same-Session StepUp. APPLIED returns callerSessionEnded=true.
After unknown outcome, normal new authentication plus original
GET /v1/account/security-settings/changes/{requestId} observes completion.
Historical true does not log out the querying newer Session. EQUAL_REPLAY
does not repeat effects; changed intent409 is not proof of success.

## Evidence and remaining work

Authoritative scopes/times are in IAM/009. Local serial race-p1: full
policy145.16s/settings86.39s/HTTP92.76s, combined327.873s; full attachment
Session concurrency68.39s/package71.889s. The new settings revoke-first test
observes the actual Account lock wait: current authority403, proof unconsumed,
no settings/completion/success fact/mail. Old bearer fixtures now assert401,
then normally re-login to retain original Allow/403 boundaries.

Prior final-production evidence: actual predecessor41.75s/package45.195s;
independent IAM pair/Audit/PaaS/dispatchers settings child145.74s (its combined
run failed solely on a now-fixed predecessor assertion; not a passing combined
package). Restricted runtime logins, committed TCP loss/restart/original
completion, old Role denial and historical delivery after actor revocation/
disable with chain verification retained. Full StepUp388.34s ran before the
settings notice addition; TOTP167.49s and Audit dual10.546s are separate scopes.
Default race/vet/Linux and stable generation passed; final integration default
race/architecture/vet/diff passed. External SKIP is not runtime proof.

Go1.26.7/GOMAXPROCS2/GOMEMLIMIT512MiB. Own native PG18.6 used Windows Job hard
2logicalCPU/1GiB/24processes,16connections,64MiB shared_buffers,4MiB work_mem,
no parallel workers. All local handles terminal; exact own executable/PID/
loopback port checked, zero other client connections, normal pg_ctl stop.
Data retained. No shared/remote service restart or cleanup.

Current test window is current source plus one fixed actual predecessor:
0a237aae5c904e0e32e5766544e31c1cfed5a02a (IAM41) to43. No schema1..N matrix,
guessed generation/qualification backfill or hypothetical N+1 path. Actual
retained bytes/receipt/facts and failure atomicity remain required; source
numbering never authorizes cross-release-profile restoration.

Still missing: remaining settings/factor mutation races; actual new settings
notification SMTP receipt (current contact code is a custody fixture and
notice only PENDING); LIVE UI; supported signed recovery/release. After CI,
give fixed-contract handoff and prepare only an own bounded LIVE environment.
Do not mark009 or the whole goal accepted. Remaining IAM also includes
password/session governance, reports, external integrations and HA/capacity
acceptance in their existing owners.

## Coordination

Installation task01a04149-5dbb-7300-9e4c-31d9e85c8ada owns protected keys,
signed consumers/journal/profile and actual restore. Sent847fc853 as a fixed
candidate with CI pending, not inherited release acceptance. Before destructive
restore, complete current AccountID/security_settings_version/requiredForUsers
must be proved outside DB rollback. Missing/unknown current state stays CLOSED,
not restored oldfalse. Current closure/custody ABI does not include it; agree
its minimal complete snapshot/sealing/replay contract before edits. No new
recovery codec or release revision allocated by this candidate.

UI task01a07b21-9a0d-7fd0-b090-7827ce18262e, feat/cloud-console-ux,
exclusively owns UI. Latest reported fixed8e2b0806/abf9a774 preserves policy
author draft/catalog through review-back;732 frontend tests/embedded/Go passed
in its owner, not imported or independently accepted here. S2c settings and
first enrollment remain isolated MOCK. Sent847fc853 fixed contracts, CI pending
and no LIVE environment yet, including UNKNOWN/new Session/history semantics.
Do not invent an API or let MOCK count as LIVE/browser evidence.

Git identity is repository-local Xiak <Jellal@aliyun.com>. No new agents/tasks,
foreign worktree edits, remote1.3/.160/.161 or withdrawn1.5/GitLab operations,
global configuration/prune/shared Docker/WSL restart, personal mailbox tests
or cleanup-policy bypass. Each companion owns its branch and resources.
Checkpoint records committed/pushed work, not local WIP.
