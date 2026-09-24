# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Write only
  this task's independent worktree. Updated 2026-09-24.
- Full IAM goal remains ACTIVE/incomplete. Read AGENTS, IAM/009 for current
  MFA work, IAM/011 for the test window, then owning code. IAM/012 owns mail;
  docs/adoption/FEAT-006-platform-authorities.md owns fixed sources.
  Markdown only. UI exclusively belongs to its own task.
- Latest locally verified, committed and pushed source candidate:
  **234a401212e4c14a739766fcbb38c17cfa162c88**.
  IAM43/Audit25/PaaS2, unchanged from parent; NOT a release profile.
- Exact https://github.com/xiak/matrix/actions/runs/36005275195 was checked
  through GitHub API: correct source SHA, pending. Independent CI is
  UNCONFIRMED. Follow this run, not an earlier green commit.
- fea7a772/Verification36002470008 has confirmed authority-storage FAILURE:
  local recovery fixture still used its operator's pre-platform-grant bearer.
  Actual401 invalidated the intended403 and real lock assertions. Go/node
  individually passed; other lanes were live/queued before this corrective
  push. Do not report this old run as green or restart on observation timeout.
- 847fc853/Verification35997837317 also failed storage at attachment matrix's
  original120s final schema replay. Its redundant unused logins were removed
  in fea7, not its48 security scenarios. Earlier aefe4f78/35972120363 seven
  jobs passed but cannot accept these later changes. Parent51516dc5 and
  earlier0b01e751 are checkpoint-only.

## Fixed implementation and current evidence

234a4012 changes only existing IAM integration tests, the existing CI routing
and009 evidence. No production API/SQL/schema/profile/UI/installation change.
Final serial ownPG18.6/race-p1:
- TestIAMSecuritySettingsRacesPostgres22.53s: six genuine independent Accounts,
  explicit policy/contact/TOTP login/operation-bound proof; settings false-to-
  true versus logout, retained-current daily password change and saved-code
  recovery start, both orders. Original outbox barrier and actual peer lock
  dependency prove order, not goroutine scheduling. Changed password keeps
  current Session but invalidates old-generation StepUp; other losers have
  no partial completion/version/code consumption/success fact/notice.
  Equal schema replay and new Authority do not revive lost qualification.
  This is not a process restart, SMTP, settings loosen or all-factor matrix.
- TestIAMLocalCredentialRecoveryPostgres24.43s; combined package50.514s.
  CI's stale operator failure first reproduced locally35.56s. After a real
  INSTALLATION attachment grant, assert old bearer401 then normally login;
  preserve original403/protected-primary and both real revoke/recovery lock
  orders, immutable receipts, SQL privileges and bootstrap/schema rejection.
- Full default race/architecture and vet, workflow YAML/14 Bash scripts,
  gofmt/diff passed. New gate uses own DB in original step-up lane, excluded
  from storage duplicate routing. No new lane/budget/cost increases. Default
  DSN SKIP is not runtime proof. Both real test handles completed; exact own
  PG identity/listener and zero other clients checked, normal stop, data kept.

847 introduced exact operation-bound SECURITY_SETTINGS_UPDATE StepUp,
same-Session proof, current USER/PDP, Account-first locks and CAS. The
transaction records immutable completion, tenant Audit fact and
SECURITY_SETTINGS_CHANGED intent to the original operator's verified contact.
Profile7 archives6; existing policies never gain new actions automatically.
PUT ends the original caller Session. After unknown outcome, normal new
authentication and original GET changes/requestId observe history; historical
callerSessionEnded does not end that newer Session. Exact replay repeats no
effects; variant409 is not evidence of success.

First required enrollment has purpose ENROLLMENT, not a Session: initial
PASSWORD_CHANGE if necessary, normal reauthentication, verified contact,
TOTP and one-time ten codes, then normal MFA login. Session and all relevant
challenges pin the Account settings version; historical NULL fails closed.
Even true-to-false ends old qualification. Actual INSTALLATION USER policy
attachment grants/revokes end old Sessions/challenges; equal replay does not
repeat. ServiceIdentity/lookup_service5/claim7/canonical stay unchanged.

fea7a772 fixes an actual delivery gap: dispatcher lacked the two closed
RECOVERY_CODES_REGENERATED / SECURITY_SETTINGS_CHANGED cases. Original SQL
could claim them but dispatcher then rejected before SMTP. Added regression
first failed for both, then passed after the minimal switch fix; unknown kinds
and verification-secret-bearing historical notices still fail closed.
No new API/SQL/schema/profile/installation/UI change.

Final serial race-p1, own PostgreSQL18.6 and real STARTTLS Postfix3.10.13:
- Full TestIAMSecuritySettingsPostgres85.06s/package88.588s. Original current
  permission/revoke-first lock/CAS/atomicity/schema/first-enrollment assertions
  retained. Actual Maildir verification code confirms first contact via HTTP;
  both settings mails received and original DATA250/ACCEPTED observations
  retained. Actual second writer disabled before worker claims its notice.
- Focused TestIAMStepUpPostgres/authenticator_recovery/regenerate38.51s,
  package42.063s, historical-mail child1.49s. New codes really recover factor,
  then USER disabled, original regeneration notice still received without
  secrets. This is NOT all nine StepUp scenarios rerun.
- Full attachment Session matrix60.69s/package64.228s, all48 scenarios and
  original2min deadline. Removed only28 unused second password logins;
  cross-Session password and platform revoke/regrant still have both actual
  Sessions. Schema replay/equal bootstrap and retained rejection remain.
- Real SMTP transport gate3.07s/package5.390s: certificate/STARTTLS, correct
  authentication, wrong-password and external-relay rejection. Mail acceptance
  and local Maildir receipt are not public Internet delivery/exactly-once.
- Final full default Go race/architecture, vet, module verification,
  Linux/amd64 all-package build, gofmt and diff passed. Default external SKIP
  is not runtime proof; no API generation changes in this fix.

Mail lookup keeps its original10s observation window and <=100 files. It now
filters the observed file set in one bounded container call, then verifies
exact body reference and parsed To/From/Received/Message-ID. Returning full
message preserves Subject/secret checks. The earlier per-file Docker loop
missed a genuinely received regeneration mail under its deadline. Settings
mail uses a normally reauthenticated, explicitly authorized separate USER,
not the root whose OTP budget the earlier attack fixture exhausted; budgets
and data are never reset to construct success.

Prior fixed source evidence remains scoped in009: real predecessor41.75s/
package45.195s, independent IAM pair/Audit/PaaS/dispatchers settings child
145.74s, TOTP167.49s, full StepUp388.34s before notice addition. Those earlier
custody/PENDING fixtures were not SMTP evidence. Do not turn their individual
passes into a combined-package or signed-release acceptance.

## Remaining work and boundaries

S2c/009/full goal incomplete: own exact CI, remaining settings loosen/factor
mutation/reset/Role races, LIVE UI and supported signed recovery/release. Also remaining password/
session governance, reports, external integrations, HA/capacity per FEAT owners.
After CI, hand off the fixed contract and prepare only an own bounded LIVE
environment; UI writing/browser work stays with UX/UI.

Current unpublished test window: current source plus one actual fixed
predecessor0a237aae5c904e0e32e5766544e31c1cfed5a02a IAM41 to43. No schema1..N
matrix, guessed generation/qualification backfill or hypothetical N+1 path.
Actual retained bytes/receipt/facts and failure atomicity remain required;
source versions never authorize cross-release-profile recovery.

Own native PG ran under Windows Job hard2logicalCPU/1GiB/24processes,
16connections,64MiB shared_buffers/4MiB work_mem/no parallel workers.
Go1.26.7/GOMAXPROCS2/GOMEMLIMIT512MiB; heavy gates serial race-p1.
All local test handles finished. Exact PG process/path/loopback port checked,
zero other clients, normal stop, data retained. Own Postfix2CPU/768MiB/Pids128
queue empty; exact task-labelled container and empty network removed,
labelled container/network/volume counts zero. No shared/remote restart.

## Coordination

Installation task01a04149-5dbb-7300-9e4c-31d9e85c8ada owns protected keys,
signed consumers/journal/profile and actual restore. Before destructive
restore, complete current AccountID/security_settings_version/requiredForUsers
must be proved outside DB rollback. Missing/unknown stays CLOSED, not restored
oldfalse. Existing closure/custody ABI lacks this; agree the minimal complete
snapshot/sealing/replay contract before edits. No recovery codec/release
revision allocated here. Candidate and mail gap reported; use fixed objects.

UI task01a07b21-9a0d-7fd0-b090-7827ce18262e, feat/cloud-console-ux, owns UI.
Latest reported fixed7499d701 +1d4a7b70 completes MOCK settings UNKNOWN/new
login/original request lookup; normal mock TOTP login clears the old Session
lock, historical APPLIED does not end the new Session. Owner's browser evidence
is not imported/inherited. LIVE remains read-only until S2c exact CI/runtime
and a real environment. No new API needed for this mail repair.

Git identity repository-local Xiak <Jellal@aliyun.com>. No new agents/tasks,
foreign worktree edits/WIP, remote1.3/.160/.161 or withdrawn1.5/GitLab operations,
global configuration/prune/shared Docker/WSL restart, personal mailbox tests
or cleanup-policy bypass. Each companion owns its branch/resources.
Checkpoint records committed/pushed work, not local WIP.
