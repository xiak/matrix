# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam; this task's
  independent worktree only. Updated 2026-09-24. Full goal ACTIVE/incomplete.
- Latest locally verified, committed and pushed source candidate:
  **a97a8a0c422d8e9d2c8cadb85f74c61c815318c6**.
  IAM43/Audit25/PaaS2 unchanged; NOT a release profile or full MFA acceptance.
- Exact Verification **36008692931** was checked through GitHub API:
  https://github.com/xiak/matrix/actions/runs/36008692931
  Correct source SHA, pending; independent CI UNCONFIRMED. Follow this run.
- Parent ba9f7ccd is checkpoint-only. Prior source234a4012/run36005275195 has
  confirmed authority-storage FAILURE. Go/node individually succeeded; its
  other database lanes were still running/queued at corrective push. Do not
  infer their success or terminal cancellation from the new push.
- Read AGENTS, IAM/009, IAM/011 test window, then owning code.
  IAM/012 owns mail; docs/adoption/FEAT-006-platform-authorities.md owns donors.
  Markdown only. UI remains exclusively owned by its separate task.

## Current fixed evidence

a97 changes only original IAM integration tests,009 and original adoption.
No production API/SQL/schema/profile/UI/installation/workflow change.

- Full TestIAMSecuritySettingsRacesPostgres: own PG18.6, serial race-p1,
  35.99s/package39.422s. Eight Accounts; settings tightening versus logout,
  keep-current password change, saved-code recovery and ordinary USER LOGIN
  verification, both actual lock orders. Verification first may legitimately
  issue a Session before settings invalidates it; both historical facts stay.
  Settings first leaves the peer OTP/challenge unconsumed with no Session.
  Schema replay/new Authority cannot revive qualification. Original3min
  deadline, cost and budgets unchanged. Not a process restart/SMTP proof.
- CI storage failed in private_references before its intended assertions:
  synthetic negative Sessions omitted today's required authentication fields.
  Reproduced on another own PG18.6 database3.31s, INSERT SQLSTATE23514.
  Fix copies actual source Session authentication facts, preserves each
  expired/stale-generation/NULL-generation defect, and proves no bearer
  lookup exists and no unrelated MFA/settings defect masks the rejection.
  No production guard disabled or weakened; no synthetic positive login.
  Complete private_references108 combinations plus schema/bootstrap replay
  passed on a fresh DB, package17.528s. NOT all seven Role gates rerun.
- Final full default Go race/architecture, vet, gofmt and diff passed.
  Default DSN SKIP is not runtime evidence. Original sole fixed predecessor,
  independent-process/SMTP/release/UI gates were not rerun in this increment.
- Own PG exact PID/executable/data/listener and zero other clients checked;
  normal stop confirmed by launcher exit0, data retained. No live own test
  handle remains, no shared/remote restart or foreign-resource cleanup.

Previous evidence and failures remain scoped in009, not inherited as current
CI acceptance. In particular:234 fixed the recovery fixture's pre-platform-
attachment bearer by asserting401 then normal login (full real gate24.43s),
and fea7a772 fixed dispatcher omission of two actual security mail kinds.
Do not weaken403/current identity assertions to accept a stale bearer.

## Next production slice: normal TOTP replacement

Detailed design is now fixed in009, not implemented or accepted. Fixed
aefe4f786242d7d6816f253b6389d5c94c314a75 was reviewed and recorded as the donor.
Reuse existing enrollment/seed/StepUp/recovery-code/outbox owners; do not
duplicate lost-factor recovery or seed custody.

- Proposed TOTPEnrollment purpose INITIAL|REPLACEMENT and TOTP_REPLACE
  operation; proposed POST /v1/auth/totp/enrollments:replace with exactly
  requestId/stepUpId/expectedFactorRevision. No public API/type/SQL edit yet.
- Current same USER PASSWORD_TOTP Session + password/old-factor proof.
  Old ACTIVE factor and batch survive prepare/cancel/expiry. New PENDING
  deadline cannot exceed the original StepUp120s absolute deadline.
- Confirm via original same still-valid Session; current generation/settings/
  subject/contact and old factor/batch must match. Atomically replace factor
  and recovery batch, revoke old Sessions/challenges, create one tenant
  iam.authenticator.replaced fact and secret-free notification.
- Preserve lock_step_up's rejection of CONSUMED. Confirmation only follows
  exact immutable new-factor origin to its already-consumed proof; no
  reusable permit. No administrator reset of another USER's factor.
- Only once deliver seed/new ten codes; unknown result uses metadata and
  normal new-factor login. Active unlink/REMOVED remains a separate gap.
- Installation owner confirms IAM44/Audit26 are unoccupied; only advance
  actual source shapes when implemented, never preallocate release revision
  or alter profile/installation files. UI accepted semantics for isolated MOCK.
  API/SQL, real concurrent PG, historical producer proof, SMTP/process and
  fixed handoff remain to implement/prove.

## Remaining boundaries / coordination

S2c still needs its exact successful CI, remaining settings loosen/factor/
reset/Role interleavings, LIVE UI and supported signed recovery/release.
Broader password/session governance, reports, HA/capacity and deferred
external integrations remain under existing FEAT owners. Goal incomplete.

Single rolling unpublished predecessor is0a237aae5c904e0e32e5766544e31c1cfed5a02a
IAM41 to43; do not rebuild schema1..N history or hypothetical N+1 fixtures.
Real retained bytes, failure atomicity and no revived authority stay required.
Source numbers never authorize cross-release-profile migration/recovery.

Installation task01a04149-5dbb-7300-9e4c-31d9e85c8ada owns signed consumers,
keys/profile/journal and actual restore. Before destructive restore, complete
current AccountID/security_settings_version/requiredForUsers needs evidence
outside database rollback; missing/unknown stays CLOSED. Existing closure/
custody ABI lacks this: coordinate fixed contract, no unilateral edits.
Owner currently validates its independent local DIND snapshot/crash gates;
it did not occupy44/26 or grant any shared environment access.

UX/UI task01a07b21-9a0d-7fd0-b090-7827ce18262e owns feat/cloud-console-ux.
Reported S4 MOCK fixed a2366dda/9481f436, not inspected/inherited here.
It will design normal replacement only in isolated MOCK and keep LIVE
decoder/write admission closed until verified fixed types/environment.
Earlier7499d701/1d4a7b70 MOCK settings unknown/new-login lookup is separate.

Go1.26.7/GOMAXPROCS2/GOMEMLIMIT512MiB; default-p2, heavy real gates serial
race-p1. Own native PG uses Windows Job2logicalCPU/1GiB/24processes,
16connections,64MiB shared_buffers/4MiB work_mem/no parallel workers.
Repo-local identity Xiak <Jellal@aliyun.com>. No new agents/tasks, foreign WIP,
remote1.3/.160/.161 or withdrawn1.5/GitLab activity, global cleanup/config
or shared Docker/WSL restart. Only fixed pushed objects for handoff.
