# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam, own independent
  worktree only. Updated 2026-09-25. Full goal ACTIVE/incomplete.
- Latest locally verified, committed and pushed source candidate:
  **e24dbdae6b4ea420365a4527a0bd89b16e0d720f**.
  Normal proof-bound TOTP replacement; actual IAM44/Audit26/PaaS2.
  NOT a release profile, accepted installation combination or full MFA.
- Exact Verification **36033828072**:
  https://github.com/xiak/matrix/actions/runs/36033828072
  GitHub API confirmed correct SHA; node-process success, go and
  authority-storage in_progress, remaining database lanes queued at inspection.
  Independent CI UNCONFIRMED. Follow this exact run, do not start a duplicate.
- Parent bd8b3474 is checkpoint-only. Rollback source
  a97a8a0c422d8e9d2c8cadb85f74c61c815318c6 / Verification36008692931
  independently confirmed all seven jobs success. No other source was adopted.
- Read AGENTS, IAM/009 normal replacement, IAM/011 test window, then owners.
  IAM/012 owns mail; docs/adoption/FEAT-006-platform-authorities.md owns donors.
  Markdown only. UI remains exclusively owned by its separate task.

## Current fixed candidate and evidence

Production is in original API/IAM/Audit and notification owners, no parallel
factor/seed/receipt framework:

- TOTPEnrollment has required purpose INITIAL|REPLACEMENT. StepUp adds
  TOTP_REPLACE. Strict POST /v1/auth/totp/enrollments:replace accepts only
  requestId/stepUpId/expectedFactorRevision; original query/confirm/cancel
  and response types remain the consumers.
- Same current PASSWORD_TOTP Session + password/old-factor operation proof.
  Prepare consumes that proof; old ACTIVE factor/batch survive. New PENDING
  retains original absolute120s deadline. APPLIED alone yields provisioning;
  replay/query never recover secrets or renew the proof.
- Confirm revalidates current identity, generation, settings/contact revision,
  old factor/batch and original Session under real lock order. Atomically
  switches factor/ten-code batch, ends old Sessions/challenges, records one
  tenant USER iam.authenticator.replaced and AUTHENTICATOR_REPLACED notice.
- Success REAUTHENTICATE requires new-factor normal login. Unknown response
  supports only nonsecret completion lookup, not another delivery of ten codes.
  New Session cannot adopt old proof; it can inspect/cancel pending metadata.
- Existing saved-code recovery atomically cancels the same USER's unfinished
  replacement so its pending slot cannot block proven recovery. No partial
  cancellation/refunded proof or administrator factor-reset capability.
- Actual IAM44/Audit26 shapes/readiness advanced; claim7, lookup_service5,
  CanonicalizeEvent and installation custody/entrypoint ABI unchanged.
  No release revision/profile, FILE/mount/topology, UI or installation edits.

Evidence belongs in009 (exact scopes/failures retained), own PG18.6/race-p1:

- Original prepare/cancel/concurrent confirm and terminal failures119.218s.
  Security6 cases212.290s; settings4 cases134.577s; mutations6 cases246.812s.
  Shared settings8-case regression35.219s. True lock dependencies observed.
- Terminal recovery-notification fault and actual same-code retry after its
  original reservation expiry: selected regressions combined90.458s.
- LOGIN versus replacement both real orders113.965s; selected common password
  and reset regressions44.834s. No budget/time changes to mask rejection.
- Original120s deadline expires while confirmation waits on a real USER lock;
  still-valid new OTP rejected without debit/effects, then old-factor login
  and saved-code recovery work. Full expiry gate137.293s. Earlier fixture UTC
  precondition failures were corrected, not counted as success.
- Final base3 + qualifications2 full real gates240.193s. Actual wrong new OTP
  persists fourth REJECTED debit across replay; valid fifth reservation plus
  terminal notification failure leaves no partial security effect and remains
  charged; immediate cross-Authority retry rejected.
  Real non-home Account and separate USER disable/enable revoke old Sessions;
  actual cross-Account enrollment read/confirm attacks rejected unchanged.
  Fresh login can inspect/cancel but cannot adopt old pending confirmation.
  USER case moved out of security rather than duplicated; each qualification
  fixture retains3min, original security6 retains5min.
- Real independent IAM/Audit/PaaS/dispatcher gate136.738s: submitted confirmation
  response TCP-aborted, two IAM processes restarted, old Sessions refused by
  all services, new factor login/nonsecret completion works. Actor disabled
  before historical outbox delivery; one event, exact replays, forged tenant/
  request refusal and complete Audit chain. Restricted actual DB logins.
- Real Postfix3.10.13 STARTTLS plus independent notification dispatcher63.382s:
  addresses verified from mail, actor disabled after replacement, original
  recipient receives secret-free AUTHENTICATOR_REPLACED. ACCEPTED/SMTP250,
  same Message-ID/bytes after worker restart, no read/exactly-once claim.
- Sole actual predecessor a97 IAM43 ->44 process gate46.788s: retained actual
  settings-qualified Sessions/factors/proofs/recovery, injected DDL rollback,
  apply twice/bootstrap/restart, new replacement on old factor, original
  receipt/canonical/proof preserved. Old IAM41 path removed, no legacy ladder.
  Audit/IAM actual schema integration8.548s.
- Final full default Go race/architecture, vet, Linux amd64 build, module
  verification, gofmt/diff and IAM/Audit65 tracked-file generation hashes pass.
  Default DSN SKIPs are not additional runtime proof.
- CI adds two serial database lanes: replacement20min and qualification15min.
  Seven fixtures use separate DBs; max-parallel=1, CPU/memory/original test
  deadlines unchanged. YAML and16 Bash blocks checked. New full CI has nine
  jobs including its aggregate; its terminal result is still pending.
- All own local runtime handles terminal. Exact PG PID/executable/data/port
  and zero other clients verified, normal stop/launcher exit0; data retained.
  Own SMTP container/empty network removed after queue check. No other cleanup.

## Next work and coordination

First follow exact CI36033828072 and diagnose any actual failure in its owner;
never infer runtime success from default skips or prior a97's green checks.
Fixed candidate has been sent to UX and installation explicitly CI-pending.
Do not call full goal or complete MFA accepted.

UX task01a07b21-9a0d-7fd0-b090-7827ce18262e owns feat/cloud-console-ux.
Its reported c724696d/9f3d3d2f mobile User directory is isolated MOCK; do not
import its worktree or claim LIVE coverage. It has exact replacement types,
original120s/unknown-result/new-login semantics. Send CI terminal confirmation.

Installation task01a04149-5dbb-7300-9e4c-31d9e85c8ada owns signed consumers,
profile/journal/keys/backup and actual restore. It prepares its own platform/
node A/B combination; e24 changes enrollment decoding but not original
credential-recovery entrypoint. It must independently choose/verify its
actual PaaS combination and release revision, retained replacement lineage,
complete current Account settings proof outside database rollback, and
restoration isolation. No profile number is assigned here and no foreign
acceptance is inherited. Do not touch its160/161 runtime or other resources.

Remaining009: ACTIVE factor unlink and proven REMOVED re-enrollment, missing
S2c settings/reset/Role interleavings, full password/session governance,
reports, real UI, signed combination. Broader HA/capacity and external deferred
requirements stay with existing FEAT owners; goal remains incomplete.

Risky next production replacement waits for a coherent verified/pushed
rollback point. Keep one actual rolling development predecessor (a97 for
this candidate), not schema1..N or hypothetical N+1. Current security,
immutable historical proof and failure atomicity remain required.

Go1.26.7/GOMAXPROCS2/GOMEMLIMIT512MiB; default-p2, real heavy gates serial
race-p1. Own native PG uses Windows Job2logicalCPU/1GiB/24processes,
16connections,64MiB shared_buffers/4MiB work_mem/no parallel workers.
Repo-local identity Xiak <Jellal@aliyun.com>. No new agents/tasks, foreign WIP,
remote1.3/.160/.161 or withdrawn1.5/GitLab activity, global cleanup/config,
or shared Docker/WSL/remote restart. Handoff only fixed pushed objects.
