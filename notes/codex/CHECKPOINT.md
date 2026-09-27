# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam; exclusive
  independent worktree only. Milestone 2026-09-27. Full goal ACTIVE/incomplete.
- Latest committed and pushed source:
  **fa27b0fbf54e94e21da38d32763dcaf89f370538**.
  Production remains **1584de22e156ea47a4db6056e91a9340b4f364f9**'s existing
  snapshot-consuming authentication recovery slice, IAM45/Audit26, above
  fixed 29668fa/dce/e24. Above 2b46's exact schema45 readiness test correction,
  fa27 fixes the original RoleSession test's first-page assumption and extends
  the existing three-database recovery gate with last-slot OTP concurrency
  and real reset/change of a generation-bound exhausted password. Only tests
  and their original FEAT owners changed. No installation release
  profile, CLI, PaaS, UI, ServiceIdentity or Audit canonical change is included.
- Exact successor Verification **36318553704**:
  https://github.com/xiak/matrix/actions/runs/36318553704
  GitHub API confirmed exact fa27 SHA; last observed pending, NOT accepted CI.
  Read fresh status/jobs/logs before claiming success. Source pushes cancel an
  in-progress branch run; do not cancel this gate with an incidental source
  push. Checkpoint-only pushes do not trigger Verification.
- Original 1584 Verification36316212546 failed on stale schema44 readiness.
  Corrective 2b46 Verification36316892387 also has an actual storage failure:
  job108613232634 reached role_management, whose deleted-role assertion
  wrongly required the one remaining Session to appear in the first scanned
  page despite over100 random-ID history records. Original bounded SQL/API
  allows empty items plus a cursor. fa27 consumes both real pages and checks
  exact target/capability and unchanged revision. Go/node succeeded on 2b46;
  runtime was still live and other lanes queued at the fa27 push. Inspect
  actual old status before declaring cancellation; no failed run is backfilled.
- Last independently verified source remains
  **29668fa330b2233b43ebd48ed37738623377f9de**, Verification36044565312 all nine
  jobs success. Its parent dce is pure snapshot/envelope codec; the prior
  production e24 IAM44 passed Verification36033828072. Those CI results do not
  validate 1584 or a signed release.

## Reading route and next outcome

Read AGENTS, IAM/009 supported backup recovery sections, then the owning
private contract, IAM SQL/usecase/CLI and tests. IAM/011 owns the rolling
single-predecessor window. docs/adoption/FEAT-006-platform-authorities.md owns
fixed donor decisions. Do not load unrelated docs or another task's checkpoint.

Resolve the exact corrective CI, then continue the full goal. The new slice
proves current-qualification-matched recovery, not recovery of old backups
after qualification changed. The latter still needs trusted current-state
carriage/rebuilding, not permanent rejection as a substitute for the goal.
Dense qualification capacity, remaining budget/security interleavings and
009's other requirements remain with their existing FEAT owners.

1584's local evidence is in IAM/009: three-database actual RR dump/restore and
nonrefunded replay/attempt floors, source close interleavings and six real
authorization mutations, 3000-item sparse full restore/reopen, strict private
processes with lost output and original completion, exact predecessor and
normal IAM/Audit/PaaS business regression. Full default race/architecture,
vet, modules, generated OpenAPI stability and Linux cross-build passed.
Default external SKIP is not runtime evidence; Windows does not prove Linux
private-file ownership, signed installation or LIVE UI. Final current-schema
runs used actual Go1.26.3; earlier measurements' Go1.26.7 must not be relabelled.

2b46's local evidence: original readiness failure reproduced in a clean PG18.6
database; three other clean databases passed complete dual-schema authority
5.31s, retained Audit tenant records0.44s, Audit HTTP1.27s. Audit default race,
architecture and vet/diff passed. This is a test-only correction, not a new
production recovery behavior or a substitute for full independent CI.

fa27's local PG18.6 race-p1 evidence: full role_management43.50s/package46.999s,
including all24 existing lock/security interleavings; full3DB RR dump/restore
80.01s/package83.475s. Two Authority pools/distinct LOGIN challenges are
observed behind the real USER lock, compete for source OTP budget4->5, and
issue exactly one Session/fact. Original valid-code replay2->3 still fails.
Second restore/Up/new Authorities retain windows/sequences. Real admin reset
and forced change advance generation while the old password floor is still
unexpired and immutable; old completion replay does not revoke the new Session.
Challenge creation can consume the MFA USER's older password window: the test
waits its real natural end before isolating OTP exhaustion, independently
checking the other USER's later live password window. No clock/counter reset
or deadline increase. New assertion initially expected successful login used1;
actual existing issue_session resets to0, now correctly tested. IAM default
race and architecture plus same-scope vet/diff passed. No full-goal or signed
release acceptance is implied.

## Contract and acceptance boundaries

The same RR backup lease now requires authenticationStateDigest independently
of original byte-preserving TOTP custody. Close emits the unique Go-coded
snapshot/closure envelope; reconcile/reopen require both original files.
New private SQL shapes are prepare2/close5/reconcile5/reopen4; old execute
overloads are removed. Generation-bound attempt floors are owned by this
recovery transaction, not fabricated login attempts. See IAM/009 for the
complete scope, invariants and explicit transport-versus-capacity distinction.

The only retained development predecessor is fixed e24 IAM44 -> IAM45.
Actual old private executable receipts stay immutable; OPEN retained history
has NULL proof and cannot execute current recovery. CLOSED old recovery is
not migration-admissible and remains unchanged after rollback. No marker,
proof backfill, older parallel fixture or release N-1 permission is created.

CurrentDatabaseProfile deliberately stays the older accepted 4/3/1+r4;
source authority-process checks actual 45/26/2 separately. Installation owns
its actual PaaS version and final signed revision. Schema numbers alone never
authorize cross-profile upgrade, rollback or recovery.

## Coordination

Installation task 01a04149-5dbb-7300-9e4c-31d9e85c8ada owns signed consumers,
profile/journal/keys/backup and actual restore, with its PaaS6/host/terminal
and security-mail owners. It was told 2b46 failed and fa27 is the successor
candidate; send exact CI success only after all jobs actually pass.
The fixed owner-specific dependency/ADAPT closure from its integrated b7
IAM40 baseline is now in docs/adoption/FEAT-006-platform-authorities.md,
section Fixed IAM40-to-snapshot integration dependency closure. Target
e0de/ef88 are read-only fixed comparison objects, not source donors. Send
final independent CI confirmation before calling this closure consumable.
Do not tree-overlay: retain its accepted AccessKey/Role business profiles,
terminal actions/proof and installation security-mail adapter/dependencies.
Do not import its WIP, profile or acceptance status into this branch.

UX task 01a07b21-9a0d-7fd0-b090-7827ce18262e owns feat/cloud-console-ux and all
UI work. Only exchange fixed contracts; no replacement UI, foreign environment
changes or inherited browser acceptance. No new UI contract is in 1584/fa27.
Installation found its old auth consumer only accepts LOGIN/TOTP/PASSWORD_CHANGE,
not existing ENROLLMENT. The fixed pure-auth-ceremony dependency request was
forwarded to UX; IAM does not implement another frontend or consume foreign WIP.

## Execution boundaries

Markdown only; existing FEAT/adoption/test owners, no duplicate framework.
Git identity exactly Xiak <Jellal@aliyun.com>, repository-local only.
Go GOMAXPROCS2/GOMEMLIMIT512MiB; default-p2, real heavy gates race-p1 serial.
Own native PG uses Windows Job2logicalCPU/1GiB/24processes,
16connections/64MiB shared_buffers/4MiB work_mem/no parallel workers.
fa27's milestone removed exactly13 owned synthetic databases (four3DB recovery
attempts and one role-management database) after zero clients, and normally
stopped its exclusive PG. Launcher confirmed terminal exit0;
there are no live local tests or PG handles. Earlier retained data was not
deleted. Inspect actual handles/ownership before any new runtime work.
Also removed one old stopped, unmounted, exactly feat-iam/task-labelled
stepup PostgreSQL container and its empty same-owner network after read-only
ownership checks. No volume or foreign resource was removed.

No new agents/tasks, foreign WIP, remote1.3/160/161 or withdrawn1.5/GitLab,
global cleanup/config, shared Docker/WSL changes or remote restarts.
Only own feature commits/resources; hand off fixed pushed objects.
