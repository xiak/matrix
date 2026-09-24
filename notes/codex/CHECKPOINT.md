# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam, own independent
  worktree only. Updated 2026-09-25. Full goal ACTIVE/incomplete.
- Latest committed and pushed source:
  **29668fa330b2233b43ebd48ed37738623377f9de**.
  Parent **dce2456adb8503c9c86d31bb2a3f63f35719ffa0** adds only bounded private
  recovery snapshot/envelope types, strict codec and FEAT design.
  296 corrects the existing process-test DSN's actual host/port/database
  round-trip. Neither commit implements snapshot-consuming SQL or advances
  IAM44/Audit26/PaaS2; neither is an accepted release profile.
- Exact Verification **36044565312**:
  https://github.com/xiak/matrix/actions/runs/36044565312
  GitHub API confirmed exact 296 SHA and all nine jobs completed/success:
  go, node-process, authority-storage/runtime/step-up/replacement,
  authority-replacement-qualification/recovery-window and authority-process.
  This final result was sent to UX and installation; it does not validate
  later uncommitted snapshot-consuming runtime changes.
- Last independently verified production behavior:
  **e24dbdae6b4ea420365a4527a0bd89b16e0d720f**, normal proof-bound TOTP replacement.
  Exact Verification **36033828072** all nine jobs completed/success, confirmed
  by GitHub API and sent to UX/installation:
  https://github.com/xiak/matrix/actions/runs/36033828072
  Full local evidence is owned by IAM/FEAT-IAM-009-security-governance.md.
  This does not prove LIVE UI, signed installation or complete MFA.
- a97a8a0c422d8e9d2c8cadb85f74c61c815318c6 remains the prior verified source
  behind e24, not a second supported historical release ladder.

## Reading route and next outcome

Read AGENTS, IAM/009's supported backup recovery and normal replacement
sections, then their owning private API, IAM SQL/usecase/CLI and tests.
IAM/011 owns the single-predecessor acceptance window; IAM/012 owns mail.
docs/adoption/FEAT-006-platform-authorities.md owns fixed donor choices.
Do not load unrelated docs or import another task's checkpoint.

Complete the existing recovery workflow's bounded current-authority evidence:
same RR exported backup snapshot, original source close barrier, unique Go
canonical digest, immutable original receipt, restored-state comparison,
nonrefunded replay/attempt floors and final reopening. Missing proof fails
closed before effects where observable. Equal qualification is a first
supported slice, not a substitute for the full requirement to handle changed
security state safely. No credential or policy resurrection after old backup.

Pure dce contract:
- Snapshot binds installation/bootstrap, original command/epoch/intent,
  closedAt, complete Account/USER membership and current authority digest.
  Replay floors/attempt windows are separate from persistent qualification.
- One api/adapter/installation/v1 canonical encoder/digest. 2MiB and 3000
  Account+USER items are transport bounds, not proven runtime capacity or
  Account creation quotas. Actual PG time/memory and completeness gates remain.
- New execution requires original snapshot; old optional fields preserve
  immutable historical bytes only, not an execution fallback.
- Envelope-to-intent validation obtains expected bootstrapDigest from the
  installer's authenticated authority, never the response/restored database.
- Pure codec/race/default architecture/vet passed locally before dce.
  Maximum Go fixture was 1,626,221 bytes and decoded; no SQL/runtime proof
  follows from this. Short fuzz was smoke only.

IAM45/Audit26 is the coordinated next authority direction, not an applied
schema or release claim in these fixed commits. Installation owns the final
release revision and its actual PaaS version. Do not advance profile metadata
before actual function shapes and consumers pass.

## Coordination

UX task 01a07b21-9a0d-7fd0-b090-7827ce18262e owns feat/cloud-console-ux.
Its backend remains old 04041d2d; e24 cannot be treated as an isolated route
patch. It prepares fixed-contract MOCK/client work without claiming LIVE.
Provide the verified minimal backend dependency/ADAPT closure at the final
IAM handoff. Do not replace its UI or attach new binaries to its old schema.

Installation task 01a04149-5dbb-7300-9e4c-31d9e85c8ada owns signed consumers,
profile/journal/keys/backup and actual restore; retain its PaaS6/host ownership.
It may consume dce pure types, not unfinished runtime changes or this branch's
profile. Its b7/40-24 baseline needs an explicit minimal fixed dependency/ADAPT
list through e24 and the final atomic recovery commit, not blind cherry-pick.
Single RR lease must bind backup v5 authenticationStateDigest; source close
envelope is durably written snapshot-first, read back, then closure before
destructive restore. Unknown outcomes reuse the original receipt and intent.
No current signed recovery acceptance or foreign evidence is inherited.

Remaining broader009 includes ACTIVE unlink/REMOVED enrollment, missing
settings/reset/Role interleavings, password/session governance, reports,
actual UI and signed combination. HA/capacity and deferred external integration
requirements remain with existing FEAT owners. Full goal stays incomplete.

## Execution boundaries

Markdown only; existing FEAT/adoption/test owners, no duplicate framework or
research diary. Commit identity exactly Xiak <Jellal@aliyun.com>, local only.
Go1.26.7, GOMAXPROCS2/GOMEMLIMIT512MiB; default-p2, real heavy gates race-p1,
serial. Own native PG fixture uses Windows Job2logicalCPU/1GiB/24processes,
16connections/64MiB shared_buffers/4MiB work_mem/no parallel workers.
Inspect actual live handles and ownership before changing runtime state.

No new agents/tasks, foreign WIP, remote1.3/160/161 or withdrawn1.5/GitLab,
global cleanup/config, shared Docker/WSL or remote restart. Only own feature
commits/resources. Handoff fixed pushed objects, not machine-local state.
Source pushes cancel in-progress branch CI; avoid interrupting the exact
live run. Checkpoint-only documentation pushes do not trigger Verification.
