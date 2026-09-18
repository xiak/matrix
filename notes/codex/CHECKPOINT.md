# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Only this
  task's independent worktree is writable. Updated 2026-09-18.
- Latest pushed test slice: **7f02d41960f6ca74e49b24f895ad8fc649fc5e49**,
  independently scheduled account-interference observation. Only existing
  test/authorityprocess/process_e2e_test.go and IAM/011 changed.
- Exact-source [Verification35338576115](https://github.com/xiak/matrix/actions/runs/35338576115)
  was freshly inspected as QUEUED after push. Its result is NOT accepted.
  Reinspect that exact run/commit before waiting; do not restart a live run
  or infer success from the preceding commit.
- Latest accepted production is still **159bb302fed89161c4b60afeb4a6f41f9bd99820**,
  S1b atomic other-login-session self-revocation, cumulatively accepted at
  **7cf857bba48eb5d7da487162c43e8f52534db133** / Verification35324569376,
  five checks completed/success. Acceptance owners fixed7e7e1ba0.
- IAM32/Audit19/PaaS2, IAM product Profile r5; published release profile and
  revision unchanged. The full IAM goal remains ACTIVE, not complete.

## Current slice and evidence

Read AGENTS, IAM/FEAT-IAM-011-acceptance.md and its existing process test.
009 owns Session/security governance; 006 owns Role/STS; 007 and ADR-0004
own signed-key/custody boundaries. No production/API/SQL, UI, installation,
permissions, workflow budgets or other worktree changed in7f02.

Original capacity paired batches forced each account to wait for its peer.
They remain intact:2000 requests,400 real logins,1200 timed decisions.
The increment adds a100-request complex-PDP control plus100 independently
progressing wrong-password requests in A and100 paced complex decisions in B.
Each independent lane has one worker; total concurrency at most2, B's planned
interval100ms. Response verification remains on the receiving goroutine.
Record actual starts/ends, lane throughput, scheduling lateness and planned
completion latency; no missing samples/retries or secret output. Actual peer
window overlap is checked, not inferred from launching goroutines.

Current test Go blob0937e73110c3b2dbcde6fc6bfcf68764fd5e548b passed full
capacity104.91s (package105.956s) on a clean source export. Go1.26.5 runner
2CPU/1536MiB/PIDs256/GOMAXPROCS2/GOMEMLIMIT512MiB; separate PG18.4
1CPU/768MiB/PIDs192,512MiB temporary data, no host port or extra swap.
12stages/23rows/2300requests, failures0;400 unique credentials were actually
authenticated on the other replica and1400 exact historical decisions were
checked, alongside current revocation, runtime DB users, outbox and chains.

B normal P99 was19.11ms and under A pressure18.35ms; planned completion P99
19.75/18.63ms.99 B samples started in A's window,90 A samples in B's.
These are bounded local observations, NOT evidence of enforced tenant
fairness, overload budgets, an open-loop saturation point or a production
SLO. The slightly faster pressured result is not a performance improvement
claim. Exact metrics and unmeasured boundaries belong only to IAM/011.

Same test source: original independent-process security flow passed56.37s
(package57.415s) in another fresh PG18 database. Clean Windows/amd64 Go1.26.3
export passed whole-repository race-p2 tests including architecture, vet-p2
and module verification, all GOMAXPROCS2. Default DSN SKIPs are not real DB
evidence. New default scheduler tests cover the original batch barrier,
independent progress, bounded concurrency, pacing, cancellation and rejection
of invalid plans; they do not substitute for real IAM/Audit/PaaS processes.

All local process handles are terminal. Both runners auto-removed; after
zero-client, exact-ID/owner/empty-mount checks, the sole task-specific PG and
empty network were stopped/removed. No local fixture is live. Preserve the
task-owned Go cache. No foreign/shared/remote resource was modified.
Next: inspect exact7f02 CI and its real capacity/storage/runtime logs, then
update acceptance only if actual gates pass. Keep full-goal gaps below.

## Accepted rollback points and Session contract

- S1 backend3080922f6ae1871f1c351d5ee30f03551fc3c605 /35301228478:
  five checks successful; own Session directory and single-target
  self-revocation, not UI or full009.
- Capacity/scheduling b6f57d0126f66be62ec0615ee22d10b7d7226a10 /35309235630:
  five checks successful; original bounded measurements, not HA/fairness.
- S1b cumulative7cf /35324569376: terminal SUCCESS, all five logs inspected.
  General IAM fixtures ran individually; full Role/STS333.093s, own Session
  three tests226.359s, retained/independent148.830s, capacity140.29s.
  Original failed159/35318292984 and2cd/35320384077 remain failures.
  Their timing/fixture repairs and exact boundaries are owned by006/011;
  do not rerun terminal jobs or retain old worktree implementations.

S1b is POST /v1/auth/sessions:revoke-others with strict{requestId}. Current
Account/USER/retained Session derive from actual LOGIN_SESSION; root and
forced-change self-reduction allowed, Role/Key/Service/selectors rejected.
Atomic immutable completion binds original caller/intent and exact other
sessions, including an empty set. Exact replay returns original count/time,
does not revoke later logins and still authenticates the current caller.
No new admin privilege, Session model/cache authority or generic receipt.
lookup_session24/revoke_session6, lookup_service5/claim7,
record9/contract4/evidence5, ServiceIdentity and old canonical/chains stay.

## Unfinished full goal and unapproved choices

S2 MFA, S3 security rules/authentication budgets and S4 reports/idle governance
remain design, not available APIs. MFA seed custody, factor recovery and
backup/non-rollback integration require an owner choice: original installation
owner or explicit authorization to expand this task. Password recovery does
not authorize removing a factor. S3's separate tenant security-settings
read/write permissions are also UNAPPROVED. No answer has arrived; automatic
goal continuation or preselected options are not approval. Do not silently
implement either expansion or reopen another task.

Those choices do not block independent in-scope progress such as7f02.
Remaining delegation/IP, signed business enforcement, service roles/ABAC,
governance, UI, capacity/HA and final signed installation/backup/release stay
with their original FEAT owners. External deferrals remain explicit in012.
Keep the full goal, not a goal narrowed to Session or test measurement.

## Shared windows and peers

UX/UI工程师01a07b21-9a0d-7fd0-b090-7827ce18262e owns UI/browser in
feat/cloud-console-ux. No foreign source/runtime writable. S1 consumer
8e8b0f608827fb00c9a0e677e78ec12a7e047315 is MOCK/DEV only; real browser
login/revoke remains deferred by human priority. It received fixed7cf/CI and
strict S1b contract as an informational handoff; no consumer/browser acceptance
is inferred. Do not commission browser/MFA/security work implicitly.

Phase3 task01a04149-5dbb-7300-9e4c-31d9e85c8ada completed and requests only
fixed-SHA/CI informational handoffs. It received accepted7cf, unchanged ABI
and boundaries. Do not reopen it or inherit consumer/release acceptance.
PaaS/Audit business enforcement, ingress/APISIX, installation/keyring/backup
and release composition are outside this test-only slice.

## Runtime discipline

No subagents/new tasks. Repository-local Xiak <Jellal@aliyun.com> only.
Go2/-p2 with bounded memory; heavy real PG gates serial race-p1 with unique
task names/labels and explicit CPU/memory/PID limits. Confirm a handle is
live before waiting and exact ownership before cleanup; no broad prune.
Clean exports outside the repository avoid ignored duplicate source in
architecture checks. Isolated Git indexes leave the actual index untouched.
Do not fake host machine-id, weaken checks/password cost, increase budgets or
discard cases/samples for green. No remote1.3/.160/.161, withdrawn GitLab/1.5,
foreign WIP/checkpoint, shared restart or global config. Machine-local paths
and uncommitted state do not belong in this portable checkpoint.
