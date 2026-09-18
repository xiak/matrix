# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Only this
  task's independent worktree is writable. Updated 2026-09-18.
- Latest pushed production implementation:
  **159bb302fed89161c4b60afeb4a6f41f9bd99820**, atomic self-revocation of other
  login Sessions (IAM/009 S1b). Remote feature HEAD was verified at this SHA.
- Exact-SHA [Verification35318292984](https://github.com/xiak/matrix/actions/runs/35318292984)
  is live, **not accepted**. Latest GitHub API observation: node-process
  success; go/authority-storage in_progress; authority-runtime queued.
  The aggregate workflow still reports queued. Verify this specific run/jobs
  next; an observation timeout is not termination and never warrants restart.
- Local final clean-export whole-source race/architecture, vet, modules,
  byte-identical API generation and Linux amd64 build passed. Real PG18.4
  restricted-role IAM/Audit/PaaS, cumulative policy/attachment/key/Role/recovery,
  actual fixed predecessor executables and independent processes passed.
  Exact scope, results and failed precursors belong IAM/009.
- Final strengthened Role security passed63.17s, including both actual
  Role-business/source-bulk-reduction orders. Quiet four-request expiry
  passed61.83s with real60-second lifetime and no serialization retry/deadlock:
  expired callers reject; expired targets are not counted.
- All local runner handles are terminal. Each successful serial fixture DB
  was dropped only after zero-client checks. The sole task-owned temporary
  PG container and empty network were removed after ownership checks.
  No local runtime/fixture remains for S1b; no other task/shared/remote resource
  was touched. Do not recreate a fixture merely to re-observe completed work.
- Current source: IAM32/Audit19/PaaS2, IAM product Profile r5. Published release
  profile/revision unchanged. No release upgrade, mixed-binary/N-1, UI or full
  IAM acceptance follows from the source versions.
- The full IAM goal remains ACTIVE, not narrowed to S1/S1b.

## Accepted rollback points

S1 implementation3080922f6ae1871f1c351d5ee30f03551fc3c605 and exact
Verification35301228478 have all five checks successful. Own Session
directory/individual self-revocation backend is accepted, not UI/full009.
S1b's retained-session gate uses that actual IAM31 executable and original
single-target completion, not every unpublished revision as a release baseline.

Gate/capacity repair b6f57d0126f66be62ec0615ee22d10b7d7226a10 and exact
Verification35309235630 also have all five checks successful. IAM/011 owns the
bounded measurement evidence. Old f6cfe47d/35306329508 remains failed/cancelled:
storage exceeded20min; capacity DNS failed before workload. Do not rerun
terminal workflows solely to re-observe results or backfill old failures.
Paired closed-loop concurrency1/2 is not saturation, fairness, a product SLO,
memory headroom or database HA.

## Current slice and next step

Read AGENTS and IAM/FEAT-IAM-009-security-governance.md, then owning code/tests.
IAM/011 owns scheduling/capacity; IAM/007 and ADR-0004 own signed-key/custody
consumers. Fixed donor decisions remain in the existing adoption owner.

S1b adds only POST /v1/auth/sessions:revoke-others with strict
RevokeSessionRequest{requestId}. Actual USER LOGIN_SESSION only, including
original root/forced-change reduction. No Role/Key/Service, selector, target
list, caller-chosen current Session or new administrator permission.
One immutable completion owns the exact other-session set, including empty.
Replay binds original caller/request and returns original count/time; it
cannot terminate later logins. Authenticate current identity before replay.
Password/generation/must-change, policies, Keys and resources are unchanged.

The original SQL owner adds forced-RLS immutable completion/target relations,
same-user FKs and sealed terminal/outbox evidence. Only API may execute
revoke_other_sessions(text,text,text,jsonb), returning count/time/applied.
Account -> stable USER -> credential -> stable Sessions preserves writer
order; post-lock database clock validates expiry. Actual serializable order,
not issuance or transaction timestamps, explains concurrent new login.

The only new tenant fact is iam.session.others-revoked: IAM source, actual
USER actor, PRINCIPAL target equal to actor, SUCCEEDED, no decision/operation,
Role/Key/SYSTEM actor, installation or target.tenantId. Original outbox proof
still works after actor disablement. lookup_session24, revoke_session6,
lookup_service5, claim7, record9/contract4, evidence5, ServiceIdentity and the
unique Audit canonical encoder/old chains are unchanged. No second Session,
Redis authority or generic receipt. Role source qualification, accepted
Operations and long connections keep their existing owner boundaries.

On all five35318292984 checks succeeding, update009 and this checkpoint, then
hand off only fixed159bb302/CI to existing consumers. Do not inherit their
UI/release acceptance or commission work implicitly. On failure inspect the
actual gate; do not increase limits/deadlines, reduce crypto cost or omit cases.

Whole-source gates use a clean Git export outside the repo: ignored duplicate
source under build is rightly rejected by the architecture walker. Slim Linux
Go lacks real machine-id; do not fake it or skip native host-probe assertions.
Native Windows whole-source checks and bounded Linux PG/process checks are
distinct evidence, not interchangeable.

## Remaining scope and unapproved choices

S2 MFA, S3 security rules/authentication budgets and S4 reports/idle governance
remain design, not available APIs. MFA requires protected seed custody,
privileged factor recovery and backup/non-rollback integration; password
recovery does not authorize removing a factor. The asynchronous choice of
installation owner/task expansion/deferral remains unanswered. A separate
choice for S3's narrow tenant security-setting read/write permissions is also
unanswered. Preselection and goal continuation are not approval.

Delegation/IP, signed business PEPs, governance, UI, capacity/HA and final signed
installation/backup/release remain with their FEAT owners. External integration
deferrals stay explicit in012. Do not substitute speculative design for
implementation or claim the complete goal achieved.

## Shared windows and peers

UX/UI工程师01a07b21-9a0d-7fd0-b090-7827ce18262e owns UI/browser in
feat/cloud-console-ux. No UI files, foreign worktree or runtime is writable.
S1 consumer8e8b0f608827fb00c9a0e677e78ec12a7e047315 is the verified parent of
ec5e832ad42cafea31cd731cfdbaa046b3537229; disregard the initially wrong full
SHA sharing its short prefix. It consumes accepted308. IAM/010 and adoption
record the fixed handoff, not acceptance. Its evidence is MOCK/DEV with no
real revoke; human priority defers real login. Do not operate/supply a bypass
fixture or commission browser/MFA/security-setting work implicitly. It
confirmed S1b's backend window and waits for fixed verified interfaces.

Phase3 task01a04149-5dbb-7300-9e4c-31d9e85c8ada opened the shared window after
fixedc2fbd9e38d424e68c0466618ee74613aced3c3fb and confirmed no S1b overlap.
It reported completion and requests fixed-SHA/CI informational handoffs only.
Do not reopen it or inherit its consumer/release state.

PaaS/Audit business PEPs, ingress/origin mapping, APISIX, installation/keyring/
backup and release composition are not edited here. No parallel signed
business consumer, moving donor, foreign checkpoint or WIP is imported.

## Runtime discipline

No subagents/new tasks. Go2/-p2, bounded memory; heavy true DB gates serial
race-p1 in uniquely named/labelled CPU/memory/PID-limited fixtures. Observe
actual live handles before waiting and exact ownership before cleanup.
Isolated-index exports preserve the actual Git index. Evidence must match
source/scope; skipped external gates are not runtime acceptance.
No remote1.3/.160/.161, withdrawn GitLab/root1.5 work, other worktrees, shared
restart, global config or Docker prune. Temporary paths and uncommitted
machine-local state are not portable checkpoint memory.
