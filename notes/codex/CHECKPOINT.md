# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Only this
  task's independent worktree is writable. Updated 2026-09-18.
- Latest pushed production: **159bb302fed89161c4b60afeb4a6f41f9bd99820**,
  atomic self-revocation of other login Sessions (IAM/009 S1b). Local complete
  gates passed, but cumulative independent CI has not passed: NOT ACCEPTED.
- Latest pushed test repair: **7cf857bba48eb5d7da487162c43e8f52534db133**.
  Only the existing Role-management security fixture and IAM006/009/011
  evidence changed. Production API/SQL, all 24 controlled interleavings,
  original deadlines, password cost and resource limits remain unchanged.
- Exact-source [Verification35324569376](https://github.com/xiak/matrix/actions/runs/35324569376)
  is live, not accepted. GitHub API observation: Go105534536961,
  storage105534537050 and node105534537109 in_progress; runtime105534537245
  queued. Observe these exact jobs next. A polling timeout is not termination
  and never justifies starting a duplicate gate.
- IAM32/Audit19/PaaS2, IAM product Profile r5. Published release profile and
  revision unchanged. Source versions do not establish release/N-1, UI or
  complete IAM acceptance. The full goal remains ACTIVE.

## Current evidence and next action

Read AGENTS, IAM/FEAT-IAM-009-security-governance.md, then owning code/tests.
IAM/006 owns Role/STS fixture preparation, IAM/011 owns cumulative CI and
capacity, IAM/007 and ADR-0004 own signed-key/custody boundaries.

The first S1b CI35318292984 failed at the shared Go ten-minute package timer;
Go/node/runtime passed. Fixed2cd045b01a27e85617f8272e5f55491fd311aaca splits
the five general IAM fixtures into separate serial processes. Its exact
CI35320384077 is terminal FAILURE, not live: all five general fixtures
actually passed, then Role management reached its own120-second deadline;
PaaS database command was not reached. Go/node/runtime passed, aggregate
correctly failed. Do not rerun either terminal run just to re-observe it.

The Role timeout was during a fixture's fresh-root forced-password change,
not the platform offline-recovery transaction. Exact2cd source reproduced
locally; CPU samples concentrated on real Argon2 and race probes. Reusing
only the unchanged Account/root was insufficient: one repetition still
timed out during final migration verification despite all24 cases passing.

Fixed7cf additionally reuses the unchanged issuing USER in ordinary cases.
Every identity is created, logged in and changed through real HTTP. Each
manager, Role, RoleSession, intent and competition remains independent;
root recovery/account suspension keep four dedicated complete fixtures.
Shared root/source are authenticated again at the end. No direct credential
seeding, fake password implementation, case removal, retry-until-green or
deadline/resource increase. Original101-history/pagination/storage attacks,
atomic outbox, double migration/bootstrap replay and deadlock tracing remain.

Exact candidate code tree5705841ac19e7697d2e80e5906ae9bfe6b2889e5 passed the
whole management group twice in distinct new PG18.4 databases:80.60s/78.18s.
PG1CPU/768MiB/PIDs192, Go1.26.8 runner2CPU/1536MiB/PIDs256,
GOMAXPROCS2/GOMEMLIMIT512MiB, serial race/p1, original120-second deadline.
Clean native Go1.26.3 export passed focused integration compilation/default
race, architecture and vet. Default external SKIPs are not database evidence.
Exact scope and failed predecessors are recorded in IAM/006.

All local handles are terminal. All runner containers ended; zero-client
checks preceded removal of this slice's synthetic databases, temporary PG
container and empty internal network. Go cache remains. No local fixture is
live; do not recreate it merely to observe completed results. No other
task/shared/remote resource was changed.

Next observe35324569376 and inspect actual executed gates, not just a green
summary. On all five checks succeeding, update009/011 and this checkpoint,
then provide fixed-source informational handoffs to existing consumers. On
failure inspect that specific test; do not raise budgets or weaken coverage.
The remaining IAM goal is not narrowed to this Session slice.

## Accepted rollback points and contract boundary

- S1 backend3080922f6ae1871f1c351d5ee30f03551fc3c605 /35301228478: all five
  checks successful; own Session directory and single-target self-revocation
  accepted, not UI or full009. S1b retained-state gate uses that actual IAM31
  executable, not every unpublished schema revision.
- Capacity/scheduling b6f57d0126f66be62ec0615ee22d10b7d7226a10 /35309235630:
  all five checks successful. IAM/011 owns bounded measurements; these are
  not saturation/fairness, a production SLO, memory headroom or database HA.
  Old f6cfe47d/35306329508 remains failed/cancelled.

S1b is only POST /v1/auth/sessions:revoke-others with strict{requestId}.
Current Account/USER/retained Session come from actual LOGIN_SESSION bearer;
root and forced-change self-reduction allowed, Role/Key/Service/selectors
rejected. Atomic immutable completion binds original caller/intent and exact
other-session set, including empty. Exact replay returns original count/time,
does not revoke later logins and still authenticates the current caller.
No new administrator privilege, Session model, cache authority or generic
receipt. SQL ACL/RLS/locks/post-lock expiry and one tenant IAM fact are owned
by009. lookup_session24/revoke_session6, lookup_service5/claim7,
record9/contract4/evidence5, ServiceIdentity and canonical/old chains stay.

## Unfinished scope and unapproved choices

S2 MFA, S3 security rules/authentication budgets and S4 reports/idle governance
remain design, not available APIs. MFA custody, privileged factor recovery
and backup/non-rollback integration require an owner choice; password
recovery does not authorize removing a factor. The user has not answered
whether the installation owner or this task should take that integration.
S3's narrow tenant security-setting read/write permissions also remain
unapproved. Preselected options and automatic goal continuation are not
approval. Do not silently implement either expansion or reopen another task.

Delegation/IP, signed business enforcement, service roles/ABAC, governance,
UI, capacity/HA and final signed installation/backup/release remain with their
FEAT owners. External integration deferrals stay explicit in012. Final
acceptance requires the original full goal, not a locally green subset.

## Shared windows and peers

UX/UI工程师01a07b21-9a0d-7fd0-b090-7827ce18262e owns UI/browser in
feat/cloud-console-ux. No foreign source or runtime is writable. S1 consumer
8e8b0f608827fb00c9a0e677e78ec12a7e047315 (parent of ec5e832) consumes308;
MOCK/DEV only, real login/revoke remains deferred by human priority.010 and
adoption own that handoff, not UI acceptance. It confirmed S1b's backend
window and awaits fixed independently verified interfaces; do not commission
browser/MFA/security-setting work implicitly.

Phase3 task01a04149-5dbb-7300-9e4c-31d9e85c8ada opened the S1b window after
fixedc2fbd9e38d424e68c0466618ee74613aced3c3fb. It has completed and requests
fixed-SHA/CI informational handoffs only. Do not reopen it or inherit its
consumer/release status. PaaS/Audit business enforcement, ingress/APISIX,
installation/keyring/backup and release composition are not edited here.

## Runtime discipline

No subagents/new tasks. Repository-local Xiak <Jellal@aliyun.com> only.
Go2/-p2 with bounded memory; heavy real DB gates serial race-p1 in uniquely
named/labelled CPU/memory/PID-limited fixtures. Verify live handles before
waiting and exact resource ownership before cleanup; no broad prune.
Clean exports outside the repository keep ignored duplicate source out of
architecture checks. Isolated Git indexes preserve the actual index.
Native host-probe and bounded Linux PG/process evidence are distinct; never
fake machine-id or skip host assertions for a slim runner.
No remote1.3/.160/.161, withdrawn GitLab/root1.5 work, foreign WIP/checkpoints,
shared restart or global configuration. Machine-local paths and uncommitted
state do not belong in this portable checkpoint.
