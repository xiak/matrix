# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam; only this
  task's independent worktree is writable. Updated 2026-09-16.
- Latest verified, pushed code is
  d45402d91c89a5bb23f52fcfde65491435cd0f55. GitHub API confirmed exact
  Verification35069879250: go/authority-process/node-process all success.
  It isolates existing Role/private-session-reference matrices into independent
  clean databases, preserving assertions, scenario limits and bounded waits.
- It includes7b597101c55cbd782e611f8da794fc84da138ebb Profile subjectTypes
  and current USER/SERVICE checks. That earlier CI35067085558 failed from
  two aggregate IAM contexts exhausting120/180seconds. Predecessor6ae975d9
  CI35063652730 was cancelled at the old10-minute JOB cap. Do not rewrite
  those runs as successes. Job cap is now20minutes; per-test, package, lock,
  resource and password-cost budgets were not increased.
- R1 Role management bf7e8fbbdffe96b8af5b250edd1ed746c5b99265 is accepted
  with CI35060352506 all-three success. R2 foundations do not imply working
  RoleSession issuance, ROLE product authorization or complete006 acceptance.
- Committed source IAM24/Audit14/PaaS1; published release profile unchanged.
  Read current Git before interpreting local edits or runtime state.

## Active goal and next substantive work

Whole IAM goal remains ACTIVE. Read AGENTS, IAM/FEAT-IAM-006-roles-and-sts.md
and owning code/tests. R2's shared contract is frozen in006. Complete actual
RoleSession issuance/private proof/RoleBoundary/ROLE public contract and tenant
PaaS/Audit consumption, then R3 and final gates; do not substitute another pure
foundation for the runtime slice. Profile subjectTypes exists, but committed
source declarations have not switched to R2 revisions. 001 owns product
declarations,005 policy/conditions,006 Role/Trust/STS,008 service/ABAC,010 peer
UI,011 HA/capacity/release,012 external deferrals. No subagents or extra tasks.

User approved separate logical Identity/Access/STS responsibilities and
LoginSession/RoleSession, retaining one IAM authority deployment/transaction
boundary. No Redis or generic interchangeable session authority framework.

## Fixed contracts and evidence

R1 Role writes require original Account Root AND current PDP AND exact bearer
Session.ID checked under locks. Root is not a bypass. Immutable IAM Profile
r1/r2, retained SYSTEM defaults, historical trust and deleted USERs are not
rewritten. New Role authority requires explicit current grants on retained data.
Metadata budgets, sorted locks and negative matrices belong006. Role writers
end with private actor_session_id: create/trust9,update/status8,delete7;
readers4/4/5/5. Attachment create10/revoke7 have no old overload.
record_authorization7/evidence5/claim7 and public USER/SERVICE remain.

The d454 test code tree e496908ecea855d6300ad8e549774719f1d46b6a passed
clean-export real PG18.4 HTTP/attachment/Role/private-reference gates263.159s,
then full race/p2,architecture,vet/p2,module verification and Linux build.
Go2/512MiB; PG1CPU/768MiB/PIDs128/max_connections64; real gates serial-p1.
This is not RoleBoundary/RoleSession, browser, HA or release evidence.
Other exact baseline gates remain in001/005/006; do not duplicate inventories.

## Peer and runtime boundaries

UX/UI工程师01a07b21-9a0d-7fd0-b090-7827ce18262e owns independent
feat/cloud-console-ux. R1 fixed source was sent; AssumeRole/temporary identity
is not delivered. Phase3 01a04149-5dbb-7300-9e4c-31d9e85c8ada waits one
final cumulative Role/STS donor and retains its own PaaS/host/profile. Do not
import peer WIP, environments, assets alone or acceptance state.

R2 public ROLE is roleId plus exactly roleSession.sessionId/sourceUserId.
Source login session, credential/trust/security generations and full source
authority vectors stay private IAM evidence. This task owns tenant PaaS
subject/Operation/outbox adaptation; platform/host/node stay closed. Use the
single Profile subjectTypes capability, not a product/scope whitelist.
Old compilations do not gain ROLE without explicit publication/default.
Mandatory RoleBoundary, once-only secret/EQUAL_REPLAY, source self-revocation,
ROLE self-exit and immutable history are specified in006. IAM25/Audit15 is
allocated for actual record8/contract3 cutover, not yet in committed source.
ServiceIdentity/lookup_service/claim7/CanonicalizeEvent and release profile
stay fixed. Do not inherit another branch's PaaS or published profile.

Go defaults GOMAXPROCS2/-p2; real gates serial-p1 in owned uniquely labelled,
CPU/memory/PID-limited fixtures. Check live object IDs before cleanup; this
checkpoint never authorizes deleting an object or assumes a live fixture.
An earlier deletion of an ignored source export was blocked: do not retry
through another mechanism or weaken architecture checks. Use an exact clean
Git export outside the source tree for whole-tree checks when needed.
No other worktree/environment, remote1.3/.160/.161, withdrawn GitLab/root1.5
work, remote or shared restart. Keep UI and shared release work with owners.
