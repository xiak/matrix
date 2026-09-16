# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Only this
  task's independent worktree is writable. Updated 2026-09-16.
- Latest verified, pushed implementation:
  0752c602ab4ce6d73a21094c8e9f75a1c8750183 (cumulative R2 Role/STS).
  GitHub API confirmed exact Verification35096275242 and all three jobs
  go/authority-process/node-process completed/success.
- R1 fixed bf7e8fbbdffe96b8af5b250edd1ed746c5b99265 and capability baseline
  d45402d91c89a5bb23f52fcfde65491435cd0f55 remain recorded in their FEAT.
  Earlier failed/cancelled foundation CI is not reclassified as success.
- Committed development source IAM25/Audit15/PaaS2; published release profile
  unchanged. R2 is not a signed release, UI, capacity, HA or whole-IAM acceptance.

## Continue the full goal

Whole IAM goal remains ACTIVE. Read AGENTS, IAM/FEAT-IAM-006-roles-and-sts.md,
then owning API/usecase/adapter/tests. R2 now has real tenant business and
immutable-history evidence; do not redo it as a foundation or shrink the goal.
The next substantive slice is R3 self-service discovery/current-role display,
followed by remaining management, UI and final requirements in existing FEATs.
The R3 design is recorded in006; it is not yet implemented. No subagents or
extra tasks. No parallel UI implementation or generic SessionStore/Redis layer.

## R2 fixed contract

USER login and RoleSession are separate, opaque purpose-bound credentials.
Public ROLE is roleId plus exactly roleSession.sessionId/sourceUserId; private
source login/generations/trust/authority vectors remain IAM evidence. Same
account USER Assume needs both current permission and Trust, with mandatory
RoleBoundary and optional immutable SessionPolicy. Source business grants do
not flow into ROLE. Once-only secret, exact non-secret replay, source self
revocation, ROLE self exit, ABA invalidation and immutable history are real.

record_authorization is the sole8-argument contract3 writer. USER/SERVICE use
explicit JSON null for its private role argument and SQL NULL role columns;
ROLE has no fake USER principal_id. Evidence5/claim7/ServiceIdentity/
lookup_service and old USER/SERVICE canonical/hash remain. Audit tenant query
uses the complete actor argument and its7-argument ABI, with full cursor
filter binding. Readiness verifies actual shapes/ACLs/invariants, not numbers.

PaaS/Audit tenant products consume ROLE through their current Profile
subjectTypes. Platform/host/probe and undeclared ManagedService stay closed.
Old compiled USER-only policy does not gain ROLE from a new catalog: explicit
publication/selection and removal of incompatible old Role sources is required.
Fixed IAM21 and actual R1 binaries prove only their explicit retained-content
interpretation boundaries, not an unpublished schema1 upgrade chain or release
admission. Evidence and fixed adoption decisions remain in their owners.

## R3 and peers

UX/UI工程师 01a07b21-9a0d-7fd0-b090-7827ce18262e owns independent
feat/cloud-console-ux and all UI/browser work. Its current Role/session
workspace is MOCK, not a live R2 consumer. We agreed the next backend shape:

- GET /v1/auth/assumable-roles: bounded current USER self discovery, no caller
  scope and no management list/read requirement; only currently eligible
  minimal roles. Empty items may still have nextAfter; no unauthorized totals,
  unlimited scanning or frontend policy evaluation.
- Replace GET /v1/auth/role-session's R2 RoleSession response with a strict
  CurrentRoleIdentity containing minimal account/role/sourceUser display and
  the exact session. R2 does not yet have this response. No compatibility alias.
  Invalid current authority still401/503; possession-only self exit still works.
- RoleAccess gains exact Assume capability using the same eligibility rules;
  RoleListing remains management-only. Do not apply root-only management
  protection to ordinary USER assumption. Admin session management remains
  separate unfinished work, not an interpretation of by-request self service.

UI will use separate in-memory USER/ROLE slots, original issuance intent for
unknown outcomes, and current USER verification before returning from a role.
Actual expiresAt is authoritative, not a promised duration. Do not turn
current-role401 or an uncertain logout into proof of server-side revocation.
Send the next verified R3 fixed object, schema/operationIds and closed
restrictions; no WIP or accidental cached-name dependency.

Phase3 01a04149-5dbb-7300-9e4c-31d9e85c8ada receives fixed cumulative donors
only and keeps its host/PaaS/release composition and evidence. Do not import
its WIP or claim its consumer integration. Shared interfaces must remain
coordinated; the R3 read projection does not authorize platform/service scope.

## Runtime discipline

Go defaults GOMAXPROCS2/-p2; real gates serial-p1 in uniquely named, labelled,
CPU/memory/PID-limited own fixtures. Never assume a live object from this
checkpoint; inspect exact ownership before running or cleaning anything.
No other worktree, peer runtime, withdrawn GitLab/root1.5 task, remote1.3/
.160/.161 access, remote/shared restart, global configuration or Docker prune.

An ignored source export inside the worktree poisons whole-tree architecture
traversal. Its earlier removal was blocked; do not retry through another
mechanism or weaken checks. Use an exact clean Git export outside the source
tree with a temporary index; preserve the real index. All local R2 gates have
terminal results; detailed scope and limitations belong006, not this file.
