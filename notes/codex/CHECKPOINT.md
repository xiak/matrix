# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam; only this
  task's independent worktree is writable. Updated 2026-09-16.
- Latest pushed code6ae975d9a65569d5215fca26ef65a16722d2cd13 adds only the
  bounded AssumeRoleRequest/schema component, carrier/deadline pure rules
  and purpose-separated ROLE_SESSION credential primitive. Exact run
  Verification35063652730 was observed in_progress; recheck its exact SHA
  and all jobs before claiming independent acceptance. No issuance HTTP,
  ROLE business subject, Profile subjectTypes or new SQL is implemented.
- R1 bf7e8fbbdffe96b8af5b250edd1ed746c5b99265 remains the accepted
  same-account CUSTOMER Role management baseline. GitHub API confirmed exact
  Verification35060352506: go/authority-process/node-process all success.
- Prior Audit head-lock fix f9ca482df5bde3c8689e9d105f382e178a6abdab
  /35054751383 and trust contract1bcaa62bf6b11c20a7b34458408a221ed0aa633c
  /35047801568 retain their all-three-success evidence.
- Committed source IAM24/Audit14/PaaS1. Published release profile unchanged;
  no new release revision. R1 backend is accepted; RoleSession/AssumeRole,
  actual role business authorization, UI and complete006 are not accepted.

## Active goal and next substantive work

Whole IAM goal remains ACTIVE. Read AGENTS, IAM/FEAT-IAM-006-roles-and-sts.md
and its owning code/tests. R2's shared contract is now frozen in006 after
Phase3 coordination. Implement the actual Profile subjectTypes/ROLE public
contract, then real issuance/private proof/RoleBoundary/PaaS/Audit and R3,
not only these preliminary rules. Read the directly related001/005 owners
before their changes; do not infer an already-implemented actor or schema.
001 owns product declarations,005 policy/conditions,006 Role/Trust/STS,
008 service/ABAC,010 peer UI,011 HA/capacity/release,012 external deferrals.
No subagents or extra tasks. UI belongs to the UX/UI engineer.

User's design question was answered: distinguish LoginSession/RoleSession
and Identity/Access/STS responsibilities now, but retain the current single
IAM authority deployment. No Redis or empty generic SessionStore framework.
Physical separation needs real scale, security, ownership or failure proof.

## R1 contracts and evidence

R1 Role writes require original Account Root AND current PDP AND actual
authenticated Session.ID revalidated under locks. Root is no bypass.
Product IAM r2 appends immutable r1, never rewrites retained SYSTEM defaults
or grants new actions. Retained Root explicitly publishes/attaches a current
TENANT policy. Complete metadata is bounded at4096 UTF-8 bytes; trust selects
a new immutable version. Deleted USER history remains, new deleted references
are rejected. Role deletion is an irreversible tombstone and closes its
active TENANT attachments; resources never become Role-owned.

Private role writers have session as their final argument: create/trust9,
update/status8,delete7; readers4/4/5/5. Current USER/GROUP/platform attachment
create10/revoke7 stay exact, with no old overload/default. Shared readiness
and verification check actual function types, ACL/proconfig and storage
invariants, not just schema numbers. Current decisions have no SessionID;
never invent historical source-session lineage.

Six tenant IAM/USER/decision facts target ROLE: created/updated/disabled/
enabled/trust-set/deleted. No new SYSTEM or ROLE actor. IAM-source proof
uses exact committed outbox; create's parent decision does not prove its
final payload. record_authorization7/evidence5/claim7, ServiceIdentity,
lookup_service and CanonicalizeEvent remain unchanged.

R1 real PG18.4 gates include full IAM HTTP106.296s, Role36.857s, private
references11.345s, full attachment regression66.139s, USER history14.090s,
independent processes53.475s, exact IAM21 retained-binary upgrade24.775s,
Audit dual schema7.999s/HTTP4.017s. These prove current roles, locks/replay,
cross-account/cursor isolation, actual restricted runtime identities,
outbox rollback and history after logout/restart, not STS/HA/release.
Frozen exact candidate outside the source tree passed full race/p2,
architecture,vet,mod verification,stable API generation and Linux build.
Evidence and negative matrices belong only to006, not this checkpoint.

The new6ae pure candidate also passed whole-tree race/p2, architecture,vet,
mod,stable generation and Linux build from an exact clean Git export.
Its input round-trip fuzz passed120526 executions in15s with2workers and
1s minimization. No new local database/process/browser gate was run for this
pure slice; existing runtime regression is not R2 acceptance. All local
commands for this milestone are terminal. Independent CI above was live.

## Peer and runtime boundaries

UX/UI工程师01a07b21-9a0d-7fd0-b090-7827ce18262e owns independent
feat/cloud-console-ux. R1 fixed API/source was sent for its UI adaptation;
AssumeRole, temporary credentials and role-switch availability are absent.
Do not import assets alone, peer WIP, environment or acceptance state.
Phase3 01a04149-5dbb-7300-9e4c-31d9e85c8ada waits one final cumulative
Role/STS donor and retains its own PaaS/host/profile. Both peers received the
R2 correction: public ROLE is roleId plus exactly roleSession.sessionId and
sourceUserId. Source login session, trust/generation and full authority
vectors stay private to IAM. This task may adapt its own tenant PaaS public
subject/Operation/outbox and Audit consumers; platform/host/node stay closed.
Use the unique Profile subjectTypes capability, not a product-name whitelist;
old registered declarations/compilations must not silently acquire ROLE.
The exact mandatory RoleBoundary, recorder8/contract3, historical-evidence5,
once-only secret/EQUAL_REPLAY and both self-revocation requirements are in006.
IAM25/Audit15 is allocated for the real cutover, not yet reflected in source.
ServiceIdentity/lookup_service/claim7/canonical and release profile stay fixed.
Do not broaden001/005/006 acceptance or inherit the peer's PaaS5 value.

Go defaults GOMAXPROCS2/GOMEMLIMIT768MiB/-p2; real gates serial-p1 in own
uniquely labelled, limited fixtures. Inspect current IDs before any cleanup;
portable memory never authorizes deleting an object. A prior attempt to
remove this task's ignored source export was blocked: do not retry through
another deletion mechanism or weaken architecture checks. Use an exact clean
Git snapshot outside the source tree for whole-tree checks if needed.
No other worktree/environment, remote1.3/.160/.161, withdrawn GitLab/root1.5
work, remote or shared restart. No peer release/profile status is inherited.
