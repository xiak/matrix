# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam; only this
  task's independent worktree is writable. Updated 2026-09-16.
- Latest pushed code f9ca482df5bde3c8689e9d105f382e178a6abdab fixes Audit
  query/verification head acquisition. Exact Verification35054751383 was
  checked through GitHub API: go/authority-process/node-process all success.
  Earlier 89cd60c9bd64ddf0fccb10b5b8df64309f5e118c CI35051957349 failed a
  platform query with 503; do not reuse its local passes as CI acceptance.
- Pure Role trust 1bcaa62bf6b11c20a7b34458408a221ed0aa633c /35047801568
  and prior runtime40407e2710a45ee1000552146cd362740074369a /34959581661
  retain their exact all-three-success evidence.
- Committed source IAM24/Audit13/PaaS1, original release profile unchanged.
  R1 Role APIs/transactions and RoleSession/AssumeRole are not yet accepted.
  Audit14 is allocated only for the actual R1 facts. No release revision.

## Active goal and next substantive work

Whole IAM goal remains ACTIVE. Read AGENTS, IAM/FEAT-IAM-006-roles-and-sts.md
and its owning code/tests. Continue the actual R1 Role management HTTP/PG/
Audit slice, then mandatory R2 issuance/current business authorization and R3.
Do not substitute metadata or pure contracts for usable roles. Inspect Git
for local progress; this portable checkpoint contains no uncommitted state.
001 owns product declarations,005 policy/conditions,006 Role/Trust/STS,
008 service/ABAC,010 peer UI,011 HA/capacity/release,012 external deferrals.
No subagents or extra tasks. UI belongs to the UX/UI engineer.

User's design question was answered: keep LoginSession/RoleSession and
Identity/Access/STS responsibilities distinct, but do not physically split
the current IAM authority or add Redis/empty generic SessionStore machinery.
Physical separation needs actual scale, security, ownership or failure proof.

## Fixed security and evidence boundaries

Attachment writes privately carry the actual authenticated Session.ID.
IAM24 replaces create9/revoke6 with exact create10/revoke7 (private session
last, no default/overload); account/principal/session/generation/expiry are
rechecked in the existing transaction. Current published decision does not
contain source SessionID; do not invent lineage in it or historical proof.
record_authorization7/evidence5/claim7, ServiceIdentity/lookup_service and
CanonicalizeEvent remain unchanged. Existing live readiness and verification
share the exact function/ACL/proconfig checks. Real attachment and preserved
policy gates,48 controlled security-change-first races and negative session
references are recorded in006; they do not prove Role-specific races.

f9ca prepares each audited-read access fact and locks its event then selected
head before the scan; it appends only after success. Its response excludes
its own fact. Installation verification first resolves the immutable probe;
PENDING has no success fact. SERIALIZABLE and five paced retries stay, without
client retries or longer timeouts. Existing Audit HTTP owner proved four
real query/verify success/rejection interleavings red then green. Frozen
candidate process races52.215s/48.042s, dual-schema5.776s, AuditHTTP3.729s,
full race/vet/mod, stable generation and Linux build passed; exact CI above.
Evidence belongs to docs/features/FEAT-006-platform-authorities.md.

## R1 and peer coordination

R1 CUSTOMER Role writes require original Account Root AND current PDP AND
exact bearer session; Root is no bypass. IAM product Profile r2 appends to
immutable r1, never rewrites retained SYSTEM defaults or grants new actions.
Retained Root must explicitly publish/attach a current TENANT policy.
Closed facts are tenant IAM/USER/decision role.created/updated/disabled/
enabled/trust-set/deleted with ROLE target; no SYSTEM/ROLE actor or new
target.tenantId use. Original create decision proves its parent, not final
payload; immutable IAM outbox proves the actual fact. R2 actor/session/
Assume/secret replay/public proof still needs its own precise freeze.

UX/UI工程师01a07b21-9a0d-7fd0-b090-7827ce18262e owns its independent
feat/cloud-console-ux branch. R1 design-start was sent; new Role API is not
yet runtime-ready. Use full UI source/assets/query/nav/style only at a
verified fixed object; no assets-only imports or peer WIP/environment use.
Phase3 01a04149-5dbb-7300-9e4c-31d9e85c8ada waits one final cumulative
Role/STS donor and retains its own PaaS/host/profile. Do not import peer
checkpoint, profile values or acceptance. Current editing window remains
this task's IAM/Audit R1; no shared release/schema admission broadening.

Go defaults GOMAXPROCS2/GOMEMLIMIT768MiB/-p2; real gates serial-p1 in own
uniquely labelled, limited fixtures. Before cleanup inspect exact live IDs
and ownership, never infer from this note. No other worktree/environment,
remote1.3/.160/.161, withdrawn GitLab/root1.5 work, remote or shared restart.
