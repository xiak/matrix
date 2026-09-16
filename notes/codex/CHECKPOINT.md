# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, exact CI and owning FEAT.

- Updated 2026-09-16. Repository https://github.com/xiak/matrix.git,
  branch feat/iam; only this independent worktree is writable here.
- Latest pushed code: 89cd60c9bd64ddf0fccb10b5b8df64309f5e118c.
  Policy attachment writes now carry/check the actual bearer session privately.
  Local real gates passed. Exact Verification35051957349 was confirmed live
  through GitHub API: go/authority-process/node-process all in_progress.
  Recheck that same run; do not restart or infer success from this note.
- Pure trust contract 1bcaa62bf6b11c20a7b34458408a221ed0aa633c /
  Verification35047801568 is independently confirmed all3 success.
  Last earlier accepted runtime40407e2710a45ee1000552146cd362740074369a /
  34959581661 all3 success; CAT06 evidence is owned by001.
- Actual source IAM24/Audit13/PaaS1; original published profile unchanged.
  Audit14 is approved for actual R1 Role facts, not implemented yet.
  No Role action/HTTP/SQL/subject or Role credential currently exists.

## Goal and next work

Whole IAM goal ACTIVE. This turn delivered the necessary session-bound
attachment transaction prerequisite, not Role/STS completion. No blocker or
repeated no-progress state. Read AGENTS then006 and its owning code/tests.
Next substantive slice is R1 Role management transactions/HTTP/PG/Audit;
preserve real RoleSession/AssumeRole and business enforcement as required R2.
Do not keep producing standalone research or call pure contracts a runtime.
001 owns product declarations,005 policy/conditions/delegation,006 Role/Trust/
STS,008 service/ABAC,010 peer UI,011 final HA/capacity/release. Remaining work
and acceptance live in their FEATs, including012 external deferrals.
No subagents or extra tasks. UI belongs to the UX/UI engineer.

## Fixed session prerequisite

Existing identityaccess Repository/Transaction remains the storage boundary.
PolicyAttachmentMutation/RevocationMutation carry ActorSessionID exclusively
from authenticated subject.Subject.Session.ID, never caller input or another
active session. No SessionStore/Redis dependency was requested or introduced.
Last ordinary user question about replaceable memory/Redis Session storage
has already been answered: preserve atomic current identity/revocation/Audit
semantics, PostgreSQL authoritative, no interface-only seamless substitution.

IAM24 removes old create9/revoke6 overloads and exposes only:
- create_policy_attachment(text,text,text,text,text,bigint,text,text,jsonb,text)
  -> jsonb;
- revoke_policy_attachment(text,text,bigint,text,text,jsonb,text)
  -> (resource_version bigint,revoked_at timestamptz,applied boolean).

Last arg actor_session_id has no default/alias. Account ACTIVE lock, sorted
actor/USER-target principal locks, then exact current session/credential
generation check. Expiry uses clock_timestamp after principal locks.
NULL/foreign/unknown/revoked/expired/stale sessions fail; forced user fails.
Existing USER/GROUP/platform semantics and root protection remain.
Private policy_attachment_contract_ready() is shared by readiness and verify;
it checks exact input/output, ACL/owner/SECURITY DEFINER, proconfig and behavior
metadata. It is not exposed to runtime roles. recorder7/evidence5/claim7,
ServiceIdentity/lookup_service and CanonicalizeEvent remain unchanged.

## Real evidence and test ownership

Existing http_postgres_test.go owns TestIAMPolicyAttachmentSessionPostgres,
opt-in MATRIX_IAM_ATTACHMENT_SESSION_POSTGRES_TEST_DSN and own
matrix_iam_attachment_ database; CI adds it to the existing authority job.
Its two-minute budget and original policy fixture four-minute budget remain.
Separate databases avoid polluting policy-directory/101-member fixtures;
no hash-cost, size, retry or timeout relaxation. Test uses real PostgreSQL
and PDP; only the private-reference negative probe substitutes a SessionID.

Own PG18.6 fixture1CPU/768MiB/Pids128/64connections, Go2/768MiB/race-p1:

- original policy plus new session gates301.225s;
- IAM HTTP/local credential recovery141.053s;
- Audit dual schema11.384s, Audit HTTP3.448s;
- independent IAM/Audit/PaaS processes77.478s, actual restricted logins and
  retained two-account resource/Operation/outbox/historical-proof checks.

Session gate includes48 controlled security-change-first interleavings,
18 exact private reference cases,4 public selector attacks, old ABI refusal,
metadata drift, twice migration and equal-bootstrap receipt/state replay.
Synthetic expired/stale/NULL rows are NOT old executable provenance.
Original implementation already rejected two logout races via SERIALIZABLE;
do not claim a reproduced exploit. Role-specific recovery/writes-first races
remain006 work; default opt-in skips are not runtime evidence.
Full race-p2/vet-p2, module verification, API generation byte stability and
Linuxamd64 CGO0 build passed. The final command's lost observation was recovered
from its original session88027, exit0; no duplicate full regression was run.

## R1 boundaries

Phase3 approved IAM24/Audit14 development window and IAM Profile r2 appended
without rewriting r1/default digests. No release revision allocation.
Use api/iam/v1/enums.go product owner (no catalog.go), role.go trust owner,
identityaccess/types.go repository/transaction (no ports.go), authority pure
rules, migrations/source.go plus existing authority/policy/groups owners,
and test/architecture/dependencies_test.go. Fixed404 source adoption is in
the original FEAT006 adoption. No legacy build/runtime dependency.

Planned Role writes end in private actor_session_id: create/trust9,
update/status8,delete7; read4/5. Implement exact typed shape and gates.
Root check is EXTRA to current PDP and only on ROLE writes; preserve current
USER/GROUP/platform attachment semantics. No decision/session-lineage fiction.
Original Root must explicitly publish/attach new TENANT policy for new actions;
schema/bootstrap replay cannot enlarge retained SYSTEM defaults or revive grants.
R1 facts are tenant IAM/realUSER/decision role.created/updated/disabled/enabled/
trust-set/deleted with realROLE target. No SYSTEM/ROLE actor or target.tenantId
expansion. Create parent decision does not prove final payload; committed IAM
outbox proves the fact. Old canonical/history/claim remain unchanged.
R2 public actor/source-session/Assume/secret replay/proof needs separate exact
freeze. Service installation verifier exception cannot become role admission.

## Peers and resource boundaries

UX/UI工程师01a07b21-9a0d-7fd0-b090-7827ce18262e,feat/cloud-console-ux.
Already received R1 design-start, CAT06 runtime and pure trust distinction;
new Role API is NOT development-ready yet. Latest known fixed UI candidate
7e01a4176764ffff2fc9b81db8f059e334ac9c76 (337641b9 docs only) reports own
447.178s real f15 backend browser gate; not integrated/accepted here.
Consume FULL peer source/assets/query/nav/styles at verified fixed objects,
never assets-only or this branch's old renderer. Peer4317 MOCK untouched.

Phase3 01a04149-5dbb-7300-9e4c-31d9e85c8ada waits ONE final cumulative
IAM/Role/STS donor and preserves its PaaS5/host/profile5/4/5+r11.
Known fixed host donorbe3c4a96b4381426c01cd6315eaa3713c2855982.
No peer WIP, checkpoint/acceptance/profile import or cross-environment use.

This turn's labelled PG container, empty network and synthetic data volume
were removed after all local gates and zero remaining client connections.
No own UI or test process remains. Earlier unrelated retained artifacts are
not a cleanup task; do not repeat bulk cleanup as progress. Go default2/
768MiB/-p2; real heavy gates serial-p1. No withdrawn GitLab/root1.5 work,
remote1.3/.160/.161, remote reboot or shared engine/service restart.
