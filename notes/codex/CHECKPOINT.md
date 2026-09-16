# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, exact CI and owning FEAT.

- Updated 2026-09-16. Repository https://github.com/xiak/matrix.git,
  branch feat/iam; only this independent worktree is writable here.
- Latest pushed code: 1bcaa62bf6b11c20a7b34458408a221ed0aa633c.
  This is ONLY the Role trust content contract, not a Role runtime.
  Exact Verification35047801568 was confirmed live through GitHub API;
  last observation: go/authority-process running, node-process success.
  Recheck that same run; do not restart or call it successful from this note.
- Last independently accepted runtime rollback:
  40407e2710a45ee1000552146cd362740074369a /34959581661 all3 success.
  CAT-06 acceptance is owned by001. Prior family runtime f15cc983a69092528a66eb49b0509b760392187c
  /34955695756 all3 success is owned by005.
- Actual source remains IAM23/Audit13/PaaS1 and original published profile.
  No Role action/HTTP/SQL/subject or schema/release number was changed.

## Goal and next work

Whole IAM goal ACTIVE. Previous goal turns made concrete progress:
de395f2c8adb3e110031abe9eee18e7b8876fb48 fixed R1 detailed design and
handed a design-start notice to UX;1bcaa62b implemented/verified/pushed
strict trust content and corrected the private session ABI proposal using
actual owning SQL evidence. No blocker or repeated no-progress state.

Read AGENTS then006 and its owning code/tests.001 owns product declarations,
005 policy/conditions/delegation,006 Role/Trust/STS,008 service/ABAC,
010 peer UI,011 final HA/capacity/release. No subagents or extra tasks.
Next substantive slice is R1 management transactions/HTTP/PG/Audit, not more
research documents or a claim that pure contracts finish Role functionality.
Preserve RoleSession/AssumeRole and actual business enforcement as required R2.
005 IP conditions/safe delegation,007 credentials,008 integration,009 governance,
010 full UI,011 HA/capacity/release and012 declared external deferrals remain.

## Implemented trust contract only

api/iam/v1/role.go owns TrustPolicyDocument, RoleTrustVersion and the sole
CanonicalizeTrustPolicyDocument(document)(canonical,contentDigest,error).
Pure strict JSON, exact USER ID syntax, explicit empty [] vs nil,8statements,
32principals/statement,256visits,16KiB, duplicate SID/principal refusal,
domain-separated matrix.iam.role-trust.v1, copied sorting/no input mutation.
Version wire includes id/accountId/roleId/document/digest/createdAt.
Syntax and digest do not prove real USER/account ownership, current selection
or permission. No prefix-derived identity or identity-policy DSL aliases.

Existing contract_test/schema_validation_test/generator own gates. Full
go test -race -p2 -count1 ./..., vet-p2, module verify, API generation byte
stability and Linuxamd64 CGO0 build passed, Go2/768MiB. No local PG/process/
browser fixture launched for this pure-data slice; default opt-in skips are
not new runtime evidence. Earlier whitespace test was corrected to enforce
the complete reader budget, not assume encoding/json passes outer whitespace
to UnmarshalJSON. Current Git is coherent/committed; no leftover failing gate.

## R1 window and corrected private ABI

Phase3 explicitly confirmed IAM24/Audit14 development window, IAM Profile r2
with original r1 bytes/digest preserved. No release revision allocation.
No PaaS/host/node/ServiceIdentity/lookup_service/installation edits. Public
R2 role actor, source session lineage, Assume/secret replay/proof need a later
separate exact proposal; service installation verifier exception stays closed.

Read actual owning files, not guessed paths:
- api/iam/v1/enums.go is current product/action source; there is no catalog.go.
- API Group models live in types.go/validation.go, no separate group.go.
- authority lives at app/service/iam/internal/authority, no domain/authority.
- migrations/source.go and000001_authority/000006_policy_authority/
  000009_groups own transaction/registry/attachments/groups.
- usecase/identityaccess/audit_producer.go owns historical admission.
- test/architecture/dependencies_test.go owns architecture.

Actual authorization_decisions/recorder7 contain no SessionID.
assert_allowed_decision binds current-transaction decision/actor/resource/
profile, NOT the bearer session. UserBoundary already carries actor_session_id
privately and locks principal then credentials/session generation.

Consumer approved last private actor_session_id text for all new Role writes:
create_role/set_role_trust_policy9,update_role/set_role_status8,delete_role7
as designs; final exact typed arguments/JSON/ACL/proconfig must accompany code.
Read4/5 unchanged. Explicit replacement of existing attachment entrypoints:
create_policy_attachment(text,text,text,text,text,bigint,text,text,jsonb,text)
returnsjsonb;revoke_policy_attachment(text,text,bigint,text,text,jsonb,text)
retains(resource_version bigint,revoked_at timestamptz,applied boolean).
Remove old9/6 overloads in the same IAM24 transaction, no default/alias.
Current source still has old9/6; do not claim this ABI already implemented.

Only actual authenticated bearer supplies that parameter. Never add it to
northbound requests/AuthorizationRequest/decision/digest/outbox/history.
Lock actor+USER targets in stable ID order as real UserBoundary does, then
verify exact session/account/user/status/expiry/credential generation and
non-forced-change; NULL/foreign/stale/revoked fails. Role Root guard is EXTRA
to PDP and ONLY the ROLE branch; preserve USER/GROUP/platform user semantics.
Do not use retries to excuse inverted locks. Check recovery/grant/revoke order.
Old SYSTEM defaults must not auto-acquire new actions. Retained Root must
explicitly publish/attach a new TENANT policy using still-accessible policy
management, with pre-attachment Role denial proven.

R1 new tenant IAM/real USER/decision facts are role.created/updated/disabled/
enabled/trust-set/deleted. Actual names are in006. No new SYSTEM or ROLE actor,
no broad target.tenantId. Attachment facts keep exact closed original-action
mapping. SourceIAM proof must still compare exact committed outbox; no later
user reauthorization. recorder7/evidence5/claim7/Audit canonical remain unchanged.

## Peers and retained evidence

UX/UI工程师:01a07b21-9a0d-7fd0-b090-7827ce18262e,feat/cloud-console-ux.
User wants proactive design/development-ready notifications; sent de395f design,
40407e CAT06 runtime and1bcaa62 pure-contract/CI-pending distinction.
Latest fixed UI candidate7e01a4176764ffff2fc9b81db8f059e334ac9c76,
337641b9 only evidence/checkpoint. Peer reports own447.178s real f15 backend+
complete UI binary browser boundaryA->B->remove, member identity/ordinary
admin readonly, retained PaaSDeveloper,360/1280/nav/deep links/Audit checks;
front528+3 tests/228contrast/213embeds and full Go race passed. Not yet
integrated/accepted here; no CI result supplied for that UI SHA.
Keep the FULL peer source/all:assets/query/nav/styles, never copy onlyassets
or overwrite with this branch's old renderer. Peer4317 MOCK stays untouched.
Policy author/version and CAT06 live wiring still peer-owned unfinished work.
No UI coding here, no peer fixture/WIP reads or restarts.

Phase3:01a04149-5dbb-7300-9e4c-31d9e85c8ada waits ONE final cumulative
IAM/Role/STS donor, retains PaaS5/host/predecessor5/4/5+r11. Final fixed host
donor be3c4a96b4381426c01cd6315eaa3713c2855982 includesplatform12+ca7.
Do not import peer checkpoint/acceptance or our23/13/1 profile into that branch.
Its explicit private SessionID ABI response is incorporated in committed006.

CAT06 unchanged: GET/v1/authorization-profiles,no selectors/body/cursor,
current USER Account + iam.policy.list PDP/boundary, full registry/source
locked match, entire profile+digest,1..16/64KiB. INSTALLATION/PROBE metadata
is not CUSTOMER permission. No writes/permit/cache fallback;503onuncertainty.
Evidence and family frozen compilation/history/old1dc gates stay001/005.

## Environment boundaries

No own container or test process currently running; CAT06 exact-labelled
PG/network cleaned, synthetic named volume retained. Earlier stopped-container/
unused-network bulk cleanup already done. Do not repeat cleanup as progress.
Go default GOMAXPROCS2/GOMEMLIMIT768MiB/-p2; real PG/race heavy gates serial-p1.
No other worktree WIP, withdrawn GitLab/root1.5 task, remote1.3/.160/.161,
remote reboot, shared engine/service restart or peer UI resource changes.
Ignored earlier CPU/EXE build artifacts are harmless; prior deletion policy
denied execution, do not try an alternate-tool deletion workaround.
