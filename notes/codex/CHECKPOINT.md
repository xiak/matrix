# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git, exact CI and owning FEAT.

- Updated: 2026-09-15
- Repository: https://github.com/xiak/matrix.git
- Branch: `feat/iam`
- Latest pushed implementation: `d3a08bfa7c248793ffb51499186486efa2ebb377`.
  Pure policy compilation and corrected unpublished first Profile declarations.
  Exact Verification34925618255 is confirmed in_progress, not accepted yet.
  Both peers received the candidate; do not call the whole CAT-05 complete.
- Previous platform12 source `2bcbe50afaa025380c76c9cd232cd204d87b67a3`:
  Verification34923411012 exact SHA and go/authority-process/node-process all
  completed/success checked through GitHub API; both peers informed and001 records it.
- Source readiness remains IAM19/Audit13/PaaS1. Published installation profile
  deliberately unchanged; process gate compares real source readiness and rejects
  publication of the unmatched development combination. No new signed release.

## Goal and reading route

Whole IAM goal ACTIVE. Read AGENTS, owning FEAT, then owning code/tests.
001 owns product declarations/registration;005 language/compilation/versions/boundaries;
008 real PEP/service roles/ABAC;010 final console;011 HA/capacity and release acceptance.
Do not reduce the goal to current CRUD, pure compilation or passing default tests.

Next work: immutable registry/current selection, actual request/decision binding,
Profile-bound PolicyVersion publication/evaluation/history, then005 action patterns.
No online directory list/detail/publish/disable API exists or is frozen.
Create/Publish must only accept author document and existing concurrency/request IDs;
IAM selects trusted current heads inside the transaction. Tenant admins never
register products; normal platform management is not product-publishing authority.

## New pure compilation contract

Existing api/iam/v1/policy.go owns:
- CompilePolicyDocument(document, profiles) -> PolicyCompilation.
- CanonicalizePolicyCompilation(document, compilation, profiles) -> canonical/digest.
- DecodePolicyCompilation(reader, document, profiles) -> strictly validated content.

PolicyCompilation: compilationVersion="1", profiles:[exact product/revision/digest],
resolvedStatements:[unique sid + sorted precise actions]. Only used products appear;
SID sets exactly equal the author document. Entire canonical author document and
compilation use domain matrix.iam.policy-compilation.v1 plus NUL, no separate
statement digest/ordinal. Both sides share the old single grammar/canonical owner;
explicit frozen capability lookup cannot borrow current global capabilities.
Current v1 document bytes/digest and PolicyVersion HTTP/SQL are unchanged.
Only exact actions supported; pure synthetic product declarations never register
or grant authority. Typed/raw limits, immutable copies, strict fields and fuzz tested.
Original default selection, live attachments/boundaries, credential generations,
current revocation and old Audit proof remain in their existing owners.

Unpublished Profile drafts are replacement-first, not compatibility artifacts:
PaaS complete platform12 is unique revision1; Audit unique revision1 has all four
record.read/integrity.verify actions COLLECTION/COLLECTION_LIST, no result kind.
Do NOT preserve erroneous old PaaS r2 or Audit instance-verify drafts in registry.
Git retains them. Profiles have never been written to a runtime registry/decision
or a published consumer. Only after true registration does a changed declaration
require revision2 and permanent same-revision content equality.

## Frozen next wire / history boundary

Installation peer accepted:
- AuthorizationRequest: mandatory exact profile ref + resourceMode.
- COLLECTION: mandatory collectionUsage and Resource.ID exactly "collection".
- INSTANCE: no collectionUsage, actual resource ID; never infer mode from ID/name.
- Validate declared action/mode/usage/kind/scope/current authenticated caller.
  Caller purpose comes from current service credentials, not request selectors.
- Allow and Deny echo exact profile/mode/usage/resource; PEP checks every field.
  Include all fields in original requestDigest and immutable evidence.
- Archive registered canonical profiles and trusted current head separately.
  Migration role only; no USER/API/worker publishing. No mixed old/new service claim.
- Mark preexisting complete legacy DB decisions in protected migration metadata.
  Missing fields alone are NOT legacy eligibility. New HTTP/record functions reject
  old/partial shapes. Historical loader uses original marked row contract, never head.
- Audit records/chain old sentinels only legacy; new four Audit reads/verifications
  use COLLECTION_LIST/"collection", tenant/platform scopes and ServiceAudit unchanged.
  Old Event targets/bytes/chain semantics must not change.
- New PolicyVersion wire must explicitly include compilationVersion and full binding.
  Registry/SQL must independently check exact refs/minimal product set/SID/actions
  and content commitment. Evaluator uses current request Profile AND frozen policy
  Profile; conflicting same-action semantics fail the whole decision closed, never
  skip old Deny. ALLOW/DENY and cross-source Deny precedence ARE implemented here.
- No lookup_service, ServiceIdentity, seven-column claim or Audit canonical changes.
  New runtime wire/record ABI requires later source readiness coordination;
  do NOT modify CurrentDatabaseProfile or invent final release compatibility.

## Verification and resources

d3 local: full Go race/vet/modules, stable API generate and Linux amd64 all builds;
final compilation fuzz15s/2workers/1s minimization passed482263 executions.
Existing independent PG18.6 restricted fixture,1CPU/768MiB/PIDs128/maxconnections64:
policy storage124.45s (package127.374), independent dual IAM/Audit/PaaS/dispatchers
65.68s (package68.494). These validate current runtime after validator refactor,
NOT new compilation persistence, mode wire or Profile-bound policy enforcement.
001/005 own exact evidence. All current Action/ALLOW/DENY projection parity passed.
Initial internal fixture network lacked published loopback port; before gates it
was replaced with own normal network. No production fix or shared config change.
Both synthetic DBs and exact-labelled sole container/network/volume cleaned after
zero clients. No active local test session or own fixture remains.
Go GOMAXPROCS2/GOMEMLIMIT768MiB/-p2; heavy PG gates serial-p1. No overlapping heavy
build/fuzz/PG. Never touch other tasks, remote machines or shared service restarts.

## Peers and final integration

ALL UI belongs to UX/UI工程师:
thread01a07b21-9a0d-7fd0-b090-7827ce18262e, branch feat/cloud-console-ux,
fixed610fef1954be84be5b4bc16e4dd2d9f6e9ff209c. It keeps MOCK flows distinct
from live Profile/API. No UI change needed for this pure contract. Do not edit old
AccountAccessRenderer/styles/embed or import peer WIP. Give only fixed HTTP contracts.

Installation/Phase3 thread01a04149-5dbb-7300-9e4c-31d9e85c8ada coordinates
shared public changes/final release. Our existing IAM/PaaS/managedservice/Audit
HTTP client/PEP narrow window is open; peer has no WIP there. No host import.
Final donor be3c4a96b4381426c01cd6315eaa3713c2855982 includes exact platform12
PEPs and ca7f6940159e53fbae183b7b6d5f379705a0cba1 enrollment historical proof.
Final predecessor already owns full platform rights; role->policy first migration
must preserve complete allow/deny and revoked bindings, not require regrant.
Future newly introduced rights cannot auto-advance existing defaults.
Peer later combines final actual IAM/Audit with its PaaS5 and exact predecessor
be3 5/4/5+r11. Our PaaS1 profile, host fixture assumptions and FEAT acceptance
must not be copied into its release. Final be3 actual PEP/migration remains a gate.

User pre-v1 agreement: final converged schema is first supported baseline; no
repeated unpublished1..N upgrade matrix. Keep actual fresh/replay/current retained
data/restart/RLS/atomicity/revocation/Audit and explicit real predecessor evidence.
Role/STS, programmatic access, trusted IP/ABAC, service roles, governance, full UX,
HA/capacity and release gates remain outstanding. No extra agents or user tasks.

User briefly sent unrelated GitLab job50579 / root@172.30.1.5 compose request,
then explicitly withdrew it and said continue IAM. It was NOT accessed or changed.
