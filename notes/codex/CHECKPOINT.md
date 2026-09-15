# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, exact CI and owning FEAT.

- Updated2026-09-15. Repository https://github.com/xiak/matrix.git, branch feat/iam.
- Latest pushed implementation1dc1079c4e7bec80f5345d06929875b492ba9a86.
  Exact Verification34933760954 in_progress, not accepted yet. Both peers received
  this fixed candidate;001 owns local evidence. Checkpoints are never donors.
- Earlier eb1aea493b6131cec4c0e6bca90adbb111cc41cb/34927744424,
  fdb880345e4e46d296330f25f7072dbfef408c87/34928316097,
  d3a08bfa7c248793ffb51499186486efa2ebb377/34925618255 and
  2bcbe50afaa025380c76c9cd232cd204d87b67a3/34923411012 exact SHA/all3 CI success.
- Published installation CurrentDatabaseProfile deliberately unchanged. Actual
  source21/13/1 is independently compared; no release/host/UI acceptance implied.

## Goal and route

Whole IAM goal ACTIVE. Read AGENTS, one owning FEAT, then code/tests.
001 owns Profile registration/request/decision;005 policy compilation/publication/
evaluation/history;008 PEP/service-role/ABAC;010 UI;011 capacity/HA/final release.
No new agents/tasks. UI entirely UX/UI peer-owned; no UI/style/embed/browser or
other worktree/WIP reads. Withdrawn GitLab/root172.30.1.5 request never accessed.
Next confirm exact1dc CI, then freeze005 compiled PolicyVersion storage/history
boundary before implementation. CAT-05 and whole goal remain incomplete.

## Fixed1dc implementation

AuthorizationRequest requires exact Profile and explicit mode; collection also
requires LIST/CREATE usage and ID=collection; INSTANCE prohibits even null/empty
usage field, may have actual ID=collection. Allow/Deny bind every repeated field
including correlationId; PEPs verify. Unknown/stale/bad Profile is error, not Deny.
IAM account-create/directory capability ID now collection; details real ID. Audit
authorization target changes do not change event records/chain or canonical bytes.

authorization_decisions contract_version integer NOT NULL has NO default.
Exclusive atomic cutover marks only real complete old rows1, new records only2.
Legacy metadata NULL, original document/outbox unchanged; replay never backfills.
recorder7 iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb,integer):
arg3 input_authorization strict internal {request,decision}, arg7 explicit2.
Usecase passes actual request; adapter must never reconstruct it. SQL validates
all repeated bindings then stores only decision. Old6 removed, no overload.
RequestDigest still unique original encoder/domain separation, no SQL clone.
read_audit_evidence original4 outputs + fifth decision_contract_version integer;
no-decision IAM facts NULL. Historical1 uses closed recorded contract;2 exact
immutable archive and its CallingService, never current head/current catalog
caller fallback. Current producer credential required; payload/final ID still
belongs to the business source's own transaction/outbox proof.

Private assert_allowed_decision old6 replaced8, explicit mode/usage, no runtime
EXECUTE. Only contract2/current exact Profile/actor/action/resource/mode/usage/sameTx.
INSTANCE/LIST/CREATE same kind/id cannot cross-consume. Readiness/verify checks
ABI/metadata/ACL. ServiceIdentity/lookup_service/claim7/Audit canonical unchanged.
Registry remains fdb: immutable archive, explicit heads, shared head lock for
whole transaction, precise archive lookup without fallback.

## Evidence / resources

1dc local PG18.6 pinned4ef4dbc,1CPU/768MiB/PIDs128/maxconn64, Go2/768MiB,
heavy gates serial race-p1. Policy full141.764s; final binding/modes/history19.621s;
IAM HTTP90.795s; dual authority6.604s; Audit HTTP4.066s; independent dualIAM/Audit/
PaaS+dispatchers final82.358s. Real restricted runtime login, dual tenants/resources/
configuration/Operation/outbox/cursor/revocation/restart preserved. Synthetic host
facts are authority protocol fixtures, not actual host PEP acceptance.
Actual384d6d76b65498ed6b428ba9a2905ef67831b919 schema8 binary retained gate14.167s:
original decisions/policy evidence/outbox/defaults/session retained, marker1 and
new metadata NULL, original missing boundary_evidence separately checked NULL.
Missing/null reason or partial binding aborts whole migration, original schema/data
unchanged. Original business proof survives restart. No release upgrade permission.
All Go race/vet/modules, stable API generate, Linux amd64 build passed; final
modified owners additionally focused race/runtime checked. See001 for exact scope.
ALL own clients stopped; exact-labelled PG container/network/synthetic database
volume removed. No active own fixture/test. No remote/shared action. Next fixture
must use new unique names/labels/ports and limits, not old checkpoint resources.

## Next005 boundary / peers

Installation thread01a04149-5dbb-7300-9e4c-31d9e85c8ada waits final cumulative ABI,
does not consume WIP. NextPolicyVersion boundary NOT frozen: it requests protected
legacy marker only for real stored rows, no absent-field inference, recompile/
rewrite of old digest/document/default or silent attachment advance. Define exact
legacy action/resource/mode under current v2 without expanding old permissions.
Server chooses current heads and derives minimal refs/resolved statements in one
locked transaction; caller cannot submit compilation or select historical refs.
Current policy wire/SQL still author document/digest; pure compiler not yet used
in publication/evaluation. No product directory management HTTP API exists/frozen.
Pure APIs in api/iam/v1/policy.go: CompilePolicyDocument,
CanonicalizePolicyCompilation, DecodePolicyCompilation. compilationVersion1,
minimal refs/SID-bound sorted actions, max16profiles/128KiB. Single domain
matrix.iam.policy-compilation.v1 commits author canonical plus compilation.
No second grammar/digest or current fallback for frozen policy capabilities.

UX/UI thread01a07b21-9a0d-7fd0-b090-7827ce18262e, feat/cloud-console-ux,
fixed610fef1954be84be5b4bc16e4dd2d9f6e9ff209c received1dc capability change.
MOCK/live separate. No UI ownership here.
Final host donor be3c4a96b4381426c01cd6315eaa3713c2855982 includes full platform12
and ca7f694 enrollment history. Initial final role->policy parity must preserve
original allow/deny/revocations, not silently grant new rights. Peer PaaS5 and
predecessor5/4/5+r11 must not import our PaaS1/profile or acceptance state.
Pre-v1 converged schema is first supported baseline; no repeated unpublished1..N
matrix. Keep current replay/retained/restart/RLS/atomicity and explicitly required
real predecessor evidence. Role/STS/programmatic/service/ABAC/governance/full UX,
HA/capacity/final release remain outstanding.
