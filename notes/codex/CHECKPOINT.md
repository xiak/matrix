# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, exact CI and owning FEAT.

- Updated: 2026-09-15. Repository https://github.com/xiak/matrix.git, branch `feat/iam`.
- Latest pushed implementation: `fdb880345e4e46d296330f25f7072dbfef408c87`.
  Registry lookup security verification follow-up, same IAM20/Audit13/PaaS1.
  Exact Verification34928316097 is in_progress, not accepted yet. Installation
  peer received the fixed candidate and evidence; do not call CAT-05 complete.
- Registry implementation `eb1aea493b6131cec4c0e6bca90adbb111cc41cb`:
  Verification34927744424 exact SHA and all3 jobs completed/success independently
  checked and recorded in001; installation peer informed. Checkpoints not donors.
- Previous pure compilation `d3a08bfa7c248793ffb51499186486efa2ebb377`:
  Verification34925618255 exact SHA and go/authority-process/node-process all
  completed/success independently checked; both peers informed,005 records it.
  Full platform12 source `2bcbe50afaa025380c76c9cd232cd204d87b67a3` /
  Verification34923411012 all3 success is recorded in001.
- Published installation CurrentDatabaseProfile deliberately unchanged. Actual
  source readiness20/13/1 is independently compared; unpublished combination
  still rejected before installation effects. No signed release or UI changes.

## Goal and reading route

Whole IAM goal ACTIVE. Read AGENTS, owning FEAT, then code/tests.
001 owns product declarations/registration;005 language/compilation/versions/boundaries;
008 actual PEP/service roles/ABAC;010 console;011 HA/capacity and release acceptance.
No extra agents/tasks. All UI remains peer-owned. Do not reduce the goal to CRUD.

Next: mandatory Profile/resource-mode request and decision binding with protected
legacy-row admission, then compiled PolicyVersion publication/evaluation/history.
005 action patterns must use frozen product capabilities, not runtime wildcards.
No product directory list/detail/publish/disable HTTP API exists or is frozen.

## Current registry implementation

Existing IAM authority SQL/Go owners only:
- authorization_profiles archive PK(product,revision), immutable canonical/digest/
  created_at. authorization_profile_heads explicit product/revision/adopted_at FK.
- Source() uses unique api/iam encoder to inject separate archive and head seeds.
  Same tuple exact replay changes no time/content; variant or downgrade rolls back
  whole migration. Future releases must include required history declarations.
  Current first registration has only complete r1 declarations, no rejected drafts.
- API role only EXECUTE current_authorization_profiles() and exact
  lookup_authorization_profile(text,bigint,text), both four output columns:
  product text, revision bigint, canonical_document text, content_digest text.
  API/worker/recovery have no direct table rights; worker/recovery no lookup grants.
  No online publishing authority or generic mutation capability.
- Current function holds shared head row locks until the surrounding transaction
  ends. PostgreSQL adapter compares complete source current set and canonical
  bytes/digests, not all archives. Same-transaction cache only, never a permit cache.
- CheckCurrentAuthorizationProfiles guards actual current decisions, management,
  CurrentIdentity/capabilities, RecordAuthorization adapter and HTTP readiness.
  Current mismatch returns existing503/ErrUnavailable without a half decision.
- LookupAuthorizationProfile requires exact triple and decodes/recanonicalizes
  registered bytes; no current fallback. Noncurrent archive is not current drift.
  Historical producer/evidence, login and self-logout do not reauthorize by head.
- SQL check independently checks digest, bounded content and closed outer identity;
  it does not implement a second JSON canonicalizer or full nested Profile grammar.
  Trusted source registration plus exact runtime comparison owns that boundary.
- fdb verify parses proconfig key and PostgreSQL identifiers semantically: unique
  search_path must be pg_catalog,pg_temp in that order. Equal whitespace works;
  unsafe/reversed/one quoted namespace fails. ACL permits only owner/API explicit
  EXECUTE and no API GRANT OPTION, any extra grantee fails. Business tables in
  both SECURITY DEFINER functions are explicitly iam-qualified. No separate IAM
  verifier DB role exists; HTTP verifier gains no lookup endpoint/DB capability.
- Existing recorder still lacks Profile/mode wire. The current adapter check is
  NOT the future independently persisted Profile-bound decision proof.

## Frozen next wire/history boundary

- AuthorizationRequest requires exact profile reference and resourceMode.
  COLLECTION requires collectionUsage and resource.id exactly "collection";
  INSTANCE prohibits usage and uses actual ID, even if that ID is "collection".
- Validate declared action/mode/usage/kind/scope/current authenticated service.
  Caller purpose comes from valid service credentials, not request selectors.
- Allow/Deny echo full profile/mode/usage/resource; PEP verifies every field.
  Include them in original requestDigest and immutable recorded evidence.
- Protect migration markers for preexisting complete legacy decision rows.
  Missing new fields alone is NOT legacy eligibility. No caller old/partial
  shapes, no legacy marker invented from a newly submitted missing field.
  Preserve original JSON/outbox/canonical bytes. Historical loader uses row's
  original marked contract, never current head.
- Audit four record.read/integrity.verify actions are COLLECTION/COLLECTION_LIST,
  AUDIT_RECORD/AUDIT_CHAIN, tenant/platform scopes, AUDIT caller, no result kind.
  Old records/chain sentinels only in protected historical loader, not new wire.
- New PolicyVersion wire explicitly carries compilationVersion/full profiles/
  resolvedStatements. Publication only accepts author document+existing IDs;
  IAM chooses trusted current heads transactionally, never caller compilation.
  SQL must independently check exact refs/minimal products/SID/actions/digest.
  Evaluate current request Profile AND frozen policy Profiles; conflicting meaning
  fails entire request closed, never skip an old Deny. ALLOW/DENY/cross-source
  Deny priority ARE already implemented.
- ServiceIdentity, lookup_service, seven-column claim and Audit canonical unchanged.
  Coordinate next source schema/ABI; do not modify published release profile.

## Pure compiler already fixed

api/iam/v1/policy.go owns CompilePolicyDocument, CanonicalizePolicyCompilation,
DecodePolicyCompilation. PolicyCompilation has compilationVersion="1",
profiles:[exact triples], resolvedStatements:[unique sid+sorted exact actions].
Minimal product set, exact SID correspondence, max16 profiles/128KiB content.
Domain matrix.iam.policy-compilation.v1 plus NUL commits entire canonical author
document and compiled content. No second statement digest/ordinal/grammar.
Explicit frozen capability lookup cannot borrow current global capabilities.
Current PolicyVersion HTTP/SQL still old document/digest. Exact actions only;
synthetic declarations in pure compiler neither register nor authorize products.

## Verification and resources

eb1 local limits: GOMAXPROCS2/GOMEMLIMIT768MiB, heavy real gates serial race-p1.
PG18.6 pinned4ef4dbc image,1CPU/768MiB/PIDs128/maxconnections64:
- Full policy storage package87.963s, including existing live policy/group/
  boundary/credential races and retained current schema/bootstrap behavior.
- Final focused registry package8.365s(parent5.56s): actual same-tuple valid
  variant collision rolls back all authority state; immutable/replay timestamps;
  role denials, absent archive FK/wrong digest, exact lookups, noncurrent archive;
  competing head advance lock timeout, source drift HTTP503/no current decision,
  original bootstrap producer digest/outbox bytes, logout and downgrade rejection.
- IAM HTTP72.82s(package75.642), dual authority3.09s(package5.606).
- Independent dual IAM/Audit/PaaS/dispatchers46.33s(package49.196), actual restricted
  runtime login, two-tenant resources/config/Operation/outbox, revocation/restart.
  Synthetic host protocol facts are not actual host implementation acceptance.
- Full Go race/vet/modules, stable API generate, Linux amd64 all build passed.
fdb final focused PG18 registry gate package8.732s(parent5.88s), IAM/architecture
race, IAM vet/Linux build passed. Actual transactions exercise safe equivalent
settings, bad function config/ACL drift and rollback; restricted raw exact lookup
returns original archive bytes. Its separate fixture and four synthetic DBs were
also removed by exact IDs/labels after zero clients. No new schema/runtime wire.
No active tests/own fixture remain. Exact labelled container/network/volume with
nine synthetic databases removed after zero clients. No shared/remote action.
Use new unique names/labels, CPU/memory/concurrency limits next time; never prune.
Prior fixture normal network used loopback publishing; --internal did not work.

## Peers/final integration

UX/UI工程师 thread01a07b21-9a0d-7fd0-b090-7827ce18262e,
branch feat/cloud-console-ux, fixed610fef1954be84be5b4bc16e4dd2d9f6e9ff209c.
MOCK distinct from live; no UI changes needed for registry. Never edit UI/styles/
embed/browser or read peer WIP. Give fixed actual HTTP contracts when available.

Installation/Phase3 thread01a04149-5dbb-7300-9e4c-31d9e85c8ada keeps host/release
unchanged until final ABI. Our narrow existing IAM/PaaS/managedservice/Audit HTTP/
PEP window is open. No host import. Final donor
be3c4a96b4381426c01cd6315eaa3713c2855982 includes full platform12 and
ca7f6940159e53fbae183b7b6d5f379705a0cba1 enrollment historical proof.
Initial final be3 role->policy migration must preserve full existing allow/deny
and revoked bindings, not regrant. Truly new future rights cannot auto-advance
old SYSTEM defaults. Peer finally combines real IAM/Audit with its PaaS5,
predecessor be3 5/4/5+r11. Never import our PaaS1/source profile/acceptance into it.

User pre-v1 agreement: converged schema is first supported baseline, no repeated
unpublished1..N upgrade matrix. Keep fresh/replay/current retained/restart/RLS/
atomicity/revocation/Audit and explicitly supported real predecessor evidence.
Role/STS, programmatic access, trusted IP/ABAC, service roles, governance, full UX,
HA/capacity/final release still outstanding.

Withdrawn GitLab job50579/root@172.30.1.5 compose request was NOT accessed.
