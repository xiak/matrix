# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git, exact CI and owning FEAT.

- Updated: 2026-09-15
- Repository: https://github.com/xiak/matrix.git
- Branch: `feat/iam`
- Latest pushed backend: `2bcbe50afaa025380c76c9cd232cd204d87b67a3`.
  Complete twelve PaaS platform actions/NODE_ENROLLMENT, PaaS Profile revision2,
  explicit complete SYSTEM PlatformOperator content version, three target lifecycle
  Audit facts and enrolled-target historical authority. Exact CI34923411012 is
  in_progress, not independently accepted yet. Both peers received the candidate.
- Previous verified source-catalog slice:
  `8afc1f94c47671c9b4d01081099572ed6183953b`.
  Exact CI34921642856 head SHA and go/authority-process/node-process all
  completed/success independently checked through GitHub API; both peers informed.
  Pure Profile predecessor c6bd0788/34920036532 also passed; its shape-local result
  field was replaced by action-local result, without alias.
- Current source readiness IAM19/Audit13/PaaS1. The existing published installation
  profile is deliberately unchanged. The process owner verifies actual source
  readiness AND rejects publication of this unmatched development combination.
  No new signed release or cross-profile upgrade is accepted.

## Resume and full objective

Whole IAM goal remains active. Read AGENTS.md, the owning IAM FEAT, then code/tests.
001 owns product declarations and registration;005 owns language/versions/boundaries;
008 owns real PEP/service roles/ABAC;010 owns console;011 owns HA/capacity,
first-release and complete acceptance. Do not reduce the goal to current policy CRUD.

Next backend work is CAT-05 actual request/decision Profile binding, immutable
historical registration and exact policy-version references, then005 action-pattern
expansion at publication. Current source declarations/getters/canonical references
do NOT implement those runtime contracts. No request/result/storage surface for
that next slice is frozen: align with installation peer before public edits.
No online catalog list/detail/version/publish/disable APIs are implemented or frozen.
Tenant admins consume published actions, not product registration authority.
Product teams own their declared vocabulary and PEP; IAM validates controlled
publication. Product registration never grants access to customer resources;
service-role consent is a separate008 contract.

Current Profile owner: api/iam/v1/authorization_profile.go plus enums.go.
One immutable source declaration per product; current action definitions, caller,
scope, resource/prefix and conditions are projections, not another editable map.
Strict bounded decoding/canonicalization/reference and nested defensive copies.
INSTANCE and COLLECTION with COLLECTION_LIST/COLLECTION_CREATE; action-level
resultResourceKind separates successful child/new facts from authorized parents.
Only existing tenant instance application-read has prefix support. IAM-owned
time/identity condition sources remain closed; no caller attribute map.
Current PaaS revision2 changes its digest; revision1 must not mean new contents.
No generic evaluator/UI branch by product name. Pure syntax/digest is not trust.

## Full platform slice and evidence

2bcbe50 selectively ADAPTed final fixed
be3c4a96b4381426c01cd6315eaa3713c2855982 and its contained
ca7f6940159e53fbae183b7b6d5f379705a0cba1 proof. No host runtime imported.
001 owns the exact twelve-action table and acceptance; adoption owns decisions.
pool.create/target.register use actual INSTANCE ID; their reads also support
COLLECTION_LIST. Enrollment create authorizes NODE_ENROLLMENT collection and
its successful fact is EXECUTION_TARGET; other enrollment commands exact INSTANCE.
Direct target proof retains exact ID. Collection proof binds historical authority,
not actual result payload/ID; PaaS transaction/outbox owns that relation. It cannot
authorize drain/activate/remove. New target facts use installation scope.
ServiceIdentity/lookup_service/claim7/old Audit canonical are unchanged.

Supported final predecessor be3 already has complete platform authority. Initial
Role-to-SYSTEM-policy migration must preserve full allow/deny and each revoked
binding, selecting the complete parity default; fresh final installation likewise.
Do not require regrant of existing be3 rights. Old five-action unpublished CAM
development data has no release compatibility obligation. After final release,
genuinely new rights require explicit version adoption, not seed/default auto-growth.
Installation owner will freeze final actual IAM/Audit plus PaaS5 and exact
be3 predecessor after001-010; do not import its profile into this PaaS1 branch.

Local gates on2bc: full Go race/vet/modules, stable generation, Linux amd64 all
builds passed. Own PG18.6 1CPU/768MiB/PIDs128,64connections; serial race-p1:
IAM HTTP101.14s, double-authority3.52s, independent processes51.26s,
policy storage110.85s. Includes actual restricted runtime logins, all12 IAM
allow/deny/attachment revocation/dual IAM/restart, original and new platform facts
replay after revocation/Audit restart, current policy/RLS/conditions/credentials/
boundary/group/outbox regressions. Synthetic platform facts prove authority wire,
not real host Operation/PEP or final be3 release migration.
Initial process fixture reused OperationID and correctly hit records_paas_operation_uq;
only fixture IDs changed, then a new DB passed. No production retry/constraint
relaxation.001 has detailed evidence and exact package timings.
All five disposable databases, sole PG container/network/volume cleaned after
zero clients and exact ID/label verification. No active own test session remains.

## UI ownership and coordination

User assigns ALL UI to existing UX/UI工程师, thread
01a07b21-9a0d-7fd0-b090-7827ce18262e, own branch feat/cloud-console-ux,
last confirmed fixed7a126d314496d71d2f64804d78bd4290754c839c.
It has advanced MOCK Policy Wizard/boundary/users/groups/roles, not proof of
live backend authorization. It will ADAPT fixed contracts into its own components,
not our old AccountAccessRenderer/styles/embed. Do not resume UI/browser work.
Peer knows product catalog is read-only tenant consumption; no fictional online
registration capability. Public query surface must freeze before live adapter.
Last old UI handoff cc5e38822d3c3856306e0eafbbc4f377ad2c8346 CI34918584314
all3success;010 owns its actual browser evidence, not final new UX acceptance.

Installation/Phase3 thread01a04149-5dbb-7300-9e4c-31d9e85c8ada coordinates
shared IAM/Audit contracts and final release. It confirmed IAM19/Audit13 source
readiness window, no CurrentDatabaseProfile edits, and be3 parity rule.
Exchange only verified fixed patches, no WIP/host acceptance/checkpoint imports.
No extra agents/tasks. Never write to another worktree or touch remote/shared
machines, services, ports, Docker config or other tasks' resources.

## Remaining boundaries

Current User-boundary implementation119f232ea7cf7ba7d91a1ef6433e132e0127f03f
passed CI34849128040. ef51b1d/34850453837 strict identity and6292fa09/34853775664
conservative capabilities passed.005/010 own those contracts/evidence.
User boundary grants nothing, intersects ordinary direct/group permissions,
keeps platform/probe separate, rechecks current session under owner locks and
preserves historical proof. Root-only high-risk management is intermediate,
not complete safe delegation. lookup_session23 columns; record_authorization
six arguments with separate boundary evidence; no fallback overload.
Current source19 changes catalog/readiness, not these function shapes.

Action wildcards/frozen expansion, trusted IP, Role/STS, programmatic credentials,
service-role/ABAC, governance, final UX, HA/capacity and complete release acceptance
remain outstanding with explicit external-integration deferrals in their FEATs.
User pre-v1 schema agreement: final converged schema is the first supported
release baseline; no repeated unpublished1..N upgrade matrix. Current fresh,
replay, retained state, atomicity, RLS, revocation and Audit gates remain required.
Real predecessor/consumer compatibility needs explicit evidence, never number
equality or a schema reset. Go GOMAXPROCS2/GOMEMLIMIT768MiB/-p2; heavy PG gates
serial-p1, uniquely labelled fixtures and explicit limits.
