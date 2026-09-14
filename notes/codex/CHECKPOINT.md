# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git, exact CI and owning FEAT.

- Updated: 2026-09-14
- Repository: https://github.com/xiak/matrix.git
- Branch: `feat/iam`
- Latest pushed implementation: `ef51b1d509e7e38dfb2146416c7e057a97638765`,
  strict CurrentIdentity boundary client and separate permission-limit display.
  [Verification34850453837](https://github.com/xiak/matrix/actions/runs/34850453837)
  is confirmed live/in_progress, not yet accepted.
- Backend rollback point: `119f232ea7cf7ba7d91a1ef6433e132e0127f03f`,
  User permission-boundary intersection and historical evidence.
  [Verification34849128040](https://github.com/xiak/matrix/actions/runs/34849128040):
  exact SHA and Go/authority-process/node-process all completed/success,
  independently checked through GitHub API. Both existing peers were informed.
- Earlier verified rollback: `b342e9da08515f9172b29d1ac237a088171c9e53`
  /34839955131. Earlier candidate failures remain in IAM/005, not an all-green history.

## Resume and full objective

Whole IAM goal remains active. Read AGENTS.md, the owning IAM FEAT, then code/tests.
005 owns language/boundaries;010 owns console;001/008 own product/profile;
011 owns first-release, real runtime, HA/capacity and final acceptance.

Next complete User boundary management UI and conservative resource capabilities,
then actual backend/browser acceptance. ef51 only repairs mandatory current
identity parsing and displays self boundary; no set/replace/remove forms or policy
editor. Do not infer eligibility from identityKind or policy name. Root-only
backend management is an intermediate boundary, not completed safe delegation.
Remaining action wildcards with fixed catalog expansion, trusted IP, Role/STS,
programmatic credentials, extensible product/service-role/ABAC, governance,
complete UI, HA/capacity/final release and explicit external-integration deferrals
remain in their FEATs. Do not reduce completion to policy CRUD or User boundaries.

User schema agreement is in011: final converged schema is first supported release
baseline. No per-FEAT schema1..N unpublished upgrade matrix. Current fresh/replay/
retained state/atomicity/RLS/revocation/Audit gates remain; real old consumers need
explicit support evidence. No number reset or install-profile admission relaxation.

## Fixed implementation and evidence

119 source IAM18/Audit12/PaaS1; installation profile unchanged.
lookup_session appends boundary jsonb after policies (23output columns);
record_authorization exactly six parameters with independent evidence, no old
overload/fallback. Boundary mutation has ten private parameters including current
bearer-derived session. ServiceIdentity/lookup_service/claim7/canonical unchanged.
005 owns exact API, lock/replay/default-following semantics and evidence.

One current TENANT boundary intersects ordinary direct/all-group authorization,
grants nothing, fails closed on malformed/missing snapshots; root cannot be bound.
Platform/probe/service authority is distinct. Root-only writes recheck credentials/
session under principal-first locks; no implicit enable/credential/platform effect.
References block Policy deletion; deleted User relations end but retain history.
set-before-default may both succeed; reverse order rejects stale policy revision.
Historical proof survives later default/removal/disable; producer must remain valid.

Final serial PG18: IAM172.824s, Audit data5.412s, AuditHTTP2.650s,
dualIAM/PaaS/Audit45.400s, PaaSdata4.310s. Multi-group/Deny, two actual apps,
cross-account/scope, revision/default/delete competition, logout lock barrier,
forced password, cursor and dispatchers/chains passed. Current data replay and
restricted runtime identities retained. Full Go race/vet/modules/generation/
Linuxbuild and exact backendCI passed. Detailed evidence belongs to005.

ef51 requires explicit boundary account/user/RV and null or strict version
reference. Missing/foreign/stale/root-bound responses reject, never become NONE.
Boundary stays separate from policySources and does not reveal a policy body.
Current display updates on refresh, clears on error, grants no UI capabilities.
103 frontend tests/type/lint/architecture/20contrast checks passed; two2-worker
static builds match59 embedded files. UI/architecture Go race, UI vet/Linuxbuild
passed. No real-browser, boundary-management or complete010 acceptance claimed.

## Isolation and coordination

No local test process or owned PG fixture remains. Exact IDs/labels and zero clients
were checked before removing own containers/networks/synthetic volumes. Never clean
another named IAM resource or restart remote/shared services. Go GOMAXPROCS2,
GOMEMLIMIT768MiB/-p2; realPG-p1 and1CPU/768MiB/PIDs128. Heavy gates run serially.

Existing UX task01a07b21-9a0d-7fd0-b090-7827ce18262e and installation task
01a04149-5dbb-7300-9e4c-31d9e85c8ada consume only fixed objects with their own gates.
Both know119 exactCI success and ongoing client scope. No other Phase WIP/profile/
environment/acceptance imported. No extra agents/tasks; only own branch writable.
