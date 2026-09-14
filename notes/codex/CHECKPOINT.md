# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git, exact CI and the owning FEAT.

- Updated: 2026-09-14
- Repository: https://github.com/xiak/matrix.git
- Branch: `feat/iam`
- Latest pushed, locally verified metadata candidate:
  `02fed1296d0f425e610812a870c85ed524295447`.
- Its exact [Verification 34819882669](https://github.com/xiak/matrix/actions/runs/34819882669)
  was confirmed in_progress. Poll the same run; observation timeout is not failure.
- Last fully CI-verified version-management milestone:
  `aa28c39ca25ad0136b4a7042f1f1ae358d4f1429`,
  [Verification 34816605258](https://github.com/xiak/matrix/actions/runs/34816605258):
  exact SHA and Go/authority-process/node-process all completed/success.
- Earlier creation/read milestone remains
  `7104b1de8f16ae82645e149b2c5376f983eae5cd` / successful CI 34814615083.

## Resume route and objective

The complete IAM replacement goal remains active. Neither IAM/005 nor the
overall product is accepted. Read AGENTS.md, the
[product contract](../../IAM/FEAT-IAM-000-product-contract.md), then
[IAM/005](../../IAM/FEAT-IAM-005-policy-versions-and-boundaries.md) and its
owning code/tests. [IAM/011](../../IAM/FEAT-IAM-011-acceptance.md) owns the
user-confirmed prelaunch schema policy, final release and capacity/HA gates.
The [existing adoption record](../../docs/adoption/FEAT-006-platform-authorities.md)
owns fixed sources; never use another worktree's dirty files.

First resolve 02fed12's exact CI. If it fails, inspect the actual failing
test, correct its owning invariant/fixture and use a fresh task-owned
database. Do not print GitHub credentials. Keep authenticated log credentials
in memory only and restrict excerpts to failed tests before the very large
post-job PostgreSQL cleanup logs.

## Pushed implementation and evidence boundary

aa28 delivers CUSTOMER version list/exact nondefault read, immutable content
creation and explicit optimistic default selection. Creation does not switch
the default or grant. Old command replay conflicts after another Policy
revision; historical decisions retain their exact original content.

02fed12 adds PATCH /v1/policies/{policyId} with UpdatePolicyRequest
(displayName/resourceVersion/requestId), returning current-default
PolicyDetail. Current PDP, original root, ACTIVE USER/Account and own ACTIVE
CUSTOMER Policy are checked in existing transaction/SQL locks.
iam.policy.update and iam.policy.updated are tenant-only, exact POLICY.
Only displayName/resourceVersion/updatedAt change; identity, content, default
and attachments do not. Equal replay requires the original result revision
to remain current. No-op, name collision, variant and stale revision conflict.
A service secret is not a user bearer and gets authentication 401, not a
successful service authentication followed by policy authorization.

Final focused PG18 metadata tests, related API/IAM/Audit/architecture race,
strict schema tests, full Go tests/vet, module verification, stable generation
and Linux IAM/Audit builds passed. The serial CI-equivalent real PG package
set passed: Audit data/history, Audit HTTP, IAM integration, dual IAM with
actual PaaS/Audit and PaaS data. Exact timings belong to 005.
They prove rename/default concurrency, publisher revocation during lock wait,
final-outbox failure rollback including the decision, cross-account/non-root
denial, old proof and unchanged application authority after rename. They do
not replace the candidate's pending independent CI.

Current development source is IAM12/Audit9/PaaS1; the preceding version slice
was 11/8/1. Installation/release profile was NOT changed. No new UI capability,
diagnostic endpoint, condition, boundary or deletion API is present.
ServiceIdentity/lookup_service, seven-column claim, canonical bytes and
sealed original-primary recovery contracts remain unchanged.

## Next implementation

Continue 005's remaining full scope: policy deletion, version deletion that
frees management capacity while retaining immutable history, bounded
wildcards/conditions, permission boundaries, safe delegation and editor UI.
Do not stop at create/version/rename as a substitute for the full FEAT.

Before deletion, inspect the existing owners:

- 000001_authority/up.sql: policies, policy_versions, terminal metadata
  guard, immutable history guard, default-version FK and list_policies.
- 000006_policy_authority/up.sql: publisher/Policy locks, version inventory,
  default selection and immutable outbox intent verification.
- The directory test currently expects a retired CUSTOMER row to remain
  listed. The complete 256-item directory would exhaust after repeated
  create/delete unless management visibility or pagination changes.
  Historical retention must not become a lifetime object/publication cap.
- Current version IDs are content-digest derived. Settle explicit
  republishing/retirement semantics before implementing deletion; no silent
  revival or removal of historical content merely to pass quota tests.
- Do not globally relax reject_policy_history_change, which protects more
  than version management. Preserve canonical/digest and historical proof.

Then continue 006–010 and 011's real final combination gates. 012 retains
explicitly deferred external requirements. Group/browser integration,
final signed installation, capacity/fairness and database HA remain open;
two processes over one database do not prove database failover.

## Coordination and isolation

UX/UI task `01a07b21-9a0d-7fd0-b090-7827ce18262e` on
`feat/cloud-console-ux` received aa28's successful exact CI and complete
version route/type/action/replay boundaries. User-initiated detail GET may
reach server authorization and show 403; creation controls stay hidden until
a fixed conservative capability projection exists. Do not infer authority
from root labels, policy names or MOCK grammar. Its WIP is not a donor.

Installation task `01a04149-5dbb-7300-9e4c-31d9e85c8ada` acknowledged aa28
but is not integrating now; it waits for 005 and final ABI. It approved the
metadata-only window and unchanged installation/host contracts. Do not edit
installation/releasebuild/profile, PaaS/node or its FEAT/checkpoint.

All local test processes finished. The rename fixture's PostgreSQL container,
network and synthetic volume were ownership-checked and removed. No live
local gate handle remains; only exact remote CI needs checking. New tests
use fresh labels/names and bounded CPU/memory/PIDs/concurrency.
An internal-only Docker network did not publish the host port on this local
engine; the verified fixture used its own ordinary bridge and loopback-only
port publication. This fixture issue does not change production topology.

Go defaults GOMAXPROCS=2/-p 2; real database packages serial/-p 1. Never
restart remote machines/shared engines or occupy another task's resources.
No additional agents/tasks. User-facing documents default to Markdown.
