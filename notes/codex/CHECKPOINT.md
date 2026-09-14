# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git, exact CI and the owning FEAT.

- Updated: 2026-09-14
- Repository: https://github.com/xiak/matrix.git
- Branch: `feat/iam`
- Latest pushed, locally verified version-retirement candidate:
  `b99e082fa9ba8a6412eeb766387f4fbeb5df0aa3`.
- Exact [Verification 34827144713](https://github.com/xiak/matrix/actions/runs/34827144713)
  is in_progress: node-process success, Go/authority-process running.
  Poll this same run; observation timeout is not terminal.
- Last fully CI-verified code is policy-deletion
  `0ac6445a33fb2e592fe94d2787a87cd7460ec4ae` /
  [Verification 34823234061](https://github.com/xiak/matrix/actions/runs/34823234061);
  exact SHA and all three jobs completed/success.
- Earlier rename candidate 02fed129 FAILED its own CI due to a first-page-only
  protection test; 0ac fixes it. Do not inherit success backwards.

## Resume and full objective

The full IAM replacement goal remains active. 005 and the overall product
are NOT accepted. Read AGENTS.md, [000](../../IAM/FEAT-IAM-000-product-contract.md),
[005](../../IAM/FEAT-IAM-005-policy-versions-and-boundaries.md), then owning code/tests.
[011](../../IAM/FEAT-IAM-011-acceptance.md) owns the user's prelaunch baseline:
unpublished schema numbers are not automatically supported upgrade origins.
Current clean apply, retained-data replay, security and explicit published
consumer obligations remain mandatory.

First resolve b99e082's exact CI. On failure inspect actual failed test before
changing code/fixtures. GitHub credentials remain in RAM only; never print
headers, credentials or full post-job database logs.

## Current fixed behavior

DELETE /v1/policies/{policyId}/versions/{versionId} accepts only
resourceVersion/requestId; current PDP plus original root, ACTIVE USER/Account
and own ACTIVE CUSTOMER locks. SYSTEM/cross-account/non-root/default reject.
Returns current-default PolicyDetail, PolicyRV+1. Exact replay is valid only
while its original result revision is current; variants/stale intents conflict.

policy_versions.retired_at is a one-way terminal transition. The original ID,
document/canonical/digest/time remain immutable; no physical deletion, initially
retired insertion, unretirement or retired default. Current read/list/default
and five-total-version budget exclude retired rows; historical proof does not.
Ordinary attachments follow Policy default and are not nondefault version pins.
Republishing retired content gets a new opaque ID bound to digest and monotonic
Policy result RV; active equal content conflicts and old IDs never revive.

iam.policy-version.delete / iam.policy-version.deleted are TENANT / POLICY.
Current development source is IAM14/Audit11/PaaS1. Installation/release profile,
ServiceIdentity/lookup_service, seven-column claim, canonical and sealed
original-primary recovery are unchanged. This is not a releasable profile.

## Verified local evidence

Focused real PG18 version lifecycle passed6.19s (parent11.33s): capacity reuse,
same-content new identity, default protection, exact replay, outbox rollback,
historical proof and four-way retirement/default/publication/Policy-delete race.
Complete final IAM integration race passed320.659s, including current policy
storage, HTTP155.29s and local recovery37.59s. Final insertion attack and strict
response checks were included. Existing real Group101+/pagination and
credential concurrency coverage was preserved.

The first serial IAM batch exhausted its shared two-minute aggregate context
at122.72s and is NOT passing evidence. Ten flows now have individual2-minute
budgets and the shared retained-data fixture has4 minutes; HTTP test requests
inherit that deadline/cancellation. No production timeout/resource change.
The final fresh database run above passed. This is not a performance SLO.

Actual independent dual IAM/PaaS/Audit passed137.207s: restricted runtime logins,
real resource access unchanged by nondefault retirement, real dispatcher/chain,
and existing Account/Operation/outbox isolation and identity-outage gates.
Audit data11.447s, Audit HTTP3.286s, PaaS data18.719s passed.
API/IAM/Audit/architecture race, full default tests/vet, module verification,
stable OpenAPI and Linux IAM/Audit builds passed; final focused race/vet passed
again after the last test harness/adapter changes. Default skipped DB tests do
not replace the real runs. No new UI/signed-installation/capacity acceptance.

## Next implementation

005 now specifies the unimplemented IAM-authoritative time-condition slice:
optional typed conditions, declared key/source, [start,end), current database
transaction time only, closed input, unchanged old canonical, same evaluator,
and a real publish/attach/PaaS/time-boundary/historical-proof path. Read its
section and [001](../../IAM/FEAT-IAM-001-authorization-profile.md) before coding.
CAT-05 is not complete: static ActionDefinition is not the final signed Profile.
Resource/source-IP/tag conditions require declared trusted product inputs;
never accept a caller-controlled generic attributes map.

Then finish bounded wildcards, string/IP conditions, permission boundaries,
safe delegation and editor/capabilities; 006–010 and011 final gates remain.
Do not redefine success around CRUD. 012 owns deferred external integrations.

## Coordination and resource isolation

UX/UI task 01a07b21-9a0d-7fd0-b090-7827ce18262e received the fixed candidate,
route/result/capacity semantics and pending CI. No management capability was
added; names/root labels/mock grammar cannot authorize UI writes.

Installation task 01a04149-5dbb-7300-9e4c-31d9e85c8ada received the same pending
candidate and confirmed no consumption before all jobs succeed. No profile
update requested. It agrees ordinary attachments are not version pins and
the budget is five total management versions including default.

All local test handles are terminal. The version-retirement task's PostgreSQL
container/network/synthetic volume were exact-ID/label checked, found client
count0, stopped and removed. No local fixture survives. Remote CI34827144713
remains the only known live gate; inspect it before restarting anything.

Only own worktree/branch is writable. No other Phase WIP, remote/shared restart,
resource cleanup or extra agents/tasks. Go GOMAXPROCS2/GOMEMLIMIT768MiB/-p2;
real DB packages serial/-p1, never overlap broad builds with real PG.
All user-facing documents default to Markdown.
