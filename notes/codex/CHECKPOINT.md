# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git, exact CI and the owning FEAT.

- Updated: 2026-09-14
- Repository: https://github.com/xiak/matrix.git
- Branch: `feat/iam`
- Latest pushed, locally verified policy deletion candidate:
  `0ac6445a33fb2e592fe94d2787a87cd7460ec4ae`.
- Exact [Verification 34823234061](https://github.com/xiak/matrix/actions/runs/34823234061)
  is in_progress: Go/node-process success, authority-process still running.
  Poll this same run; an observation timeout is not a terminal result.
- Previous rename candidate `02fed1296d0f425e610812a870c85ed524295447`
  FAILED CI 34819882669 in a pre-existing first-page-only protection test.
  The new candidate fixes that test and proves a target beyond page one.
- Last fully CI-verified code remains
  `aa28c39ca25ad0136b4a7042f1f1ae358d4f1429` /
  [Verification 34816605258](https://github.com/xiak/matrix/actions/runs/34816605258),
  exact SHA and all three jobs completed/success.

## Resume and full objective

The complete IAM replacement goal remains active; 005 and the overall product
are NOT accepted. Read AGENTS.md, [000](../../IAM/FEAT-IAM-000-product-contract.md),
[005](../../IAM/FEAT-IAM-005-policy-versions-and-boundaries.md), then its existing
code/tests. [011](../../IAM/FEAT-IAM-011-acceptance.md) owns the user's prelaunch
schema baseline and final release/capacity/HA gates. Do not automatically run
every unpublished schema from 1; current clean apply, data replay, security
and explicit published-consumer obligations remain mandatory.

First resolve 0ac6445's exact CI. If it fails, inspect the actual failed test
before changing code or fixtures. GitHub log credentials stay in RAM only;
do not print headers, credentials or full post-job database logs.

## Current fixed behavior and evidence

Policy create/read, immutable version list/read/create/default selection,
metadata rename and terminal Policy deletion use the current PDP plus original
Account root, ACTIVE USER/Account and own CUSTOMER checks. No implicit grants.
DELETE /v1/policies/{policyId} accepts only resourceVersion/requestId and returns
RETIRED Policy metadata. Any unrevoked User/Group attachment blocks deletion,
including disabled identities. Content/default/history remain immutable.
Only exact deletion replay can inspect its terminal result; public detail,
version reads and other mutations remain active-only. Management PolicyList
now excludes retired metadata, freeing active capacity and display names.

New iam.policy.delete / iam.policy.deleted is TENANT / exact POLICY.
Current development source shape is IAM13/Audit10/PaaS1. Installation/release
profile, ServiceIdentity/lookup_service, seven-column claim, canonical bytes,
original-primary sealed recovery and other product production code did not change.

Final real PG18 focused deletion passed 3.18s (parent8.82s). Complete IAM
integration race passed199.938s: policy86.46s, HTTP94.02s, local recovery16.52s.
The group101+ pagination remains real HTTP; platform protection uses returned
opaque cursors and forces the protected HTTP-created USER beyond the first page.
The four-way delete/rename/version/default race proves only the winner's state
and its lifecycle fact bound to the committed authorization decision. An
authorization-decided audit is not a second lifecycle success.

Independent dual IAM/PaaS/Audit passed51.364s with actual restricted DB logins,
real dispatcher/tenant chain and existing cross-account resource/Operation
and outbox matrices. Audit data17.765s, Audit HTTP4.405s, PaaS data5.848s passed.
One overlapping-build local batch exhausted the original two-minute policy
budget and is NOT counted as passing; fresh serial revalidation above passed
without extending timeouts or cutting Group scale/coverage.

API/IAM/Audit/architecture race, full Go tests/vet, modules, stable OpenAPI
generation and Linux IAM/Audit builds passed. Only a final test assertion changed
after the broad runs; it then passed focused/full real IAM and vet.
No UI, signed-installation, capacity or whole-FEAT acceptance is implied.

## Next actual implementation

005 now defines the next version-deletion slice; it is not implemented:
DELETE the exact nondefault version, return unchanged-default PolicyDetail,
retire management visibility without destroying historical content, release
the five-version budget, and retain old proof/replay invariants. New publication
of retired content receives a new opaque version ID bound to content digest
and monotonic Policy result revision; never revive a retired ID. Existing
digest-derived IDs remain unchanged. Active duplicate content still conflicts.

Read that section before coding. Modify existing policy_versions and its precise
transition guard rather than relaxing the shared immutable-history guard or
adding a parallel content store. Public lists/read/default selection exclude
retired versions; historical evidence does not. Test full capacity reuse,
default/delete/create/Policy-delete races, exact intent conflict, outbox rollback,
current-schema replay and retained old proof. Record fixed 0ac adoption only
after its independent result is known.

Then continue conditions/wildcards, boundaries, safe delegation and editor/
capabilities; 006–010 and011 final gates still remain. Do not stop at CRUD as
a substitute for LANG-01–08 or the full objective. 012 retains deferred external
integration requirements. Two IAM processes do not prove database HA.

## Coordination and resource isolation

UX/UI task `01a07b21-9a0d-7fd0-b090-7827ce18262e` received 0ac's candidate
route/type/error/active-directory boundary and the planned version deletion.
It must wait for fixed successful contracts; no capability has been added and
root labels/policy names/MOCK grammar cannot authorize UI mutations.

Installation task `01a04149-5dbb-7300-9e4c-31d9e85c8ada` received the same
candidate and waits for exact CI/final005 ABI. No profile change or integration
is requested. Do not touch its worktree, host/PaaS/node or installation owner.

All local gates are terminal. This slice's task-labelled PostgreSQL container,
network and synthetic volume were ownership-checked, stopped and removed;
no live local test handle remains. Only remote CI34823234061 is still running.
Do not reuse removed database names as though their state survives.

Go defaults GOMAXPROCS=2/-p2; real DB packages serial/-p1. Never overlap broad
builds with the bounded real PG suite. Use new task-labelled resources, explicit
limits and loopback publication. No remote/shared restarts, no other Phase
resource cleanup, no extra agents/tasks. User-facing documents remain Markdown.
