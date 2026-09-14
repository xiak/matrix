# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git, exact CI and the owning FEAT.

- Updated: 2026-09-14
- Repository: https://github.com/xiak/matrix.git
- Branch: `feat/iam`
- Latest pushed implementation: `b208ab081ac2f08aab81f63b8cfefb17ebdc6c82`,
  trusted identity string conditions.
- Exact [Verification 34836760785](https://github.com/xiak/matrix/actions/runs/34836760785)
  matches this SHA and is in_progress; final CI is NOT yet confirmed.
- Last fully CI-verified rollback point:
  `581ce7584527470e1fe377040eb98ffe161e83de`,
  [34833032924](https://github.com/xiak/matrix/actions/runs/34833032924);
  exact SHA and Go/authority-process/node-process completed/success.
- Earlier time candidate7218 failed alias competition; do not inherit581 success
  backwards. Existing FEAT evidence owns details.

## Resume and full objective

The entire IAM goal remains active. Read AGENTS.md, IAM/FEAT-IAM-000-product-contract.md,
IAM/FEAT-IAM-005-policy-versions-and-boundaries.md, then owning code/tests.
001 owns trusted condition sources;011 owns first-release schema and final
release/capacity/HA gates. The user reaffirmed prelaunch development versions
do not require a complete schema1 history chain on every FEAT.

First verify b208ab0's exact live CI. No local test handle remains.
Then continue005: bounded action/resource wildcards, trusted IP conditions,
User/Role permission boundaries, safe delegation and editor/capabilities.
Current time plus identity strings do NOT complete LANG-04 or005.
006 roles/STS,007 programmatic credentials,008 product/service-role/ABAC,
009 governance,010 console,011 acceptance and012 explicit deferred integrations
remain as specified. Do not redefine completion around policy CRUD/conditions.

## Current pushed implementation

b208ab0 adds iam.account-id and iam.principal-id, STRING with
IAM_AUTHENTICATED_IDENTITY source, only declared TENANT/USER authorization.
Values come from the current owner-validated IAM Account/Subject, not Group,
policy owner, resource, alias, caller body/header/cursor or service credentials.
STRING_EQUALS is any exact match; STRING_NOT_EQUALS is all values unequal.
Each set has1–16 distinct valid IDs, case-sensitive without coercion/wildcards.
Duplicate key/operator or value rejects; different keys may use the same op.
Multiple conditions AND; matched Deny wins across all direct/group sources.
Mandatory identity/time missing or invalid fails the entire decision closed;
there is no negative-match fallback to Allow or generic context map.

The sole private evaluator receives typed policyEvaluationContext through
EvaluateAttachedPolicies. No exported bypass or parallel evaluator retained.
Existing canonical owner copies/sorts values; reordering preserves digest and
request replay. Old absent-condition/single-time bytes remain unchanged.
Go, generated OpenAPI and current SQL publisher validate bounded semantics;
schema maxContains rules also reject duplicate key/op with different values.
No second canonical encoder. Current source IAM16/Audit11/PaaS1; installation
release profile unchanged. ServiceIdentity, lookup_service, seven-column claim,
Audit canonical and sealed recovery remain untouched. This source combination
is not a signed install/profile compatibility assertion.

581 retry behavior remains: five whole-transaction attempts, only40001/40P01
retry, released connection before bounded jitter25–50/50–100/100–200/100–200ms,
context-aware cancellation; exhaustion unavailable, not fabricated409.

## Actual local evidence for b208ab0

Strict contract and evaluator positives first failed, then passed. Tests cover
EQ/NEQ, AND, case, Group's actual USER, Deny/source ordering, missing authority,
invalid source/operator/shape/duplicates/bounds, canonical stability and cursor
reauthorization after default change. OpenAPI duplicate-pair test red→green.

Real PG18 focused version/identity gate11.29s(parent15.57/package18.454):
two accounts with same User/Group/Policy names and resource ID, two group members,
selected current USER, default selection, remove/rejoin membership, attachment
revocation, forged body/header, restricted SQL attacks and historical proof.
Fixture corrections preserved public Denied identity privacy and existing
unqualified root/qualified ordinary User login contract; no production weakening.

Full serial real PG18 race batch passed:
Audit data5.449s, Audit HTTP3.060s, IAM integration172.276s,
independent dualIAM/PaaS/Audit45.125s, PaaS data4.427s.
Actual PaaS combines identity/time, allows within window, denies after expiry;
publication alone does not change default; explicit negative-set default
allows/excludes the actual USER on the same bearer. Real dispatchers and
tenant chains, restricted logins, cross-account resources/Operation/outbox,
credential concurrency and current-state replay gates preserved.
Final service-credential-as-USER attack added afterward passed a new focused
database11.31s(parent15.80/package18.343). An earlier last output was unavailable,
process and PG clients were terminal before this evidence replacement run.

Final full Go race/vet, modules, stable API generation and Linux amd64 whole-repo
build passed. Existing canonical fuzz15s/2workers/1s minimization passed549,059
executions. Default-skipped DB tests are not substituted for real batch.
No UI, installation, capacity or whole-FEAT acceptance implied.

Own PG18 fixture used1CPU/768MiB/PIDs128/64connections. Exact container/network/
volume identity and task labels confirmed, client count0, stopped and deleted;
only synthetic test data removed. No local fixture/live test survives.
Never overlap broad builds/fuzz and the real PG gate.

## Coordination and isolation

Existing UX/UI task01a07b21-9a0d-7fd0-b090-7827ce18262e and installation task
01a04149-5dbb-7300-9e4c-31d9e85c8ada consume only fixed objects and own their
verification. No UI capability, install profile or other Phase acceptance
transferred. Mandatory authority absence differs from future optional business
attribute absence; identity negatives never implicitly allow.

Only own worktree/branch writable; no extra agents/tasks, no other Phase WIP,
no remote/shared restart or other-resource cleanup. Go GOMAXPROCS2,
GOMEMLIMIT768MiB/-p2; real DB serial/-p1. Markdown documentation only.
