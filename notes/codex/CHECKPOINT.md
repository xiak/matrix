# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git, exact CI and the owning FEAT.

- Updated: 2026-09-14
- Repository: https://github.com/xiak/matrix.git
- Branch: `feat/iam`
- Latest pushed implementation: `b342e9da08515f9172b29d1ac237a088171c9e53`,
  literal resource prefixes constrained by explicit action capability.
- Exact [Verification 34839955131](https://github.com/xiak/matrix/actions/runs/34839955131)
  matches this SHA and is in_progress; final CI is NOT yet confirmed.
- Identity implementation `b208ab081ac2f08aab81f63b8cfefb17ebdc6c82` /
  [34836760785](https://github.com/xiak/matrix/actions/runs/34836760785) FAILED:
  authority-process/node-process succeeded; Go failed the preexisting
  TestPinnedSSHExecutorHonorsCancellationDuringHandshake stage expectation.
  Do not treat b208 as an independently successful candidate.
- Last fully CI-verified rollback point:
  `4f22e223398fbe4523bc09d6a369677cb23767db`,
  [34837563263](https://github.com/xiak/matrix/actions/runs/34837563263);
  exact SHA and Go/authority-process/node-process completed/success.
- Earlier time candidate7218 failed alias competition; do not inherit581 success
  backwards. Existing FEAT evidence owns details.

## Resume and full objective

The entire IAM goal remains active. Read AGENTS.md, IAM/FEAT-IAM-000-product-contract.md,
IAM/FEAT-IAM-005-policy-versions-and-boundaries.md, then owning code/tests.
001 owns trusted condition sources;011 owns first-release schema and final
release/capacity/HA gates. The user reaffirmed prelaunch development versions
do not require a complete schema1 history chain on every FEAT.

First verifyb342e9d's exact live CI. No local test handle remains.
Then continue005: action wildcards with pinned Profile/catalog semantics, trusted IP conditions,
User/Role permission boundaries, safe delegation and editor/capabilities.
Current time plus identity strings do NOT complete LANG-04 or005.
006 roles/STS,007 programmatic credentials,008 product/service-role/ABAC,
009 governance,010 console,011 acceptance and012 explicit deferred integrations
remain as specified. Do not redefine completion around policy CRUD/conditions.

## Current pushed implementation

b342e9d adds PREFIX_IN_AUTHORITY to the existing kind/match/id selector.
ID is a literal nonempty ASCII stable-ID prefix<=128bytes, not a star/glob/regex,
path or name. Matching is bounded strings.HasPrefix, current tenant and exact
kind still required. ActionDefinition.ResourcePrefixAllowed defaultsfalse,
only paas.application.read declarestrue after checking its exact applicationId
PEP. Create/list/collection/platform/probe/unknown/future actions do not gain it.
All same-kind actions in a statement must support PREFIX. API validation and
generated schema consume that one catalog; SQL storage constraints are checked
against every catalog action in the real PG gate. No evaluator product-name
branch. Existing EXACT/ANY and canonical/decision history retained.
Final validator aggregates unsupported kinds once per statement, not scanning
the entire catalog again per resource. Current sourceIAM17/Audit11/PaaS1;
installation profile, ServiceIdentity, lookup_service, seven-column claim,
Audit canonical and PaaS production code unchanged. Full CAT05/008 not done.

Contract/schema/evaluator positives first failed, then passed. Prefix grammar,
scope, mixedread/create, full action acceptance matrix, Deny/source ordering,
max-length comparison and cursor snapshot tests pass. Actual two-account/group
HTTP gate with same resource IDs/prefixes, foreign attachment refusal, exact
membership/version evidence, default/revoke and retained proof passed11.64s
(parent16.38/package19.111). Initial malformed-input fixture replaced a prefix
substring inside another valid ID; actual stored canonical proved the mistake;
fixed exact-field mutation, no production relaxation.
Full serialPG18 passed Audit data5.434s, AuditHTTP2.620s, IAM164.055s,
dualIAM/PaaS/Audit46.279s, PaaSdata5.044s. PaaS creates two real apps before
revocation; sole prefix+time+identity grant allows matching and denies actual
nonmatching app. Original default/revoke, restricted runtime identities,
cross-tenant resources/Operation/outbox and historical chains remain.
Full Go race/vet/modules/stable generation/Linuxbuild passed, then final pure
validation loop aggregation passed API/authority/usecase/architecture race,
fullvet/Linuxbuild and fuzz15s/2workers/1s minimization634172executions.
Exact final code's full PG is pending new independentCI, not claimed inherited
from the pre-aggregation local tree. No capacity/UI/install acceptance implied.
Own PG18 used1CPU/768MiB/PIDs128/64connections. Default Docker subnet pools were
exhausted; read-only subnet inventory established an unused explicit /28 for
only this fixture. No network pruning or shared configuration changes. Exact
IDs/labels and zero clients confirmed before removing container/network and
synthetic volume. No local resource or process handle survives.

4f22e22 changes only the existing SSH test and005's CI evidence. Server Accept
does not prove client DialContext completed, so cancel there can legitimately
return ssh-connect/UNAVAILABLE instead of ssh-handshake/UNAVAILABLE.
The owning installation task granted a test-only window. Receive a full client
SSH-2.0 version line with1s ReadDeadline/255byte cap, without replying, before
cancel. Preserve500ms exit and exactstage, check connectionEOF and accept
goroutine cleanup. No production/error classification changes. Original test
passed locally200 times (not a local red); CI provided actual failure evidence.
Corrected test passedrace200; full adapter/architecture/vet and uncached full
Go race-count1/vet/Linux amd64 build passed. Its exact three-job CI now SUCCESS.
No local PG or remote operation in that correction.

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
Go, generated OpenAPI and SQL publisher validate bounded semantics;
schema maxContains rules also reject duplicate key/op with different values.
No second canonical encoder. Identity fixed baseline IAM16/Audit11/PaaS1; installation
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
