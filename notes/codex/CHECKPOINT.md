# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git, exact CI and the owning FEAT.

- Updated: 2026-09-14
- Repository: https://github.com/xiak/matrix.git
- Branch: `feat/iam`
- Latest pushed, locally verified transaction-contention fix (including time conditions):
  `581ce7584527470e1fe377040eb98ffe161e83de`.
- Exact [Verification 34833032924](https://github.com/xiak/matrix/actions/runs/34833032924)
  is queued. Poll this same run; observation timeout is not terminal.
- Time candidate `7218e1671378a227d78d020686a68d164982e2ac` /
  [34830294815](https://github.com/xiak/matrix/actions/runs/34830294815) FAILED.
  Go/node succeeded; authority-process failed alias competition503/200.
  PG logs prove five40001 on one backend in36ms, exhausting immediate retries
  before the winner committed. Time-condition/process subgates passed, but
  this candidate must not be treated as CI-successful.
- Last fully CI-verified code is version-retirement
  `b99e082fa9ba8a6412eeb766387f4fbeb5df0aa3` /
  [Verification 34827144713](https://github.com/xiak/matrix/actions/runs/34827144713);
  exact SHA and Go/authority-process/node-process completed/success.
- Earlier 0ac6445 policy deletion also passed all jobs34823234061;
  its predecessor02fed129 failed a first-page-only protection test. Do not
  inherit success backwards.

## Resume and full objective

The full IAM replacement goal remains active; 005 and the product are NOT
accepted. Read AGENTS.md, [000](../../IAM/FEAT-IAM-000-product-contract.md),
[005](../../IAM/FEAT-IAM-005-policy-versions-and-boundaries.md), then owning
code/tests. [001](../../IAM/FEAT-IAM-001-authorization-profile.md) owns condition
source declarations. [011](../../IAM/FEAT-IAM-011-acceptance.md) owns prelaunch
schema baseline and final release/capacity/HA gates. Unpublished numbered
schemas do not automatically require a complete upgrade chain from1.

First resolve581ce75's exact CI. If failed, inspect actual failure before
changing code/fixtures. GitHub credentials remain in RAM only; never print
headers, credentials or full post-job PostgreSQL cleanup logs.

## Current fixed behavior and scope

581ce75 fixes existing whole-transaction retry scheduling, owned by003.
Default five attempts unchanged. Only retryable transaction errors wait;
jitter ceilings50/100/200ms (half-ceiling minimum), capped200ms per wait.
Connections/locks are released before waiting; context cancellation stops
waiting and is rechecked before each attempt. Success/definitive business
errors/final exhaustion never wait again. Exhaustion stays unavailable,
not a fabricated409. No API/SQL/schema/profile or UI changes in this fix.

Statement.conditions is optional; current key iam.current-time has source
IAM_TRANSACTION_TIME and type TIME, declared only for current TENANT actions.
Only USER authorization consumes conditions; platform/probe/service-subject
conditional authority is closed. Operators DATE_GREATER_THAN_EQUALS and
DATE_LESS_THAN take one canonical UTC/microsecond value, combining [start,end).
Unknown fields/keys/operators, null/empty arrays, duplicate key/operator,
bad dates/precision/timezones and empty/reversed windows reject.

PolicyDocument owns strict decoding/canonical; no-condition bytes/digest
remain unchanged. The sole evaluator now requires explicit databaseTime.
Actual Decide, capability projection and cursor reauthorization use the
existing transaction_timestamp source. No caller attributes/currentTime map.
Matched Deny still wins across sources; nonmatching conditional Allow does
not cancel another valid Allow. Historical decisions retain exact versions,
membership evidence and original DecidedAt; expiry does not prevent delivery.

The current source is IAM15/Audit11/PaaS1. IAM reflects changed document/
publication semantics, not a supported historical upgrade promise.
Installation/release profile, ServiceIdentity/lookup_service, seven-column
claim, Audit canonical and sealed original-primary recovery are unchanged.
CAT-05 full signed Profile/revision/digest/granularity is NOT implemented.

b99 remains the version-retirement baseline: five management-visible total
versions including default, terminal nondefault retirement releases a slot
without deleting proof. Republication gets a new opaque ID; active equal
content conflicts and retired IDs never revive. Ordinary attachments follow
Policy default; they are not nondefault version pins.

## Actual local evidence

581ce75: fake-clock contention and cancellation tests first failed, then
passed; race20 repetitions, terminal outcomes and limits1/5/10 covered.
Existing HTTP alias gate now runs8 distinct contested aliases: exactly one
200 and one409, loser Account/reservation/success fact unchanged, both
original USER/login-index unchanged, exactly one winner fact. Original
CAS/request replay409 leaves state/fact counts unchanged (not an idempotent
success-receipt route). Runtime tracer counts only40001/40P01, no SQL/args.
Focused PG passed70.43s(parent73.33s/package76.342s);7 rounds actually retried
40001 successfully. Final USER/index/replay checks passed full real batch:
Audit data7.611s, Audit HTTP3.083s, IAM integration race233.732s, independent
dualIAM/PaaS/Audit55.976s, PaaS data7.149s. All current time/policy/credential/
history/isolation gates retained; no unpublished full-schema upgrade chain.
Full default Go race/vet, modules, stable API generation and Linux amd64
whole-repo build passed after real DB tests ended. No capacity/UI/install
acceptance implied. Own fixture exact-ID/labels checked, client count0,
container/network/synthetic volume removed. All local handles terminal.

Time-condition strict positive parser test first failed, then passed.
Unit/contract tests cover microsecond window boundaries, Deny precedence,
source order, invalid authority time, closed schema, stable canonical,
and cursor rejection exactly when the granting policy expires.

Real PG18 focused versions/time passed9.47s (parent18.33s, package21.540s).
The first time test still had a prior explicit unconditional AccountAdmin
attachment: stored evidence correctly showed that surviving Allow. The test
now revokes that attachment through HTTP; production union semantics were
not weakened to make the test pass.

Final full real PG18 serial batch passed: Audit data5.702s, Audit HTTP3.326s,
IAM integration race246.989s, PaaS data6.202s. Final IAM time test uses real
Group creation/membership/attachment, asserts exact inherited evidence inside
the5-second database window and no matched evidence after expiry. Preserves
current-schema/bootstrap replay, Group101+/pagination, version lifecycle,
credential concurrency, immutable history and local platform recovery.

Independent dual IAM/PaaS/Audit passed45.75s (package48.644s). Real direct
attachment allows inside6-second window, expires on same bearer, newly
published version alone remains denied, explicit default selection permits,
then attachment revocation denies. Real dispatchers and full tenant chain,
restricted runtime logins and existing cross-account resource/Operation/
outbox/fail-closed gates remain.

API/IAM/Audit/architecture race, full default Go tests/vet, modules, stable
OpenAPI and Linux IAM/Audit builds passed. Final API/authority race passed
again. Fuzz with timed seed15s/2workers/1s minimization passed132,238 executions;
not a performance or full-language proof. The prior default60s minimization
spent the short run minimizing; no failing corpus or production change.
No UI, signed-installation, capacity or whole-FEAT acceptance is implied.

The policy aggregate retains4-minute total/2-minute-per-flow test budgets
from b99; no production deadline/resource changes. Never overlap broad
builds/fuzz with the bounded real PostgreSQL suite.

## Next implementation

After exact CI, record final confirmation in003/005 and notify existing peers.
Then continue full005: bounded wildcards, typed string/IP conditions and their
declared trusted sources, User/Role permission boundaries, safe delegation,
editor and capabilities. Current time support is NOT full LANG-04.
Source IP cannot come from an untrusted forwarding header; product tags
require008 PEP contracts. Do not add generic caller-controlled attributes.
Read existing001/005/008 and directly relevant ADR before crossing boundaries.

006 roles/STS,007 programmatic credentials,008 product/service-role/ABAC,
009 governance,010 console and011 final gates remain;012 retains explicitly
deferred integrations. Do not redefine the goal around policy CRUD/time.

## Coordination and isolation

UX/UI task01a07b21-9a0d-7fd0-b090-7827ce18262e and installation task
01a04149-5dbb-7300-9e4c-31d9e85c8ada received b99 final success,7218 failure,
and581ce75 pending CI candidate semantics/evidence. No new UI capability or installation profile
was published; names/root labels/mock grammar never authorize writes.
Only fixed objects are exchanged; peers do not inherit this branch's gates.

All local test handles are terminal. Time/alias-slice PostgreSQL container/network/
synthetic volumes were exact-ID/label checked, found client count0, stopped
and removed. No local fixture survives. Only CI34833032924 is known queued.
Do not reuse old database names as if data survives.

Only own worktree/branch is writable. No other Phase WIP, remote/shared
restarts, other-resource cleanup or extra agents/tasks. Go GOMAXPROCS2,
GOMEMLIMIT768MiB/-p2; real DB packages serial/-p1. Documents remain Markdown.
