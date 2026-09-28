# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch feat/iam, independent
  worktree. Milestone2026-09-29. Full goal ACTIVE/incomplete.
- Latest pushed source **21b3de3a3034713fd4ddfa08ec654bb648694bc8**,
  source IAM50/Audit27. Exact Verification **36462106282** was confirmed
  pending, not successful:
  https://github.com/xiak/matrix/actions/runs/36462106282
- It implements the original administrator-reset completion query and its
  atomic immutable relation. Parent **bd211c40c6699d5f8c26de70e9af2af09bbb452a**
  downloads/verifies dependencies before the read-only capacity-container
  mount. No UI or installation/profile code changed.
- Prior **9df45126 / 36455507556** is not accepted: capacity failed during
  package setup because the read-only module cache lacked dependencies.
  Go/roles/storage/runtime/node successes do not cover that failure.
- Latest independently accepted cumulative source remains
  **3178b649f6e61c59786f6d0b14828ff3196876f3**, IAM46/Audit27,
  Verification36391053858 completed/success, all12 jobs.

## Reading route and remaining outcome

Read AGENTS, IAM/FEAT-IAM-009-security-governance.md S3b/reset-completion,
then its accounts/usecase/HTTP/SQL and original integration/process tests.
011 owns capacity/CI and the single real predecessor; the original
FEAT-006 adoption record owns fixed-source decisions.

Confirm21b3's exact CI before calling this combined candidate accepted.
Continue009 password expiry, then remaining idle sessions/reports,
service-role/ABAC/actual business credentials, UX, signed installation and
capacity/HA. The full goal is not only UI or testing. Do not introduce
another recovery capability as part of expiry.

## Current reset contract

GET /v1/users/{userId}/password-resets/{resetRequestId}
requires exactly one canonical resourceVersion query parameter containing
the original expected version, no body or identity selector. Only the
original actor's currently authorized LOGIN_SESSION may read, using exact
iam.user.reset-password permission, not user-list. No Role/Key/Service or
forced Session is admitted.

The immutable relation binds original Account/actor/USER/request/expected
and resulting versions to the original event and timestamp. The existing
reset transaction commits credentials/generation/forced-change/revocation/
fact/relation together. GET contains no password material or replay permit.
200 confirms the original metadata-bound commit, not password equality,
today's validity or Audit delivery. 404 remains UNKNOWN; never auto-POST.
Old rows are not backfilled. Old success facts reject reused request IDs
without becoming new completion receipts.

IAM49 new-only private recovery inspection and000015 remain unchanged.
Projectionv4, FILE contracts, ServiceIdentity/lookup_service/claim7 and Audit
canonical remain unchanged. Published CurrentDatabaseProfile stays
**4/3/1+r4**, not source schema; no cross-profile permission is implied.

## Local evidence and cleanup

Own PG18.4:1CPU/768MiB/PIDs192/max_connections24. Native Go1.26.3:
GOMAXPROCS2/GOMEMLIMIT512MiB; heavy race-p1 gates serial.
Full IAM HTTP143.22s passed; final focused password-session/receipt gate
31.28s passed after fact-binding and retarget negatives. Fixed42035189
actual IAM45->50 predecessor118.49s passed: original facts/receipt/canonical,
no invented completion, old used request ID cannot execute again.
Final independent IAM replicas/PaaS/Audit/dispatchers155.30s passed, with
real reset-commit TCP reply loss, peer query, restart, later change/disable
and actual Role/Key rejection. Dual-authority storage7.45s passed.

Full repository race-p2/architecture, vet, module verification, all122 API
files' stable generation and Linux amd64 build passed. Default external
SKIPs are not runtime evidence. No SMTP/browser/signed-release claim.
The pinned Go1.26.5 container reproduced cold-cache read-only failure;
after download/verify the same read-only cache resolved test dependencies
with network disabled. This proves preparation, not capacity measurement.
YAML and19 Bash scripts parsed successfully.

All local test handles are terminal. After zero-other-client verification,
the sole owned PG was normally stopped; its container, synthetic data and
module-cache volumes, and empty network were removed. No foreign or remote
resources changed.

## Coordination and boundaries

Installation thread **01a04149-5dbb-7300-9e4c-31d9e85c8ada** owns signed
consumer/profile/journal/materials/backup runtime. It has no capacity matrix
lane in its own workflow. Do not import its PaaS/profile/acceptance.
Share21b3 as a locally verified candidate with CI pending, not a release.

UX thread **01a07b21-9a0d-7fd0-b090-7827ce18262e**, branch
feat/cloud-console-ux, owns all UI/browser work. It awaits the implemented
GET; pure20b736a2 was insufficient. Its6ed234ba catalog alignment is MOCK,
not LIVE service-role authorization. Original reset input stays immutable;
404/409 never mean success or permission to repeat.

Markdown/existing owners only. No new agents/tasks, foreign WIP, remote
1.3/160/161/withdrawn1.5, shared Docker/WSL/global changes or remote restarts.
Go GOMAXPROCS2/-p2; real PG race-p1 serial with owned bounded resources.
Local Git identity Xiak <Jellal@aliyun.com>. Own branch only.
