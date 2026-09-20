# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Write only
  this task's independent worktree. Updated 2026-09-21.
- Full IAM goal remains ACTIVE/incomplete. Read AGENTS, IAM/009 for MFA or
  IAM/012 for mail, then owning code/tests. Fixed adoption belongs to
  docs/adoption/FEAT-006-platform-authorities.md, not this checkpoint.
- Latest fixed/pushed test increment:
  **80a6e6d18288df7f5d89ffee40722ee9aa614ee7**. Only existing integration
  owner, CI and FEAT009/011. No production/API/SQL/profile/UI change.
- Latest production remains **48e56cbb1d3490ee8cee8314a41cfc26d1f24b2e**,
  pure-codec parent c13f6d11. Source IAM38/Audit22/PaaS2; release profile/
  revision unchanged/unallocated. No cross-release acceptance inferred.
- Exact https://github.com/xiak/matrix/actions/runs/35531111030 completed/
  failure: all six jobs runner_id=0/steps=0; payment/spending-limit annotation
  prevented execution. Independent CI is NOT accepted. Previous48's
  35528886088, f5's35520219893 and c13's35521839561 also did not execute.
  Do not alter billing, weaken tests or repeatedly rerun unchanged blockage.
  Earlier5e185e95's actual Audit runtime-probe failure remains separate;
  subsequent local passes do not rewrite it. FEAT owners retain its evidence.

## Latest runtime and CI increment

Existing integration owner now separates TestIAMTOTPRecoveryExhaustionPostgres
from the original TestIAMTOTPEnrollmentPostgres via one shared fixture.
No production budgets, clock, password cost or positive consumption rows
are changed. Actual PG18.6, API role, two Authority handlers in one process:

- Ten original saved codes consumed through HTTP handlers over three shared
  windows, crossing two real ten-minute intervals. Race passed1229.25s,
  exhaustion subcase1202.09s/package1232.773s. Exhaustion still permits exact
  metadata lookup, but used code401 grants no new intent/Session/completion.
  The current tenth ceremony can finish; old ten consumed/new ten unconsumed,
  nine SUPERSEDED/one COMPLETED, ten start facts/one completion/eleven notices,
  and normal password+new-factor login all proved. Not an SMTP/browser gate.
- A second fresh DB reran original enrollment/recovery:66.03s/package69.540s,
  original3m context,41 schema damage cases, all non-mail recovery cases and
  actual USER lock expiry31.34s. Two SMTP subcases explicitly SKIP; do not
  inherit prior real mailbox results as this run's evidence.
- Both used exact Go source blob67fa7c06dd7caf9b2a2e29d61f00764ea658e32c.
  Go1.26.7/GOMAXPROCS2/GOMEMLIMIT512MiB, race-p1 runtime; PG1CPU/1GiB/Pids192,
  max_connections16. Full default race/architecture, vet, modules, gofmt and
  diff checks passed afterward. Default external SKIPs are not runtime proof.
- Original storage/runtime CI lanes remain20m. New recovery-window lane30m,
  Go27m/context25m for natural-time gate only. All three lanes max-parallel1;
  aggregate closes on any failure/cancel/skip. YAML and13 Bash blocks checked;
  actual compiled15 tests assigned once:general5/Role1/runtime8/window1.
- Both real test handles and full checks terminated successfully. After no
  DB clients remained, exact owned temporary PG container and empty network
  removed; task labels show zero containers/networks/volumes. No live fixture
  or test session remains from this milestone. No shared or remote changes.
  Earlier policy-denied temporary-directory cleanup is NOT retried/bypassed.

## Fixed online recovery contract and prior evidence

48e56cbb's three strict no-bearer routes are in IAM/009 S2b recovery:
:recover, :confirm-recovery and :recovery-result under auth/challenges/{id}.
Current LOGIN proof plus an original saved code starts irreversible recovery;
old factor/sessions/challenges end, original LOGIN deadline is retained.
Confirmation issues new ten codes once and REAUTHENTICATE, not a Session.
Unknown replies never replay secrets/refund codes; current password proof can
inspect original nonsecret metadata. No password/forced/role/contact change.
LOGIN/RECOVER requires exact original recovery lineage, not a loose state flag.

IAM38 narrow read/start/confirm/inspect functions are5/17/10/4 args,jsonb.
USER-self tenant facts recovery-started/recovered and original-recipient
RECOVERY_STARTED/AUTHENTICATOR_RECOVERED mail. Preserve ServiceIdentity,
lookup_service5, Audit claim7, lookup_session24, revoke_session6, oldcanonical,
record9/contract4/evidence5 and private mailclaim18. No new hash/dispatcher.

FEAT009/012 retain prior local evidence: real Postfix recovery and disabled
USER historical delivery; independent IAM pair/Audit/PaaS/two dispatchers
with actual post-commit TCP loss, three restarts and complete history chain;
actual fixedf5 IAM37 executable retained MFA→38 including completed recovery
followed by double migration/bootstrap/restart without resurrection; selected
IAM32/36 predecessors. Those remain scoped source/database evidence, not
full release/profile/UI acceptance or a requirement to replay every schema.

Next backend work remains009 S2 step-up, restricted first forced enrollment,
S3 settings/expiry and S4 governance; full UI and release gates remain open.
Standard OTP math uses pquerna/otp1.5.0; MATRIX owns custody, replay/budgets
and transaction policy, not another HMAC/OTP implementation.

## Shared ownership and fixed UI review

Installation01a04149-5dbb-7300-9e4c-31d9e85c8ada exclusively owns offline
close-before-restore/reconcile/one-time-reopen, including
api/adapter/installation/v1.AuthenticationRecoveryClosure and installation/
release/profile/CLI/journal. It has fixed48 and exact shapes/evidence/gaps.
Do not edit those or import its PaaS6, WIP, host files, profile or acceptance.

UX/UI01a07b21-9a0d-7fd0-b090-7827ce18262e owns ALL UI on its own branch.
Fixed3c9a49fb251ceb80331b611b76843233ad1dafd1 added the recovery client.
Read-only review found precommit confirm loss could loop after LOGIN/RECOVER,
pending A recovery could affect B login, and first-enrollment unknown intent
was lost on content remount without by-request lookup. UX then fixed these in
**d7d6333d135a65648269443789799d1fccf0b638**, doc689305d8. Read-only review of
that fixed diff and its five added tests confirms the intended branches:
fresh LOGIN/RECOVER inspects original nonsecret result; loginName isolation;
Session-owned enrollment intent survives content remount and requires exact
query/cancel before restart, while404 remains unknown. No seed/code replay.
UX reports657 frontend tests and539px MOCK; those are NOT executed or accepted
as real UI/browser gates here. No UI was imported. Do not read WIP or build a
parallel UI. Other Role/IdP MOCK/LIVE reports also remain candidates.

UX asked about a product-declaration publishing workspace. Replied from fixed
80a6e6d1/001/008: immutable AuthorizationProfile and exact revision/digest plus
GET /v1/authorization-profiles under iam.policy.list exist. There is NO fixed
online Profile draft/validate/publish workflow or management permission name.
Keep proposal MOCK-only; pure Go validation is not a trusted publication,
platform/admin/service identity is not publishing authority, and a catalog
is neither permission nor proof a product PEP is implemented. No new API was
promised merely to serve a MOCK design. Online registration remains001/008.

Only fixed-object exchange. Git identity Xiak <Jellal@aliyun.com> locally.
No extra agents/tasks, foreign worktree writes, remote1.3/.160/.161 or withdrawn
GitLab/1.5 work, global settings, Docker/WSL/system restart or prune. Unique
bounded fixtures, Markdown only; no personal mailboxes.
