# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Write only
  this task's independent worktree. Updated 2026-09-21.
- The full IAM goal remains ACTIVE/incomplete, not narrowed to this MFA slice.
  Read AGENTS, IAM/009 for MFA or IAM/012 for mail, then owning code/tests.
  Fixed adoption: docs/adoption/FEAT-006-platform-authorities.md.
- Latest fixed/pushed implementation:
  **48e56cbb1d3490ee8cee8314a41cfc26d1f24b2e**, parent pure-codec c13f6d11.
  Source IAM38/Audit22/PaaS2; release profile/revision unchanged/unallocated.
- Exact https://github.com/xiak/matrix/actions/runs/35528886088 is completed/
  failure. All five jobs runner_id=0/steps=0; account payment/spending limit
  prevented execution. No independent CI acceptance. Do not change billing,
  weaken gates or repeatedly rerun an unchanged external condition.
- Previous f5cec0e132ad18900d9a5a5629eae04fda4817f1 (IAM37/Audit21) and
  c13f6d11db8055b660c18731a427594d265ff9b2 also had zero-run billing failures.
  Earlier 5e185e95 CI had an actual Audit runtime-probe failure, cause unknown;
  later local passes do not rewrite that result. Mail/custody predecessors'
  distinct CI evidence remains in their FEAT owners.

## Fixed online recovery increment

48e56cbb implements the three constrained HTTP routes and atomic PostgreSQL
state machine described in IAM/009 S2b受限自助恢复增量. It reuses f5's real
factor/ten saved-code verifiers, shared USER budget, challenge and outbox.

- Current LOGIN proof plus one original saved code starts irreversible
  recovery: revoke original factor, LOGIN_SESSIONs and challenges, consume
  code, advance revision, bind new PENDING factor/RECOVERY challenge to the
  original LOGIN deadline. No password/forced/role/contact change or Session.
- Confirm new TOTP once, end original batch, issue ten new codes once,
  REAUTHENTICATE. Lost reply never reissues seeds/codes or refunds a code.
  Fresh password proof can query original nonsecret metadata. Another
  explicit saved code/new intent supersedes a lost unfinished ceremony.
- LoginResponse still only contains LOGIN challenges. RECOVERY_REQUIRED
  permits LOGIN/RECOVER only with exact original recovery lineage; corrupt
  retained state does not acquire proof. Exhausted codes still allow only
  metadata access, not a new recovery. Full ten-code runtime gate is pending.
- IAM38 adds authenticator_recoveries and narrow read/start/confirm/inspect
  functions (5/17/10/4 arguments, jsonb). Exact tables/constraints/RLS/ACL/
  ALWAYS triggers/function shapes participate in verify/readiness.
- Tenant USER-self PRINCIPAL facts: iam.authenticator.recovery-started and
  iam.authenticator.recovered. Original verified-contact mail kinds are
  RECOVERY_STARTED/AUTHENTICATOR_RECOVERED. No second canonical/dispatcher.
- Preserve ServiceIdentity/lookup_service5, Audit claim7, lookup_session24,
  revoke_session6, record9/contract4/evidence5 and old canonical/receipt/proof.
  No installation/CLI/profile/offline ABI edit belongs to this increment.

## Evidence and remaining gates

FEAT009/012 own details. Local Go1.26.7, GOMAXPROCS2/GOMEMLIMIT512MiB;
default full race/architecture, vet, modules, all122 tracked API hashes,
gofmt/diff checks and all-package Linux amd64 build passed. Default skips
are not runtime evidence. Owned PG18.6 gates serial race-p1:

- Enrollment/recovery+real Postfix3.10.13:89.54s/package93.080s, including
  41 schema damage cases and12 recovery cases. Real mail recovery12.83s:
  actual contact verification, independent restricted production worker,
  start notice, stop/restart, completed notice after USER disable; original
  DATA250/ACCEPTED persisted, no secrets. Not public-mail/read/browser proof.
- Actual USER lock wait:31.39s, observed pg_blocking_pids, original30s attempt
  elapsed while OTP remained valid;401/no partial state/no refunded budget.
  Missing/wrong sealed custody also returns503 before consumption.
- Independent IAM pair/Audit/PaaS/two dispatchers:83.36s/package86.631s.
  Real post-commit TCP loss at start/confirm, three IAM pair restarts,
  superseded exact deadline, original/new credential separation, disabled
  USER historical proof/replay/full chain. Contact transport here synthetic,
  not the separate SMTP gate.
- Actual fixed f5 IAM37 executable retained MFA→38:18.01s/package21.417s.
  Original factor/codes/consumption/challenges/Session, double migration,
  equal bootstrap/restart; real recovery then repeat migrate/verify/restart
  preserves completed state/no resurrection. Original IAM32/36 regressions
  14.05s/15.05s. Not cross-release compatibility or an unpublished schema ladder.
- Original custody/backup/password gates package126.157s; Audit dual-schema
  8.159s and HTTP4.112s. SMTP mailbox/auth/relay gate3.07s/package5.267s.
- Exact owned container/network labels checked; current PG/SMTP fixtures
  removed, zero container/network/volume residue. Static SMTP files removed;
  empty temp directory removal rejected by tool policy, not bypassed. Older
  denied temp-file cleanup remains manual. No shared/remote restart or prune.

Next online work: prove ten-code exhaustion across actual budget windows,
then other S2 (step-up, restricted forced enrollment), S3 settings/expiry and
S4 governance per existing FEAT. UI/browser and full release remain missing.
No factor/session recovery acceptance is inferred from algorithm unit tests.
OTP standard math remains pquerna/otp v1.5.0 fixed upstream5971b1ef; MATRIX
owns custody, database time/replay and transaction policy, not a second HMAC-OTP.

## Shared ownership

Installation01a04149-5dbb-7300-9e4c-31d9e85c8ada received fixed48e56cbb,
exact function/schema shape, local evidence and zero-run CI boundary.
It exclusively owns offline close-before-restore/reconcile/one-time-reopen,
including api/adapter/installation/v1.AuthenticationRecoveryClosure,
installation/release/profile/CLI/journal. Do not implement or edit those now.
Its fixed002d788b adapts f5 while retaining PaaS6; do not import its profile,
WIP, host files, checkpoint or acceptance. Source version alone is not ABI.

UX/UI01a07b21-9a0d-7fd0-b090-7827ce18262e owns all UI on its own branch.
It received fixed48e56cbb routes, secret/unknown completion rules and gaps.
Recent UI fixed reports:80225dce first binding;d4bff0d3 Role LIVE read-only;
6066bf2b Role MOCK workflow;fb08f614 IdP/federated mapping MOCK. These are
peer-reported candidates, not read-only reviewed/accepted here. No guessed
LIVE SSO writes. Do not create interfaces merely to match MOCK screens.
Earlier fixed2c460a39's MOCK UNKNOWN persistence path was reviewed only for
that narrow behavior; no inherited UI/runtime acceptance.

Only fixed objects, no foreign worktree changes. Git identity exactly
Xiak <Jellal@aliyun.com>, repository-local. No extra agents/tasks, remote1.3/
.160/.161, withdrawn GitLab/1.5, global settings or Docker/WSL/system restart.
Unique bounded fixtures; Markdown only; no personal mailboxes.
