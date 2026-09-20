# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Write only
  this task's independent worktree. Updated 2026-09-20.
- IAM goal remains ACTIVE. User approved actual security mail and bounded
  original-primary MFA recovery/backup isolation. Full MFA, security settings,
  recovery, reports, real UI and release acceptance remain incomplete.
- Latest fixed/pushed backend: **f5cec0e132ad18900d9a5a5629eae04fda4817f1**.
  Source IAM37/Audit21/PaaS2; published profile/revision unchanged.
- Exact https://github.com/xiak/matrix/actions/runs/35520219893 is FAILURE.
  All five jobs have runner_id=0/steps=0; GitHub annotations say account
  payments failed or spending limit needs increasing. Nothing ran.
  Independent CI remains missing. Do not weaken gates/change billing or
  repeatedly rerun while the external condition is unchanged.
- Read AGENTS, IAM/009 for MFA or IAM/012 for mail, then owning code/tests.
  Fixed adoption: docs/adoption/FEAT-006-platform-authorities.md.

## Fixed backend slice

f5cec0e1 replaces password-only authentication for actually BOUND users.
LoginResponse strictly separates AUTHENTICATED from CHALLENGE_REQUIRED.
Only LOGIN/TOTP and its verified PASSWORD_CHANGE child exist currently.
Challenge secrets are not Session/Role/Service bearers.

Self active nonforced LOGIN_SESSION can read/start/query/cancel first TOTP
enrollment. APPLIED provisioning is one-time; replay returns metadata only.
Verified contact is checked before password reservation and again in the
final transaction. Confirmation consumes OTP, binds factor, issues ten
hashed recovery codes once, commits notice/iam.authenticator.bound and
revokes all old Sessions. Reauthenticate.

Bound login uses five-minute challenges, maximum three pending, shared
USER five/ten-minute attempt budget and durable reservations. Cross-replica
OTP consumption is atomic. PASSWORD_TOTP Session facts are immutable.
Forced-change exchanges verified TOTP for a distinct PASSWORD_CHANGE
challenge without extending expiry/issuing a Session. Its completion bumps
credential generation, revokes all old Sessions/challenges and requires
normal new login. Existing /v1/auth/password retention semantics are unchanged.

Recovery codes are issued but NOT consumable/regenerable yet. First forced
enrollment, recovery/rebinding, step-up/security-settings and complete release
remain unimplemented/unaccepted. Known lifecycle checks replace ANY-factor
rejection, but unknown/corrupt history stays closed. Actual contract/readiness
checks include tables/constraints/RLS/ACL/function shapes/triggers.
Old USER state initializes only if the original state table was absent,
through existing account_roots/tenant scope. Replay never repairs missing
authority into NEVER_BOUND.

Standard construction is github.com/pquerna/otp v1.5.0, fixed upstream
5971b1ef1d6652fec2caed37f11e5cacd9249f78, SHA1/6digits/30seconds.
Only authority imports it; MATRIX owns strict input/database time/replay,
custody/budgets/transactions. No duplicate HMAC-OTP remains; no certification.

## Local evidence and limitations

FEAT009/012 own evidence. Go1.26.7/GOMAXPROCS2/GOMEMLIMIT512MiB full default
race/architecture, vet, modules, all122 tracked API hashes and Linux build pass.
Default skips are not runtime evidence. Real PG18.4 was serial race-p1:

- Independent IAM pair/Audit/PaaS/two dispatchers74.71s: original scenarios,
  real TCP loss after binding/password commits, IAM restarts, cross-process
  one OTP success, cross-service carrier rejection, disabled-USER historical
  Audit append/replay/full chain. Contact HTTP is real but code transport uses
  synthetic fixture decryption, not SMTP.
- TOTP enrollment package37.688s including33 schema/ACL damage checks and
  missing-state migration denial; custody2.28s.
- Notification86.58s/package90.146s, actual lease/retry/current-authority races.
  SMTP subtests explicitly skipped in final round; prior actual Postfix
  evidence stays separately scoped, not inherited as final release acceptance.
- Actual fixed IAM32/36 binary retained upgrade14.01s/14.90s, Role process18.62s,
  Audit storage5.20s/retained tenant partition0.22s. Not release/N-1 permission.
- Exact owner/task/ID checked; current fixture containers/networks/volumes
  removed, labels show zero. No shared/remote services restarted.
  Older denied temporary-file cleanup remains manual; do not bypass rejection.

Original5e185e95 Verification35506581374 failed an actual Audit runtime-login/
bounded-connection probe; cause unknown. Only sanitized failure diagnostics
were added. Subsequent local passes do not rewrite its CI. 07aa5062 mail/contact,
285706e3 custody,841ebe89 SMTP,8ccc6327 codec have independently verified
five-job CI success per their owning FEATs.

## Next work and shared ownership

Installation01a04149-5dbb-7300-9e4c-31d9e85c8ada received f5cec0e1 and exact
CI no-run boundary. It owns release/profile/topology/CLI/journal/offline.
Next jointly freeze purpose-limited close/inspect/reconcile/reopen:
pre-restore IAM close is overwritten by old DB. External durable CLOSED must
precede destruction and SAME closure must reconcile restored DB before any
normal auth process opens. Old receipt/NOT_FOUND/unknown never creates new
intent/epoch. No new ABI/schema/revision frozen; existing credential recovery
is not this capability. Epoch/key/primary identity alone cannot prove current
restored USER/password/Key/Role/attachments/contact/factor authority.
Missing current proof stays closed; no invented recovery bypass.

UX/UI01a07b21-9a0d-7fd0-b090-7827ce18262e owns all UI on its own branch.
It received f5cec0e1 public contract/no-CI/no-release boundaries. Account rules
remain explicit MOCK, no guessed LIVE endpoint/authorization.
Read-only review of6d8825a3 required keeping UNKNOWN after both save and
preview journaling fail, even after successful reload/remount.
Fixed2c460a3904daebcd5c00e4cb9683e89ab8b169b4 has been read-only reviewed:
session-scoped UNRECOVERABLE survives ordinary workspace reload/remount and
closes query/secret entry. Accepted only that MOCK path, not LIVE persistence
or peer test/browser acceptance. UX is adapting the fixed login union next.

Installation requested missing f5 ancestors. Against fixed
e08b837ad1a6275a2efedbac0ef4be6d1495b91b, sent minimal ADAPT sequence:
ad93 recovery-code credential hunks +5e final totp/library (not old algorithm),
841ebe89 SMTP,8ccc6327 private mail,07aa5062 contact/worker,thenf5.
e08 already has04041d wrapping/285706 custody and31/a36 password reservations.
Do not import unrelated own-Session directory/bulk APIs, docs or workflow;
preserve peer PaaS6/host/Audit installation actions. Actual e08 old binary
retained upgrade remains peer responsibility; same schema numbers are not
proof of matching reduced API/ABI or accepted release compatibility.

Preserve ServiceIdentity/lookup_service5, Audit claim7, lookup_session24,
revoke_session6, record9/contract4/evidence5, old canonical/receipt/proof.
Only fixed objects; no foreign WIP/checkpoint/profile/acceptance.
Local identity Xiak <Jellal@aliyun.com>. No extra agents/tasks, remote1.3/
.160/.161, withdrawn GitLab/1.5, global settings or Docker/WSL/system restart/
prune. Unique bounded fixtures. Markdown only; no personal mailboxes.
