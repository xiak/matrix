# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Only this
  task's independent worktree is writable. Updated 2026-09-20.
- IAM goal remains ACTIVE. User approved verified-address/SMTP/retry security
  mail and bounded original-primary MFA recovery/backup isolation. Full MFA,
  durable notification, recovery, security settings/report and real UI remain
  unfinished. Do not redefine the goal as preparation or crypto alone.
- Latest fixed/pushed implementation:
  **8ccc632796727261563c952a89e4dfd3ce947144**, private mail contracts/material.
  Exact Verification35498547391 was QUEUED at last GitHub API observation:
  https://github.com/xiak/matrix/actions/runs/35498547391 . Confirm exact SHA
  and all five job conclusions before independent-acceptance claims.
- Source remains IAM35/Audit19/PaaS2; published profile/revision unchanged.
  The mail slice has private pure contracts, no public HTTP, SQL, runtime FILE,
  installation, worker or UI change.
- Read AGENTS, the one owning FEAT (IAM/012 for mail, IAM/009 for MFA), then
  its code/tests. Adoption: docs/adoption/FEAT-006-platform-authorities.md.
  This checkpoint is not a duplicate requirement or acceptance owner.

## Fixed private mail contracts and material

8ccc6327 fixes strict private SecurityMailSMTPChannel and independent
EmailVerificationKeyring codecs in api/iam/v1. Ordinary JSON/formatting
cannot disclose their secrets; no insecure TLS or caller file/URL selector.
The sole EmailVerificationCipherContext binds installation/bootstrap,
Account/USER, original verification, exact recipient, credential/contact
versions and original UTC-microsecond lifetime. Eight-digit uniform random
codes and purpose-separated AES-GCM/HKDF remain pure material, not current
eligibility, a durable attempt budget, consumption or an authentication key.
ASCII address syntax moved to its sole API owner; no compatibility alias.

Exact clean export passed full default race/architecture, vet, modules,
122-file API generation inventory/hash equality and Linux amd64 build.
Six code/test files matched the export. Both private codecs passed bounded
20-second/2-worker fuzz. Existing DB/mailbox SKIPs are not new runtime proof.
IAM/012 owns the detailed first-contact, shared budget, durable lease/retry
design; its proposed HTTP/SQL/worker is not yet implemented/frozen for UI.

## Independently accepted S1a transport

**841ebe89aa55121ac4686dc469006ed10b47f0eb**:
Verification35496641320 exact SHA completed/success for go, node-process,
authority-storage, authority-runtime and authority-process, confirmed by API.
https://github.com/xiak/matrix/actions/runs/35496641320 . This does not fill
the newer contract slice's still-pending independent CI.

Existing IAM authority owns the closed SecurityMail projection;
data/smtp isolates the real external side effect.
Verification and seven security templates have no caller-provided subject,
body, headers, links or attachments. Secret-bearing values redact formatting
and refuse ordinary JSON. This is not an address-verification endpoint.

Only verified STARTTLS/implicit TLS >=1.2, followed by advertised AUTH PLAIN.
No plaintext/insecure fallback or request-supplied channel. Two concurrent
slots, no local wait queue, one connection/recipient, bounded time/input.
Final DATA 250 = ACCEPTED, explicit 4xx/5xx = REJECTED, uncertain completion
= UNKNOWN, effect-before failure = UNAVAILABLE. No implicit retries. Stable
Message-ID binds installation/notification, not exactly-once delivery.

Same production clean export: full default race/architecture, vet, modules,
API generation inventory/hash equality and Linux build passed. Final test
addition: clean-export IAM/architecture race/vet and two complete SMTP runs.
Actual task-exclusive Debian13/Postfix3.10.13, 2CPU/768MiB/Pids128, loopback
dynamic port: synthetic verification/security mail reached real Maildir;
bad password and external relay refused, duplicate ID delivered twice.
Final real runs 5.39s/6.57s; package15.906s. The test container/network were
removed after empty-queue and identity checks; other resources untouched.
Protocol fixtures and this mailbox are not verified USER contact, durable
retry, MFA event-atomic notification, published SMTP config or full S1.

Next mail slice must remain in the same012 owner: implement verified contact,
durable intents/leases/retry and installer private configuration before
exposing a usable endpoint. No generic message
center, shared Audit worker credentials or recovery-by-email authority.
Do not invent new public APIs or deployment FILE contracts without aligning
the current authentication/challenge and installation consumers.

## Independently accepted TOTP/backup preparation

**285706e3adf76fb0c109dad474f06266c8b67ab5** (IAM35 same-snapshot custody):
Verification35494523608 exact SHA completed/success for go, node-process,
authority-storage, authority-runtime and authority-process, confirmed by API.
https://github.com/xiak/matrix/actions/runs/35494523608 . Final handoff sent
to installation owner; it does not inherit installation acceptance.
Predecessors a36a35c2 (IAM34), 92e3073 (original gate corrections),04041d2
(private TOTP material) also have confirmed five-job success in IAM/009.

Installation contract donors: fixed d479e1c57b6458852dd029227d32f3d56df6c5ad
and 2e6714bd95ee7c0d90a289b7b9902539717386d3. Sole custody/lease codec is
api/adapter/installation/v1. No duplicate digest or foreign profile.

- matrix-iam-backup-custody snapshot reads only
  MATRIX_IAM_BACKUP_CUSTODY_DATABASE_DSN_FILE. Dedicated role/login:
  matrix_iam_backup_custody / matrix_iam_backup_custody_login; only
  read_totp_backup_custody(), no table/auth/registration/recovery powers.
- RR READ ONLY snapshot and all retained factor references are one view.
  Canonical lease line, max600s; stdin exactly RELEASE\n plus EOF. Exit0
  only rollback+close; 2INVALID/3FORBIDDEN/6UNAVAILABLE sanitized errors.
  Snapshot is transient, never persistent evidence or current recovery proof.
- Migration-only MATRIX_MIGRATION_IAM_BACKUP_CUSTODY_DSN_FILE. Existing
  migrationprocess exact sorted/unique FILE limit is now5, not arbitrary.
- Real PG18 retained IAM32 executable ->35, apply-twice/verify/restart,
  restricted login, actual pg_dump/restore, interruption, dual authorities
  and original independent IAM/Audit/PaaS/dispatchers passed (IAM/009).
- MATRIX_IAM_TOTP_KEYRING_FILE -> /run/matrix/iam-totp-keyring.json remains
  IAM-only individual read-only. One deployment's replicas share controlled
  material; no auto-regeneration or per-replica key. Registration/custody
  actually compares sealed bootstrap and exact known material commitments.
- Preparation binary rejects ANY retained factor row, including REVOKED,
  at actual Login/Session and readiness. MFA enabling must replace this
  with real state/session behavior, not remove the guard. No active MFA yet.

Preserve ServiceIdentity/lookup_service5, claim7, lookup_session24,
revoke_session6, record9/contract4/evidence5, old canonical/receipt/proof.
S3a password debit remains durable before hashing, max5/60s per USER and
generation, one in-flight/30s, no refund on crash/unknown; Login/ChangePassword
share it. Do not restore no-attempt or raw-hash authentication overloads.

## Coordination and remaining security boundaries

Installation owner01a04149-5dbb-7300-9e4c-31d9e85c8ada,
feat/phase3-mfa-recovery: exclusively owns backup consumer/install/profile
window. It received 285/841 final CI and8ccc6327 pure-contract candidate with
CI pending. Its same-snapshot consumer9815916 has reported final CI success;
it now owns the separate35/18/6+r13 preparation release. Do not import its
profile, WIP, node state or inherited acceptance. Current mail window is
pure IAM contract/design; next runtime/DB/worker and migration-file6 boundary
was requested, not yet approved. No FILE/SQL/shared migrationprocess edit
until that owner alignment; HTTP is still only proposed in IAM/012.
Later CLOSED/reopen must use backup-external epoch, exact immutable intent,
invalidate old Session/challenge/enrollment and fence OTP/attempt state;
backup key availability is not current recovery eligibility. Unimplemented.

UX/UI owner01a07b21-9a0d-7fd0-b090-7827ce18262e, feat/cloud-console-ux,
owns all UI. Current MOCK/report progress is separate, not active MFA wire.
Notify its owner of a fixed strict-union Login contract before real adapter.
Reports preserve UNKNOWN versus FALSE/N/A and actual evidence coverage.

Only fixed verified commits exchanged, no foreign WIP/resources. Local Git
identity Xiak <Jellal@aliyun.com>. Go2/-p2, heavy PG serial race-p1, uniquely
labelled limited resources. No new tasks/subagents. No remote1.3/.160/.161,
withdrawn GitLab/1.5, global changes or Docker/system restart. No personal
email/credentials. Markdown deliverables only.
