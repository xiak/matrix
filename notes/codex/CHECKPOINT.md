# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam; only this
  task's independent worktree is writable. Updated 2026-09-20.
- IAM goal remains ACTIVE. User approved minimal verified-address/SMTP/retry
  security email and original protected-primary MFA recovery/backup isolation.
  Do not stop at preparation/crypto or redefine the goal smaller. Full MFA,
  notification, recovery, security settings/report and real UI remain unfinished.
- Latest fixed and pushed **a36a35c2eddbeb7c76a8d7c140e180b24a169aab**:
  IAM34 TOTP runtime custody preparation, Audit19/PaaS2 source, published profile
  unchanged. Exact Verification35491802049 was QUEUED at last observation:
  https://github.com/xiak/matrix/actions/runs/35491802049 .
  Confirm exact SHA/conclusion before claiming independent acceptance.
- Predecessor **92e3073e290104089af3e02ddaaa6a7d8fb2c457** CI35489211152
  completed/success (go,node-process,authority-storage,authority-runtime,
  authority-process) independently verified by GitHub API.
  Production31c18531 S3a shared password attempts remains; 92e corrects original
  Audit/bulk-session fixtures, not production relaxation. Original31c CI failed.
- Foundation **04041d2d3f7ed55225a5164bc2bc05251d25a6f1** CI35485632542
  success: independent private TOTP keyring, commitments and seed protection.
- Requirements/design/evidence belong IAM/009 and012; fixed adoption belongs
  docs/adoption/FEAT-006-platform-authorities.md. No new roadmap or diary.

## Fixed IAM34 behavior and evidence

Read AGENTS, IAM/009 S2a/S3a, then existing IAM owners. Network process requires
MATRIX_IAM_TOTP_KEYRING_FILE, checks actual sealed bootstrap, registers nonsecret
scope/revision/active/digest/key commitments and then full readiness before Serve.
Original protected file mechanics shared with AccessKey, never its purpose/key.
New000012_totp protects immutable registry/history and real seed ciphertext.
register_totp_keyset(jsonb) has no HTTP route; exact replay read-only, same ID
cannot change material, same revision cannot change set, no downgrade or
retirement. Runtime read holds SHARE for the request transaction.

Actual Login reservation/final issuance, Session/Role/Key and readiness compare
the process's exact material snapshot to current registration. This preparation
binary rejects ANY retained authenticator row, including REVOKED. It cannot
infer never-bound or enable MFA. Enabling must replace the rule with real factor
and Session semantics, not delete a check. Historical service/outbox stays
independent. No raw TOTP material retained by the preparation Authority.

Own native PG18.6 under2 logicalCPU/1GiB/24process job;16connections/64MiB buffers,
Go2/512MiB/race-p1 serial:
- custody2.52s: exact replay/negative atomicity, held reader blocks registration,
  two conflicting revision writers only one wins, real retained REVOKED cipher
  refuses actual Login/Session/restart, apply-twice retains history.
- Original IAM HTTP104.94s.
- Actual fixed7cf857bb IAM32 executable ->34 retained/restart15.13s.
- Full independent IAM/Audit/PaaS/two dispatcher gate106.91s: actual runtime
  logins, real new IAM registration makes old two live processes refuse direct
  Login/Session503, matching process preserves original valid Session.
- Final same production clean-export all default race/architecture+vet passed;
  modules,728-file generation inventory/hash equality,Linux amd64 build passed.
No Docker/remote/other workspaces borrowed. These are source schema tests, not
signed release compatibility, active MFA, same-snapshot backup or reopening.

S3a unchanged: five durable attempts per60s perUSER/generation; maxoneinflight,
30s expiry; Login/ChangePassword share. Debit commits before real/dummy hash;
crash/failure/unknown/expiry no refund. Only complete issuance/change resets.
Two local crypto slots,429 iam.authentication.busy/Retry-After1 only capacity,
identity-specific suppression401. No-attempt/raw-hash overloads removed.
Preserve lookup_session24/revoke_session6,lookup_service5/claim7,
record9/contract4/evidence5 and old canonical/receipt/proof.

## Next bounded work and coordination

Installation owner01a04149-5dbb-7300-9e4c-31d9e85c8ada,
feat/phase3-mfa-recovery; fixed objects only, no WIP/resource borrowing.
- TOTP FILE/path frozen: MATRIX_IAM_TOTP_KEYRING_FILE and
  /run/matrix/iam-totp-keyring.json, IAM-only individual read-only.
- Fixed **d479e1c57b6458852dd029227d32f3d56df6c5ad**, CI35491112269 success
  independently confirmed: sole api/adapter/installation/v1 custody/lease.
  This branch lacks its authentication_recovery.go dependency. Read exact fixed
  closure before narrow adoption, not installation moving branch/profile/docs.
- Frozen next helper: matrix-iam-backup-custody snapshot; only
  MATRIX_IAM_BACKUP_CUSTODY_DATABASE_DSN_FILE; role/login
  matrix_iam_backup_custody / matrix_iam_backup_custody_login.
  Only read_totp_backup_custody(), no table/registration/auth/recovery privileges.
  Own RR READ ONLY tx reads all retained ciphertext references and exports
  snapshot; exact canonical lease line, hard10min. stdin exactly RELEASE\n then
  EOF; only normal rollback+close exits0. Before-complete EOF/extra bytes/
  deadline/DB failure closes nonzero. Codes2 INVALID,3 FORBIDDEN,6 UNAVAILABLE
  prefixed IAM_BACKUP_CUSTODY_; sanitized stderr only. No time/SQL selector.
- Installation accepts write8+close stdin after live-snapshot pg_dump, dump
  validation and trusted local keyring superset; waits0 before manifest.
  SnapshotID never persisted. Missing/null != explicitly proven empty keys.
  Purpose-limited migration DSN env:
  MATRIX_MIGRATION_IAM_BACKUP_CUSTODY_DSN_FILE. Source targetIAM35/Audit19,
  no release revision allocated; own implementation/real gates still TODO.
- No backup digest is current recovery qualification. Later CLOSED/reopen
  must use backup-external epoch, exact intent/immutable completion, invalidate
  old Session/challenge/enrollment, fence OTP current window and attempts, and
  never resurrect revoked authority/contact/password/Key. Still unimplemented.
- Real SMTP channel/mailbox not configured. Wire fixture/Audit enqueue !=mail
  acceptance. No personal credentials or fake delivery evidence.
- UX/UI01a07b21-9a0d-7fd0-b090-7827ce18262e on feat/cloud-console-ux owns all UI.
  Current MOCK/report work is separate, no real MFA wire frozen yet. Notify
  exact Login strict-union SHA before its real adapter. No UI import/acceptance.
  Reports must preserve UNKNOWN versus FALSE/N/A and actual evidence coverage.

Keep next implementation in IAM/API/SQL and original tests; installer exclusively
owns installation/releasebuild/profile integration. No new tasks/subagents.
Local Xiak <Jellal@aliyun.com> only. Go2/-p2; heavy PGserial race-p1, unique
limited resources. Clean exports outside repo, task-specific temporary Git index.
No remote1.3/.160/.161,withdrawnGitLab/1.5,foreign resources or global changes.
