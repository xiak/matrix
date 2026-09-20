# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Only this
  task's independent worktree is writable. Updated 2026-09-20.
- IAM goal remains ACTIVE. User approved real security mail and bounded
  original-primary MFA recovery/backup isolation. Full MFA, recovery,
  security settings/report and real UI remain incomplete. Crypto/custody
  and notification preparation are not the completed goal.
- Latest fixed/pushed production candidate:
  **5e185e95c9d474443a26171a5f2616816e53bdba**, pinned OTP construction
  replacement only. Its exact Verification35506581374 is still running:
  https://github.com/xiak/matrix/actions/runs/35506581374 . Verify all five
  jobs before final handoff; do not cancel it with another production push.
- Source IAM36/Audit20/PaaS2; published profile/revision unchanged. No
  installation, releasebuild, UI or other worktree changes are adopted.
- Read AGENTS, IAM/012 for mail or IAM/009 for MFA, then owning code/tests.
  Fixed adoption belongs to docs/adoption/FEAT-006-platform-authorities.md.

## Fixed first-contact and durable mail

07aa50627318708ed4d3ac9ce481b1e5829669d6 / Verification35504960145 was
rechecked through authenticated GitHub API: exact SHA, go/node-process/
authority-storage/authority-runtime/authority-process all completed/success.
Both installation and UX received that final confirmation, not their own
integration or release acceptance.

07aa5062 owns four notification-contact HTTP routes, strict private request
codecs and current LOGIN_SESSION first-address-only workflow. Contact
NONE/VERIFIED, original verification state and SMTP observation are separate.
No Role/Service/challenge carrier, caller identity selector, existing-address
replacement, MFA enablement or mail-based authentication/recovery.

The original shared password budget adds a closed intent-bound purpose;
reserve/consume have seven parameters, no old five-parameter bypass.
Confirmation debit commits before code comparison. Final transaction checks
current Account/USER/Session/generation and original intent/expiry. Contact,
completion, immutable IAM fact and safety notice commit together. The two
new tenant Audit actions require same actual USER actor/target, never email,
password, code or envelope. Committed facts and safety notices remain
deliverable after USER disable; old address codes do not remain acceptable.

matrix-iam-notification-dispatcher has its own role/login, two connections
and two bounded loops. Claim commits before SMTP, 45s fence/lease and bounded
retry; expired in-flight means UNKNOWN, not unsent. DATA250 is ACCEPTED,
not final delivery/read or exactly once. Keyset/registration and sealed
bootstrap scope are checked before work; missing/wrong custody fails closed.

Frozen role/login: matrix_iam_notification_worker /
matrix_iam_notification_worker_login. Migration adds exactly sixth protected
FILE MATRIX_MIGRATION_IAM_NOTIFICATION_DSN_FILE. API/worker consume
MATRIX_IAM_EMAIL_VERIFICATION_KEYRING_FILE; only worker consumes
MATRIX_IAM_SECURITY_MAIL_SMTP_CHANNEL_FILE and
MATRIX_IAM_NOTIFICATION_DATABASE_DSN_FILE. Public process selectors:
MATRIX_IAM_NOTIFICATION_WORKER_ID / MATRIX_IAM_NOTIFICATION_LISTEN_ADDRESS.
No TOTP/AccessKey/bootstrap/recovery/Audit-worker capability for mail delivery.

IAM/012 owns real PG mail/lease/attack evidence, HTTP + independent restricted
worker + actual Postfix Maildir code confirmation, historical safety notice,
controlled confirmation/lifecycle races, Audit all-action/chain checks,
original service processes, retained IAM32 executable ->36 and actual
snapshot/dump. Full default race/architecture, vet, modules, generation and
Linux build passed. SKIP is not runtime evidence. Contact HTTP is an
in-process real handler; the mail worker is a separate executable.
All task fixtures from these gates were removed; no other resources touched.

Remaining: installer configuration/release; real UX; actual MFA
enrollment/login/recovery/step-up and safety events; existing-address
replacement; aggregate operational alerts; post-restore contact/pending-intent
isolation. No claim of complete S1 or MFA.

## Independently verified foundations

- 8ccc632796727261563c952a89e4dfd3ce947144 mail codecs/material:
  Verification35498547391 exact SHA and all five jobs success, rechecked
  through authenticated GitHub API (not its former queued state).
- 841ebe89aa55121ac4686dc469006ed10b47f0eb SMTP:
  Verification35496641320 all five success, bounded real TLS/Postfix evidence.
- 285706e3adf76fb0c109dad474f06266c8b67ab5 snapshot custody:
  Verification35494523608 all five success; IAM/009 owns restricted helper,
  retained data and actual dump evidence. Contract donors d479e1c5/2e6714bd.

Preserve ServiceIdentity/lookup_service5, Audit claim7, lookup_session24,
revoke_session6, record9/contract4/evidence5 and old canonical/receipt/proof.
Preparation rejects ANY retained TOTP factor at Login/Session/readiness.
MFA enabling must replace that with actual lifecycle/session rules, not
remove a guard or infer authentication from missing state.

5e185e95 reuses github.com/pquerna/otp v1.5.0 at upstream
5971b1ef1d6652fec2caed37f11e5cacd9249f78, pinned Go sums. Original local OTP
construction is deleted. Only authority may import otp/hotp; fixed SHA1/6
digits/30 seconds, strict canonical input BEFORE upstream normalization,
database time and all-match collision/replay checks remain MATRIX rules.
The library does not persist consumption or authenticate a Session.
RFC/independent Node vectors, focused race and 20s/2-worker fuzz passed.
Per-command Go1.26.7 full default race/architecture, vet, modules, generation
and Linux build passed. No global Go setting or schema/API/profile change.
govulncheck v1.8.0 on actual IAM entry found zero reachable/imported-package
alerts with Go1.26.7, three unused-module alerts; not a security certification.
The default local Go1.26.3 had seven reachable standard-library findings;
installation was told to assess its own actual signed build, not inherit this.

## Shared owners

Installation01a04149-5dbb-7300-9e4c-31d9e85c8ada exclusively owns
layout/localmachine/topology/release/releasebuild/FEAT005/offline. It received
07aa5062 with final five-job CI success. IAM owns its contracts/migration/worker
and only sixth-FILE shape in shared migrationprocess. Restoration CLOSED,
current recovery qualification and safe reopen remain unimplemented here.
Key availability/old receipt cannot prove current post-backup authority.

UX/UI01a07b21-9a0d-7fd0-b090-7827ce18262e owns all UI on its branch.
It received07aa final CI and first-contact limits. loginProtection
and SSO selection stay explicit MOCK, no invented LIVE endpoint. Existing
Role/STS fixed62a18a48 plus0567c8b2 handed off for current public contracts;
peer must independently verify its own integration/browser.

Only fixed objects exchanged; never foreign WIP/profile/acceptance.
Xiak <Jellal@aliyun.com>, Go2/-p2, heavy PG serial race-p1 and unique limits.
No extra agents/tasks, remote1.3/.160/.161, withdrawn GitLab/1.5, global
configuration, Docker/WSL/system restart or prune. Markdown only, no personal
mailboxes or credentials.
