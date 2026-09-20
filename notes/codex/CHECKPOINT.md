# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam; only this
  task's independent worktree is writable. Updated 2026-09-20.
- IAM goal remains ACTIVE. User approved minimal verified-address/SMTP/retry
  security email and original protected-primary MFA recovery/backup isolation
  with installation. No further scope approval is pending for those increments.
- Latest pushed production **31c18531957ea6d2b52a8ac2cdcd084e13287031**:
  S3a shared password attempts, source IAM33/Audit19/PaaS2; published profile
  unchanged. Exact [Verification35488659078](https://github.com/xiak/matrix/actions/runs/35488659078)
  was QUEUED at last observation. Confirm exact SHA before claiming success.
- Previous rollback **04041d2d3f7ed55225a5164bc2bc05251d25a6f1**:
  exact Verification35485632542 completed/success confirmed by API; independent
  TOTP private-keyring/seed-protection foundation only, not runtime MFA.
- Requirements, design and acceptance belong to IAM/009 and012; adoption
  remains docs/adoption/FEAT-006-platform-authorities.md. No parallel roadmap.

## Fixed S3a behavior and real evidence

Read AGENTS, IAM/FEAT-IAM-009-security-governance.md S3a, then authentication.go,
management.go, PostgreSQL transaction/000001_authority and original tests.
Same real USER/generation, realm alias/ID, replica and Login/ChangePassword
share five reservations per60sec, max one in-flight,30sec attempt expiry.
Debit commits BEFORE real/dummy verification; failure/crash/cancel/unknown/
expiry never refunds. Sequence increases across window/generation changes.
Only complete single-factor issuance/password change resets; future partial
MFA must not call that successful issuance path. Hashing is outside DB locks.

Final mutation consumes exact attempt ID/sequence/purpose/actual Session,
current Account/User versions and credential generation under original lock
order, with lock-after database time. Session/password/outbox stays atomic.
Reserve SQL five inputs/seven outputs; issue_session and change_password
each nine inputs. Remove no-attempt overloads and lookup_password; lookup_login
is private canonical realm resolver. API/worker have no raw hash/table/consume
permissions. SQL trusts the actual IAM verifier, not a fabricated Go proof.
Each Authority has two nonqueued crypto slots; only Login/ChangePassword
returns429 iam.authentication.busy + Retry-After:1 at local capacity. All
successful wire shapes unchanged; identity-dependent suppression remains401.
This is not Account fairness, flood capacity, MFA or full009 acceptance.

Own native PostgreSQL18.6 with two logical CPUs/1GiB/24process job limits,
16connections/64MiB shared buffers/no parallel workers, Go2/512MiB/race-p1:
- New shared-budget final gate63.39s, including real expiry and duplicate/
  wrong-purpose Session SQL attacks; rejected attacks do not consume proof.
- Original IAM HTTP84.36s, password options/races/platform protection retained.
- Actual fixed7cf857bb IAM32 executable retained upgrade/restart20.10s.
- Independent IAM/Audit/PaaS/two-dispatcher real process gate68.66s.
- Same final production source clean-export all default race/architecture;
  final extra test also passed real PG. Final vet/module verification,
  724-file generation inventory/hash equality, Linux amd64 build passed.
Docker was unavailable; no shared engine was started or restarted. Own native
PG stopped normally, no live test/server handles remain. Fixtures are synthetic.
Unknown/expired/NULL lineage, old receipt/canonical/proof stay protected.
No release compatibility is inferred from this source-schema experiment.

## Coordination and next actual MFA slice

Installation owner01a04149-5dbb-7300-9e4c-31d9e85c8ada has independent
feat/phase3-mfa-recovery; only fixed objects, no WIP/environment borrowing.
- Its fixed29421c16f63b9a17caf6067a67df0a8bde26865e supplies key generation/
  scope/replay/mount; reported CI35487240158 success. No runtime consumer,
  profile or backup/reopen evidence imported. b17b7a is duplicate04041 codec.
- TOTP FILE/path frozen: MATRIX_IAM_TOTP_KEYRING_FILE,
  /run/matrix/iam-totp-keyring.json; IAM-only individual read-only mount.
  IAM runtime registry/dependency consumer remains unimplemented.
- Concrete CLOSED/recovery-intent codec belongs api/adapter/installation/v1
  on its branch. Fixed59da642/4ca0bdd are not imported; inspect exact objects
  before consuming, not its moving branch. No new shared ABI/revision frozen.
- Same-snapshot custody needs dedicated signed IAM helper/local role holding
  a REPEATABLE READ READ ONLY exported snapshot until pg_dump imports it.
  Registered commitments and all actually needed factor keys use that view.
  A keyset digest is not the required-key summary; raw keyring never goes to
  backup/helper, material is not bundled in backup. Scope/current supersets,
  active/pending/retained ciphertext references and bounded output fail closed.
- Preparation N must refuse unsupported factor/Session behavior at actual
  authentication paths, not merely /ready=false. No generic capabilities list.
- Future reopen must consume exact CLOSED intent and advance backup-external
  recovery epoch; Session/challenge/enrollment issuance AND lookup must fence
  restored states. End old pending ceremonies, guard current OTP window and
  attempts, immutable receipt/outbox. No public recovery or resurrection of
  revoked role/Key/password/contact authority. This is not implemented.
- Long-lived local capability proves source, not current qualification. Root
  whole-machine rollback is outside supported product backup/recovery threat
  model. No source profile migration permission is inferred.

UX/UI owner01a07b21-9a0d-7fd0-b090-7827ce18262e, feat/cloud-console-ux,
owns /console/access and real browser tests. Mock63a6ea/5bc618/f0ae remain its
independent preview; no IAM/UI evidence imported. It received31c18531 pending
CI and429 semantics. Current Policy/PolicyVersion + PolicyAttachment is the
online authority; historical RoleBinding IDs are not a legacy online UI.
Role/RoleSession is real trust/assumption, not the old BuiltinRole enum.

After confirming31c CI, continue actual MFA material consumer, enrollment/
confirm, restricted login/recovery challenge, one-time OTP and Session strength
in existing IAM owners; freeze mutually exclusive Login wire with that slice
and send exact SHA to UI. Minimal012 email and protected-primary/backup
recovery remain release prerequisites, not substitutes for actual MFA.
FEAT006/007 old MFA-deferred prose must be narrowed with corresponding owner
implementation/evidence; do not mark completed by editing documentation.
No real SMTP acceptance channel/mailbox is configured yet. Do not borrow
personal credentials or treat a wire fixture/Audit task as mail delivery.

Preserve current lookup_session24/revoke_session6,lookup_service5/claim7,
record9/contract4/evidence5,ServiceIdentity and old Audit canonical/chains.
No new tasks/subagents. Local Xiak <Jellal@aliyun.com> only.
Go2/-p2; heavy PG serial race-p1 and unique resources/quotas. Use clean exports
outside repo; isolated temporary Git indexes never replace the real index.
No remote1.3/.160/.161,withdrawn GitLab/1.5,foreign resources/global changes.
