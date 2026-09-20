# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Only this
  task's independent worktree is writable. Updated 2026-09-20.
- The IAM goal is ACTIVE, not complete. Do not narrow it to primitives/tests.
- User explicitly approved both pending questions: minimal verified-address/
  SMTP/retry security email, and original protected-primary MFA recovery/
  backup isolation jointly with installation. No new approval is pending
  for those bounded scopes. Implementation/ABI/real acceptance is not implied.
- Design6fa39fda; authorized scope fixedb426541d; latest pushed implementation
  **04041d2d3f7ed55225a5164bc2bc05251d25a6f1** is S2a TOTP private keyring/
  seed-protection foundation. Its exact
  [Verification35485632542](https://github.com/xiak/matrix/actions/runs/35485632542)
  was only QUEUED at last observation. Do not claim CI success yet.
- Previous algorithm source **ad93b84fa1cbe902b148e62a9d0f0924a5473a98**:
  exact [Verification35484114635](https://github.com/xiak/matrix/actions/runs/35484114635)
  confirmed completed/success by API. It does not cover04041d2d.
- Current HTTP Login, SQL, schema/profile, UI and installation remain unchanged.
  Source IAM32/Audit19/PaaS2, IAM product Profile r5 remain as before.
  All requirements/design/evidence stay in IAM/009 and012; adoption in the
  original FEAT006 record. No second roadmap or implementation diary.

## Fixed implementation and checks

Read AGENTS, IAM/FEAT-IAM-009-security-governance.md S2/S3, then actual
api/iam/v1/totp_wrapping.go and authority/totp.go/tests. ADR0004 specifically
owns AccessKey custody; TOTP has a distinct kind/purpose/keyring/codec.

04041d2d freezes Validate/Encode/DecodeTOTPKeyring, TOTPKeyMaterialCommitment,
TOTPKeysetDigest and TOTPSeedContext. Scope includes installationId AND the
single-owner BootstrapDigest; revision1..MaxInt64,1..8 strictly sorted unique
keys, active present, format1, canonical32-byte RawBase64URL material,8192-byte
bound. Ordinary JSON/formatting cannot expose secrets. Per-key commitment
EXCLUDES revision/active; the set digest includes them. Codec cannot prove
historical monotonicity, key retirement or same-snapshot database dependency.
The existing AccessKey uint32BE framing moved byte-preservingly into encoding.go
as credentialBindingBytes; original context/signature/nonce vectors still pass.
No duplicate Audit canonical or generic keyring/provider was added.

Seal/OpenTOTPSeed use independent HKDF-SHA256 and random-nonce AES256-GCM.
Identity binds bootstrap/install,Account,USER,factor,key and format; state and
set revision are not ciphertext identity. Lifecycle must enforce one seal per
factor/key and row CAS for rewrap; these primitives do not implement that.
Original TOTP fixed20-byte/SHA1/6-digit/30-second verifier and purpose-bound
mrc1 recovery verifier remain. A returned time step is not durable consumption.

Focused new and old AccessKey/API/authority race passed. Independent Node
standard-crypto vectors verify material/set hashes, derived key, GCM envelope
and resulting RFC OTP. Private-file and ciphertext fuzz each20sec/2workers:
547018 and705841 executions, no failure; not throughput evidence.
Exact code in clean export passed all default race/architecture-p2/count1,
vet, module verify, full file-set/hash equality after go generate and
Linux/amd64 build; GOMAXPROCS2/GOMEMLIMIT512MiB. External SKIPs are not runtime.
No new PG/container/network/service/remote started. All local test/build
handles are terminal; preserve normal compiler/fuzz caches.
04041 is pushed and supplied to installation and UX peers; CI is not yet
accepted. Do not import their WIP, profile, checkpoint or acceptance.

## Coordination and unresolved gates

Phase3 owner task01a04149-5dbb-7300-9e4c-31d9e85c8ada owns its independent
installation worktree/branch feat/phase3-mfa-recovery:
- Fixed16b42679 credentials/topology/backup code inspected and recorded as
  REFERENCE, not a TOTP implementation.
- Fixede7d31b6f03a885f576ecb0979d8776b6a6abe26d pure CLOSED contract inspected,
  not imported. Peer CI unconfirmed. Concrete api/adapter/installation/v1 is
  its exclusive owner; IAM must not make another codec.
- Peer may add exact AuthenticationRecoveryIntent/digest in that adapter.
  Actual verified signed manifest digests bind complete source/target
  profiles; pure digest does not perform signature/admission/qualification.
- No OPEN/reopen/helper transport/receipt authority frozen. No new revision.
- TOTP same-PG-exported-snapshot custody lease is still unfrozen. A SQL
  function alone cannot keep a cross-process transaction alive. Set digest
  is not a backup's required-key summary. Backups never carry live keyring.
- Single-engine isolation must prove all own old processes unreachable
  BEFORE restore. Atomic host-file replacement does not prove a running
  container sees it. No multi-host HA claim.
- Long-lived backup-external capability proves source, not later Account/
  USER status or platform revocation. Restoring T0 then signing its old
  expected values cannot prove T1 current eligibility. Do not reopen until
  password/Key/Role/attachments/ordinary USER/contact rollback is covered,
  not just primary's factor. Existing password recovery is not MFA recovery.
- Preparation release may not ignore later factor/Session semantics on OPEN
  data; gate-aware name alone is not a safe rollback predecessor.
- Installation handles protected configuration only; IAM owns012 mail/
  verification/retry. Real SMTP channel and verified acceptance mailbox have
  not been provided; do not borrow personal credentials or fake delivery.

UX/UI owner01a07b21-9a0d-7fd0-b090-7827ce18262e may independently implement
high-fidelity MOCK. A/B/D/G/H are stable flow skeletons; state words do not
freeze wire enums. No real MFA/UI acceptance. It has04041 design locations.
First mandatory setup has no Session: a currently qualified ENROLLMENT
challenge may verify only a first notice address after forced password
change. It cannot replace an existing trusted address or serve lost/corrupt/
restored identities. Mail is not an MFA or recovery factor. This prerequisite
and unavailable-channel state must not be hidden by issuing a weak Session.

## Continue the goal

Confirm04041 exact CI without restarting accepted gates. Continue009's actual
shared attempts/committed failures and restricted challenge vertical slice,
and012's closed address/notice contract in parallel with peer installation.
Current Login/ChangePassword still hash inside callback transactions and
callback errors roll back; no shared durable attempt budget exists yet.
No MFA endpoint/SQL consumption/session-strength/runtime acceptance exists.
S3's exactly two security-settings actions remain designed, not granted.
No Refresh Token, new Identity/STS service, blanket SELF/SYSTEM or online
administrator resetting another person's MFA. Recovery eligibility remains
a real gate, not an excuse to infer new authority.

Preserve S1 source3080922f; S1b cumulative7cf857bb/CI35324569376 accepted.
Capacity observation7f02d419/CI35338576115 accepted only within011 limits.
lookup_session24/revoke_session6,lookup_service5/claim7,record9/contract4/
evidence5, ServiceIdentity and old Audit canonical/chains stay unchanged.
No new tasks/subagents. Local Xiak <Jellal@aliyun.com> only.
Go2/-p2; heavy PG serial race-p1 with unique labels and explicit quotas.
Use clean exports outside repo to avoid ignored duplicate build sources;
temporary indexes never replace the real index. No lowering cost/gates.
No remote1.3/.160/.161, withdrawn GitLab/1.5, foreign resources or global
configuration. Absolute machine paths are not portable memory.
