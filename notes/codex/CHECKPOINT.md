# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Only this
  task's independent worktree is writable. Updated 2026-09-20.
- User requested continuing the IAM goal from the detailed MFA design.
  The goal is ACTIVE, not complete; do not narrow it to primitives or tests.
- Design fixed and pushed: **6fa39fda**. IAM/FEAT-IAM-009-security-governance.md
  owns S2/S3 details; its existing adoption record owns source decisions.
- Latest pushed implementation: **ad93b84fa1cbe902b148e62a9d0f0924a5473a98**,
  first S2a internal TOTP and purpose-bound recovery-code primitives.
  [Verification35484114635](https://github.com/xiak/matrix/actions/runs/35484114635)
  was confirmed for the exact SHA. Go/node-process completed successfully;
  authority-storage was running and authority-runtime queued. No overall
  CI success claim.
- This slice changes only authority credential/TOTP code and tests plus009
  and adoption. No public API, SQL, current authentication path, UI,
  installation, workflow, schema or release profile change.
  Source IAM32/Audit19/PaaS2 and IAM product Profile r5 remain unchanged.

## Current implementation and evidence

Read AGENTS, IAM/FEAT-IAM-009-security-governance.md S2/S3, then the actual
authority code/tests. ADR-0004 is specifically AccessKey custody; TOTP
does not reuse its keyring, wrapping purpose or private codec.

TOTP uses20-byte random seed, canonical Base32, HMAC-SHA1,6 ASCII digits,
30 seconds and a fixed adjacent-step window. The pure verifier takes an
authoritative database instant and the factor's locked consumption watermark.
It returns only a candidate step, rejects any consumed matching step and
handles the independently found adjacent collision at910737/910738.
-1 means proven never consumed, never missing/unknown. No local replay cache.

Recovery codes are mrc1 plus128 random bits in strict unpadded Base64URL.
The one-way verifier binds purpose, installation, Account, USER, batch and
code ID. This is not a generic bearer type, password-reset capability or
completed recovery. Original Secret redaction/serialization remains.
No seed envelope, enrollment, challenge endpoint, SQL consumption, attempt
budget or MFA-enabled login is implemented by this fixed slice.

Local evidence: six focused behavior tests with race; original authority/API
race and vet;20-second/2-worker fuzz completed83581 executions, no failure.
RFC vectors and independent Node standard-crypto vectors cover epoch/2038/
maximum date, windows/collision and recovery verifier. They are synthetic
algorithm oracles, not real authenticator/browser acceptance.
Clean-source Go1.26.3 Windows export passed all default race tests-p2/count1,
architecture, vet and module verification; Linux/amd64 build passed.
GOMAXPROCS2/GOMEMLIMIT512MiB. Default external SKIPs are not PG/runtime gates.
No PG/container/network/service/remote resource started; all local test/build
handles are terminal. Preserve normal compiler/fuzz caches.

## Next scope and dependencies

Confirm the exact-SHA CI without restarting unchanged or terminal gates.
Continue009's declared slices, not another repetition of accepted Session/
capacity work. Shared durable attempts and committed rejection are required
before MFA can open. Current Login/ChangePassword still verify passwords
inside the old callback transaction; callback errors roll back. Do not claim
rate limiting exists or store a counter only in a rolled-back error path.

Public login eventually uses a strict authenticated/challenge union, never
a half-valid Session. Initial enrollment, proven voluntary removal, lost
factor and corrupt/unknown state have distinct qualifications. Root and
unrevoked platform attachment protections remain. security-settings is not
an authorization Policy; exactly two designed read/update actions are
planned, not registered/granted. Approval to continue does not mean shared
implementation has been accepted or that these APIs are currently usable.

On2026-09-20 fixed design6fa39fda was sent to existing peers for bounded
contract review; following explicit user approval, each now has its own
bounded work below. No foreign WIP/environment is read or modified:
- Phase3 task01a04149-5dbb-7300-9e4c-31d9e85c8ada returned a read-only review.
  Its fixed installation source16b42679 was inspected at credentials.go,
  topology.go and the backup commitment test, and recorded as REFERENCE.
  It owns protected material/configuration and closed restore isolation.
  It may own the concrete api/adapter/installation/v1 gate contract; IAM
  owns TOTP private API/codec and authentication rules. No new revision yet.
- UX/UI工程师01a07b21-9a0d-7fd0-b090-7827ce18262e received the interaction
  proposal. Its later request to do high-fidelity MOCK has been answered:
  restricted login/enrollment/recovery/error flows and S1b are appropriate,
  wire enums and mail/recovery integrations remain unfrozen. MOCK is not
  real MFA acceptance. It owns UI/browser; no UI edits here.

Phase3 confirmed four unfrozen dependencies:
1. Dedicated TOTP keyring bound to installationId AND bootstrapDigest,
   keysetRevision/activeKeyId and multiple keys. IAM supplies a same-snapshot
   nonsecret custody summary of all required key IDs/commitments for backup.
   Backups must not archive or overwrite live keyring material.
2. Installation seals a restore authentication CLOSED barrier outside the DB
   rollback scope, consumed by every IAM route/readiness; old gate-unaware
   releases must be rejected before effects. ABI/capability not frozen.
3. Reopening requires trustworthy post-backup security evidence OR independently
   authorized invalidation/rebinding. Neither exists. Original password-only
   recovery does not authorize MFA recovery or prove no later revocation.
4. FEAT012 S1 now owns minimal security email, with installation protected
   SMTP configuration. No real channel, verified recipient or delivery yet.
   Audit or a mock inbox cannot substitute.

The user explicitly answered YES to both async questions: implement minimal
verified-address/SMTP/retry security email, and jointly implement bounded
original protected-primary MFA recovery/restore isolation. These approvals
are not pending. FEAT009/012 now own their scope; current recovery evidence,
same-snapshot custody, gate and notification ABIs/runtime remain unaccepted.
A backup-external long-lived capability proves source, not absence of later
User/Account disablement or platform revocation. Do not reopen from old DB
expected values. Do not claim a preparation release is safe merely because
it understands an OPEN marker but ignores later MFA/Session state.
No new tasks/subagents, new generic recovery system, blanket SYSTEM actor,
Refresh Token or physical Identity/STS split.

## Preserved accepted rollback points

- S1 own-session3080922f6ae1871f1c351d5ee30f03551fc3c605.
- S1b production159bb302fed89161c4b60afeb4a6f41f9bd99820, cumulative
  7cf857bba48eb5d7da487162c43e8f52534db133 / Verification35324569376,
  five checks successful. Evidence stays009; UI/full009 not accepted.
- Independent account-interference measurement7f02d41960f6ca74e49b24f895ad8fc649fc5e49
  / Verification35338576115, five checks successful. All measurements and
  limits stay011. Neither observations nor this MFA slice prove fairness,
  overload enforcement, production capacity or database HA.
- lookup_session24/revoke_session6, lookup_service5/claim7,
  record9/contract4/evidence5, ServiceIdentity and old canonical/chains remain.

## Runtime discipline

No subagents/new tasks. Repository-local Xiak <Jellal@aliyun.com> only.
Go2/-p2 with bounded memory; heavy PG gates serial race-p1, unique names/
labels and explicit CPU/memory/PID limits. Verify ownership and terminal
handles before cleanup; no broad prune/shared restart.
Clean exports outside the repository avoid ignored duplicate build sources
in architecture checks. Temporary indexes never replace the real index.
Do not weaken password cost, timeouts, gates or coverage for green.
No remote1.3/.160/.161, withdrawn GitLab/1.5, foreign WIP/checkpoint or global
configuration edits. Machine-local paths are not portable memory.
