# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Only this
  task's independent worktree is writable. Updated 2026-09-17.
- Latest complete, independently verified contract requires both backend
  62a18a48168e87a4158b95eba41427b445ed10d1 and public-schema correction
  0567c8b2699521b137db0f8b69f17630c59f04fb. Administrator RoleSession
  directory/read/revocation, cumulative through R1/R2/R3 and source authority.
  GitHub API verified exact Verification35136745680 completed/success:
  go, authority-process and node-process all succeeded. This is the rollback
  point, not full IAM, UI, capacity or release acceptance.
- Required public-schema correction 0567c8b2699521b137db0f8b69f17630c59f04fb
  has exact Verification35139789639 completed/success, independently checked
  through GitHub API: go, authority-process and node-process all succeeded.
  It fixes RoleListing capabilities to exactly9 and RoleAccess to10-266;
  the prior 62a18 CI omitted these complete-response schema bounds. Existing
  API tests reproduced both valid-response rejection and missing lower bounds,
  then full API/generator race and deterministic generation passed. Do not
  hand off 62a18 alone as a complete UI contract. No SQL/authority change.
- Previous source-authority point 1ebab37aef4bce12b963f52d3919748a9d50d4c6 /
  Verification35123738141 all three success. Original R2 had incomplete ABA
  coverage; R3 fixed960416dd/35110913530 failed its aggregate timer. Do not
  relabel either historical result.
- Current source IAM28/Audit16/PaaS2, IAM product Profile r4. Published release
  profile/revision unchanged; record8/evidence5/claim7, ServiceIdentity,
  lookup_service and old Audit canonical unchanged.

## Programmatic-credential foundation

Pure material implementation is pushed as
be4974e68fc167b418c9eee00c96aaf1b844693f. Exact Verification35142407084
was independently checked through GitHub API: all three jobs completed/success. The
existing credential owner implements the agreed record-bound HKDF/AES-GCM
format, private structured envelope and independent Node/Go attack vectors.
Local whole-source race/architecture/vet/modules/generation/Linux passed.
This is not AccessKey API, transaction, once-only Seal, signature, installation
or whole007 acceptance. No new schema, profile, FILE env or public actor ABI.
The uncommitted direct-KEK draft was replaced, not retained as compatibility.

The complete private-file contract is pushed as
bc7d059571b55ee84c58b62adf1d794cf63ff9a6. Exact Verification35145879997
was confirmed live with all three jobs running; poll that run to terminal.
It provides strict one-key canonical private Encode/Decode, per-key immutable
material commitment and the sole api/iam/v1 context encoding. The old authority
encoder was deleted; format1 vectors remain unchanged. Whole-source race,
architecture, fuzz, vet, modules, deterministic generation and Linux passed.
No runtime loader, registry, schema, public endpoint or installation changed.
Phase3 waits for exact final CI before consuming the fixed codec, not our FEAT,
profile or acceptance state. A successful codec is not K1 runtime acceptance.

Next K1 management and custody constraints belong only to IAM/007, including
the frozen FILE contract, immutable historical wrapping-key registry, exact
CAS targets, ENABLED/DISABLED key states and four closed Audit facts. Implement
the actual authority transaction, file/receipt/registry readiness checks,
bounded User deletion cascade, once-only secret response and real multi-process
gates there. Installation owns actual file generation/mount/backup/recovery;
do not modify its WIP. Existing password/session semantics must not be silently
reinterpreted as long-term key revocation. Do not turn remaining work into a
generic credential service or a second PDP.

## Continue the full goal

Whole IAM goal remains ACTIVE. Read AGENTS,
IAM/FEAT-IAM-007-programmatic-credentials.md and ADR-0004, then owning credential,
PDP and PEP code. Further policy delegation/IP, program credentials,
product/service integration, governance, UI and cumulative HA/capacity/release
acceptance remain in their FEAT owners. Do not shrink the goal to Role/STS
or add a generic SessionStore/Redis layer.

## Verified role-session boundary

ROLE and USER credentials are distinct. RoleSession version2 binds monotonic
source USER authorization and all membership/GROUP generations; old qualified
version1 business access stays closed while original nonsecret intents,
self-termination and immutable historical proof remain. No migration or
restored source grant revives an old session. Current credentials and actual
non-key actor locks remain required; do not hide deadlocks with retries.

Administrator sessions live only under an exact Role. The three USER/TENANT
actions list/read/revoke authorize exact ROLE/ROLE_SESSION targets, not
root-only administration. Page filters are bounded; sparse empty pages with
nextAfter are valid. Server lifecycle is not business eligibility. Role or
source invalidity does not prevent an authorized live administrator from
terminating a remaining unexpired record. Expired/new terminal intents
conflict; only the original successful intent may equal-replay under current
authority. New USER admin-revoked fact requires its real decision, unlike
old source self-revocation/possession-only exit.

The separate per-Role session directory counter changes only on actual
issuance/termination. It is not a session authorization generation. Exact
replay and rollback do not advance it. Actual old R2 executable, old SYSTEM
defaults, explicit new grants, original outbox/Operation/canonical and current
two-IAM/PaaS/Audit behavior were verified. No complete unpublished schema1
chain or release compatibility is inferred. Details and evidence belong006.

## Shared windows and peers

UX/UI工程师 01a07b21-9a0d-7fd0-b090-7827ce18262e owns its independent
feat/cloud-console-ux and all UI/browser work. Hand off only verified fixed
objects; its role-session preview is not a production contract. The agreed
page is Role detail > Role sessions, no global directory or batch operation.

Phase3 01a04149-5dbb-7300-9e4c-31d9e85c8ada consumes only verified fixed
objects and preserves its host/PaaS/release composition. Current 007 ownership
alignment leaves IAM contracts, key material, nonce/current PDP and tests
here; actual request construction belongs to product PEPs, installation
keyring/files/backup/recovery/rotation to installation. FILE/codec and K1
management contracts are frozen in007; public signed actor/evidence and final
schema/release changes still require exact coordination before handoff.
No root/ROLE/SERVICE long-term keys; no fake
Session or reusable USER permit. Keep current host admission unchanged.

The fixed f51 foundation donor is not present in the available object stores;
sources.yaml has only its logical repository name, no physical URL/path.
Do not guess the repository, claim a fresh inspection or copy another WIP.
Its existing adoption record remains the boundary for prior reference.

## Runtime discipline

No subagents/new tasks. Go2/-p2; real gates serial race-p1, in own uniquely
named/labelled CPU/memory/PID-limited fixtures. Verify actual ownership before
use or cleanup. Whole-source gates use a clean Git export outside the
checkout with a temporary index; preserve the real index and all other work.
No peer runtime/worktree changes, withdrawn GitLab/root1.5 work, remote1.3/
.160/.161 access, remote/shared restart, global configuration or Docker prune.
