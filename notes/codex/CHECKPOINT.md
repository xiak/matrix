# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Only this
  task's independent worktree is writable. Updated 2026-09-18.
- Latest pushed implementation is
  3080922f6ae1871f1c351d5ee30f03551fc3c605, owner-bound login Session
  self-management (S1). Local whole-source race/architecture, vet, modules,
  identical generation, Linux build, cumulative PG18 IAM/Role/Audit/PaaS,
  actual fixed predecessor executables and independent authority processes
  passed. Exact evidence and failed precursor boundaries belong IAM/009.
- Verification35301228478 belongs to that exact SHA and was confirmed queued
  after push. Its independent CI is NOT yet accepted. Inspect that same run;
  do not re-trigger or restart it merely because an observation times out.
  Latest independently verified cumulative predecessor remains
  644fff09446fc8ffb003cc53cf2fb55d4f58828a, Verification35184409378,
  all five jobs successful.
- Current source is IAM31/Audit18/PaaS2, IAM product Profile r5.
  Published release profile/revision unchanged. Backend verification does
  not establish UI, signed business, installation or final release acceptance.
  The full IAM goal remains ACTIVE and is not narrowed to S1.

## Current implementation boundary

Read AGENTS and IAM/FEAT-IAM-009-security-governance.md, then owning
code/tests. IAM/011 owns gate scheduling. IAM/007 and ADR-0004 own the
existing signed-key and secret-custody consumer boundary.

S1 has two closed self routes: GET /v1/auth/sessions and
POST /v1/auth/sessions/{sessionId}:revoke. Only the actual current USER
LOGIN_SESSION is accepted, including forced-change reduction. No Role,
AccessKey, ServiceIdentity, tenant/user selector or fabricated business
decision is accepted. A Session is not a physical device or proof of online
activity. The current identity comes from the real bearer, not UI metadata.

The original SQL owner now has lookup_session24 output columns,
list_own_sessions4 arguments/4 columns and revoke_session6 arguments.
The old revoke5 function is removed. Current actor Session and generation
are revalidated under existing identity locks; expiry uses the database
clock after lock acquisition. The exact original caller/target/request
completion, terminal target and immutable outbox commit atomically.
Completed history does not grant current permission.

record9/contract4, evidence5, claim7, lookup_service5, ServiceIdentity and
old Audit canonical bytes are unchanged. Source IAM31 is not an allocation
of a release revision or permission for mixed-binary/N-1 operation.

The source was committed only after the final clean-export gates passed.
A forgotten Audit test expectation of IAM30 was corrected to actual IAM31
without weakening initialized/uninitialized readiness. The quiet real-expiry
gate rejects the pre-fix transaction-time behavior, including a reproduced
expired caller returning200. Prior attachment-matrix timeouts remain recorded;
later passes do not explain away those failures or justify weaker costs.

## Next delivery step

Verify exact CI35301228478 and every job before calling3080922f independently
accepted. On failure inspect the actual failing owner and preserve original
budgets/cases; on success update the existing009 evidence and this one
checkpoint, then hand the fixed source to UX/UI for the Session UI.
No UI/browser work is done in this branch.

The remaining009 design is already committed: S2 local MFA, S3 password/
authentication budgets and S4 reports/idle governance. They remain design,
not available APIs. Public fields, protected material, authentication-failure
facts, budgets and privileged recovery must be frozen with their owners
before corresponding shared implementation. No generic SessionStore,
Redis authorization authority, fake Session or second PDP.

Remaining delegation/IP, product/service integration, governance, UI,
capacity/HA and signed installation/backup/release gates stay with their
FEAT owners. External integrations remain explicitly deferred in012.
Do not expand speculative design to replace implementation or claim the
whole goal complete from a local backend slice.

## Shared windows and peers

UX/UI工程师 01a07b21-9a0d-7fd0-b090-7827ce18262e owns UI/browser work
in feat/cloud-console-ux. It has the S1 and MFA design references, not a
handoff of independently accepted3080922f. Its latest reply confirms that
unfrozen MFA APIs will not be wired.

Phase3 01a04149-5dbb-7300-9e4c-31d9e85c8ada explicitly opened the S1
window after fixed c2fbd9e38d424e68c0466618ee74613aced3c3fb.
That task subsequently reported completion and asked for fixed SHA/CI-only
handoffs; further integration requires a user-opened integration goal.
Do not reopen its work or assume its consumer/release acceptance belongs
to this branch.

The PaaS/Audit business PEPs, shared ingress parsing/origin mapping, APISIX,
installation/keyring/backup and release composition are not edited here.
No parallel PaaS2 signed-business consumer is introduced. Source/profile,
working trees, node evidence and checkpoints from other branches are not
imported. Fixed donor decisions belong the existing adoption owner.

## Runtime discipline

No subagents/new tasks. Go2/-p2 and bounded memory; true DB gates serial
race-p1 in uniquely named/labelled CPU/memory/PID-limited fixtures. Verify
actual ownership and live handles before use or cleanup. Clean Git exports
use an isolated index and preserve the actual index. Match evidence to its
exact source and scope; skipped external gates are not runtime acceptance.

No remote1.3/.160/.161, withdrawn GitLab/root1.5 work, other Phase worktrees,
shared restart, global configuration or Docker prune. Temporary paths and
unfinished machine-local processes are not portable checkpoint state.
