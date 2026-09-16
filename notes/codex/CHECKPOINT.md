# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam. Only this
  task's independent worktree is writable. Updated 2026-09-17.
- Latest locally verified, pushed implementation:
  1ebab37aef4bce12b963f52d3919748a9d50d4c6, cumulative through R3 self-service
  and irreversible RoleSession source authority. Exact Verification35123738141
  is still running: go/node-process success, authority-process in_progress.
  Recheck the exact run; do not mark this candidate independently accepted yet.
- Last independently verified R2 fixed point:
  0752c602ab4ce6d73a21094c8e9f75a1c8750183, Verification35096275242 all three
  jobs success. Its original ABA matrix did not cover the four source changes
  now repaired. R3 fixed960416dd/35110913530 failed its aggregate IAM timeout;
  never reclassify that run as successful.
- Current development source IAM27/Audit15/PaaS2. Published release profile
  unchanged. Local evidence and exact retained-source boundaries belong006;
  execution-budget/CI boundaries belong011. This is not whole IAM acceptance.

## Continue the full goal

Whole IAM goal remains ACTIVE. Read AGENTS, IAM/FEAT-IAM-006-roles-and-sts.md,
then owning API/usecase/adapter/tests. Finish the exact candidate CI first;
then implement the pending administrator RoleSession directory/revocation
slice in006, followed by the remaining FEAT requirements. Do not shrink the
goal to R2/R3, duplicate UI or create a generic SessionStore/Redis layer.

All local candidate gates are terminal and passed: exact clean-source whole
race/architecture/vet/module/generation/Linux checks, complete serial IAM
and Audit PG18 matrices, actual fixed IAM21/R1/R2 retained executables and
independent IAM/PaaS/Audit business/dispatcher gates. One process assertion
initially still expected IAM26; only that source-shape expectation changed
to27 and the complete process gate passed again in new databases. Nothing
weakened release admission or converted skipped browser/history tests to pass.

## Current security boundary

USER and ROLE credentials remain separate. Current RoleSession version2
binds a monotonic USER authorization generation and every current membership,
including empty groups, with ordered GROUP generations. Specific mutation
triggers advance only their sources in the same transaction/outbox. The
account directory row is only a writer lock barrier, never a global session
generation. Exact replay/failure does not advance; restore cannot revive old
ROLE business access. New issuance requires a new explicit intent.

Only complete actual old issuances receive protected version1, without
fabricated generations. Their current business access is closed; original
non-secret intent, self-revocation/exit and exact historical proof/delivery
remain. Immutable history does not compare today's source generations.

Runtime diagnostics exposed actor FK KEY SHARE to FOR UPDATE conversion
deadlocks in Role/Policy writers, User boundaries and attachment create/revoke.
Those non-key-changing Principal locks now use ordered FOR NO KEY UPDATE,
including self-target rereads. Real credential/session/platform protections
remain; final policy/attachment/Role fixtures reject deadlocks hidden by retry.
record8/evidence5/claim7, ServiceIdentity/lookup_service, public R3 API and old
Audit canonical remain unchanged. No platform/service/cross-account assumption.

## Peers and next shared contract

UX/UI工程师 01a07b21-9a0d-7fd0-b090-7827ce18262e owns independent
feat/cloud-console-ux and all UI/browser work. Candidate1ebab37a was sent
explicitly pending CI, not as an accepted donor. Send exact success afterward.
R3 public endpoints are listAssumableRoles and currentRoleIdentity; no further
wire change in the source-generation repair. Sparse pages may be empty with
nextAfter; no management permission needed for self discovery or cached permit.

UX confirmed the next admin surface is Role detail > Role sessions, not a
global directory, batch operation or new assumption screen. Its current
preview model is not a live contract to preserve. Requirements are now in006:
bounded role-nested filters, matched non-secret USER display, server lifecycle
observation, exact row capability, precise read for unknown outcomes and one
irreversible revoke intent. No fake resourceVersion merely to imitate CRUD.
The exact new action/read/write/receipt/cursor/audit contracts still need
freezing and real lock/permission evidence before implementation handoff.

Phase3 01a04149-5dbb-7300-9e4c-31d9e85c8ada receives fixed cumulative donors
only and preserves its own host/PaaS/release composition. Candidate1ebab37a
and pending exact CI were sent; do not import its WIP, profile or acceptance.
Coordinate new shared actions/ABI before the next public implementation.

## Runtime discipline

No subagents/new tasks. Go2/-p2; real gates serial race-p1, in own uniquely
named/labelled CPU/memory/PID-limited fixtures. Inspect actual ownership before
use or cleanup. For whole-source gates use a clean Git export outside the
checkout with a temporary index; preserve the real index and all other work.
No peer runtime/worktree changes, withdrawn GitLab/root1.5 work, remote1.3/
.160/.161 access, remote/shared restart, global configuration or Docker prune.
