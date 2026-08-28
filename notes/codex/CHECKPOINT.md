# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-08-28
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam-xxx`
- Pushed implementation milestone: `5721b7b1a985f25c9730ddb9229a51f7f6c3b63a`

## Resume route

1. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md) owns the
   multi-tenant target, invariants and backend/runtime evidence.
2. [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md) owns
   console behavior, installed-release browser evidence and the user-deferred
   native keyboard-only usability gate.
3. [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md) owns
   the exact release profile and signed populated upgrade/rollback/recovery.
4. Read the relevant adoption record and directly related ADR only when
   changing those boundaries, not the whole documentation tree.

The user chose protected original primary ownership plus revocable child
administrators. Daily handoff never transfers the primary identity. Online
tenant recovery restores only the original primary, refuses every unrevoked
platform binding and cannot implicitly resume a suspended tenant. Password
changes in the test journey are performed by the agent, not delegated to the
user.

The current password policy keeps only the transactionally revalidated current
bearer during forced replacement; ordinary replacement defaults to revoking
other sessions, with explicit false retaining only valid same-user sessions.
Credential generation is a monotonic counter, not a timestamp. Legacy sessions
without generation evidence remain NULL and fail closed; no migration backfill
or retention option may promote them. The fixed old `9fd45b0` and `a36cf98`
IAM executables' retained-data migration/restart gates and concurrent
change/reset/recovery/logout/login gates pass.

The complete current profile is IAM3/Audit2/PaaS1 plus contract revision 3,
including the exact seven-column IAM claim and generation-bound password
function. Different complete profiles fail before effects, including recovery;
schema numbers alone never establish binary compatibility. Never reuse the
pre-`cf003e4` process DSN evidence as proof of restricted executable logins.

Signed A/B releases from `5721b7b` pass the populated, network-disabled
PostgreSQL 18 lifecycle and owned local-engine restart gates. Retained valid
sessions survive; revoked/temporary sessions do not revive. FEAT-005 owns
these results and their limits: same-source A/B is not arbitrary historical
N-1 or cross-profile compatibility. No remote machine or shared daemon was
restarted.

The real installed browser passes same-name child creation, forced and
ordinary password policies, cross-session reset, two real same-ID databases
and measured 360-pixel controls. FEAT-007 owns exact evidence and preserves
the earlier signed lifecycle/renderer/refresh checks. The current source
passes 90 frontend tests, bounded repeated exports, full-repository Go gates
and all three independent Verification jobs at run `33138242923`.

The prioritized minimum IAM slice is complete on this feature branch. Native
keyboard-only verification is explicitly deferred by the user, not counted
as passed or used to hold the core goal open. Do not infer complete Phase 2,
Phase 3, public-cloud IAM or supported cross-profile installation upgrade.
User-facing documents default to Markdown; the architecture reading copy
does not replace the existing FEAT owners.

Keep work, commits and test resources in this task's independently verified
worktree and feature branch. Phase 2 owns its separate console branch;
Phase 3 owns host/Operation and its offline profile. Exchange only mutually
confirmed fixed verified commits, never another worktree's uncommitted state.
Do not start extra agents/user tasks, change other Phase environments or import
their checkpoint/acceptance state. Do not restart remote machines or shared
host services. Replace this checkpoint only at a committed-and-pushed milestone.
