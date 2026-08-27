# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-08-27
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam-xxx`
- Pushed implementation milestone: `a36cf9817f522549b995ea9c1f0d873499b4fe62`

## Resume route

1. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md) owns the
   multi-tenant target, invariants and backend/runtime evidence.
2. [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md) owns
   console behavior, installed-release browser evidence and the remaining
   native keyboard-only gate.
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

The verified backend retains fixed accounts `6a0f417`, platform credential
protection `686efca`, installation authority `6401e96`, historical producer
proof `26f3569` and lifecycle `c9fa43d`. `cf003e4` corrects the old process DSN
which serialized the migration login; never reuse the superseded executable
least-privilege claim. `05f3675` adds the application/configuration/Operation
tenant matrix. Current profile is IAM2/Audit2/PaaS1 plus contract revision 2,
including the exact seven-column IAM claim. Different complete profiles fail
before effects; schema numbers alone never establish binary compatibility.

`b3a6f81` implements the signed profile boundary. The populated offline gate
in `d2c787a` passes on clean, network-disabled real Docker/PostgreSQL 18,
including signed A/B upgrade, failed-candidate rollback, data-preserving
rollback, selected-backup recovery and whole-engine restart. FEAT-005 owns
exact source and evidence limits; same-source A/B does not prove arbitrary
historical N-1 or cross-profile runtime compatibility.

The installed browser then verifies the primary/member/password, same-name
realm, two real database and lifecycle paths in FEAT-007. `464910f` fixes a
denial notice hidden behind a compact context panel; `a36cf98` fixes refreshed
installation choices without silently rebinding a target. Both are exercised
as real signed C/D upgrades, not only development assets. The current source
passes 75 frontend tests, type/lint/architecture/contrast, repeated two-worker
exports and Go embed gates. Independent Verification `33075458596` passes
`go`, `authority-process` and `node-process` for the exact current SHA.

Only native keyboard-only end-to-end browser acceptance remains open. A
pointer-driven path, DOM snapshot, component key event or focus assertion is
not a substitute. The persistent goal remains active until that gate is
actually demonstrated; do not claim the entire multi-tenant target accepted
merely because the other checks pass.

Keep work, commits and test resources in this task's independently verified
worktree and feature branch. Phase 2 owns its separate console branch;
Phase 3 owns host/Operation and its offline profile. Exchange only mutually
confirmed fixed verified commits, never another worktree's uncommitted state.
Do not start extra agents/user tasks, change other Phase environments or import
their checkpoint/acceptance state. Replace this checkpoint only at another
committed-and-pushed milestone.
