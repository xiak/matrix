# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-08-28
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam-xxx`
- Pushed local-recovery backend: `aa345eca5f1ed3921000aa5380d5bfd2aa6d0a50`
- Accepted minimum multi-tenant implementation: `5721b7b1a985f25c9730ddb9229a51f7f6c3b63a`

## Resume route

1. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md) owns IAM,
   Audit, the accepted multi-tenant boundary and this subsequent local
   installation-primary recovery backend.
2. Its [adoption record](../../docs/adoption/FEAT-006-platform-authorities.md)
   owns fixed source decisions. Public capability/private-file contracts and
   the single BootstrapDigest owner were fixed at `91af848` before the atomic
   implementation.
3. [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md) and
   [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md) retain
   the installed-browser and signed lifecycle evidence for the accepted
   minimum slice. Do not extend that evidence to the new recovery profile.
4. Phase 3's installation/CLI integration remains in its separate task and
   FEAT-008 owner. Read only confirmed fixed objects when integration is
   requested; never inspect or import another worktree's WIP/checkpoint.

## Current boundary

The minimum primary/subaccount IAM goal remains complete. Primary ownership
never transfers to a child administrator; tenant ownership and platform roles
remain separate. The password-session contract uses monotonic credential
generation. Forced replacement revokes other temporary sessions; ordinary
replacement defaults to revoking other sessions, with explicit false retaining
only already valid same-user sessions. Legacy NULL generations fail closed.
The user deferred native keyboard-only verification, not the core IAM goal.
User-facing documents default to Markdown.

The subsequent local recovery backend is implemented and independently
verified. It accepts only the sealed original installation primary while its
USER and organization are ACTIVE and its exact platform binding is unrevoked.
The fixed one-shot entry has only inspect/apply modes and purpose-only private
files/database authority; no northbound permission or route exists. It changes
only the password hash, credential generation, principal version, forced-change
flag and old sessions, with immutable completion plus one closed SYSTEM Audit
fact in the same transaction. It cannot grant/regrant roles, enable identities,
transfer ownership or recover service credentials.

Original command/commitment receipt inspection remains available after later
password changes or revocation and after private intent cleanup. Equal replay
only returns original completion; missing receipt never issues fresh expected
state. The trusted executable checks the MAC; PostgreSQL authenticates the
dedicated role and enforces sealed ownership/atomic state, not the MAC itself.

Current source profile is IAM4/Audit3/PaaS1 plus contract revision 4, with the
existing seven-column IAM claim and unchanged ServiceIdentity/lookup_service/
CanonicalizeEvent bytes. Different complete profiles still fail before effects.
The installation owner adapts to its own PaaS2 composition and independently
validates 4/3/2+r4; it must not import this branch's profile or acceptance state.
This branch has not integrated or accepted the new signed installation/CLI
consumer. New schema support does not imply a usable signed recovery command,
cross-profile release transition or historical binary compatibility.

## Verified fixed milestone

`aa345ec` passes full-repository race/architecture/vet, strict generation,
dependency verification and Linux builds. Dedicated PostgreSQL 18 tests prove
actual restricted identities, closed facts, immutable receipts, both ordered
recovery/revoke races and the other credential/session/role races. The actual
fixed `5721b7b` executable creates retained schema-3 state before current
migration/restart; old canonical bytes, valid sessions and revoked history
retain their meanings. Older `9fd45b0`/`a36cf98` upgrade and dual-tenant
resource/Operation/outbox regressions remain covered.

The independent-process gate runs the real local executable, normal forced
password replacement, original receipt lookup without its old secret file,
Audit outage delivery, exact action/SYSTEM filtering and historical replay
after password change, platform revocation and IAM restart. It does not claim
a Docker transport interruption, signed CLI journal or release integration.
GitHub API verifies exact-SHA
[Verification 33153170437](https://github.com/xiak/matrix/actions/runs/33153170437)
with go, authority-process and node-process all successful.

Phase 3 task `01a04149-5dbb-7300-9e4c-31d9e85c8ada` owns the remaining
installation/CLI/journal/release integration and has received the fixed
implementation and exact CI confirmation. Do not start extra agents/tasks,
change other Phase environments, infer authorization for a new recovery/grant
slice, or reopen the completed minimum IAM goal. Never restart remote machines
or shared services. Keep commits and tests in this task's own feature branch
and isolated resources; replace this checkpoint only at pushed milestones.
