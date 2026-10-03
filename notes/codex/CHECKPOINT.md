# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-03
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `5e124ab49`
- Pushed documentation milestone: `d6bf2209b`

## Authoritative route

- IAM client requirements, status and boundary evidence:
  [`FEAT-IAM-010`](../../IAM/FEAT-IAM-010-console.md).
- AccessKey protocol and product-enforcement evidence:
  [`FEAT-IAM-007`](../../IAM/FEAT-IAM-007-programmatic-credentials.md) and
  [`FEAT-IAM-008`](../../IAM/FEAT-IAM-008-product-enforcement.md).
- Shared UX requirements, status and verification evidence:
  [`FEAT-007`](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed-source adoption decisions:
  [`FEAT-007 adoption review`](../../docs/adoption/FEAT-007-control-plane-console.md).
- Shared product boundary:
  [`ADR-0002`](../../docs/architecture/ADR-0002-product-boundary.md).

Do not restate or amend those owners here. Read this checkpoint only after
compaction or handoff, then validate it against Git and the linked FEAT.

## Latest pushed milestone

The inspectable DEV MOCK remains available at `http://127.0.0.1:4317`, and
login verification remains disabled for UX review. Access Analysis Finding
details now expose the exact recovery epoch, recovery command, completion time
and the new generation's observation start through one reusable boundary.
Epoch zero must omit recovery command/time; a post-recovery epoch must bind a
nonblank command and cannot start observing before recovery completed. A
`RESTORE_GAP` is elevated above individual coverage rows: pre-recovery Findings
are not current conclusions and the new epoch must not create, migrate or
automatically remediate Findings until every required IAM source rebuilds the
complete threshold window. The first MOCK Finding uses an explicitly synthetic
epoch 2 and cannot be interpreted as installation or backend evidence.

Source and synchronized embed are pushed at `5e124ab49`; FEAT evidence is
pushed at `d6bf2209b`. The affected four-file run passed 218 tests; after adding
the blank-command rejection, the pure domain file's 7 tests passed again.
Typecheck, lint, architecture, 228-pair style checks, 45-route production
export, 249-file embed equality and repository Go test/vet passed. The full
Vitest run was stopped after extended silent execution and is not claimed as
evidence. Desktop and `390 × 844` DEV showed the recovery boundary without
horizontal overflow or browser warning/error.

Earlier Account security report, federation replacement, Deployment lifecycle,
AccessKey carrier, Application tag recovery, service authorization, policy
compilation/provenance and shared navigation/loading milestones remain owned
and indexed by FEAT-IAM-010 and FEAT-007; load only the relevant evidence row.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits after the IAM owner explicitly marks the contract consumable.
The client recovery invariant is implemented, but installation backup recovery
has not yet been inherited as a running or release-accepted integration. When
the IAM owner fixes and publishes that integration, verify the exact epoch,
command/time provenance, `RESTORE_GAP` rebuilding window and no-auto-disposition
behavior against the installed runtime before changing the LIVE status.

The earlier managed-service Profile/template compatibility milestone remains
release validation only: it is not Account consent, Role relation, binding,
RoleSession or permission. Browser code must not call IAM internal bind/session
endpoints, and real managed-service consent/unbind remains MOCK until its
northbound/BFF wire is mounted and browser-verified.

Continue without reintroducing whole-page loading, hidden broad Context
subscriptions, fabricated totals, duplicate components or login verification
before UX acceptance.
