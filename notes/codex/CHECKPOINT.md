# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-14
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam`
- Pushed, verified Group backend/repository milestone:
  `0bd6dd9dd8166fe31c67edb8cd49cd523606a401`
- Exact independent Verification:
  [34805149946](https://github.com/xiak/matrix/actions/runs/34805149946),
  completed/success for Go, authority-process and node-process.

## Resume route

1. Read AGENTS.md and [IAM product contract](../../IAM/FEAT-IAM-000-product-contract.md).
2. Continue [IAM/004](../../IAM/FEAT-IAM-004-groups-and-delegation.md), then its
   owning API, IAM authority/use cases/SQL, integration and authorityprocess tests.
3. Read [IAM/011](../../IAM/FEAT-IAM-011-acceptance.md) for the current first-release
   schema policy and final acceptance boundaries. The user explicitly removed
   the default obligation to upgrade through every unpublished development schema.
4. Use [IAM navigation](../../IAM/README.md) for later FEAT owners, and the
   [existing adoption record](../../docs/adoption/FEAT-006-platform-authorities.md)
   only when reviewing fixed donors. Do not read another worktree's dirty files.

## Current milestone

The original complete IAM replacement goal remains active. The first Group
slice is a verified backend/repository milestone, not acceptance of IAM/004 or
the whole product. The old checkpoint's IAM/002 starting point is superseded.
Policy persistence, Account/RootIdentity/User replacement, management
capabilities and user profile/deletion are already implemented; their own
FEATs retain the exact preceding evidence and remaining UI/release boundaries.

0bd6dd9 adds Group, terminal GroupMembership and tenant group attachments to
the existing single policy authority, rather than adding another evaluator or
attachment table. CurrentIdentity uses DIRECT/GROUP policySources. Group
evidence binds the actual membership and immutable policy version; later
removal does not prevent delivery of already-committed historical outbox facts.
Current source/readiness is IAM9/Audit6/PaaS1. Existing signed release profile
has not been rewritten; the source tuple is deliberately not advertised as an
installable release. The final complete profile must be frozen with the real
product/installation consumer after IAM converges.

Local full Go race/vet, module/generation checks and Linux builds passed.
Current PG18 policy/group, IAM HTTP, original local recovery, Audit/old-chain,
PaaS database and independent two-IAM process gates passed. Frontend 100 tests,
type/lint/architecture/styles and two 2-worker static exports passed; 59 files
matched. These are local frontend gates, not an independent frontend CI job.
All objects from this milestone's task-labelled PG fixture were cleaned.
There is no required running database/container to resume.

The default CI now runs the actual current policy-storage gate. Historical IAM
binary tests remain explicit optional diagnostics, not an automatic complete
development-version upgrade chain. Current clean apply, populated replay,
failure atomicity, runtime permissions, revocation and history remain required.
No user/other-task data may be erased to satisfy that policy.

## Required next work and coordination

IAM/004 still requires the product's opaque/MAC cursor contract and complete
multi-member pagination/UI acceptance. The current first slice uses account-
and group-confined ID keyset continuation. This is documented as incomplete,
not substituted for the final signed cursor requirement. Review the current
credential and Audit cursor owners before designing IAM continuation: a
bearer-derived credential digest is not a server-private signing key, and IAM
must not import Audit internal packages or reuse its signing purpose. Coordinate
any installation-key delivery change with its owner before editing that owner.

UX/UI task `01a07b21-9a0d-7fd0-b090-7827ce18262e` on
`feat/cloud-console-ux` owns Group providers/scenes/renderers and real browser
acceptance. It has received the fixed 0bd6dd9 contract and local gate results;
consume only subsequent verified fixed objects, never WIP or its acceptance
status. This task owns domain/wire/repository, so do not implement a duplicate
Group UI. The frozen first slice has no membershipCount or user summary;
members are identified by userId and removed by membership ID/revision. UI
passes continuation unchanged and keeps the explicit command ID/input after
uncertain outcomes. Unknown results do not authorize a new intent or automatic
compensation.

IAM/005 and later FEATs, signed release integration and capacity/HA acceptance
remain outstanding; follow their owners rather than treating this Group
milestone as completion. Product reference material remains fixed at 1ad6884
and the public-source study at b0e8627, not runtime dependencies.

## Isolation

Keep the existing sealed ServiceIdentity/lookup_service, seven-column outbox
claim, canonical historical bytes and original-primary recovery boundaries.
New development numbers are not N-1 compatibility proof. Do not change another
Phase's branch, worktree, environment, profile or acceptance state. No extra
agents/tasks, remote restarts or shared-service changes. Use task-labelled,
uniquely named, bounded local resources; Go defaults remain GOMAXPROCS=2/-p 2.
All user-facing document deliverables are Markdown.
