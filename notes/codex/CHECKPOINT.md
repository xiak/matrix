# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-14
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam`
- Pushed, verified Group and signed-directory milestone:
  `8117c54c112c842106d82fe934e460a280862549`
- Exact independent [Verification 34808378047](https://github.com/xiak/matrix/actions/runs/34808378047):
  Go, authority-process and node-process all completed/success.
- Preceding verified Group implementation:
  `0bd6dd9dd8166fe31c67edb8cd49cd523606a401`.

## Resume route

1. Read AGENTS.md and [IAM product contract](../../IAM/FEAT-IAM-000-product-contract.md).
2. Read [IAM/004](../../IAM/FEAT-IAM-004-groups-and-delegation.md) for the delivered
   Group, inherited authority, signed paging and remaining UI boundaries.
3. Continue [IAM/005](../../IAM/FEAT-IAM-005-policy-versions-and-boundaries.md)
   using its existing API, evaluator, use-case, persistence and test owners.
   Do not create another policy evaluator or duplicate the UX task's Group UI.
4. Read [IAM/011](../../IAM/FEAT-IAM-011-acceptance.md) for first-release schema,
   capacity/HA and final combination gates. Unpublished development versions do
   not require a default complete upgrade chain beginning at schema 1.
5. Read the [existing adoption record](../../docs/adoption/FEAT-006-platform-authorities.md)
   only for fixed-source review. Do not inspect another worktree's dirty files.

## Current milestone

The original complete IAM replacement goal remains active. Policy authority,
Account/RootIdentity/User replacement, actor-relative capabilities and Group
backend/repository are implemented; their FEAT owners retain exact evidence.
Neither IAM/004 nor the whole product is accepted merely by this milestone.

Group inheritance uses the single policy authority and immutable historical
membership/attachment/version evidence. 8117c54 replaces raw-ID continuation
for Account, User, Group and GroupMembership directories with a bounded,
purpose-separated MAC cursor. Routes and after/nextAfter remain unchanged;
there is no old-ID fallback. Each page reauthenticates and authorizes against
the current transaction before cursor verification. The binding covers sealed
installation, current account/principal/session, exact query and all current
policy sources. Reading sealed installation for this MAC does not populate an
ordinary tenant subject's platform context or grant installation authority.

The network IAM entry requires MATRIX_IAM_CURSOR_KEY_FILE: exactly 64 lowercase
hex characters in a protected file, representing an independent 32-byte key.
There is no random fallback, bearer-derived key or Audit-key reuse. Replicas
and restart use the same persistent key; changing it invalidates old cursors.
The offline non-paging recovery entry does not need this key. Exact public
shape, TTL, errors and query constraints belong to IAM/004 and the fixed API.

Local stable-tree full Go race/vet, architecture, module/generation and Linux
build gates passed. Current real PG18 policy/group, IAM HTTP and independent
two-IAM/Audit/PaaS process gates passed, including 100+1 actual directories,
cross-scope attacks, runtime logins, restart, revocation and historical outbox.
Frontend 101 tests, type/lint/architecture/styles and two 2-worker static
exports passed; 59 embedded files matched. These are local frontend gates,
not an independent frontend CI job. Exact timings belong to IAM/004.

All task-labelled PG containers, networks and synthetic data volumes from
this milestone have been cleaned. No running database or container is needed
to resume; do not reuse or remove another task's resources.

## Next work and fixed coordination

UX/UI task `01a07b21-9a0d-7fd0-b090-7827ce18262e`, branch
`feat/cloud-console-ux`, owns Group providers/scenes/renderers and real browser
acceptance. This task owns domain/wire/repository. Consume only its subsequent
verified fixed objects, never WIP or inherited acceptance. Group UI must not
invent memberCount, require N+1 user reads, infer authority from names, or
replace unknown command outcomes with new intents. Its current-loaded-page
filtering is not server search. The frozen names and permission relationships
were also explained using formal IAM/000, 003, 004 and 010 owners, separate
from supplier research and future, not-yet-implemented capabilities.

Installation task `01a04149-5dbb-7300-9e4c-31d9e85c8ada` will integrate the
independent IAM cursor key, protected persistent file, signed topology and
backup/recovery checks only when IAM/001–010's actual ABI has converged.
Do not edit that owner's deployment/profile in intermediate IAM slices.
Current development readiness/schema is IAM9/Audit6/PaaS1; the previously
signed release profile is unchanged. This source tuple is not an installable
release or a promise about the final product's PaaS version.

IAM/005 and later implementation, Group browser acceptance, final signed
release integration and capacity/HA remain outstanding. The first-release
schema policy retains current clean apply, populated replay, failure atomicity,
runtime permissions, revocation and history. Historical binary diagnostics
are optional unless a precise retained-data starting point is explicitly
supported. Never erase user or other-task data to satisfy that policy.

## Isolation

Preserve sealed ServiceIdentity/lookup_service, seven-column outbox claim,
canonical historical bytes and original-primary recovery. A development
schema number is not N-1 compatibility proof. Keep all code, commits and
resource mutations within this feature's ownership. No extra agents/tasks,
remote restarts or shared-service changes. Use unique task-labelled bounded
local resources; Go defaults remain GOMAXPROCS=2/-p 2. All user-facing document
deliverables are Markdown.
