# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git, exact CI and the owning FEAT.

- Updated: 2026-09-14
- Repository: https://github.com/xiak/matrix.git
- Branch: `feat/iam`
- Latest pushed, locally verified version-management candidate:
  `aa28c39ca25ad0136b4a7042f1f1ae358d4f1429`.
- Its exact [Verification 34816605258](https://github.com/xiak/matrix/actions/runs/34816605258)
  was confirmed in_progress; do not treat it as success or rerun merely because
  an observation times out.
- Last fully CI-verified policy creation/read milestone:
  `7104b1de8f16ae82645e149b2c5376f983eae5cd`,
  [Verification 34814615083](https://github.com/xiak/matrix/actions/runs/34814615083):
  Go, authority-process and node-process all completed/success.
- `4fcc983abbb8b7a66dd0d9b6f0718cb8ab12eae3` is the preceding implementation,
  not the accepted CI point: its dual-authority test retained two schema9
  assertions while IAM had advanced to 10. 7104 fixes only those assertions;
  the actual restricted-role/PG gate was independently rerun, not weakened.
- Signed directory/Group milestone remains
  `8117c54c112c842106d82fe934e460a280862549` / successful CI 34808378047.

## Resume route and objective

The complete IAM replacement goal remains active; neither IAM/005 nor the
overall product is accepted. Read AGENTS.md, [product contract](../../IAM/FEAT-IAM-000-product-contract.md),
then [IAM/005](../../IAM/FEAT-IAM-005-policy-versions-and-boundaries.md) and its
owning code/tests. Read [IAM/011](../../IAM/FEAT-IAM-011-acceptance.md) for
first-release schema, exact compatibility, capacity/HA and final acceptance.
Use the [existing adoption owner](../../docs/adoption/FEAT-006-platform-authorities.md)
only for fixed sources. Do not load another worktree's dirty files.

First resolve the exact aa28c39 CI result. If it fails, read the failing job's
actual test output, correct the owning invariant/fixture, and verify it on
fresh task-labelled PG18 databases. Do not infer failure from elapsed time.
Keep GitHub credential material in memory only; do not print it. CI cleanup
contains very large expected PostgreSQL attack logs, so restrict log excerpts
to the failed test section before post-job cleanup.

## Pushed implementation and evidence boundary

7104 delivers root-only CUSTOMER policy creation and exact current-default
content read, using the existing PDP, serializable transaction, attachment
and historical Audit owners. Creation does not attach or grant. Its public
API/Go types, exact route/action scope, replay and rejected cases are in 005.

aa28c39 adds customer version inventory/exact nondefault reads, immutable
version creation and explicit optimistic default selection. It does not add
policy/version deletion, conditions, boundaries, full delegation, diagnostic
HTTP endpoints or new UI capabilities. Version creation does not switch the
default. A later policy revision makes an old command replay conflict.
Current-version evidence and old Audit proofs retain their original content.

Locally, related API/IAM/Audit/architecture race, strict schema contracts,
generation stability, full Go tests/vet, module verification and Linux
IAM/Audit builds passed. Real PG18 focused gates prove failure rollback,
concurrent revision conflicts, exact replay, cross-account/non-root refusal,
bounded versions and actual authorization changes. The complete serial
CI-equivalent PostgreSQL package set passed, including dual authorities,
Audit history/HTTP, IAM HTTP/policy/recovery, two IAM processes with real
PaaS/Audit consumers, and PaaS storage. Exact timings belong only to 005.
These local results do not substitute for aa28c39's still-unconfirmed CI.

The current source tuple is IAM11/Audit8/PaaS1; it is not a signed release
profile. The earlier source milestone was 10/7/1. Published installation
profile/topology/admission remain unchanged. ServiceIdentity/lookup_service,
seven-column claim, unique canonical bytes, sealed bootstrap and original
primary recovery boundaries are preserved.

## Next implementation

Continue 005's full requirements after the version-switch milestone:
policy metadata/deletion, version deletion that frees management capacity
without destroying historical proof, bounded wildcard/condition semantics,
permission boundaries and safe delegation. Five manageable versions must
not become a lifetime five-publication limit. Keep one evaluator/compiler,
immutable evidence, current-account derivation and transactional outbox.
Use the current owners rather than another roadmap/test framework.

Then continue the remaining 006–010 scope and 011 final combination gates.
012 retains explicitly deferred external integration requirements. Group
browser acceptance, final signed integration, capacity/fairness and actual
database HA remain outstanding; no mock or multi-process/single-database
fixture substitutes for those requirements.

## Coordination and isolation

UX/UI task `01a07b21-9a0d-7fd0-b090-7827ce18262e` owns Group and IAM scenes
on `feat/cloud-console-ux`. It received 7104's exact successful CI and public
type/route/action/status/replay boundaries, including absent capabilities.
Only send later version contracts after their exact successful CI. Preserve
its own UX/MOCK work; no implicit authority from names, root labels or menus.
Its reported 9d10600/12287bc objects have not been imported by this task.

Installation task `01a04149-5dbb-7300-9e4c-31d9e85c8ada` will integrate
only after 001–010's final ABI. It accepted 7104 as a reviewable fixed object
but is not importing it now. Do not edit installation/releasebuild/profile,
PaaS/node or its FEAT/checkpoint. No other worktree/environment mutations.

All local PG containers, networks and synthetic volumes used in this
milestone were verified task-owned and removed; no live local gate process
needs resuming. Create fresh uniquely labelled resources for new real gates.
Do not recreate a CI job merely because local fixtures are gone. Do not
restart remote machines/shared engines or use another task's test services.
Go defaults GOMAXPROCS=2/-p 2; heavy real gates serial and CPU/memory/PID
bounded. No additional agents/tasks. All user-facing documents are Markdown.
