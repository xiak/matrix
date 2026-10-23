# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, the host goal and the owning FEAT.

## Pushed milestone

- Repository `https://github.com/xiak/matrix.git`, branch `feat/iam`; repository-local
  identity is `Xiak <Jellal@aliyun.com>`.
- The completed bounded goal is FEAT-008 Account service activation with an
  uncertain-result recovery journey. It does not accept every remaining IAM
  console path or a new product provider.
- Fixed production/test source is
  `56e3e9c3bbb0b1e4ca45a84f73a70056ea974cc8`. Its ancestors include the
  backend gate `e00f1772609b167a2e95dddb3aa7bf58814157b5`, selective adoption
  of UX/UI owner source `5fc00122c656a4324e6f82e9cdd2c6b3a9989ce5` at
  `6377e66592a21cc190ae83a93d27fb44331809ed`, and the final outbox-contract
  assertion fix. No UX documentation or unrelated branch status was imported.
- No API, SQL, schema or release Profile changed. The accepted signed release
  remains `5935fa5005529b2c4e1da943b98f49300430ba10`
  (IAM87/Audit39/PaaS7+r37); its sole rolling data predecessor remains
  `08e1dc4a6ce81386ea7223e62d03356f82aeee58` (r36). FEAT-005 owns those
  release claims.

## Exact verification

- [Verification 39936868627](https://github.com/xiak/matrix/actions/runs/39936868627)
  attempt 1 is the exact `56e3e9c3b` source and finished `Success` in 30m51s.
  Go, console, node-process, installation-postgres-ha, fourteen authority lanes
  and the final authority-process summary all completed successfully. This is
  run/job verification, not a complete log audit or signed-release acceptance.
- The opt-in real journey used a task-owned PostgreSQL 18.6 database with
  1 CPU, 1 GiB and PIDs 256. A synthetic USER submitted exactly one activation;
  the transaction committed while its success response was lost. The first
  exact activation read returned 503, the page stayed UNKNOWN and made zero
  further writes. One explicit check read the original 200 fact and opened the
  workspace gate; the following product-resource read correctly remained 403
  because activation does not grant resource access.
- The race test passed in 95.33s (package 98.897s). It verified one
  Account/service row, the exact definition reference and idempotency key, the
  original USER/decision/request digest, one delivered PaaS outbox fact, one
  public Audit fact and a complete tenant chain. FEAT-008 owns full semantics;
  FEAT-011 owns the CI boundary.
- The first two local attempts found test-only stale outbox assumptions
  (`event_document`, then the internal target-kind spelling). The fixed gate
  now queries the current `document` column by public action and target ID;
  the public Audit record still proves canonical target kind. Production
  effects were not relaxed.

## Cleanup and coordination

- The task browser, PostgreSQL container, dedicated network and data volume
  were removed after exact ownership-label and network-membership checks.
  A final label query returned zero containers, networks and volumes. No prune,
  shared/remote restart, other Phase object or retained environment was used.
- UX/UI owner is thread `01a07b21-9a0d-7fd0-b090-7827ce18262e`, branch
  `feat/iam-console-release-candidate`. It owns later visual/table work and will
  consume this fixed IAM result; do not duplicate that UI work on `feat/iam`.
- FEAT-008 and FEAT-011 contain the authoritative status and remaining gaps.
  Do not rerun this accepted browser journey merely to fill CI wait time, and
  do not infer that service activation grants quotas, resource permissions or
  a service Role.
