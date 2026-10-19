# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`.
  The renewed IAM first-release goal is ACTIVE and incomplete.
- Latest fixed production candidate:
  `28f2da7e15c4720c262cae241f3425ada200ca9e`, IAM87/Audit39/PaaS7+r37.
  It selectively consumes UX fixed `dbe5add33d8ef1cac663f2186e965f8fff041671`
  and `323d7417ae230cf20d83d3903429b2492c0efb7f`, preserves IAM renderer
  tests and regenerates its own 324 embedded assets. Local static, component,
  deterministic build and Go UI/architecture gates passed. Its exact
  [Verification 39193669814](https://github.com/xiak/matrix/actions/runs/39193669814)
  attempt 1 is still pending whole-run confirmation.
- Latest accepted test predecessor:
  `c80e58165b46f57ad309eabbdb3c33b0e2bc782e` /
  [Verification 39191085161](https://github.com/xiak/matrix/actions/runs/39191085161)
  attempt 1. All 19 jobs completed/success; the test expert finished the
  necessary actual-log audit, all 57 top-level authority roots RUN/PASS.
  Default opt-in browsers and seven Postfix subtests are not real execution
  evidence. Do not repeat the closed log audit.
- Accepted signed-release source remains
  `741dceb6f0092fbc33706842862980816fe72d15`,
  IAM87/Audit39/PaaS7 + contractRevision37. Its exact CI39012317180 and
  same-profile signed A/B lifecycle and restart verification passed.
  New UI is not yet accepted as a signed combination. The single rolling
  predecessor remains `08e1dc4a6ce81386ea7223e62d03356f82aeee58`,
  IAM86/Audit39/PaaS7+r36.

## Reading route and remaining outcome

Read AGENTS, IAM/FEAT-IAM-010-console.md, then
IAM/FEAT-IAM-011-acceptance.md and the relevant existing
test/authorityprocess/process_e2e_test.go fixture. FEAT010 owns individual
UI paths, evidence and gaps; FEAT011 owns combined acceptance.

The old UI has accepted Group attachment CREATE/REVOKE response-loss and
Group deletion effects, including exact immutable results, next-request
authorization and unique outbox/Audit facts. The new fixed UI retains
visible completion receipts and explicit completion navigation. Historical
Account settings receipt reads no longer expire a later valid Session;
actual apply and real 401 retain their scoped behavior.

The new Group browser run stopped before its final deletion, without a
finish marker; the new REVOKE receipt rerun did not start. Neither is
accepted. Tool-mandated action-time human confirmation cannot be replaced
by blanket authorization or another tool/API. Do not repeatedly ask the
user or start another long waiting fixture without this prerequisite.

Continue the existing nonDeferred FEAT010 matrix, including these final
receipt operations, daily password change, direct User/Role attachments
and remaining policy/security/resource paths. Do not repeat accepted
gates without an affected boundary. Deferred integrations and deployment
prerequisites are not silently part of this goal.

## Coordination and delivery boundaries

- UX/UI engineer `01a07b21-9a0d-7fd0-b090-7827ce18262e` owns UI on its
  own branch. Consume fixed reviewed deltas only, preserve this branch's
  tests and rebuild embedded assets; no foreign WIP or inherited acceptance.
- Test expert `01a12f7b-be04-7590-acb1-3ba4f0dab999` owns independent
  CI/log review. Continue independent work while necessary CI runs;
  fix security/contract failures before acceptance.
- Routine product development/test actions are human-authorized without
  repetitive approval. Mandatory tool-specific human handoff remains binding.
  Isolate task resources; do not reset shared Docker/WSL, restart remote
  machines/shared services or touch unrelated resources.
- Use uniquely owned limited resources, GOMAXPROCS2 and bounded Go concurrency;
  serialize heavy real database gates. Verify ownership and remove unused
  task resources after evidence collection. Do not infer all historical
  local resources are removed from one successful remote cleanup.
- Markdown and existing document owners; repository-local Git identity
  Xiak <Jellal@aliyun.com>; push only the task branch.
