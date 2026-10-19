# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`.
  The renewed IAM first-release goal is ACTIVE and incomplete.
- Latest fixed test source:
  `c80e58165b46f57ad309eabbdb3c33b0e2bc782e`.
  It strengthens the existing Group deletion browser fixture. Its
  [Verification 39191085161](https://github.com/xiak/matrix/actions/runs/39191085161)
  is still pending final confirmation; do not inherit the predecessor's CI.
- Fixed `0c00ef988cb74f4a812fe0a3eb43b9dd454c3455` has exact
  [Verification 39188263855](https://github.com/xiak/matrix/actions/runs/39188263855)
  attempt 1 completed/success, all 19 jobs. The test expert completed the
  actual-log audit: all 57 top-level authority roots RUN/PASS. Default
  opt-in browsers and seven Postfix subtests are not real execution evidence.
- Product and accepted signed-release source remains
  `741dceb6f0092fbc33706842862980816fe72d15`,
  IAM87/Audit39/PaaS7 + contractRevision37. Its exact CI39012317180 and
  same-profile signed A/B lifecycle and restart verification passed.
  The single rolling predecessor remains
  `08e1dc4a6ce81386ea7223e62d03356f82aeee58`, IAM86/Audit39/PaaS7+r36.

## Reading route and remaining outcome

Read AGENTS, IAM/FEAT-IAM-010-console.md, then
IAM/FEAT-IAM-011-acceptance.md and the relevant existing
test/authorityprocess/process_e2e_test.go fixture. FEAT010 owns individual
UI paths, evidence and gaps; FEAT011 owns combined acceptance.

Group attachment CREATE and REVOKE have real browser/PG18/process evidence:
one committed POST, lost reply, one exact receipt GET, zero subsequent
attachment writes, next-request authorization and unique completion/outbox/
Audit with a complete chain. REVOKE uses fixed
`77923f7839633002eb2a6c732c35fec6bea19436`, which connects that mode to the
existing browser observation budget without extending production HTTP timeouts.

The c80 Group final-deletion browser effect also passed: exact one-membership
and one-attachment cascade, directory removal, next PaaS denial, still-valid
member identity and surviving system Policy, unique outbox/Audit and chain.
The old UI immediately returns to details/directory in these two flows and
does not retain visible immutable completion/counts. That UX gap remains open;
backend effects do not replace visible receipt acceptance.

Continue the existing nonDeferred FEAT010 matrix, including those receipt
presentation fixes, daily password change, direct User/Role attachments and
remaining policy/security/resource paths. Do not repeat accepted gates without
an affected boundary. Deferred integrations and deployment prerequisites are
not silently part of this goal.

## Coordination and delivery boundaries

- UX/UI engineer `01a07b21-9a0d-7fd0-b090-7827ce18262e` owns UI on its
  own branch. Consume fixed reviewed deltas only, preserve this branch's
  tests and rebuild embedded assets; no foreign WIP or inherited acceptance.
- Test expert `01a12f7b-be04-7590-acb1-3ba4f0dab999` owns independent
  CI/log review. Continue independent work while necessary CI runs;
  fix security/contract failures before acceptance.
- The user authorizes routine product development/test actions without
  repetitive approval. Mandatory tool-specific human handoff remains binding.
  Isolate task resources; do not reset shared Docker/WSL, restart remote
  machines/shared services or touch unrelated resources.
- Use uniquely owned limited resources, GOMAXPROCS2 and bounded Go concurrency;
  serialize heavy real database gates. Verify ownership and remove unused
  task resources after evidence collection.
- Markdown and existing document owners; repository-local Git identity
  Xiak <Jellal@aliyun.com>; push only the task branch.
