# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`.
  The renewed IAM first-release goal is ACTIVE and incomplete.
- Latest pushed candidate:
  `0c00ef988cb74f4a812fe0a3eb43b9dd454c3455`.
  It changes only the existing authorityprocess test owner and FEAT010/011.
  The Group PolicyAttachment CREATE receipt-recovery browser gate passed;
  REVOKE is implemented but has not run in a real browser. Its independent
  CI is not yet accepted.
- Parent `a79ca1454401e24427c0bbef667b4d43b2db1522` has exact
  [Verification 39118086883](https://github.com/xiak/matrix/actions/runs/39118086883)
  attempt 1 completed/success, all 19 jobs. The test expert is finishing
  detailed log review; job success does not replace opt-in browser or SMTP
  evidence.
- Product and signed-release source remains
  `741dceb6f0092fbc33706842862980816fe72d15`,
  IAM87/Audit39/PaaS7 + contractRevision37. Its exact CI39012317180 and
  same-profile signed A/B lifecycle and restart verification passed.
  The single rolling predecessor remains
  `08e1dc4a6ce81386ea7223e62d03356f82aeee58`, IAM86/Audit39/PaaS7+r36.

## Reading route and remaining outcome

Read AGENTS, IAM/FEAT-IAM-010-console.md, then
IAM/FEAT-IAM-011-acceptance.md and the relevant existing
test/authorityprocess/process_e2e_test.go fixture. FEAT010 owns individual
UI paths, evidence and remaining gaps; FEAT011 owns combined acceptance.
Do not infer completion from this checkpoint or repeat accepted gates.

Continue Group attachment REVOKE, then the remaining nonDeferred UI
paths in FEAT010. Daily password change and Group final deletion have
opt-in fixtures but no accepted final browser execution. Direct User/Role
attachments and remaining policy/security/resource paths retain their
own acceptance boundaries. Deferred external integrations and deployment
prerequisites are not silently part of this goal.

Current test increment proves CREATE with one committed POST, lost reply,
one exact original receipt GET, no later attachment writes, next-request
PaaS authorization, one authoritative row/completion/outbox/Audit fact and
a complete tenant chain. Its default authorityprocess and architecture
race tests, vet and diff checks pass; default SKIP is not REVOKE evidence.
No production API, SQL, UI, profile or encoding changed.

## Coordination and delivery boundaries

- UX/UI engineer thread `01a07b21-9a0d-7fd0-b090-7827ce18262e`
  owns UI on its own branch. It is handling already observed UNKNOWN,
  cancellation, membership-removal and security-settings messages.
  Consume only its verified fixed changes, not WIP or foreign FEAT status.
- Test expert thread `01a12f7b-be04-7590-acb1-3ba4f0dab999`
  owns independent CI/log review. Submit necessary CI once and continue
  independent development; fix security/contract failures before acceptance.
- User authorizes routine test decisions and starting Docker Desktop if
  stopped. This does not authorize resetting shared Docker/WSL, restarting
  remote machines, consuming foreign resources or changing global settings.
- Use uniquely owned limited resources, GOMAXPROCS2 and bounded Go
  concurrency; serialize heavy real database gates. Remove no-longer-needed
  task resources after evidence collection. Cleanups must verify ownership.
- Keep docs Markdown and existing owners, Git identity
  Xiak <Jellal@aliyun.com>, and push only the task branch.
