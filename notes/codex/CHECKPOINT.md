# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`.
  Repository-local identity is exactly `Xiak <Jellal@aliyun.com>`.
- The active bounded goal is AccessKey and same-account Role real-console
  closure, necessary fixes, independent verification and cleanup of unused
  own test resources. `IAM/FEAT-IAM-010-console.md` owns UI-K1/K2 and UI-R1/R2;
  007 and006 retain credential and Role contracts. Do not reopen the already
  accepted permission-aware increment or claim the overall IAM matrix complete.
- Latest pushed production/test candidate:
  `da9426f608a99d564d573d3d4153714ba1198ada`, parent
  `4448e916ca437423347fcd820ba25b638244f90e`.
  The parent adds page-owned Key/Role opt-in fixtures and bounded observers.
  The candidate selectively consumes UX fixed
  `ceb38eab2cb3075573dcea640d9ca5d38e097a3e` navigation source/tests, not
  donor assets or acceptance. Six of nine resulting blobs match; existing
  Shell tests and two locale deltas are retained. No API/SQL/Profile change.
- Applications, IAM and Audit have console-owned implemented SPA destinations.
  Managed-product membership still comes only from backend ServiceDefinitions;
  loading or failure of that directory cannot remove platform links. Preview
  routes stay out of LIVE. Visibility is not permission, health or activation.
  FEAT-007 owns this boundary; its adoption record owns the fixed source.
- Consumer regressions first failed on the original missing Applications links
  (2 cases,10.01s), then passed unchanged after the fix (8.69s).
  Three relevant files/174 tests passed49.90s; type/lint/architecture,
  234 contrast pairs and8 Node tests passed. Node22.22.2,2GiB,
  one test worker and two build workers produced324 byte-identical unset/0
  exports and rebuilt this branch's embedded assets. Go UI/architecture/
  default authorityprocess race passed7.376/1.797/3.909s; vet passed.
  These are not real-browser or signed-release acceptance.
- Exact CI for da9426f is pending independent closure by the existing Test Expert.
  Do not inherit the prior candidate's green result or donor's2072 tests.
- Previous fixed `640f0f59045b194466807329a12f7bc6c6b58a08` /
  Verification39586936643 attempt1 is independently CLOSED SUCCESS:
  https://github.com/xiak/matrix/actions/runs/39586936643 .
  Terminal2026-10-21 11:18:38UTC;19 jobs,370 steps
  (175success/195matrix-designed skips),14lanes/57actual roots,
  33JSON packages and1164Test identities reconciled.
  Frontend2059+8,234contrast,324assets; full evidence belongs to011.
  The15browser/13response-loss declarations were not executions.
  Do not re-fetch closed logs or rerun CI for documentation.
- Earlier9062 /39559359986, P1 andP2 remain closed under their original
  Actions/Git evidence. Permission-aware and Policy RETIRE UNKNOWN actual
  browser evidence stays in010 and is not rerun merely for this goal.
- Latest accepted signed source remains
  `5935fa5005529b2c4e1da943b98f49300430ba10`,
  IAM/Audit/PaaS87/39/7+r37. Sole rolling data predecessor:
  `08e1dc4a6ce81386ea7223e62d03356f82aeee58`,86/39/7+r36.
  FEAT-005 owns signed A/B artifacts/lifecycle. Later code does not inherit it.

## Current acceptance and next boundary

- Read AGENTS,010's bounded Key/Role closure, then relevant006/007 code/tests.
  For navigation read only relevant FEAT-007/ADR-0002 and its adoption owner.
  011 owns independent CI; signed operations additionally need FEAT-005.
- K2 SET_STATUS, NETWORK and DELETE each passed a separate real PG18/process/
  browser response-loss journey, exact original replay, independent read-back
  and unique effect/completion/outbox/Audit chain. Accurate requests/versions/
  runtimes and differing consumer sources are in010, not duplicated here.
  API-prepared Keys do not prove UI creation, one-time Secret or recovered-create.
  Issue5 remains open for its unreconciled original browser scope.
- Normal K1 is implemented as an opt-in page-owned fixture, not accepted.
  Its first preparation used an invalid application name; after correction,
  another fresh run created zero Keys and timed out waiting for the specific
  browser confirmation (1800.06s/race1802.516s). It is not a product creation
  failure or a pass. Its processes/connections ended and its database was
  removed. Do not submit to old local URLs or manufacture completion markers.
- The first640f ROLE/REVOKE browser run really assumed a Role but failed because
  Applications had no visible SPA entry. No attachment was revoked.
  Failure361.16s/race363.704s is preserved. The new fixed navigation needs its
  own fresh R2 browser proof: actual Role business200, one administrator
  attachment revoke with lost response, GET-only original receipt recovery,
  Role401/BLOCKED, explicit source validation and USER business403.
- R1 and the distinct exact administrator RoleSession revoke use one new
  opt-in journey: page-created CUSTOMER Role/trust/boundary/positive attachment,
  actual member assume, application200/Audit403 boundary intersection, then
  revoke only the browser-issued Session. A separate sibling remains usable;
  Role/trust/attachments and immutable issuance stay unchanged. Default unit
  observers and API setup are not the actual page writes.
- Key creation/Secret handling, two-Key real signed PaaS requests and quota
  release must still be visibly observed; do not read Secrets from DB or
  put them in logs/browser storage. Markers only trigger independent
  postconditions after an actual browser report.
- Normal Key observer15 cases and Role observer19 cases plus bounded/transparent
  response capture run in the original authorityprocess owner. The new browser
  roots are opt-in; default skips are never acceptance.
- This goal does not close every010 IAM-UI-01–08 path or the overall011 goal.
  No SSO/WebAuthn/cross-Account/role-chain/signed-release expansion.

## Coordination and operating boundaries

- UX/UI owner:01a07b21-9a0d-7fd0-b090-7827ce18262e.
  It owns UI implementation and actual page observations. Consume only
  reviewed fixed Git objects, not its worktree, generated assets or status.
- Test Expert:01a12f7b-be04-7590-acb1-3ba4f0dab999.
  Its one existing monitor owns exact CI closure. No duplicate monitors,
  user chats or subagents. CI and independent development proceed in parallel;
  contract/security failures must be fixed before dependent work.
- User authorizes MATRIX development/test operations autonomously.
  Read actual current browser rules rather than asking for every permission
  change: ordinary authorized sign-in and reducing test access differ from
  creating persistent credentials or expanding access. Respect genuine
  action-time confirmations/handoffs and actual tool denials; never bypass.
  No DOM-injected links/private router tricks or API substitute for UI proof.
- Only exact task-owned resources, unique labels, explicit CPU/memory/PID caps,
  GOMAXPROCS2 and Go-p2. Heavy real gates are serial. Use process-local
  Node22.22.2, one Vitest worker/2GiB and two export workers, no global nvm.
- Inspect live processes/connections before cleanup. Keep compact evidence;
  remove only no-longer-needed own databases, temporary packages and objects.
  Tool-blocked cleanup is not completed and cannot be retried through another
  tool, renamed path or parent removal.
- No remote machine or shared service restart. Do not touch1.3/1.5/161, other
  tasks' workspaces/resources or retained signed installations. Authorized160
  experiments require their own bounded identity.
- Markdown and existing documentation owners only. This checkpoint describes
  pushed work, not machine-local runtime addresses, uncommitted source or a
  parallel runbook.
