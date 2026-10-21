# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`.
  Repository-local identity is `Xiak <Jellal@aliyun.com>`.
- Active bounded goal: AccessKey and same-account Role real-console closure,
  necessary fixes, independent verification and cleanup of unused own resources.
  `IAM/FEAT-IAM-010-console.md` owns K1/K2 and R1/R2;007/006 retain credential
  and Role contracts. Do not reopen accepted permission-aware work or mark
  the overall IAM matrix complete.
- Latest pushed code candidate: `4760581e035ec299003ef8f777b777feda38a218`,
  parent `0884b4e8d3a144ba586dc1cd126a5b9fa8d44cd5`.
  Its exact independent CI is pending the existing Test Expert's closure.
- 0884 changes only the existing Role browser observer and010: after real
  page-issued Role application200 and observed admin revocation, the first
  exact same-credential GET401 may come from Applications, the implemented
  managed-service directory, or current Role identity. 403/503, another bearer,
  unrelated route/method or pre-revoke401 do not qualify. Explicit source
  validation200 and source application403 remain mandatory. No extra request
  with an already blocked credential is required. Two new positives first
  failed;27 scenarios then passed. No API/SQL/UI change.
- 476 changes only storage's orchestration envelope20→25 minutes. Complete YAML
  semantic comparison proves unchanged tests, fixture deadlines, lanes,
  database limits, concurrency and fail-closed summary;24 Bash steps parse.
  Default process/architecture race3.948/2.591s and vet passed. Opt-in skips
  are not actual PG/browser evidence.
- UI candidate `da9426f608a99d564d573d3d4153714ba1198ada` selectively consumes
  UX fixed `ceb38eab2cb3075573dcea640d9ca5d38e097a3e`, not donor assets or
  acceptance. Platform Applications/IAM/Audit use implemented SPA destinations;
  managed entries still come only from ServiceDefinitions. Directory failure
  cannot remove platform links; preview routes remain outside LIVE. Visibility
  grants no permission, health or activation. FEAT-007/adoption owns this.
  Consumer red/green,174 tests, Node22 type/lint/architecture,234contrast/
  8Node tests, own324 identical dual exports and Go race evidence belong to010.
- da9426 /Verification39593652955 attempt1 is CLOSED CANCELLED:
  https://github.com/xiak/matrix/actions/runs/39593652955 .
  storage check119204314631 explicitly exceeded20m. Its19m07s test step passed,
  but setup/cleanup crossed the job limit and final summary failed. Storage raw
  logs are partial, not accepted as complete. No evidence of manual/concurrency
  cancellation. Do not redownload closed huge logs or rerun old CI. 011 owns
  the exact evidence and476 correction.
- Last fully accepted CI: `640f0f59045b194466807329a12f7bc6c6b58a08` /
  Verification39586936643 attempt1,19jobs success. Older9062/P1/P2 remain closed
  under original evidence; no refetch. Browser default skips are not runs.
- Last accepted signed source: `5935fa5005529b2c4e1da943b98f49300430ba10`,
  IAM/Audit/PaaS87/39/7+r37. Sole predecessor
  `08e1dc4a6ce81386ea7223e62d03356f82aeee58`,86/39/7+r36.
  FEAT-005 owns its signed lifecycle; later UI/test changes do not inherit it.

## Acceptance and next boundary

- Read AGENTS,010's Key/Role section, then owning code/tests. Navigation changes
  additionally need relevant FEAT-007/ADR-0002/adoption;011 owns CI.
- K2 SET_STATUS, NETWORK and DELETE each passed separate actual PG18/process/
  browser response-loss, exact replay, independent read-back and unique
  completion/outbox/Audit chain gates. Requests/versions/runtimes/sources are
  in010. API-prepared Keys do not prove K1 or recovered-create. Issue5 stays
  open for its unreconciled original browser scope; Issue6 Observe diagnosis
  and signed Issue3 remain separate.
- K1 opt-in fixture exists: page creates two Keys, observes one-time Secret,
  toggles/deletes first, creates replacement; real signed requests prove overlap,
  immediate disable/delete and quota release. Its earlier fresh attempt created
  zero Keys and timed out awaiting action-time confirmation. No actual creation
  accepted. Do not reuse dead URLs/stale confirmations. Secret stays in bounded
  test-process memory, never logs or DB reads.
- R2 first640f run failed for missing Applications navigation before revocation.
  da9426's next actual page run reached UNKNOWN/receipt/zero attachments/
  BLOCKED/explicit source403 but failed the old application-only401 observer
  (400.18s/race402.669s). Do not backfill it or invent missing network evidence.
- Fresh0884 run assumed once and read the actual application; final revocation
  was not submitted. UX's actual browser instructions required action-time
  confirmation, unlike this chat's instructions. Stop rather than evade that
  execution boundary. No marker; exact own UI was stopped and gate failed
  `browser UI exited during observation`716.88s/race719.354s. Attachment
  remainedv1/unrevoked. Tabs/processes/listeners/DB clients ended; disposable
  database and own PG container removed, compact logs retained. No fresh
  browser runtime retained. Do not restart heavy fixtures merely to idle.
- R1 plus distinct exact admin RoleSession revocation fixture exists, unrun:
  page-created CUSTOMER Role/trust/boundary/positive attachment, actual assume,
  App200/Audit403 intersection; revoke only that Session, Role401/BLOCKED→
  explicit source200→sourceApp403. Sibling stays200; Role/trust/attachments/
  issuance unchanged, five unique facts and full chain.
- Actual page observations plus exact effects are required. Markers only trigger
  checks after the observed journey; no API/component substitute. No SSO,
  WebAuthn, cross-account, role-chain or signed-release scope. Goal not complete.

## Coordination and operating boundaries

- UX/UI owner:01a07b21-9a0d-7fd0-b090-7827ce18262e; fixed objects only, no WIP,
  donor assets/acceptance or interference with retained MOCK environment.
- Test Expert:01a12f7b-be04-7590-acb1-3ba4f0dab999; one existing exact-SHA CI
  monitor, no new chats/subagents/duplicate monitors. Develop independently while
  CI runs; contract/security failures must precede dependent consumers.
- User authorizes autonomous MATRIX development/testing. Actual tool
  confirmation/handoff restrictions still apply; different execution chats can
  receive different policy text. Do not force another chat to ignore its actual
  restriction or substitute an executor/API for a blocked final action. Avoid
  repeated ordinary product-authorization questions. No injected links/private
  router tricks or credential persistence to fake browser acceptance.
- Unique labels/exact ownership, CPU/memory/PID limits, GoGOMAXPROCS2/-p2,
  heavy gates serial; process-local Node22/2GiB, one test/two build workers.
  No global nvm, prune, shared or remote restart, or other Phase writes.
- Clean completed own test objects after identity/client checks. A previously
  tool-blocked interrupted temporary directory remains; do not retry via
  alternate tools, rename or parent deletion, or claim it cleaned. No1.3/1.5/161
  or retained installation operations. Authorized160 work requires its own scope.
- Markdown and existing owners only. Checkpoint records pushed work, not volatile
  local URLs, absolute machine paths, uncommitted state or another runbook.
