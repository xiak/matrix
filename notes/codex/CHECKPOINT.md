# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, the host goal and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`; repository-local
  identity `Xiak <Jellal@aliyun.com>`.
- Incomplete bounded goal: AccessKey and same-account Role real-console closure,
  necessary fixes, independent verification and cleanup of unused own resources.
  The host goal is authoritative. Do not reopen accepted permission-aware work
  or mark the overall IAM matrix complete.
- Latest test-only milestone after `dea0af7fdcdb82533c20704015fafaa6ec3ff81c`:
  `fix(test): preserve role recovery response-loss transport`. It keeps the
  loss boundary on the actual connection and observes the upstream response
  inside it. The shared real-HTTP assembly failed on the old wiring with an
  empty200 (race2.553 seconds), then passed with actual partial-body/EOF,
  one receipt read and the exact credential journey. Related probes passed
  race3.795 seconds, default process/architecture5.541/2.772 and vet passed.
  No production/API/SQL/UI/profile change. Its exact-SHA CI and fresh R2
  remain pending; do not inherit earlier CI.
- Prior pushed code: `b3c3d157fd58af0743f4ef4721123b27de05abf8`.
  Verification39746740451 attempt1 is completed/success: the exact SHA and all
  nineteen jobs were independently checked through GitHub API. Four precheck
  logs were fully audited; authority logs are not yet audited. Only the existing
  R1 test and IAM/010 changed: Role names live in metadata, not a standalone
  name column. Its original lookup failed with SQLSTATE42703 in actual PG18.4;
  the corrected exact live CUSTOMER lookup returned the right Role and no
  match in another existing Account. Default process/architecture race passed
  5.452/1.917 seconds and vet passed. This does not execute/accept R1 or R2.
  No UI/API/production SQL/profile change; embedded build remains
  `matrix-f0c6f4f1a804dcfebbf2`.
- Previous code `7d6db51b0bbb676c446e08f82af0bf50ccc33a5b`,
  Verification39743005047 attempt1, is completed/success: exact SHA and all
  nineteen jobs were independently checked through GitHub API. Test Expert
  verified the actual short client root1.45 seconds, full four-product root
  128.51 seconds and Analyzer41.08 seconds. The complete product summary and
  pinned client marker each matched once. Sixteen logs are fully audited and
  three are partial; the original in-memory log-reading session was lost.
  Whole-log audit is not sealed. Do not claim all root details were audited or
  inherit browser/release status. IAM/011 owns exact evidence.
- That slice uses the fixed volume-free Docker27.5.1 CLI client; image resolution
  rejects declared volumes/missing Config before creation, and the short real
  gate executes the CLI and checks actual mounts. Original runtime mount,
  database identity, private archive and three-/five-second budgets remain.
  The old DinD image reproduced the unexpected-volume failure; the corrected
  short gate passed. SQLSTATE-only Analyzer tracing changes no migration,
  scanner, retry or deadline. IAM/011 owns exact evidence.
- Prior22591/Verification39736548709 is CLOSED FAILURE, with all nineteen logs
  now audited. Storage failed at the final Analyzer schema replay without an
  underlying SQLSTATE; its next six roots did not RUN. Products passed the short
  input root but failed the unexpected-volume assertion after HTTP readiness.
  Never refetch closed logs or rewrite this as success.
- Earlier ef909,08e0d76 and958 CI attempts are also closed failures. Linux source
  ownership and client image volumes were separately reproduced/corrected.
  These do not identify the original Engine/Observe timeout; Issue6 stays open.
  Never blindly rerun old attempts or increase production probe budgets.
- Latest fully audited successful CI source remains
  `e22d7481fec9ecaa33d0cdfe6df7942cabc6c064`, Verification39604675084 attempt1,
  until the newer audit is explicitly sealed. IAM/011 owns its scope.
- Latest accepted signed production source remains
  `5935fa5005529b2c4e1da943b98f49300430ba10`, IAM/Audit/PaaS87/39/7+r37.
  Sole retained-data predecessor:
  `08e1dc4a6ce81386ea7223e62d03356f82aeee58`,86/39/7+r36.
  FEAT-005 owns signed lifecycle evidence. Later test/UI commits do not inherit
  a new signed-release conclusion.

## Acceptance and next boundary

- Read AGENTS, IAM/FEAT-IAM-010-console.md's AccessKey/Role section and owning
  tests. IAM/007 owns Key rules, IAM/006 owns Role rules, IAM/011 owns CI.
  Navigation changes additionally use FEAT-007/ADR-0002/adoption. No parallel
  acceptance document or browser framework.
- K2 SET_STATUS, NETWORK and DELETE each have actual browser/process/PG18
  response-loss, exact replay, independent readback and Audit proof in010.
- K1 normal lifecycle is accepted on clean113a2299, code08e0d76 and embedded e22.
  The original UX executor completed all seven confirmed page writes; fresh
  PG18 and actual IAM/Audit/PaaS/dispatchers passed727.31 seconds, race730.876.
  Actual signing proved overlap, disable/enable, deletion, quota release and
  replacement; seven exact facts and the complete tenant chain matched.
  Secrets stayed in one-time UI/test memory. This does not accept R1/R2.
- R1 creation/trust/boundary/attachment/assume plus exact RoleSession revocation
  is accepted on clean382243922, codeb3c3 and actual PG18.4. The original UX
  executor obtained direct confirmation for the fresh destination/objects and
  completed all five page actions. Root834.25 seconds/race837.760, exit0.
  Actual single assumption and application200/Audit403 were observed; exact
  revocation produced same-Role401 on managed-services, explicit original
  source200 and source application403. Source Session remained valid; the
  independent sibling retained IAM/application200 and Audit403. Role/trust/
  attachment were unchanged, five exact facts and the complete chain matched.
  The temporary product-menu overlay was dismissed before the successful return;
  it is not a proven backend/session defect. No relogin or second assumption.
  Postconditions found Role1/active attachment1/RoleSessions2 (one revoked,
  one valid sibling), zero clients/processes/browser listener; tabs are closed.
  This attempt's PG/network/empty-root cleanup was denied before execution.
  Those resources remain; do not retry through another route or claim cleanup.
  IAM/010 owns the precise acceptance; R2 attachment recovery remains separate.
- R2 attachment revocation remains unaccepted. The fresh clean-dea0 run made
  one actual revocation and read the original receipt. Its Role detail401,
  explicit original source200 and source application403 were observed, but
  loss injection returned false and recovery reads were not counted. Root
  554.94 seconds/race557.535, exit1; no full-chain acceptance. The exact
  original receipt/outbox and version2 revoked attachment each exist once.
  The test-only wrapper composition cause is fixed above; never backfill the
  failed run from DOM. Processes/listener/clients are zero and tabs closed;
  this run's PG/network/empty root cleanup was denied before execution and
  remains untouched. Its URL/objects are no longer a browser intent.
- The current observer requires the issued Role's prior application200, actual
  admin revocation, protected401 before natural expiry, explicit original
  source validation200 and source application403. Never request again using a
  credential already blocked by the UI or widen exact resources.
- Every accepted journey needs both page observations and independent effects.
  Markers only trigger verification; API/component tests do not substitute for
  page writes. No SSO, WebAuthn, cross-account or role-chain expansion.

## Coordination and operating boundaries

- UX/UI owner:01a07b21-9a0d-7fd0-b090-7827ce18262e, fixed UI source
  `7a704f5f2f3deb25e7972015a495a503288f4733`.
  Use the original executor and fixed objects only; no WIP/retained MOCK use.
  It requires action-time confirmation for Key/permission writes. Do not
  substitute another executor/API to evade that requirement, transfer an
  expired confirmation or start another heavy fixture merely to idle.
  K1's consumed approval is not a Role or later Key-fixture approval.
- Test Expert:01a12f7b-be04-7590-acb1-3ba4f0dab999. Keep its one existing monitor,
  no new chat/agent/duplicate monitor. Follow b3c3/39746740451 and preserve the
  unfinished7d6 log audit. Prioritize exact-SHA required-job outcomes and affected
  roots; distinguish checked evidence from unaudited detail. Closed logs do not
  need fetching again.
- User authorizes autonomous MATRIX development/testing; no product-design
  decision is missing. Actual tool confirmation/handoff restrictions remain.
- Own unique labels/IDs with explicit CPU/memory/PID limits. Go GOMAXPROCS2/-p2,
  heavy gates serial; process-local Node22/2GiB with bounded workers. No global
  nvm, prune, shared/remote restart, other Phase writes or retained install use.
- Clean only verified own unused resources. Tool-denied cleanup is not done and
  must not be retried through another executor, shell, rename or parent deletion.
  A generated Linux test binary, an older stopped diagnostic container, empty
  task directories, Analyzer PG/network, successful R1 PG/network/root and
  the failed R2 PG/network/root
  remain denied residues. The PGs were last read-only checked running with zero
  fixture clients.
  Do not ask another task to bypass the denial or claim complete cleanup.
  Machine-local handles are not portable runtime evidence.
- Markdown and existing owners only. Keep this single checkpoint for pushed
  work; no transient URLs, absolute machine paths or another owner's WIP.
