# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, the host goal and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`; repository-local
  identity `Xiak <Jellal@aliyun.com>`.
- Incomplete bounded goal: AccessKey and same-account Role real-console closure,
  necessary fixes, independent verification and cleanup of unused own resources.
  The host goal is authoritative. Do not reopen accepted permission-aware work
  or mark the overall IAM matrix complete.
- Latest pushed code: `b3c3d157fd58af0743f4ef4721123b27de05abf8`.
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
  remains unaccepted. Prior clean6f24 prepared only the review page: no direct
  action-time confirmation reached the original executor and no page writes
  occurred. The fixture expired; zero Roles/facts and zero clients/listeners
  were independently checked, and its PG/network/page were closed.
  Do not reuse its URL/confirmation. Consume fixed b3c3 before the next run.
  The user subsequently confirmed readiness for a new R1. The original UX
  executor has restored its browser capability and explicitly requested a fresh
  fixture. This milestone contains no new page-write acceptance: use new
  resources and identifiers, then require the actual journey and effects.
- R2 attachment revocation remains unaccepted. R2d made the actual UI write,
  but its old observer missed exact application-detail HTTP evidence. Never
  backfill that evidence from DOM. Fixed958's R2e made no revocation and expired
  unchanged; its URL/request/confirmation is not a resumable intent.
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
  task directories and the latest Analyzer PG/network remain denied residues.
  The latter was last read-only checked running with zero fixture clients.
  Do not ask another task to bypass the denial or claim complete cleanup.
  Machine-local handles are not portable runtime evidence.
- Markdown and existing owners only. Keep this single checkpoint for pushed
  work; no transient URLs, absolute machine paths or another owner's WIP.
