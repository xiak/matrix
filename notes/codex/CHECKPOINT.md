# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, the host goal and the owning FEAT.

## Pushed milestone

- Repository https://github.com/xiak/matrix.git, branch `feat/iam`; repository-local
  identity `Xiak <Jellal@aliyun.com>`.
- Active, incomplete bounded goal: AccessKey and same-account Role real-console
  closure, necessary fixes, independent verification and cleanup of unused own
  resources. The host goal is authoritative. Do not reopen the accepted
  permission-aware work or mark the overall IAM matrix complete.
- Latest code: `08e0d76bbea2d63c59b790e61c2870162d928c19`. Only the existing
  authorityprocess test owner and IAM/011 changed. Child Start/Wait observation
  times and reported CPU times improve a readiness-failure diagnosis; they are
  not exact kernel/CLI timings or a fix. Default Windows race/architecture/vet
  and the bounded Linux child-process test passed. The unchanged real Docker
  probe also passed locally, which is non-reproduction, not CI acceptance.
  Verification39711834716 attempt1 was confirmed in_progress at the milestone:
  https://github.com/xiak/matrix/actions/runs/39711834716 . Recheck its terminal
  state through the existing Test Expert; do not infer success from this note.
- Prior test candidate `958d5b46649abc3dac2936892bb323005af97bde` fixes the Role
  observer's exact application detail and natural-expiry boundary. Its complete
  Verification39646488455 attempt1 is CLOSED FAILURE: managed-products worker
  exited before readiness with the closed Docker Engine probe timeout code;
  the aggregate correctly failed. All nineteen logs were audited. No underlying
  resource, CLI-scheduling or daemon cause was established. IAM/011 owns this
  evidence; Issue6 remains open. Never refetch the closed logs, blindly rerun
  the old attempt or increase the production three-/five-second budgets.
- Latest fully audited successful CI source remains
  `e22d7481fec9ecaa33d0cdfe6df7942cabc6c064`, Verification39604675084 attempt1.
  Its full logs are closed; IAM/011 owns scope and limits. It changes only
  generated console delivery for the existing build fingerprint. It supplies
  no acceptance for later browser journeys or signed releases.
- Latest accepted signed production source remains
  `5935fa5005529b2c4e1da943b98f49300430ba10`, IAM/Audit/PaaS87/39/7+r37.
  Sole retained-data predecessor: `08e1dc4a6ce81386ea7223e62d03356f82aeee58`,
  86/39/7+r36. FEAT-005 owns signed lifecycle evidence. No later UI/test-only
  commit inherits a new signed-release conclusion.

## Acceptance and next boundary

- Read AGENTS, `IAM/FEAT-IAM-010-console.md`'s AccessKey/Role section and owning
  tests. IAM/007 owns Key rules, IAM/006 owns Role rules, IAM/011 owns CI.
  Navigation changes additionally use FEAT-007/ADR-0002/adoption; no new parallel
  acceptance document or browser framework.
- K2 SET_STATUS, NETWORK and DELETE have separate actual browser/process/PG18
  response-loss, exact replay, independent readback and Audit proof in010.
  API-prepared Keys do not prove normal UI creation or one-time Secret display.
- K1 normal lifecycle is not accepted. The existing opt-in fixture starts from
  no Keys; page writes and real signing prove overlap, disable/enable/delete,
  quota release and replacement. Secrets stay in bounded process memory only.
- R1 creation/trust/boundary/attachment/assume plus exact RoleSession revocation
  has a ready opt-in fixture but no actual page acceptance. Positive business
  reads, boundary denial, surviving sibling, exact effects and Audit are required.
- R2 attachment revocation is not accepted. R2d performed the actual UI write
  but its old observer missed exact detail requests; never backfill missing HTTP
  evidence from DOM. Fixed958's R2e performed its pre-read but submitted no
  revocation, received no completion marker and timed out; exact state stayed
  unchanged. That URL/request/confirmation is expired, not a resumable intent.
- Current observer requires the issued Role's prior application200, actual
  administrator revocation, subsequent protected401 before natural expiry,
  explicit source validation200 and source application403. Never make another
  request with a credential already blocked by the UI or widen exact resources.
- Real page observations and independent effects are both required. Markers only
  trigger verification; API/component tests do not substitute for browser writes.
  No SSO, WebAuthn, cross-account, role-chain or full signed-release expansion.

## Coordination and operating boundaries

- UX/UI owner:01a07b21-9a0d-7fd0-b090-7827ce18262e, fixed source
  `7a704f5f2f3deb25e7972015a495a503288f4733`. Use the original executor, fixed
  objects only and no WIP or retained MOCK interference. Its current rules still
  require action-time confirmation for Key/permission writes; a fully enumerated,
  continuous bounded flow can combine confirmation only within its actual rules.
  Do not substitute another executor/API to evade them, transfer old confirmation
  to a new fixture or launch another heavy fixture merely to idle.
- Test Expert:01a12f7b-be04-7590-acb1-3ba4f0dab999. Keep the one existing monitor,
  no new chat/agent/duplicate monitor. It is tracking fixed08e0d76, not rerunning958.
  Prioritize exact-SHA required-job outcomes and affected roots; distinguish
  checked evidence from unreviewed detail instead of repeatedly fetching huge logs.
- User authorizes autonomous MATRIX development/testing; this is not a missing
  product-design decision. Actual tool confirmation/handoff restrictions remain.
- Own unique labels/IDs and explicit CPU/memory/PID limits; GoGOMAXPROCS2/-p2,
  heavy gates serial, process-local Node22/2GiB and bounded workers. No global
  nvm, prune, shared/remote restart, other Phase writes or retained install use.
- Clean only verified own unused resources. A tool-blocked cleanup is not done;
  do not retry it through another executor, shell, rename or parent deletion.
  Machine-local diagnostic residues are not portable runtime handles. Do not
  claim full cleanup while these restrictions remain unresolved.
- Markdown and existing documentation owners only. This checkpoint carries
  pushed work, not transient local URLs, absolute paths or another owner's state.
