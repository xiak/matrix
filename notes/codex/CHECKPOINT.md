# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-04
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `63b4643bc`
- Pushed documentation milestone: `e7a78b45c`

## Authoritative route

- IAM console behavior and acceptance evidence:
  [`FEAT-IAM-010`](../../IAM/FEAT-IAM-010-console.md).
- Shared console outcome and current UI evidence:
  [`FEAT-007`](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed donor decisions:
  [`FEAT-007 adoption review`](../../docs/adoption/FEAT-007-control-plane-console.md).
- AccessKey and product-enforcement contracts:
  [`FEAT-IAM-007`](../../IAM/FEAT-IAM-007-programmatic-credentials.md) and
  [`FEAT-IAM-008`](../../IAM/FEAT-IAM-008-product-enforcement.md).

Do not restate or amend those owners here. Read this checkpoint only after
compaction or handoff, then validate it against Git and the linked FEAT.

## Latest pushed milestone

The inspectable DEV MOCK remains available at `http://127.0.0.1:4317`; login
verification remains disabled for UX review. Source/embed `63b4643bc` consumes
fixed IAM source `91649497a0c53be1174d8835326a2df51fe74a55` for per-User
AccessKey network restrictions, authorization observations, complete account
security settings and the dedicated key-network mutation. The strict client
keeps Account and key CIDR layers independent, freezes the key layer into
creation/retry intent, renders absent authorization history as unknown and
never converts historical Allow/Deny into a current permit or business result.

The stable page shell renders immediately; user, key and Account-security data
load independently. A failed Account read preserves known key evidence instead
of replacing the page or showing a false unrestricted state. Key network
editing stays in the content area and uses its own versioned action; no Dialog
or status-action reuse was added. The explicit MOCK uses the same information
architecture without becoming a production fallback.

Full acceptance at this milestone: 62 frontend files / 1,046 tests, three
static-normalization tests, typecheck, lint, architecture, 228 theme-contrast
pairs, 45-route production export, 249-file embed equality, repository
`go test -p 2 ./...` and `go vet -p 2 ./...`. Desktop and `390 × 844` DEV
checks passed with document/body client and scroll widths at 390px; a fresh
reload emitted no warning/error.

Documentation milestone `e7a78b45c` replaces the service-authorization read
baseline with cumulative IAM source
`a464299b6656becc73054cd53b4a31b44104540b`; Verification `36779942782`
completed all 14 tasks successfully. The accepted browser boundary is only the
three current-`LOGIN_SESSION` customer reads for templates, Account relations
and exact bindings. Account remains outside browser selection, IAM stays
read-only, and product bind/unbind remains unmounted pending its own fixed
source and terminal evidence.

## Continuation boundary

Keep the MOCK preview available. Consume IAM changes only from fixed, pushed
sources with terminal evidence. The AccessKey client is contract-complete but
still needs a real-IAM browser mutation flow and installed-release acceptance;
product PEP enforcement, current permit and cloud-product credential usability
must not be inferred from IAM observations.

The service-template / Account-relation / workload-binding read surface is now
an accepted contract baseline but still needs real-IAM browser verification.
For the next UI slice, prefer an Access Analyzer rule only after its exact
backend source has a successful terminal gate; otherwise keep the existing
isolated MOCK. A template being `ACTIVE` is not Account consent, a binding or a
credential. Do not call `/v1/internal/*`, invent product selectors or expose a
write action whose public contract has not been accepted. Preserve current
page-shell loading, local data feedback, shared tables and content-area actions.
