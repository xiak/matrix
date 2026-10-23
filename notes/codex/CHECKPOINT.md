# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, the active host goal and the owning FEAT before acting.

## Pushed release-candidate milestone

- Repository `https://github.com/xiak/matrix.git`, branch
  `feat/iam-console-release-candidate`; repository-local Git identity is exactly
  `Xiak <Jellal@aliyun.com>`.
- This checkpoint belongs to the release-candidate commit containing it. The
  integrated parents are console milestone `14f743087` and IAM documentation
  successor `0c74d9478`; the latter is documentation-only and fixes production
  and test source at `56e3e9c3b`.
- The candidate remains a Phase 1 modular monolith. IAM owns authorization and
  real-process evidence, FEAT-007 owns shared console UX, and generated Go embed
  assets are rebuilt from the single frontend source rather than merged by hand.

## Accepted integration evidence

- Service activation now preserves the exact Account/service definition,
  request ID and idempotency key when the success response is lost. The UI does
  not auto-repeat the POST: it first exposes an explicit read-only result check,
  and only an authoritative not-found result permits replay of the same request.
- A fresh PostgreSQL 18.6/race browser gate proved one POST, lost response, one
  injected 503 activation read, stable UNKNOWN with zero automatic writes, and
  one explicit GET recovering the committed result. The Account singleton,
  original USER decision and request digest, one outbox event, one Audit event
  and the full tenant chain matched. Resource read remained an independent 403,
  so service activation does not manufacture product-resource permission.
- Exact source `56e3e9c3b` passed
  [Verification 39936868627](https://github.com/xiak/matrix/actions/runs/39936868627)
  in 30m51s: Go, console, node-process, installation-postgres-ha, all fourteen
  authority lanes and the final authority-process aggregate succeeded. IAM/008
  and IAM/011 own the exact scope and limitations; this is not signed-release
  acceptance and the opt-in browser gate is accepted only by its recorded run.
- The integrated candidate passed the authorityprocess focused observer and
  default package, Go vet, typecheck, lint, architecture checks, 234 theme
  contrast pairs, 80 frontend files / 2,112 tests, eight export tests, two
  deterministic production exports, 59 pages / 57 normalized routes and exact
  equality of all 322 embedded files.

## Console UX state

- Shared table toolbars keep search, filter trigger and result count on a stable
  first row. Search is bounded to 320px on larger layouts; disclosed filters use
  labelled 220–260px controls, wrap without shifting primary actions and become
  full-width only in the small-container layout. Shared table footers and page
  controls remain the only pagination presentation.
- The built-in browser entered the isolated MOCK and traversed all eighteen IAM
  directory routes through client navigation. Every route retained the session,
  exposed the expected page title and avoided login fallback, 404 and application
  error states. The User directory visibly separates the Account owner from
  selectable ordinary Users and preserves the compact query workspace.
- The isolated MOCK stays available on the development server for progress
  review and never writes the real IAM backend. LIVE acceptance must continue to
  use authoritative sessions, API responses and database/Audit postconditions.

## Remaining release boundary

- The accepted signed production baseline remains
  `5935fa5005529b2c4e1da943b98f49300430ba10`, IAM/Audit/PaaS `87/39/7+r37`,
  with sole rolling predecessor `08e1dc4a6ce81386ea7223e62d03356f82aeee58`
  (`86/39/7+r36`). FEAT-005 owns that lifecycle evidence.
- Before calling this release candidate accepted, verify the exact combined
  branch with its independent CI, then run any newly required signed lifecycle
  and installed-browser gates under their existing FEAT owners. Do not inherit
  the older signed result, MOCK behavior or another fixed source's browser result.
- Continue coordination with the IAM development thread for backend-contract
  defects. Do not create a second IAM model, compatibility layer, duplicate
  checkpoint or parallel generated asset tree.
