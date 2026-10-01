# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `61b626c35`
- Pushed documentation milestone: `2860081aa`

## Authoritative route

- IAM client requirements, status and boundary evidence:
  [`FEAT-IAM-010`](../../IAM/FEAT-IAM-010-console.md).
- Shared UX requirements, status and verification evidence:
  [`FEAT-007`](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed-source adoption decisions:
  [`FEAT-007 adoption review`](../../docs/adoption/FEAT-007-control-plane-console.md).
- Shared product boundary:
  [`ADR-0002`](../../docs/architecture/ADR-0002-product-boundary.md).

Do not restate or amend those owners here. Read this checkpoint only after
compaction or handoff, then validate it against Git and the linked FEAT.

## Latest pushed milestone

The independent DEV MOCK remains available at `http://127.0.0.1:4317`, and
login verification remains disabled for UX review. The User-scoped AccessKey
workspace separates credential lifecycle, product credential-carrier admission
and effective authorization. LIVE and MOCK share one default-collapsed
programmatic-access guide that reads the existing authorization Profile client
only when opened; a real catalog failure remains local and never falls back to
preview data. It lists only exact Actions that explicitly admit both `USER` and
`ACCESS_KEY`; omitted authentication methods never become broad support. The
shared Table/Footer paginates future results. Product acceptance is labelled as
metadata, not a grant: every request must still revalidate the key, User,
current policies, target resource, conditions and explicit denies. The browser
does not retain the Secret, sign a request or issue a synthetic product call.
The isolated MOCK alone adds a second default-collapsed disclosure for the
fixed `paas.application.create` public outcomes: `202 Operation`,
`400 INVALID_ARGUMENT`, `401 UNAUTHENTICATED`, `403 PERMISSION_DENIED`,
`409 CONFLICT` and `503 IDENTITY_UNAVAILABLE`. It records only verified nonce
semantics (`400` not consumed; `403` and `409` consumed) and makes no inference
for `401` or `503`. LIVE never renders this unreleased fixture.

Fixed IAM source `40adf6d828180050992a8a6c139f05a83afc753f` advances the PaaS
Profile to revision 7 and admits AccessKey for exactly
`paas.application.create`. The isolated preview now carries that exact
`ROLE + USER` and `ACCESS_KEY + LOGIN_SESSION` declaration; every other sampled
PaaS Action remains login-session-only. Source and synchronized embed are
pushed at `61b626c35`; FEAT evidence is pushed at `2860081aa`. Focused
preview/LIVE behavior and the complete 57-file/931-case frontend suite passed
with three normalization cases, typecheck/lint/architecture/228-pair style gates, 42-route
export, 233-file embed equality and full repository Go test/vet. Desktop and
`390 x 844` DEV verified the single revision-7 Action, collapsed disclosure,
labelled stacked outcome rows, no Dialog or horizontal overflow and a clean
post-reload browser log.

The previously pushed Application tag recovery, AccessKey owner directory,
policy-compilation provenance, service-authorization, policy-coverage, Audit,
cross-service loading/navigation and other console milestones remain owned and
indexed by FEAT-007; load only the relevant row when resuming that work.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits. IAM fixed source `40adf6d8` has passed local PostgreSQL,
independent-process, race/vet and Linux-build gates, but independent
Verification `36842829292` and the APISIX/northbound signed installation remain
unfinished; do not label the programmatic product path LIVE or add a browser
signature/test-request flow. The IAM engineer's revision-8 resource-graph
successor has passed its five-process gate and is still completing predecessor
verification, but remains unfixed and unpushed. Do not infer AccessKey support
from a collection shape: consume only each fixed Action's explicit credential-carrier set. Accepting a
credential carrier must never become an effective-access claim. Continue
without reintroducing whole-page loading, hidden broad Context subscriptions,
fabricated totals, duplicate components or login verification before UX
acceptance.
