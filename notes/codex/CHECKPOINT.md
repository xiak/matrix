# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `f11ac6582`
- Pushed documentation milestone: `c936fb709`

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

Fixed IAM source `40adf6d828180050992a8a6c139f05a83afc753f` advances the PaaS
Profile to revision 7 and admits AccessKey for exactly
`paas.application.create`. The isolated preview now carries that exact
`ROLE + USER` and `ACCESS_KEY + LOGIN_SESSION` declaration; every other sampled
PaaS Action remains login-session-only. Source and synchronized embed are
pushed at `f11ac6582`; FEAT evidence is pushed at `c936fb709`. Focused 257-case
coverage and the complete 57-file/931-case frontend suite passed with three
normalization cases, typecheck/lint/architecture/228-pair style gates, 42-route
export, 233-file embed equality and UI-host Go test/vet. Desktop and
`390 x 844` DEV verified the single revision-7 Action, labelled stacked rows,
no Dialog or horizontal overflow and viewport/document/body width all 390px;
the browser emitted no warning or error.

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
signature/test-request flow. The IAM engineer has started a revision-8 resource
graph successor for four additional collection-create Actions, but it is still
an unfixed working tree. Do not infer AccessKey support from a collection shape:
consume only each fixed Action's explicit credential-carrier set. Accepting a
credential carrier must never become an effective-access claim. Continue
without reintroducing whole-page loading, hidden broad Context subscriptions,
fabricated totals, duplicate components or login verification before UX
acceptance.
