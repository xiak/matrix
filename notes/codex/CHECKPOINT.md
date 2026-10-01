# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `e79cb85d1`
- Pushed documentation milestone: `7979b50ce`

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
login verification remains disabled for UX review. The capability directory
keeps one persistent search and discloses authority-scope, admitted-subject and
USER-credential filters only on request; active conditions remain visible as
removable chips. One domain projection owns the sealed legacy credential
ceiling for catalog search, declaration rows and AccessKey carrier inspection:
omitted methods mean login-session-only and non-USER Actions have no USER
credential.

The User-scoped AccessKey workspace separates credential lifecycle,
credential-carrier admission and effective authorization. Its lazy,
default-collapsed region lists only exact Actions that explicitly admit both
`USER` and `ACCESS_KEY`; catalog failure stays local and never falls back to a
fixture. Fixed IAM source `63ab867d30113b70a71e6ce6ddc5f16020380d36`
and evidence owner `1e4c2d515` define PaaS revision 8, digest
`sha256:553bb69f2eed79887305f7884188769894f786459391ca8df71fe95e07f71812`,
and exactly five carrier Actions: `paas.application.create`,
`paas.configuration.create`, `paas.configuration-revision.create`,
`paas.application-revision.create` and `paas.deployment.create`. The isolated
MOCK copies only that immutable-resource graph and never infers support from an
HTTP method, namespace or collection shape.

The isolated MOCK also groups the six public outcomes into one collapsed table
instead of repeating them for each Action: `202 Operation`,
`400 INVALID_ARGUMENT`, `401 UNAUTHENTICATED`, `403 PERMISSION_DENIED`,
`409 CONFLICT` and `503 IDENTITY_UNAVAILABLE`. It records `400` as not consumed
and `403`/`409` as consumed, makes no nonce inference for `401` or `503`, does
not assume the original `401` signature is reusable, and requires state
confirmation plus a new nonce after uncertain `503` instead of automatic
intent replay. LIVE receives only the lazy read-only catalog and never renders
this outcome fixture or signs/sends a product request.

Source and synchronized embed are pushed at `e79cb85d1`; FEAT evidence is
pushed at `7979b50ce`. The complete 57-file/931-case frontend suite and three
normalization cases passed with typecheck/lint/architecture/228-pair style
gates, 42-route export, 233-file embed equality and full repository Go
test/vet. Desktop and `390 x 844` DEV verified the exact five-Action result,
collapsed filters and outcome disclosure, document/body equal to the 390px
viewport, no Dialog or overflow and a clean browser warning/error log.

The previously pushed Application tag recovery, AccessKey owner directory,
policy-compilation provenance, service-authorization, policy-coverage, Audit,
cross-service loading/navigation and other console milestones remain owned and
indexed by FEAT-007; load only the relevant row when resuming that work.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits. Independent CI `36847285739`, APISIX edge coverage and signed
installation acceptance remain unfinished; do not label the programmatic
product path LIVE or add a browser signature/test-request flow. Consume only
each fixed Action's explicit credential-carrier set. Accepting a carrier must
never become an effective-access claim. Continue without reintroducing
whole-page loading, hidden broad Context subscriptions, fabricated totals,
duplicate components or login verification before UX acceptance.
