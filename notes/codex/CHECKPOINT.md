# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `28c4202e2`
- Pushed documentation milestone: `9d60a9669`

## Authoritative route

- IAM client requirements, status and boundary evidence:
  [`FEAT-IAM-010`](../../IAM/FEAT-IAM-010-console.md).
- AccessKey protocol and product-enforcement evidence:
  [`FEAT-IAM-007`](../../IAM/FEAT-IAM-007-programmatic-credentials.md) and
  [`FEAT-IAM-008`](../../IAM/FEAT-IAM-008-product-enforcement.md).
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
fixture. Fixed IAM implementation `b6d15c89a` and status owner `018f34ec5`
define PaaS revision 9, digest
`sha256:14aa8bee8819bde9b1a5434774b26308866ea1a17d9ccfd3cc3ccf252cb297c6`,
and exactly six carrier Actions: `paas.application.create`,
`paas.configuration.create`, `paas.configuration-revision.create`,
`paas.application-revision.create`, `paas.deployment.create` and
`paas.application.read`. The read remains an Application instance operation
with the product-owned `resource.tag/environment` condition. The isolated MOCK
never infers sibling reads, lists or label writes from method, namespace or
resource shape.

Once this exact carrier set is non-empty, the workspace offers one same-User
next task without claiming authorization. MOCK and LIVE both open the exact
User detail; MOCK deep-links to the permission-source tab so direct policies,
group inheritance, explicit Deny and the permission boundary are inspected
together instead of preselecting an unrelated generic Action. The copy keeps
this a configuration-source review; request-time Action, resource, condition
and explicit-deny evaluation remain outside the browser.

The isolated MOCK groups public outcomes into create and read sections instead
of repeating them for each Action. Create retains `202 Operation`; exact
Application GET adds `200 Application` and post-authorization `404 NOT_FOUND`.
Both retain the fixed `400`, `401`, `403`, `409` and `503` boundaries with only
verified nonce semantics. Internal subject resolution, signature material,
nonce, digest and Account selectors remain hidden. LIVE receives only the lazy
read-only catalog and never renders this outcome fixture or signs/sends a
product request.

Source and synchronized embed are pushed at `28c4202e2`; FEAT evidence is
pushed at `9d60a9669`. The complete 57-file/931-case frontend suite and three
normalization cases passed with typecheck/lint/architecture/228-pair style
gates, 42-route export, 233-file embed equality and full repository Go
test/vet. Desktop and `390 x 844` DEV verified the exact six-Action result,
same-User `principal-lin` handoff to
`/console/access/users/?id=principal-lin&tab=policies`, selected
permission-source tab, distinct create/read outcome groups, document/body equal
to the 390px viewport, no Dialog or overflow and a clean browser warning/error
log.

The previously pushed Application tag recovery, AccessKey owner directory,
policy-compilation provenance, service-authorization, policy-coverage, Audit,
cross-service loading/navigation and other console milestones remain owned and
indexed by FEAT-007; load only the relevant row when resuming that work.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits. Independent CI `36853816880`, APISIX edge coverage and signed
installation acceptance remain unfinished; do not label the programmatic
product path LIVE or add a browser signature/test-request flow. Consume only
each fixed Action's explicit credential-carrier set. Accepting a carrier must
never become an effective-access claim. Continue without reintroducing
whole-page loading, hidden broad Context subscriptions, fabricated totals,
duplicate components or login verification before UX acceptance.
