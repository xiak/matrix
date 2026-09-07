# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-08
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `d5029c0`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 remains the authoritative owner and is `In progress`; read it and
  the directly owning code/tests before continuing.
- Pushed `d5029c0` closes the first authenticated source-ingress slice: the
  selected DevOps runtime receives an endpoint-bound Gitea `1.27.3` webhook,
  verifies its untouched body with current/previous private file keys, emits a
  provider-neutral change, and invokes the existing atomic run admission.
- Admission now compares the SourceConnection version used for HMAC and the
  signed target branch inside the serializable transaction. Equal replay still
  succeeds without depending on current source readiness or Pipeline state.
- Only a selected DevOps product receives the private source-secret root and
  high-priority APISIX ingress route. Webhook traffic cannot carry IAM or
  caller correlation headers; normal DevOps APIs retain Bearer authorization.
- Full tests, vet, affected race and 20-run repeated suites, Linux/amd64
  CGO-disabled build, a five-second authenticated-payload fuzz run, and the
  updated PostgreSQL 18 source-to-two-run integration journey passed.
- The user-owned untracked `app/ui/paas/` tree remains untouched.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Continue FEAT-007 with the run-lifecycle foundation: close the current
state-transition, cancellation, lease/fence, and reconciliation contracts and
their tenant-isolated PostgreSQL worker boundary before invoking any source,
executor, or reporter effect. Preserve pragmatic DDD, replacement-first pre-v1
changes, optional-product isolation, and repository-local Git identity
`Xiak <Jellal@aliyun.com>`.
