# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-12
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `afc1ba4556bcc1dab83e4e34065fc5a0ce147a2e`

## Authoritative route

- Shared console outcome, service-enablement UX and current gate evidence:
  [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md).
- IAM console behavior and real-IAM acceptance:
  [FEAT-IAM-010](../../IAM/FEAT-IAM-010-console.md).
- Account and platform authority:
  [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md).
- Product-enforcement boundaries:
  [FEAT-IAM-008](../../IAM/FEAT-IAM-008-product-enforcement.md).
- Fixed donor decisions:
  [FEAT-007 adoption](../../docs/adoption/FEAT-007-control-plane-console.md).

## Pushed milestone

The four managed-product workspaces reuse the current shell, data feedback,
navigation and Account-scoped service-enablement gate. Gate and data-provider
composition now share matching-product presentation admission: first-use and
no-resource-access pages do not pre-read resources, refresh or poll; late errors
and polling completions cannot restore resource controls after reset. The
isolated MOCK remains inspectable and its first-use scenarios can be reset.
Current frontend, static export, embedded-asset equality and PaaS UI host gates
passed; exact evidence and the identity/capability contract are recorded in
FEAT-007.

The IAM engineer's fixed-contract correction is included in the pushed source:
frontend product route keys are presentation identifiers; the current IAM
ProductID remains `managedservice`, and product facts show the returned Offering
ID. No frontend-generated IAM product namespace remains.

## Continuation boundary

Keep the accepted MOCK UI available and adapt its existing composition and
repository boundaries when integrating real contracts. Formal login/API
verification remains deferred until the other UX review is accepted.

There is no adopted public Account/service enrollment API in this milestone.
Direct LIVE product-enablement routes remain non-submittable and never consume
browser MOCK consent. The IAM engineer's activation design is fixed at
`aed5845e0a9b6a22c086836b926fad60113e8832` and recorded as reference only; its
implementation and real-runtime gates are not adopted. Consume only a fixed,
pushed implementation with the required terminal evidence. Keep
enablement, quota entitlement, human grants and service-role consent independent.
Do not add a browser internal API, infer authority from identity/role names, or
turn a MOCK result into LIVE acceptance. Remaining real IAM, managed-service,
installation and release gates stay with their authoritative FEAT owners.
