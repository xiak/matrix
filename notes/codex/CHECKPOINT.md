# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-12
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `7bab1df8c20db151b187d3c383eded42a2c40cce`

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

The existing managed-product gate now composes a strict LIVE service-directory
and Account-activation adapter alongside the isolated, inspectable MOCK. The
adapter consumes the fixed public contract at backend
`b015b07864c2fcdf85129d57a0babe8332e3356f`; its public wire is unchanged from
parent `599d994cddda5f1cb2ee1b4f53b84eafd1458e58`. No backend or IAM-branch UI was
imported. Current frontend, static export, embedded-asset equality and Go gates
passed. Fixed donor decisions, behavior and exact evidence are owned by FEAT-007
and its adoption record.

## Continuation boundary

Keep the accepted MOCK UI available and adapt its existing composition and
repository boundaries when integrating real contracts. Formal login/API
verification remains deferred until the other UX review is accepted.

The service-activation client is ready for selective integration with the fixed
backend, but this milestone performed no real activation POST or formal login,
SMTP or TOTP browser acceptance. Coordinate the same-origin test environment
and authority inputs with the IAM engineer before the real browser gate. MFA
page coverage and remaining LIVE lifecycle gaps stay with FEAT-IAM-010; they are
not part of this service-activation commit. Keep service enablement, quota,
human grants and service-role consent independent. Remaining real IAM,
managed-service, installation and release gates stay with their owning FEATs.
