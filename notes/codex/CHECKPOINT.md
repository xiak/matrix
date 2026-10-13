# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-13
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `2fe2b43cddd1319c43c3d930767c07a382b06917`

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

The existing managed-product command surface now supports read-only recovery
of original uncertain outcomes, including an explicit non-secret summary that
can be carried to an isolated browser. The strict LIVE client consumes the
fixed public contract at backend
`964d7c85d2e9249541996d22b9b2d9b9189922ab`; it correlates the original public
idempotency key, not a private IAM request identity or a client-computed digest.
The accepted MOCK composition remains available. No backend or IAM-branch UI
was imported. Current supported-runtime frontend, static export,
embedded-asset equality and UI-host Go gates passed. Exact scope, donor
decisions and acceptance evidence stay with the authoritative owners above.

## Continuation boundary

Keep the accepted MOCK UI available and adapt its existing composition and
repository boundaries when integrating real contracts. Do not silently enable
mandatory authentication in the user's UX preview environment.

The IAM engineer received the fixed source/embed milestone for selective
integration and owns the separate real PG/IAM/Audit/PaaS and two-isolated-browser
UNKNOWN gate. This UI milestone does not claim those runtime or signed-install
results. Existing login/MFA pages and remaining LIVE lifecycle gaps stay with
FEAT-IAM-010; do not infer acceptance from a MOCK page or an HTTP adapter alone.
Keep service enablement, quota, human grants and service-role consent
independent. Remaining IAM, managed-service, installation and release gates
stay with their owning FEATs.
