# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-14
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed candidate: `3876516a902fd020d1ab1cd4be8f339f9a9034b1`

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

The existing managed-product authorization client now follows the trusted
directory's ACTIVE template head by stable workload semantics instead of a
browser-pinned version. It preserves the exact received reference in original
commands and portable summaries, while UNKNOWN recovery remains read-only and
correlates only the original public idempotency key. The fixed public backend
source remains `964d7c85d2e9249541996d22b9b2d9b9189922ab`; no donor backend or UI
was imported, and the inspectable MOCK remains available.

Supported-runtime focused source checks, production export, embedded equality
and UI-host Go gates passed. Two complete local frontend attempts were not
green; do not replace that boundary with the focused or isolated results.
Exact failures and outcomes stay with FEAT-007. The candidate awaits the IAM
branch's existing independent Node 22 console job. Selected source blobs and
the complete embedded tree have been verified against integration
`355815f3d992edaf4f677374d7407554bd96ec7f`; exact integration and CI references
stay with FEAT-007. No workflow or unrelated timeout was changed.

## Continuation boundary

Keep the accepted MOCK UI available and adapt its existing composition and
repository boundaries when integrating real contracts. Do not silently enable
mandatory authentication in the user's UX preview environment.

The IAM engineer received the fixed source/embed candidate for selective
integration and owns the separate real PG/IAM/Audit/PaaS and two-isolated-browser
UNKNOWN gate. This UI milestone does not claim those runtime or signed-install
results. Existing login/MFA pages and remaining LIVE lifecycle gaps stay with
FEAT-IAM-010; do not infer acceptance from a MOCK page or an HTTP adapter alone.
Keep service enablement, quota, human grants and service-role consent
independent. Remaining IAM, managed-service, installation and release gates
stay with their owning FEATs.
