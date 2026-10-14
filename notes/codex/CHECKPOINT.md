# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-14
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed candidate: `11151a06aa920438ae9d9f55252ec203a1f491d8`
- Functional parent: `ca08dcc4fac9c85e29b89524f103a1e0d2a882fd`

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

The existing personal-security UI now consumes the fixed IAM public factor
lifecycle, including lawful removal and new enrollment, with owner/phase
fencing, first-response-only materials and read-only UNKNOWN handling. Missing
LIVE role interfaces no longer fall back to a submit-capable preview. The
inspectable MOCK remains separate and available; no mandatory preview login,
donor backend, SQL, profile, runtime resource or shared DEV process was changed.

Supported-runtime focused and complete frontend checks, production export,
embedded equality and fresh UI-host Go gates passed. Exact evidence and the
final counter-boundary recheck stay with FEAT-007; protocol and remaining
browser boundaries stay with FEAT-IAM-010. The older integration's accepted
console CI cannot be inherited by this new candidate. No workflow or unrelated
timeout was changed. Previous managed-service client milestones remain in
their existing owners.

## Continuation boundary

Keep the accepted MOCK UI available and adapt its existing composition and
repository boundaries when integrating real contracts. Do not silently enable
mandatory authentication in the user's UX preview environment.

The IAM engineer received the fixed source/embed candidate and exact ADAPT
paths for selective integration and independent console CI. The engineer owns
the separate real device/PG/IAM/Audit/PaaS and signed-install browser gates.
This UI milestone does not claim those results. Original personal-factor
intents survive only in the current provider memory across content navigation
and same-user reauthentication; do not claim reload or cross-browser recovery.
Remaining lifecycle/browser paths stay with FEAT-IAM-010; do not infer acceptance
from a MOCK page, historical replay, HTTP adapter or an older green CI run.
Keep service enablement, quota, human grants and service-role consent
independent. Remaining IAM, managed-service, installation and release gates
stay with their owning FEATs.
