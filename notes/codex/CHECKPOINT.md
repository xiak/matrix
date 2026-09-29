# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-29
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed UI source: `255b9bf7`
- Pushed documentation head: `c353b0a9`

## Authoritative route

- IAM client requirements, status and boundary integration evidence:
  [`FEAT-IAM-010`](../../IAM/FEAT-IAM-010-console.md).
- Shared UX requirements, status and verification evidence:
  [`FEAT-007`](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed-source UI adoption decisions:
  [`FEAT-007 adoption review`](../../docs/adoption/FEAT-007-control-plane-console.md).
- Shared product boundary:
  [`ADR-0002`](../../docs/architecture/ADR-0002-product-boundary.md).

Do not restate those owners here. Read this checkpoint only after compaction or
handoff, then validate it against Git and the linked FEAT.

## Durable pushed state

The UI source above is committed and pushed to this feature branch. Its
development verification is not complete IAM, installation, upgrade or release
acceptance. Evidence, limitations and remaining work belong only to the linked
FEAT owners. Integrate fixed backend contracts while preserving this branch's
UI, full static host/export and independent MOCK entry; do not replace them
with another branch's renderer or inherit that branch's UI acceptance.

The current milestone keeps the independent MOCK preview, fixed-contract LIVE
paths and synchronized static Go host. Its access simulator now separates
principal-policy evaluation, optional permission-boundary evaluation and their
final intersection, and classifies evidence as `MATCH`, `NOT_MATCH`,
`CONTEXT_MISSING` or `CONTRACT_UNAVAILABLE`. Request-context guidance remains
truthful: source IP and time are operator-constructed preview facts, browser and
forwarded-header values are not trusted, and the UI does not claim to simulate
a gateway, proxy or product PEP. The product-onboarding MOCK now also exposes
the immutable Profile reference and digest, condition fact sources, the calling
service's PEP responsibility and an explicit unverified runtime-evidence state.
The isolated policy author also exposes all/partial/unsupported condition
coverage for the selected Actions and blocks empty, malformed, host-bit-set or
exact duplicate source CIDR input without silently splitting a statement. Its
shared multi-line control preserves the invalid state and receives focus after
failed progression. These are diagnostics, not a permit or published registry
state. No LIVE condition key, Profile publication or unpushed IAM
network-context work was adopted. The existing LIVE member Role self-service
and independent MOCK Role journey remain intact. Exact behavior, verification
evidence and replacement rules belong to the linked FEAT owners. Real
IAM-process Role/network browser, product PEP, installation and release
acceptance remain open.

The MOCK User permission page now summarizes direct and group-derived policy
sources, current default documents containing explicit deny statements, and
permission-boundary configuration before its relationship table. It labels
each row's current-document effect while explicitly refusing to call that an
effective-access result. This slice does not read a new LIVE PolicyVersion
contract or infer missing policy content; adopt it into LIVE only from a fixed
pushed IAM response whose ownership and failure semantics are recorded by
FEAT-IAM-010.

The MOCK Role detail now reuses that authorization-overview hierarchy while
keeping trust admission, permission policies and the optional boundary
independent. It summarizes only current default policy documents, labels
explicit deny statements in the policy table and does not claim a request-level
decision. The overview owns its responsive container, yielding a two-by-two
fact grid at 390px without page overflow. It remains MOCK-only until IAM
publishes a fixed authoritative projection; do not assemble it from separate
User, Group and Policy reads or reinterpret denial as empty data.

The MOCK Group detail now completes the same hierarchy: members inherit the
group's directly attached policies, policy rows expose current-default document
effects, and the overview states that groups do not have permission boundaries.
The shared renderer displays that summary only when its caller supplies complete
current-document coverage. The LIVE Group adapter deliberately omits it under
the current contract and performs no policy-detail fan-out, name inference or
denial-to-empty fallback. MOCK and LIVE member/policy association flows now
replace the Group detail body instead of opening a wide dialog, while retaining
the existing select/review/submit and LIVE request/readback semantics. Returning
keeps the source member/policy tab and restores focus to the source action, with
a stable edit-action fallback during authoritative refresh; deletion remains a
focused confirmation. Target-User and Group grant-source/effect projections
remain backend-owned and unimplemented until a fixed pushed IAM contract exists.

LIVE Group loading now follows the shared stable-structure rule. Directory
heading, search and create command stay mounted across initial read, failure and
retry; direct detail keeps a heading and back path while only remote facts use a
delayed local skeleton. Directory request generations reject late results, and
fast responses never render an intermediate empty directory. The DEV browser
still exercises the explicit MOCK repository, so responsive browser evidence
does not substitute for delayed real-IAM network acceptance.

## Continuation

Continue from the owning FEAT's open acceptance items. Coordinate IAM through
fixed pushed commits, never another task's dirty working tree. Inspect Git and
worktrees and select `feat/cloud-console-ux`, not the unrelated CI/CD or IAM
checkout in the original directory. Do not move those branches or introduce
their unrelated features. This checkpoint does not authorize a merge or runtime
upgrade. Preserve existing user installations; use an owned fresh test
environment. Real browser acceptance cannot be replaced by MOCK or API-only
checks. Do not duplicate the donor application or move installer-owned secrets
into the UI.

Next integration must select one fixed boundary from the owning FEAT. Session
activity/touch, Passkey registration and trusted network request context remain
MOCK until IAM provides a fixed, pushed commit with their required gates. The
Role self-service client still requires real IAM-process browser verification;
do not infer additional Role, SSO, session or network-context endpoints,
persisted fields, operators or credentials from the MOCK UI or from another
task's unpushed work.

Replace this file only at another committed-and-pushed milestone. Do not append
command logs, chat transcripts, secrets, raw provider payloads, or machine-local
paths.
