# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-30
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed UI/test source: `1afa1b2f`
- Pushed synchronized embed: `c6a3cf9b`
- Pushed documentation head: `cac3e7f7`

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

Shared cross-service navigation now focuses the stable destination `H1` both
when an accepted target frame is projected and after the Next route commits.
This applies to product launcher, service navigation and browser-history route
changes without remounting feature content or adding data reads. The held-route
gate now covers Region, Application hosting, PostgreSQL, Logs, DevOps and
Observability; IAM keeps its own data-region case. A fresh desktop DEV pass
opened all product entries plus IAM with exact-width pages and no new browser
warning/error. Feature-owned inline workflow focus remains separate.

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

LIVE User detail now follows the same rule without broadening authority. A
selected directory row immediately supplies its already verified read-only
identity summary; only the exact `UserAccess` region loads or fails. Mutation
actions stay absent until the exact detail and capabilities arrive, and a
failure retains the locator context with an in-place retry. No real failure
falls back to MOCK, and the compact DEV check remains responsive evidence only,
not real-IAM delay/failure acceptance.

IAM initial CurrentIdentity/scene bootstrap now follows that stable-structure
rule at the route boundary. Every access route mounts its semantic destination
heading immediately; User, tenant, Group, Policy and Role directories limit
initial feedback to their table region, while other routes retain their own
content geometry. Verified scene refresh continues to keep current content.
This is shared loading behavior, not a new data model or LIVE acceptance, and
the independent MOCK entry remains available for inspection.

The previously open dedicated compact theme/keyboard audit is now accepted for
the independent DEV MOCK only. All 13 IAM destinations were rechecked at the
compact viewport in light and mixed themes, including stable destination focus,
closed overlays, exact page width and the shared page-action menu's keyboard
open/Escape focus return. Detailed evidence and the remaining real-IAM boundary
belong to the linked FEAT owners; this does not accept backend or release work.

The long Account settings stream now starts with stable sign-in identity,
personal security and Account security anchors. They focus and scroll to the
already mounted section without route changes, local selection state or an
identity refetch. LIVE and explicit MOCK map to their existing section owners;
no settings contract was added.

The service-authorization MOCK is now tenant-first. Its default directory shows
current-Account service-linked Role relations with active/total binding counts,
while the platform-template directory remains a separate read-only tab. Opening
a relation preserves the existing template, Account relation, exact binding and
unissued-session boundaries; opaque cursor controls do not invent totals. The
isolated managed-service instance remains the product-owned consent entry, and
authorize, revoke, unbind and session actions remain absent or disabled. Fixed
IAM source `cb62ed2f6c307f5a50aa27480f89c8c58cf081ee` now publishes matching
northbound list/detail read shapes with Role metadata owned by `relation.role`,
complete template references and a release-owned immutable PolicyVersion
ceiling. This milestone does not yet consume those LIVE routes; use their
generated OpenAPI and closed decoding in the next adapter slice. Exact evidence
and limitations belong to FEAT-IAM-010 and FEAT-007.

LIVE member Role discovery also keeps its verified source identity, discovery
heading and temporary-access boundary mounted while only role cards load. An
initial directory failure creates no RoleSession and retries in place; an
already verified directory remains visible through later errors. The explicit
MOCK Role experience is unchanged and remains independently inspectable.

Shared compact Tabs now expose overflow through a theme-aware native scroll
cue without React state, observers or parent rerenders. The responsive browser
and full verification evidence is owned by FEAT-007.

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

Next integration must select one fixed boundary from the owning FEAT. The
relation/binding observation reads may now adopt fixed IAM source
`cb62ed2f6c307f5a50aa27480f89c8c58cf081ee`; do not infer authorize, revoke,
unbind, product-owned consent lifecycle or ServiceRoleSession commands from
those reads. Session activity/touch, Passkey registration and trusted network
request context remain MOCK until IAM provides a fixed, pushed commit with
their required gates. The Role self-service client still requires real
IAM-process browser verification; do not infer additional Role, SSO, session or
network-context endpoints, persisted fields, operators or credentials from the
MOCK UI or from another task's unpushed work.

Replace this file only at another committed-and-pushed milestone. Do not append
command logs, chat transcripts, secrets, raw provider payloads, or machine-local
paths.
