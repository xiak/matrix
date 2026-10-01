# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `6f4ac7c2`
- Pushed documentation milestone: `6f4ac7c2`

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

## Durable pushed state

The independent MOCK console remains the inspectable UX surface and login
verification remains disabled. The current service-authorization UX keeps
platform template, Account consent/service-linked Role, exact workload binding
and runtime observation as four separate facts; configuration never implies
runtime use. Its local non-secret session examples now use the fixed public
`SERVICE_ACCOUNT` source, `UNREVOKED | EXPIRED | REVOKED` lifecycle and explicit
revoke capability. `UNREVOKED` is never presented as current usability.

The former permission simulator is replacement-first removed. Component, view,
route, localization, Go static-route and embedded-export ownership now use only
`policy-coverage`; no compatibility path remains. The worksheet inventories
only local fixture input, referenced policy/default-version statements and
boundary references, while runtime remains `NOT_EVALUATED`. User detail opens
the same route with the exact identity preselected. The page does not import the
preview evaluator and does not render match states, effective permission,
final Allow/Deny, a reason tree or remediation. Source IP and time remain
operator-entered information-architecture fields only; they now live in a
default-collapsed "additional request context (record only)" region so the
identity, product, resource and Action form one uninterrupted core task flow.
Source/embed `87ad088e` passed the full 55-file/896-test frontend, export/embed
and focused Go UI host gates; desktop and `390 × 844` DEV inspection had no
overflow or warning/error. FEAT-IAM-010 owns the evidence at `bc930eb5`.

The PostgreSQL instance and product-specification directories retain their
product-server visibility boundary and truthful loaded-record wording. The
control-plane repository no longer performs one product-wide four-collection
read for every non-IAM route. Each destination requests only its declared
resource slices; preview-owned Applications, Logs, DevOps and Observability
make no managed-service request, while catalog, Regions, Quotas and PostgreSQL
installations have distinct least-privilege read sets. Requested slices merge
into a credential-owned cache, missing slices are never treated as empty, and
terminal installation refresh rereads only entitlements and installations.
The browser still does not call IAM batch authorization or hide denied rows.
Source/embed `46b72b04` passed 55 frontend files / 896 tests, static
normalization, type/lint/architecture, 228 theme contrast pairs, 41-page
export, 228-file embed equality and focused Go UI host test/vet. Real DEV
IAM-to-Logs and IAM-to-PostgreSQL transitions took about 199ms and 205ms in the
local automation observation; `390 × 844` inspection had no overflow or
warning/error. Existing MOCK pages remain available. Durable details and
limits are owned by FEAT-007 at `49df1c8b`.

The shared contextual workspace now mounts its quota, installation or platform
status body only after the named page action is first accepted. A closed,
never-used workspace therefore has no hidden form subscribing to the broad
control-plane context. After first use, collapse keeps the body inert and
mounted so the operator's draft survives reopen; a different current workspace
does not render the previous body. Source/embed `1509b0f0` passed the same full
55-file/896-test frontend, export/embed and focused Go UI host gates. A real DEV
installation check proved zero initial forms, retained a changed display-name
draft across collapse/reopen, no overflow and no browser warning/error. The
contract is owned by FEAT-007 at `960c7ef9`.

The fixed administrator RoleSession northbound contract is consumed only by
Role detail. The service-authorization MOCK still reuses its public fields
without sending real requests. Product-side LIVE bind/unbind now uses only the
fixed managed-services northbound contract from an exact installation, with a
content-area review and preserved same-key retry for unknown results; the IAM
directory remains read-only and the browser never calls IAM internal routes.
Account-relation revoke, product runtime-session observation and real integrated
product-PEP browser evidence remain closed. Source/embed `60b60619` passed the
full 55-file/899-test frontend, export/embed and focused Go UI host gates; its
contract and limitations are owned by FEAT-IAM-010 at `8aeed58b`.

The shared LIVE/isolated-MOCK visual policy author derives conditions from the
selected Actions' exact Profile capability intersection and keeps the catalog
snapshot used for that edit. Edit and review now show the selected Actions'
product/Profile revision while making clear that this is not an authorization
result: the browser submits no Profile, digest, compilation or resolved Action
set, and only the server-returned `PolicyVersion.compilation` is authoritative
after publication. Fixed IAM source `710c1557f48611179715671cac76ff4dfe447c1b`
owns trusted request context; cumulative source
`49aaf21657ef71cb83b1b9b51d835f3600f6ce9d` confirms the publication boundary.
Resource-tag ABAC and tag mutation remain disabled because their contract is
not frozen. Source/embed/docs `6f4ac7c2` passed 57 frontend files / 913 tests,
static normalization, type/lint/architecture, 228 theme contrast pairs,
42-route export, 233-file embed equality and repository Go test/vet. Desktop
and `390 × 844` DEV flows displayed catalog provenance in edit and review
without a Dialog or horizontal layout failure. FEAT-007 owns the UX evidence
and FEAT-IAM-010 owns the backend semantics and exclusions.

Audit is now an independent console product rather than an IAM submenu. The
record directory exposes only the accepted bounded time, Action, actor,
page-size and opaque-cursor inputs. Its tenant LIVE adapter rejects an
installation-scoped response, while the closed decoder enforces the contract's
exactly-one authority, ROLE session lineage, optional USER access-key lineage,
published target kinds and unknown-field rejection. The form reveals only the
lineage fields required by the selected actor type. Record evidence and bounded
integrity verification use content-region views, the fixed shell renders
immediately, and loading stays local to data surfaces. LIVE never falls back to
MOCK; the retained preview adapter is visibly marked, includes role-session and
access-key evidence, and rejects invalid cursors and ranges beyond its chain
tail. Source, documentation and 233 embedded export files are pushed at
`91e969c5`; the full 57-file/910-test frontend gate,
type/lint/architecture checks, 228 contrast pairs, 42-page production export,
Go web test/vet, desktop and `390 × 844` browser checks all passed. A cold DEV
reload after the responsive check produced no new warning/error. FEAT-006 owns
the durable contract and evidence.

The earlier navigation stress gate remains unchanged: 200 alternating suspended
IAM Group and Role destinations preserve the latest click and clear pending
state after stale work completes.

## Continuation

Keep the DEV MOCK available for progress review. Coordinate only against fixed,
pushed IAM commits and record independent verification separately. IAM owner
prioritizes the service-authorization governance flow: immutable template,
current-Account consent/service-linked Role, exact workload binding, then
short-lived session observation and single revocation. Product-owned bind and
unbind remain the northbound mutation boundary; the browser never calls IAM
internal endpoints or moves Role-detail session authority into the product
authorization page.

Keep permission analysis as the explicitly isolated, non-evaluating worksheet.
Do not reintroduce a risk score, effective-permission result, Deny reason tree,
remediation action or future API. Request-context authoring may consume only
exact Profile capabilities from the fixed IAM source; do not add resource-tag
fields, arbitrary `resource.tag/*`, tag mutations or permission names until IAM
publishes their fixed contract. Treat IAM batch authorization only as a
product-side server filtering candidate until its exact pushed source, fields
and calling boundary are fixed; never reinterpret it as customer bulk
authorization.

Continue the console-wide UX audit from the next uncovered customer workflow,
preserving fixed page structure, localized data loading, compact responsive
behavior and content-area actions. Do not move unrelated branches, enable login
verification before UX acceptance, merge, or claim release completion.
