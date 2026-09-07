# FEAT-008: Private-cloud product foundation and unified shell

- Status: In progress; UX and architecture complete; Gate A discovery runtime and Gate B unified-shell slice implemented; fixed productless-predecessor and fresh current-release offline lifecycles verified; second-product and authenticated-browser evidence pending
- Target release: Unscheduled multi-product release
- Contract: `installation.matrix.xiak.com/v1`
- Target design date: 2026-09-07

## Outcome

Turn the accepted Application-PaaS-only distribution into a Matrix
private-cloud platform that can declare and present independently selectable
products. Deliver one authenticated UI shell and read-only installed-product
discovery while preserving every accepted Application PaaS flow.

The first accepted release contains Foundation plus Application PaaS. The same
contract later admits Matrix DevOps when its own gates pass. This FEAT does not
implement a marketplace, online install, billing, product purchase, arbitrary
plugin, dynamic remote UI, or a second product's business behavior.

## Boundary and ownership

| Concern | Owner |
| --- | --- |
| Signed release identity and declared product inventory | `installation` |
| Runtime product readiness projection | `installation`, from exact declared component probes |
| User session, organization, roles, and product-read authorization | `iam` |
| Product discovery and navigation shell | `app/ui/platform` consuming public APIs |
| Application pages and resource behavior | Application PaaS UI module and `apphosting` API |
| DevOps pages and resource behavior | DevOps UI module and `delivery` API; not implemented here |

Foundation does not own Application, Pipeline, Artifact, Deployment, or
provider state. The shell does not join product responses into a new source of
truth and does not import service internals.

## Installed-product contract

The signed release manifest gains a closed product inventory. Each entry has:

- a closed `productId` (`APPLICATION_PAAS` or `DEVOPS` in this release
  line), exact product version, and required component identities;
- a compiled route key understood by the release topology and UI;
- declared dependency product IDs, which must be acyclic and satisfied;
- a readiness policy composed only from named release components.

Display names, icons, route code, JavaScript URLs, health URLs, commands,
container definitions, and credentials cannot be supplied by a bundle as
arbitrary executable configuration. The release compiler maps a closed product
ID to reviewed topology and UI code.

`GET /v1/installed-products` returns only products in the current committed
release that the current IAM subject may see. Each projection contains exact
ID/version, `READY|DEGRADED|UNAVAILABLE`, a safe bounded reason code, and
observation time. It exposes no native health payload, internal URL, image,
credential, filesystem path, or undisclosed product. Discovery is read-only;
install, add, remove, upgrade, and rollback remain `mx platform` operations.

The API derives release inventory from the authenticated committed-release
manifest mounted by the installation topology and checks its identity against
the release bound to the running service. Caller headers, query parameters, UI
configuration, database rows outside installation, and downstream
self-registration cannot add a product. A declared product is `READY` only
when every required component proves the exact release-compatible readiness
contract.

## Unified UX

The shell owns:

- Matrix identity and private-cloud installation context;
- sign-in/session-expiry handling and current organization;
- installed-product switcher;
- current product name, local navigation slot, user menu, readiness indicator,
  and correlation-safe global error surface;
- shared responsive tokens, accessibility behavior, and safe API client.

The product switcher lists only authorized installed products. Application
PaaS opens its existing application, deployment, operation, capacity, and
configuration experience. DevOps appears only after its signed product
inventory and readiness are installed. A degraded product remains navigable
for diagnosis with a clear non-destructive banner; an unavailable product
cannot present mutation controls.

Deep links preserve product route and organization after login. Changing
organization clears product-local cached data before the next request. The
shell never lets a browser-supplied tenant, route, cached role, or product
availability override IAM and API authority.

The existing tracked `app/ui/paas` implementation and
`matrix-paas-ui` release component are replaced atomically by
`app/ui/platform` and `matrix-ui`. There is no pre-v1 alias or duplicate
shell. Git provides rollback; the accepted PaaS routes and behavior move into
the Application PaaS module in the same slice.

Required shell states include first load, no authorized product, product ready,
degraded, unavailable, session expired, IAM unavailable, discovery unavailable,
route not found, and stale observation. Desktop and 360-pixel layouts, keyboard
navigation, visible focus, WCAG AA contrast, reduced motion, and Chinese/English
text expansion are part of acceptance.

## Transactions and failure behavior

Product inventory changes only when installation atomically commits a verified
release. A failed candidate cannot leak its inventory into discovery. Upgrade,
automatic rollback, explicit rollback, backup recovery, and restart all return
the product list corresponding to the current committed release.

Readiness observation is bounded and cached only with its observation time.
Timeout produces `DEGRADED` or `UNAVAILABLE` under the declared policy; it
does not remove a product or substitute stale healthy data. Equal reads have no
side effect. Product-discovery access and release inventory changes emit closed
sanitized Audit facts without recursively logging every component probe.

## Incremental acceptance

### Gate A: release and API contract

1. Manifest schema, canonicalization, signature, topology compilation, and
   strict Go/OpenAPI examples reject unknown product IDs, duplicate products,
   missing/cyclic dependencies, undeclared components, executable bundle data,
   drift, unsafe text, and oversize responses.
2. Installation commit, failed upgrade, rollback, recovery, and exact replay
   tests prove discovery always reflects one committed signed release.
3. IAM defines the closed product-read action; unauthenticated, revoked,
   cross-organization, caller-tenant, and unavailable-IAM requests fail closed.
4. Architecture tests enforce shell-to-public-API dependencies, product module
   ownership, and the absence of runtime plugin or service-internal imports.

### Gate B: unified Application PaaS experience

1. The platform UI replaces the tracked PaaS UI and serves through APISIX with
   production caching, security headers, CSP, body limits, and no internal
   route or configuration leakage.
2. A real administrator and PaaS viewer log in, switch organizations and
   products, deep-link, expire/revoke sessions, and exercise existing PaaS
   create/read/update/rollback/stop and Operation views without authority or
   behavior regression.
3. Ready, degraded, unavailable, stale, empty, denied, and recovery states are
   tested with real discovery/IAM contracts. Browser cache and forged
   tenant/product data cannot reveal another tenant or enable a mutation.
4. Component, API, and end-to-end accessibility tests cover keyboard-only use,
   focus restoration, labels, live status, contrast, reduced motion, 200%
   zoom, and 360-pixel layout.

### Gate C: offline lifecycle

1. A clean network-disabled signed release installs Foundation, the new Matrix
   UI, and Application PaaS from an empty root; discovery returns exactly that
   inventory and all accepted PaaS runtime checks still pass.
2. Upgrade to a release that adds a fixture second product exposes it only
   after commit. Injected failure restores the prior inventory; explicit
   rollback and backup recovery restore matching UI, API, and component state.
3. Restart, verify, status, and sanitized support evidence correlate the exact
   release and product readiness without secret, native payload, internal URL,
   or absolute path leakage.

Common generation-drift, schema, architecture, unit, vet, race, repeated,
cross-platform build, Markdown-link, accessibility, security-header,
tenant-authority, offline, upgrade/rollback/recovery, and
`git diff --check` gates pass on the same committed worktree.

## Current implementation evidence

- Fresh bootstrap remains a strict five-service contract. The only retained
  pre-product compatibility is the exact four-service bootstrap inventory,
  accepted solely as an equal replay of an existing `READY` receipt with the
  same installation, organization, and canonical content digest.
- Upgrade staging preserves that legacy bootstrap byte-for-byte for rollback
  and creates the installation-owned Platform credential once in its separate
  fixed secret path. Repeated staging consumes no entropy and never rotates it.
- The IAM migration changes the closed database constraint, enrolls or verifies
  exactly `service-platform` under the migration authority, keeps the legacy
  bootstrap receipt unchanged, and emits one additional sanitized
  `iam.bootstrap.applied` Audit fact with a fixed migration actor/request
  identity. IAM API and worker roles cannot execute the migration-only
  functions; retaining the accepted action keeps the event consumable after
  an N-1 rollback.
- A disposable PostgreSQL 18 integration run applied every platform migration
  twice, installed a fixed four-service legacy authority state, enrolled the
  Platform service twice, proved one credential and one Audit fact, preserved
  the old receipt, rejected a different credential, and reverified runtime
  schema isolation. Unit and contract tests also pin the accepted legacy
  canonical digest and reject legacy initialization, reordering, or mutation.
- Installed-release authentication admits only the signed canonical
  productless predecessor from source commit
  `c88a84f379afcf94431e2aca7332fe6ec3136dc7`, with its fixed Docker/Compose
  floor, four-GiB space floor, schema profile, seven-image inventory, topology
  digest, and gateway configuration. New installation, target staging, and
  upgrade-candidate verification remain on the strict current product
  manifest contract.
- The current `mx` lifecycle can authenticate that predecessor, compile its
  byte-pinned nine-service Compose topology, run its three legacy migration
  verifiers without requiring the future Platform credential, and restore its
  exact Compose and APISIX inputs after failure, explicit rollback, or backup
  recovery. Backend transition tests cover upgrade plus explicit rollback;
  the configuration restoration test also passes in a network-disabled Linux
  container.
- Live product readiness is observed before the list's committed observation
  time, so a real downstream `checkedAt` is not misclassified as future data.
  Productless backup recovery streams the two fixed post-product IAM function
  removals and the authenticated `pg_restore` SQL through one
  `psql --single-transaction`; restore failure cannot leave the compatibility
  cleanup partially committed.
- A fresh privileged Docker-in-Docker host with outer network mode `none`,
  Docker 27.5.1, and zero initial images, containers, and volumes completed the
  cross-version lifecycle from signed Release A
  `matrix-v0.1.0-c88a84f379af` to signed Release B
  `matrix-v0.2.0-ea4e80820e4a`. It passed old-release installation, real
  IAM/PaaS/Audit behavior, a failed candidate with automatic rollback, a
  successful B upgrade with exactly one signed Application PaaS product in
  `READY`, explicit rollback with discovery unavailable, old-backup recovery,
  application rollback and stop, bounded support leakage scans, and a restart
  of the entire isolated host followed by status and verification.
- A second clean network-disabled host completed the same lifecycle using two
  signed releases built from current commit `e2249bc`. Release A
  `matrix-v0.1.0-e2249bcdd535` installed the Foundation, Matrix UI, Platform
  API, and Application PaaS from an empty root; its first authenticated product
  read returned exactly the signed Application PaaS version and route in
  `READY`. Failed upgrade, successful upgrade, explicit rollback, backup
  recovery, application behavior, zero-leakage support evidence, and full-host
  restart also passed without falling through the legacy compatibility path.
- On this implementation slice, `go generate ./...`, `go test ./...`,
  `go vet ./...`, `go test -race ./...`, ten repeated installation contract
  runs, Linux cross-builds, and `git diff --check` pass.

This evidence closes the fixed productless-to-product-foundation compatibility
portion and the fresh-current-install portion of Gate C. Gate C remains open
until an upgrade adds a fixture second product with matching UI/API/component
behavior. The authenticated browser and accessibility evidence in Gate B also
remains open.

## Deferred

Online catalog, licensing UI, billing, self-service product installation or
removal, independent product release trains, dynamic micro-frontends, remote
JavaScript, third-party plugins, customer-authored product manifests, product
telemetry, quota/metering foundation, and foundation-as-IaaS remain outside
this FEAT.

The costly shared boundary is owned by
[ADR-0002](../architecture/ADR-0002-product-boundary.md).
