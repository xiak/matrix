# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-02
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `90a5f0184`
- Pushed documentation milestone: `58aaac0f5`

## Authoritative route

- IAM client requirements, status and boundary evidence:
  [`FEAT-IAM-010`](../../IAM/FEAT-IAM-010-console.md).
- AccessKey protocol and product-enforcement evidence:
  [`FEAT-IAM-007`](../../IAM/FEAT-IAM-007-programmatic-credentials.md) and
  [`FEAT-IAM-008`](../../IAM/FEAT-IAM-008-product-enforcement.md).
- Shared UX requirements, status and verification evidence:
  [`FEAT-007`](../../docs/features/FEAT-007-control-plane-console.md).
- Fixed-source adoption decisions:
  [`FEAT-007 adoption review`](../../docs/adoption/FEAT-007-control-plane-console.md).
- Shared product boundary:
  [`ADR-0002`](../../docs/architecture/ADR-0002-product-boundary.md).

Do not restate or amend those owners here. Read this checkpoint only after
compaction or handoff, then validate it against Git and the linked FEAT.

## Latest pushed milestone

The independent DEV MOCK remains available at `http://127.0.0.1:4317`, and
login verification remains disabled for UX review. The account security report
now opens a stable content-area confirmation and seals one synchronous,
all-or-nothing immutable MOCK result; the older credential inventory remains a
separate surface. It fixes current-Account scope, exact create/read/download
permissions, retention and volume limits, and distinguishes `UNKNOWN`,
`NOT_OBSERVED_IN_RETAINED_IAM_STATE` and `NOT_INCLUDED`. It adds no report
directory, pending job, polling, risk score, automatic remediation, generated
file, LIVE repository, HTTP decoder or Action. The download affordance remains
stable and disabled until a backend runtime is both pushed and explicitly
consumable.

Source and synchronized embed are pushed at `90a5f0184`; shared-console and
IAM-client FEAT evidence is pushed through `58aaac0f5`. The complete frontend
gate passed 58 files/954 cases plus three normalization cases,
typecheck/lint/architecture/228-pair style checks, 42-route export, 233-file
embed equality and repository Go test/vet. A fresh browser session completed
login, report review and generation without warning/error. Desktop and
`390 x 844` checks had no horizontal overflow; compact document/body/client and
scroll widths were all 390px. IAM-009 S4a remains uncommitted pure-contract WIP
without HTTP/SQL runtime, so the report stays MOCK-only.

Earlier federation replacement, Deployment lifecycle, AccessKey carrier,
same-User permission-source handoff, Application tag recovery, service
authorization, policy compilation/provenance and shared navigation/loading
milestones remain owned and indexed by FEAT-007; load only the relevant
evidence row when resuming them.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits with an explicit consumable confirmation. The IAM engineer has
fixed Audit Profile r3 at implementation `620960989`, FEAT/head
`0c688302b9dea1050653eded2b9442a6b1322155`, digest
`sha256:83a1c4665b2363af22d882202f318f1ebb7ed16d33244723d18183ee3a404186`
and independent run `36876149921`; that run remains pending, so the Audit
AccessKey carrier is not yet an accepted LIVE console dependency. Product
Audit Profile r4 and its trusted-edge `request.source-ip` condition are not
fixed or pushed and therefore remain absent from the UI; the browser must not collect
or submit a client IP for this decision. Product
Profile publication, service-related roles and permission boundaries already
have backend-owned contracts and must not receive parallel frontend models.
The IAM AccessKey network/usage successor candidate is fixed at
`4e79ef783410bbb596232763a9be80412b5e0846` and leaves the frontend contract
unchanged. Verification `36897183328` has passed go, node-process and
authority-storage, while the remaining authority matrix is still running and
no explicit consumable confirmation has arrived. Keep `05fe4a74c`
browser-memory-only; add no parallel LIVE model or inferred wire.
IAM-009 S4a currently defines only an uncommitted pure contract for immutable
account security reports. Keep `90a5f0184` as information architecture only;
do not mount create/read/content adapters or enable CSV until IAM supplies a
fixed pushed commit, runtime evidence and explicit consumable confirmation.
External assertions remain configuration-only: do not reintroduce a persistent
federated-account/external-subject object, HTTP adapter, successful assumption
path, RoleSession issuance or authorization claim until IAM publishes and
explicitly exposes a fixed IdP/Role trust contract.
An authoritative effective-access/policy-simulator API does not exist; keep the
configuration review non-evaluating and do not create a decision-shaped MOCK.
Continue without reintroducing whole-page loading, hidden broad Context
subscriptions, fabricated totals, duplicate components or login verification
before UX acceptance.
