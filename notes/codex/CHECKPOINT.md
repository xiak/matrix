# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-03
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `7b040479f`
- Pushed documentation milestone: `071dda4d9`

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

The inspectable DEV MOCK remains available at `http://127.0.0.1:4317`, and
login verification remains disabled for UX review. The isolated service-
authorization directory now follows the fixed FEAT-IAM-008 template vocabulary
without presenting a template as Account consent: the release-owned template
defines an account-scoped permission ceiling and 15-minute maximum, while the
exact `SERVICE_INSTALLATION` remains an independent workload binding. The
review also exposes product bind, service-linked-role create and role-pass as
three separate checks. Concrete subjects, resources, PolicyVersion IDs,
digests and session records stay visibly MOCK.

Source and synchronized embed are pushed at `7b040479f`; FEAT evidence is
pushed at `071dda4d9`. Service-authorization 4-case, role-workspace 202-case and
product-resource 69-case runs passed. A complete 60-file run reached 1025/1026;
the unchanged audit-lineage case exceeded the five-second limit only under full
load and passed 5/5 in an immediate default-timeout rerun. Typecheck, lint,
architecture, 228-pair style checks, three normalization cases, 45-route
export, 249-file embed equality and repository Go test/vet passed. Desktop and
`390 × 844` DEV showed no Dialog, overflow or browser warning/error.

Earlier Account security report, federation replacement, Deployment lifecycle,
AccessKey carrier, Application tag recovery, service authorization, policy
compilation/provenance and shared navigation/loading milestones remain owned
and indexed by FEAT-IAM-010 and FEAT-007; load only the relevant evidence row.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits after the IAM owner explicitly marks the contract consumable.
The IAM engineer confirms `GET /v1/service-role-templates` and service-linked-
role list/detail as LIVE read-only surfaces. A browser must never call IAM
internal bind/session endpoints. Real bind/unbind starts at the exact managed-
service installation and goes through the product northbound/BFF plus internal
PaaS/IAM credential chain; until that wire is mounted and browser-verified,
consent, unbind and unknown-result recovery remain explicit MOCK.

Do not infer tenant authorization from an ACTIVE template, Profile registration
or installation identity. Do not infer current permission from historical
binding counts, configuration state or an `UNREVOKED` session. A
`SERVICE_LINKED` Role remains read-only and separate from ordinary Role edit.
Profile-to-template matching may be shown only as release validation, never as
automatic installation, consent or grant.

Continue without reintroducing whole-page loading, hidden broad Context
subscriptions, fabricated totals, duplicate components or login verification
before UX acceptance.
