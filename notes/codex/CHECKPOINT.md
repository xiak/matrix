# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-10-01
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/cloud-console-ux`
- Pushed source/embed milestone: `8dc17ca77`
- Pushed documentation milestone: `9150ecf4c`

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

## Latest pushed milestone

The independent DEV MOCK remains available at `http://127.0.0.1:4317`, and
login verification remains disabled for UX review. The User-scoped AccessKey
workspace now separates credential lifecycle, product credential-carrier
admission and effective authorization. Its programmatic-access region stays
collapsed by default and reads the current authorization Profile directory only
when opened. It lists only exact Actions that explicitly admit both `USER` and
`ACCESS_KEY`; omitted authentication methods never become broad support. The
shared Table/Footer paginates future results. Product acceptance is labelled as
metadata, not a grant: every request must still revalidate the key, User,
current policies, target resource, conditions and explicit denies. The browser
does not retain the Secret, sign a request or issue a synthetic product call.
Unavailable or unauthorized catalog reads fail closed.

Source and synchronized embed are pushed at `8dc17ca77`; FEAT evidence is
pushed at `9150ecf4c`. The focused 176-case IAM workspace file and complete
57-file/929-case frontend suite passed with three normalization cases,
typecheck/lint/architecture/228-pair style gates, 42-route export, 233-file
embed equality and UI-host Go test/vet. Desktop and `390 x 844` DEV verified
collapsed and expanded states with no Dialog or horizontal overflow; viewport,
document and body width stayed 390px. A fresh validation tab emitted no warning
or error.

The previously pushed Application tag recovery, AccessKey owner directory,
policy-compilation provenance, service-authorization, policy-coverage, Audit,
cross-service loading/navigation and other console milestones remain owned and
indexed by FEAT-007; load only the relevant row when resuming that work.

## Continuation boundary

Keep the inspectable MOCK available and consume IAM changes only from fixed,
pushed commits. The current preview directory intentionally exposes no
AccessKey product Action. The IAM engineer is testing a PaaS Profile revision-7
candidate whose first programmatic path is Application creation, but its
predecessor/readiness gate is still being repaired and no final fixed SHA has
been supplied. Revalidate its exact Action, credential carriers, public failure
codes and independent CI before updating the preview declaration or adding a
strict LIVE/product adapter. Accepting a credential carrier must never become
an effective-access claim, and the browser must not test or retain the Secret.
Continue without reintroducing whole-page loading, hidden broad Context
subscriptions, fabricated totals, duplicate components or login verification
before UX acceptance.
