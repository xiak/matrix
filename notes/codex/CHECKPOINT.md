# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-11
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam`
- Pushed design baseline: `38f348e6b4e00fcd4961abebb91cacbb9e28442a`
- Pushed verified action-catalog slice: `3b11eb9dbabd70211e665c00e4e665658b461bd1`
- Pushed policy-core/replica-gate milestone: `273196d2442fd70b6824ec10fcd4ef8ba0f95a38`

## Resume route

1. Read AGENTS.md, then [IAM product contract](../../IAM/FEAT-IAM-000-product-contract.md).
2. [IAM/001](../../IAM/FEAT-IAM-001-authorization-profile.md) owns the accepted
   CAT-01–04 action-catalog slice and exact local/CI evidence. Full Profile
   behavior is not implemented.
3. Continue [IAM/002](../../IAM/FEAT-IAM-002-policy-authority.md), then its
   owning API/domain/use-case/SQL/tests and the
   [existing adoption record](../../docs/adoption/FEAT-006-platform-authorities.md).
4. [IAM navigation](../../IAM/README.md) links all requirements/features.
   [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md) retains the
   old accepted foundation/multi-tenant/local-recovery evidence; it is not
   acceptance of the new IAM system.

## Current milestone

The user-requested IAM replacement goal is active, not complete. The branch
name is exactly feat/iam; feat/iam-cam remains the research baseline. All
user-facing deliverables are Markdown. Product references are fixed at
1ad6884 and the completed public-source study at b0e8627, not runtime dependencies.

The catalog owns each current action's product, authenticated calling service,
resource kind and tenant/platform/probe scope. Policy documents now have a
strict bounded language, canonical digest and immutable version identity.
Actual decisions use the single deny-first evaluator; RoleAllows was removed.
The current old binding loader still selects system-policy content. Persisted
policies/versions/attachments, management API/UI replacement and decision
version evidence remain required in IAM/002. There is no completed IAM6 storage
cutover, group or STS implementation. Current wire/SQL/profile are unchanged.

The exact 3b11eb9 CI run 34565145241 completed successfully for go,
authority-process and node-process. Local full race/vet/generation/module
verification/Linux builds and isolated PG18 HTTP, least-privilege,
independent-process and actual 5721 retained-upgrade gates passed. The task's
temporary PG container, network and volume were cleaned; no running fixture
is required to resume.

273196d additionally passed full default race/vet, generation/module checks,
Linux builds, focused race/fuzz, isolated PG18 IAM HTTP/local recovery and the
independent-process/actual 5721 retained upgrade gates. The real process gate
now exercises two IAM instances, cross-instance authority/session revocation,
surviving-peer access and fail-closed database disconnection using separate
restricted logins. Its exact CI run 34567733186 was still in progress at this
checkpoint; do not infer success. The task's new temporary PG/network/volume
were cleaned. IAM/000 and 011 own availability/capacity design and the remaining
load-balancing, fairness, capacity and database-HA evidence gaps; two IAM
processes sharing one database are not full HA acceptance.

## Integration boundary

Phase 3 granted this task the public IAM/Audit edit window. The final agreed
composition is IAM6/Audit4/PaaS5 + contractRevision 12; do not reuse IAM5/r11,
import a moving branch, or label a PaaS1 composition as the final installable
product. This branch still has the prior 4/3/1+r4 runtime profile.

Use only confirmed fixed objects for consumer adoption. The fixed 66f772ea
snapshot exposes IAM5 host/terminal actions and producer mappings; inspecting
it is not adoption or inherited acceptance. Keep sealed ServiceIdentity,
lookup_service, seven-column claim, canonical/history, original primary,
local-recovery capability and revoked binding identity semantics while
atomically migrating actual consumers. Consult IAM/002 and IAM/011 before
changing the ABI.

No extra agents/tasks, remote restarts, shared-service changes, other
worktree mutations or shared fixture reuse. Use this branch and uniquely
named, labelled and bounded local test resources only.
