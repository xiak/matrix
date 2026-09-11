# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-11
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/iam`
- Pushed design baseline: `38f348e6b4e00fcd4961abebb91cacbb9e28442a`
- Pushed verified action-catalog slice: `3b11eb9dbabd70211e665c00e4e665658b461bd1`
- Pushed policy-core/replica-gate milestone: `273196d2442fd70b6824ec10fcd4ef8ba0f95a38`
- Pushed atomic-migration/Audit-retry correction: `0f99ec98ef52bdb69017fd16dfe21f1c2cc55177`
- Pushed policy/attachment relationship contract: `3b370ca2c3ab299ec80b554ef970e70d609e2b29`

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
restricted logins. Its exact CI run 34567733186 failed authority-process:
five immediate Audit serialization retries collided with an ongoing chain
writer and returned 503. Go and node-process succeeded, not the whole candidate.
IAM/000 and 011 own availability/capacity design and the remaining
load-balancing, fairness, capacity and database-HA evidence gaps; two IAM
processes sharing one database are not full HA acceptance.

0f99ec9 replaces per-fragment IAM commits with one context-owned transaction
including final verification. The actual 5721 retained-state gate injects both
a late DDL failure and invalid RLS rejected by the final verifier; both roll
back without changing retained authority or exposing the new recovery table.
The DDL failure was observed red before the fix, then both cases passed
(15.386s including normal upgrade/recovery/restart). This is schema3-to-4
atomicity evidence, not the still-unimplemented IAM6 policy cutover.

The same correction paces only known rolled-back Audit conflicts with bounded,
cancellable exponential jitter. Default attempts remain five; no client retry
was added, unknown commit outcomes and denials are not retried. Local full
race/vet/module checks, stable generation and Linux builds pass. Isolated PG18
dual-schema/old-chain, Audit HTTP and IAM HTTP/recovery gates pass (5.802s,
3.100s, 91.862s). Retained upgrade plus independent process passes 57.432s;
two more fresh-database process runs pass 46.505s and 51.722s. All task-owned
temporary PG/container/network/volume resources were cleaned. The exact
0f99ec9 CI run 34569666803 is confirmed completed/success for the exact SHA,
including go, authority-process and node-process. It is the verified/pushed
rollback point before the remaining risky storage replacement.

3b370ca defines Policy metadata (SYSTEM/CUSTOMER, owner/scope, ACTIVE/RETIRED,
default immutable version) and PolicyAttachment (carrier, physical Account,
sealed platform/probe installation, revision and terminal revocation). Strict
decoders do not add a management endpoint. EvaluateAttachedPolicies validates
every current ownership/default-version link before using the sole statement
evaluator; bad later records cannot leave partial Allow/evidence. Direct
subjects cannot use unproved group/role inheritance. It returns exact sorted
attachment ID/revision and policy/version/digest evidence. This is not yet
called by the old SQL loader/Decide path: do not claim persistence integration.
API/IAM/architecture no-cache race, vet, stable generation and IAM Linux build
pass; three repeated API/domain race runs pass. No new runtime fixture or
schema/profile change was introduced. Its exact CI run 34570914253 is confirmed
live/in_progress; inspect that same run rather than infer success.

Next required implementation remains IAM/002 persisted policy versions,
attachments, decision evidence and atomic replacement of old role authority
across management API/UI and sealed recovery consumers. Keep the whole IAM
goal active; neither this safety prerequisite nor the pure evaluator accepts it.

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
