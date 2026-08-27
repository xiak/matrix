# FEAT-008 adoption review: existing Linux hosts

- Status: Pending fixed-source review
- Target: [FEAT-008](../features/FEAT-008-linux-host-management.md)
- Target design date: 2026-08-27
- Direct donor dependency allowed: No

## Fixed baselines

| Donor | Commit | Inspection rule |
| --- | --- | --- |
| Legacy PaaS | `69336e51f94fa98f6aa278fa4c62382e224dbeaf` | Git objects only; never the donor worktree |
| IAM/Audit and delivery foundation | `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d` | Git objects only; narrow execution/observability/lifecycle slices |
| PaaS design | `338d9b5fcb820120c32265e380c55e5f171cdb75` | Git objects only; rationale, not runtime evidence |

Source identities are owned by [the fixed-source entry](sources.yaml).
Relevant slices are classified as `REUSE`, `ADAPT`, `REFERENCE`, or `REJECT`
after the target design commit and before implementation.
