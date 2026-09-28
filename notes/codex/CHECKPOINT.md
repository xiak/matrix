# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-28
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/phase3-mfa-enabling`
- Fixed runtime source: `6b47736b603fa018901fcc683d4df6fe260896fc`,
  [Verification](https://github.com/xiak/matrix/actions/runs/36416198588) successful
  in all four jobs.
- Fixed signed-browser gate driver: `bbcc28f21666ffe84aacb131331794cb1d52e0ff`,
  [Verification](https://github.com/xiak/matrix/actions/runs/36420261718) successful
  in all four jobs. Its only code changes are in the existing installation
  test harness; production release source remains `6b47736b`.

## Resume route

1. [FEAT-008](../../docs/features/FEAT-008-linux-host-management.md) owns the
   accepted current-composition signed two-host runtime result. Its A-to-B gate
   passed with actual `172.30.1.160` and `.161` enrollment, workloads,
   terminal, drain and removal. The task-local signing key is not a published
   production trust root.
2. [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md)
   owns the now-verified signed current-profile recovery lifecycle and the
   remaining integrated two-host/recovery requirements; neither the local
   recovery gate nor the earlier two-host gate alone closes them.
3. [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md) owns the
   signed LIVE browser evidence and its remaining user-facing gates; do not
   infer full console acceptance from login and directory reads.
4. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md)
   owns the IAM/Audit boundary. Later IAM work in another branch is not part
   of this fixed release composition.

The host gate used a source-preserving task-only `/32` alias. Both remote test
hosts were returned to zero containers and zero running Matrix test units;
temporary routes, node roots, private test key and gate images were removed.
Neither remote machine, its Docker daemon, Phase 2, nor `172.30.1.3` was
restarted or modified. Do not reuse the gate's transient resources as product
installation state.
