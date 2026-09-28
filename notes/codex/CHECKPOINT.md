# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-28
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/phase3-mfa-enabling`
- Fixed runtime source: `d3339f5b582dd5fe134d6098b352c938dc7d4ac2`,
  [Verification](https://github.com/xiak/matrix/actions/runs/36407253372) successful
  in all four jobs.
- Fixed corrected gate driver: `72a09e09ec7c66c514c02ef3fe8e3d09399d59b2`,
  [Verification](https://github.com/xiak/matrix/actions/runs/36412101868) successful
  in all four jobs. It changes only the native runtime CPU assertion.

## Resume route

1. [FEAT-008](../../docs/features/FEAT-008-linux-host-management.md) owns the
   accepted current-composition signed two-host runtime result. Its A-to-B gate
   passed with actual `172.30.1.160` and `.161` enrollment, workloads,
   terminal, drain and removal. The task-local signing key is not a published
   production trust root.
2. [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md)
   owns the remaining full integrated release/recovery requirements; the
   two-host result does not close them.
3. [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md) owns the
   separate LIVE browser journey; do not infer it from the process gate.
4. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md)
   owns the IAM/Audit boundary. Later IAM work in another branch is not part
   of this fixed release composition.

The host gate used a source-preserving task-only `/32` alias. Both remote test
hosts were returned to zero containers and zero running Matrix test units;
temporary routes, node roots, private test key and gate images were removed.
Neither remote machine, its Docker daemon, Phase 2, nor `172.30.1.3` was
restarted or modified. Do not reuse the gate's transient resources as product
installation state.
