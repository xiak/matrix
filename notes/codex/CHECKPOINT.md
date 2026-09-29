# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-29
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/phase3-mfa-enabling`
- Latest pushed evidence: `3c1d419d` (FEAT-005/007/008); UI correction
  `63ac0ed4d3ad5a10f006a838e2d8647f070cf92d` passed all five jobs in
  [Verification 36529052870](https://github.com/xiak/matrix/actions/runs/36529052870).

## Resume route

1. [FEAT-008](../../docs/features/FEAT-008-linux-host-management.md) owns the
   signed revision-16-to-17 two-host gate and the later browser-ready run on
   `172.30.1.160`/`.161`: independently enrolled nodes, live sourced host and
   container measurements, actual terminal I/O and resize, closed ticket and
   delivered Audit facts. Signed runtime is fixed `1602fad3925b` followed by
   `648aac4ec956`; the later UI copy commit was not in that signed pair.
2. [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md) owns the
   installed password-plus-TOTP browser login and session revocation. The
   separate source correction stops calling every terminal 404 a stale
   generation; its 169 tests and deterministic 73-file embed gate passed.
3. [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md)
   owns release/recovery acceptance. The task-local signer is not a published
   production trust root; do not infer a production-signed release or
   cross-profile restore from the test-key-signed gates.
4. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md)
   owns the IAM/Audit boundary. Later IAM work in another branch is not part
   of this fixed release composition.

All task-only workloads, node and collector units, startup units, node roots,
test image, DIND containers/volumes, temporary address and routes, browser
session and 8.3 GiB local test packages were removed. Both remote Docker
daemons and default routes remain intact; neither remote machine, Phase 2 nor
`172.30.1.3` was restarted or modified. The persistent goal remains active
until the final production release boundary is independently verified.
