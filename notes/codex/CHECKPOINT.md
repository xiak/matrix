# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-29
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/phase3-mfa-enabling`
- Latest pushed evidence: `68350e8a` (FEAT-005/007/008). UI correction
  `63ac0ed4d3ad5a10f006a838e2d8647f070cf92d` passed all five jobs in
  [Verification 36529052870](https://github.com/xiak/matrix/actions/runs/36529052870)
  and is an ancestor of the accepted signed source.

## Resume route

1. [FEAT-008](../../docs/features/FEAT-008-linux-host-management.md) owns the
   accepted signed revision-16-to-17 two-host gate on `172.30.1.160`/`.161`,
   including one-time registration, live measurements and real container
   terminal I/O. The later current-source installed UI independently rendered
   the same fixed registration command and final terminal-unavailable copy.
2. [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md) owns the
   current installed password-plus-TOTP browser gate, session revocation,
   360-pixel no-overflow result and keyboard open/close operation.
3. [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md)
   owns the current signed A/B lifecycle from exact source `684fb8c2`, profile
   IAM 49 / Audit 27 / PaaS 6 + revision 17. The task-local signer is not a
   published production trust root; do not infer cross-profile restore.
4. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md)
   owns the IAM/Audit boundary. Later IAM work in another branch is not part
   of this fixed release composition.

All task-only workloads, node and collector units, startup units, node roots,
test images, DIND containers/volumes/networks, temporary address/routes,
browser session, 8.3 GiB two-host packages and the final 0.98 GiB local
package directory were removed. Both remote Docker daemons and default routes
remain intact; neither remote machine, Phase 2 nor `172.30.1.3` was restarted
or modified. The repository-owned Phase 3 release-candidate boundary is
accepted; publishing and safeguarding a real production signing root remains
an operator release action, not a claim of these task-key-signed gates.
