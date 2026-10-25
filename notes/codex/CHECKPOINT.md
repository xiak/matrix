# Codex working checkpoint

> Non-authoritative portable memory. Validate Git, the active host goal and the owning FEAT before acting.

## Pushed IAM release milestone

- Repository `https://github.com/xiak/matrix.git`; the release work is based on
  fixed production source `95a343ae2f4efb4c9845c9af25d0225e722f870c` and
  repository-local identity `Xiak <Jellal@aliyun.com>`.
- The current complete profile is IAM/Audit/PaaS `87/39/7+r37`; the sole rolling
  data predecessor remains fixed `08e1dc4a6ce81386ea7223e62d03356f82aeee58`
  (`86/39/7+r36`). Cross-profile transitions remain closed before effects.
- UX/UI remains owned by the UX engineer. This branch consumes the frozen
  deterministic export; do not create a parallel frontend or infer LIVE browser
  acceptance from the signed package.
- The UI owner has reconciled FEAT-007 and its adoption record to the current
  four-product release and fixed the foreground-Session consumer at
  `8fbf2fcc` plus deterministic export `3ec28ae6`. The formal release consumes
  the identical `093b29dee` UI tree and `matrix-a88a124cebcd3748a05e` build ID.

## Accepted fixed evidence

- [Verification 40085311144](https://github.com/xiak/matrix/actions/runs/40085311144)
  attempt 1 matches `95a343ae` and completed successfully with all nineteen jobs.
- Same-source signed A/B releases `.r37.35` and `.r37.36` passed the existing
  network-disabled lifecycle in 4197.458 seconds and the exact-container
  post-restart gate in 435.593 seconds. The cold gate includes real SMTP/TOTP,
  four managed products, failed-upgrade recovery, normal upgrade, rollback,
  selected-backup recovery, old credential fencing, Analyzer `RESTORE_GAP`,
  application rollback/stop and support zero-leakage.
- The first post-restart runner invocation failed before test compilation because
  its offline Go cache variables were omitted. It made no product request; the
  corrected `GOPROXY=off` invocation used the original caches and passed. Keep
  both records distinct.
- FEAT-005 owns the manifest, trust and delivery archive identities. The archives
  were re-extracted and compared for bytes, type, uid/gid and mode, then rehashed
  after transfer; no private signer or installation state is included.
- Fixed test source `6efc6c8febc8221e5cf2b9ecf737c8192643c26b`
  passed the real same-origin foreground-Session browser gate: 61 seconds of
  passive page work emitted zero touches; three immediate trusted pointer
  interactions emitted exactly one valid touch and advanced only the current
  browser Session. The untouched peer and its ordinary protected read did not
  advance its activity waterline. FEAT-IAM-010 owns the exact evidence and the
  distinction from server-owned natural idle expiry.
- [Verification 40097217325](https://github.com/xiak/matrix/actions/runs/40097217325)
  accepted that exact source with all nineteen jobs `completed/success`.
  The default workflow compiles the opt-in browser test and runs its adjacent
  automated regressions; it does not replace the separately executed human-input
  browser journey.
- Fixed `76b166b2d816be546c46cf2c9dc8203cdb36d344` reused the existing
  policy-attachment recovery fixture in two fresh PostgreSQL 18.6 browser runs.
  USER/CREATE passed in 109.88 seconds and ROLE/CREATE passed in 93.74 seconds:
  each issued one write, observed UNKNOWN after the successful response was
  lost, read the immutable original receipt once, issued zero post-loss writes
  and passed the exact permission, unique outbox/Audit and complete-chain
  checks. The Role run additionally closed the old RoleSession and required an
  explicit fresh assumption. FEAT-IAM-010 owns the exact request, target and
  attachment identities. Both disposable `--rm` containers were removed and
  the task label had no residual container.
- Fixed `80ca44282225e119377c31909dbbc8b4e7a3f769` reused the existing Account
  lifecycle recovery owner in a fresh PostgreSQL 18.6 two-origin browser run.
  Root-credential recovery submitted once, rendered UNKNOWN after its successful
  response was lost, exported only a non-secret command summary, performed one
  completion GET from the second origin and issued zero post-loss writes. The
  authoritative Account detail retained the same Root identity at version 2;
  old credentials and Sessions were fenced, the replacement credential required
  password change, and the unique completion/outbox/Audit chain passed. The
  disposable `--rm` container had no task-labelled residue after the run.
- Fixed `72dc37c714825ccfe5f38464ff66f398a13e45b9` reused the existing managed-
  service command-recovery owner for `INSTALLATION_TERMINATE`. A real disposable
  PostgreSQL installation was read at version 3, reviewed and submitted once;
  after the accepted response was lost, the second browser origin imported only
  the non-secret intent, read the matching completion and re-read the same
  installation as `TERMINATED` version 6 with the matching termination Operation.
  The fixture/package passed in 141.74/145.271 seconds with one mutation, zero
  post-loss writes, an authoritative input commitment, unique request Audit fact
  and a verified complete tenant chain. A first pre-UI invocation failed closed
  on the existing worker readiness prerequisite; only the fresh run after
  `vm.max_map_count=1048576` was established counts. Database, worker container
  and worker volume labels had no residue after cleanup.

## Remaining boundaries

- FEAT-IAM-010 owns remaining non-Deferred LIVE UI journeys. Backend, component,
  CI and signed-lifecycle evidence do not mark an unexecuted browser path green.
  Foreground Session activity and the complete GROUP/USER/ROLE × CREATE/REVOKE
  policy-attachment recovery matrix are now accepted, as is the Account
  Root-credential recovery final submit/UNKNOWN path and managed-service
  termination final submit/UNKNOWN path. The finite gaps previously named by
  this checkpoint are closed. Do not infer overall release completion from that
  list: derive any remaining non-Deferred gate from the owning FEAT matrix and
  current Git/CI/runtime state before changing the release status.
- [Issue #6](https://github.com/xiak/matrix/issues/6) remains open: the current
  green four-product and signed runs do not retroactively establish the unique
  cause of the preserved Docker observation timeout.
- Production account-fairness SLO and installation-grade database HA remain
  Deferred until their deployment prerequisites and real failover environment
  exist. Functional acceptance is not either claim.
