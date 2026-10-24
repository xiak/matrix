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

## Remaining boundaries

- FEAT-IAM-010 owns remaining non-Deferred LIVE UI journeys. Backend, component,
  CI and signed-lifecycle evidence do not mark an unexecuted browser path green.
  The immediate IAM-UI-02 gap is a real-browser foreground-activity gate: one
  trusted interaction touches the exact current Session, passive/background
  events do not, and an untouched comparison Session still expires.
- [Issue #6](https://github.com/xiak/matrix/issues/6) remains open: the current
  green four-product and signed runs do not retroactively establish the unique
  cause of the preserved Docker observation timeout.
- Production account-fairness SLO and installation-grade database HA remain
  Deferred until their deployment prerequisites and real failover environment
  exist. Functional acceptance is not either claim.
