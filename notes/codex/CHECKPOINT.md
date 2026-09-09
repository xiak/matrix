# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-09
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `3ccd8da`

## Goal

Evolve Matrix into a private-cloud foundation with independently selectable
PaaS and DevOps products, then deliver DevOps through the accepted UX,
architecture, FEAT, implementation, test, and release gates.

## Current milestone

- FEAT-007 is the authoritative owner and remains `In progress`.
- Pushed `3ccd8da` expands the disposable Linux Docker `29.6.2` and pinned-
  runsc execution gate. The normal canonical archive still crosses both TLS
  1.3 mTLS gateway roles, the durable spool, journal, workspace, production
  runner workflow, both fixed Go steps, authenticated normalized-log read, and
  exact terminal receipt with no residual container.
- A malicious source archive now proves credential/proxy environment removal,
  denial of Docker/control-plane sockets, credential files and privileged
  devices, read-only source/root filesystems, loopback-only networking, failed
  reserved/private/metadata egress, and actual fixed-PID exhaustion. Pinned
  runsc returned `ENOMEM` after 112-113 child starts; the test accepts only the
  runsc `ENOMEM` or native-cgroup `EAGAIN` resource denials before 384 attempts.
- The same runner store publishes a different tenant's immutable decoy source
  and gives its exact host path to the attacker. Direct read/list, `..` read/
  write, and a writable-cache symlink escape fail while a control symlink to
  the attacker's own source succeeds. The trusted side re-proves the unchanged
  decoy and zero residual containers for both tenants. Combined with existing
  real PostgreSQL tenant-concealed run/log reads, Gate B's malicious-repository
  containment item is complete.
- Secret-shaped, absolute-path, ANSI, control-byte, invalid-UTF-8, and overlong
  native lines become exact closed markers, with raw sentinels absent. A
  separate real sandbox writes 129 64-KiB blocks, hits the fixed 8 MiB whole-run
  limit with no returned chunks or progress, and is cancelled, deleted, and
  observed absent. The expanded journey passed in 48.04 seconds; affected Linux
  vet and full Windows repository tests and vet pass on the same worktree.
- Earlier pushed `e9ad554` remains the real Gitea/PostgreSQL source-process and
  provider-report recovery evidence: one signed event and run, fetch and report
  fence-two recovery without duplicate provider effects, terminal Audit outbox
  delivery, and the unchanged run reaching `SUCCEEDED / COMPLETED`.
- Gate B still lacks one joined physical IAM/Audit/executor journey and the
  other unproved external-effect restarts. UI Gate C has not begun.

## Adoption boundary

- Prow remains fixed at
  `1a000594c40919068dd43a5704f279f273135d18` and is reference/selective
  adaptation only, never a Matrix dependency.
- CODING remains a product-experience reference; Matrix owns the unified
  product experience and keeps execution behind adapters.

## Continuation

Join the existing physical IAM/Audit/executor evidence where that materially
protects the end-to-end boundary, without duplicating their already proved
isolated gates. Complete remaining external-effect restarts with no duplicate
provider outcome. Only after complete Gate B passes begin formal Matrix UI
integration from the accepted UX baseline.

Keep runner authority away from PostgreSQL, source/report credentials, IAM,
Audit, PaaS, and executor-admin operations. Preserve pragmatic DDD,
replacement-first pre-v1 changes, optional-product isolation, and
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
