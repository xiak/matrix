# Troubleshooting handbook

This runbook is the single quick-search owner for difficult, repeatable
diagnoses. Feature requirements and acceptance evidence remain in their FEAT
owners; this file records only verified diagnostic and recovery procedures.

Search it before repeating a broad investigation:

```text
rg -n -i "<symptom|error-code|component>" docs/runbooks/troubleshooting-handbook.md
```

## Entry criteria and shape

Add or update an entry only after all of these are known:

1. Searchable keywords and the affected boundary.
2. The externally visible symptom.
3. The fastest safe discriminator.
4. A verified root cause, not a working theory.
5. The smallest verified resolution.
6. Exact cleanup and safety limits.
7. Links to the owning code, test, or FEAT evidence.

Never include credentials, recovery material, private machine paths, raw
untrusted command output, or a chronological investigation transcript. If a
failure belongs to an existing class, improve that entry instead of appending
a new incident diary.

## Mandatory test-resource closure

Every real-runtime test owns a unique task label or exact generated name and a
bounded CPU, memory, process, network, and storage scope. On success, failure,
or interruption, its final gate must:

1. stop and remove only its owned containers or processes;
2. remove its owned networks, volumes, temporary worktrees, exported source,
   test binaries, profiles, archives, and logs when they are no longer needed;
3. preserve durable evidence in the owning FEAT or CI result, not in a running
   test environment;
4. query the exact owner labels and paths again and require zero unintended
   remnants; and
5. report anything intentionally retained, including its owner and reason.

Cleanup is part of test acceptance. A passing assertion with leaked runtime
resources is not a completed test. Never substitute a global Docker prune,
filesystem-wide delete, WSL shutdown, engine restart, or remote-host restart
for exact owner-scoped cleanup.

## Signed release gate fails before or during predecessor installation

**Keywords:** DIND, Docker-in-Docker, signed release, fixed base image,
manifest digest, containerd snapshotter, `No such image`,
`INVALID_COMMAND_INPUT`, `northbound-origin`, disk cleanup, release gate,
发布门禁, 镜像摘要, 磁盘空间, 旧版本安装

**Boundary and safety:** This procedure was verified in the isolated,
GitHub-hosted release gate. Destructive cache or image cleanup below is safe
only for that ephemeral runner. Never translate it into a broad prune or
recursive delete on a developer workstation, shared host, remote machine, or
long-lived Docker engine. Inventory and resolve task-owned resources first on
any persistent system.

### Symptom-to-discriminator map

| Symptom | Fastest safe discriminator | Verified cause and resolution |
| --- | --- | --- |
| Release assembly stops at the fixed-image check | Pull the declared `name@sha256:...`, then compare the expected digest with `docker image inspect <tag> --format '{{.Id}}'` | A mutable tag drifted, or the classic image store exposed the selected platform config rather than the multi-platform manifest identity. Pull immutable digests and use a manifest-aware containerd image store for the gate. Do not weaken the identity assertion. |
| Cleanup reports `No such image` for an image that was just present | Check whether the command names both a tag and its digest for the same image | Removing the tag can also remove the final digest reference. Remove one resolved reference, then make cleanup idempotent. Do not treat this as disk corruption. |
| The signed bundles assemble, but the predecessor install fails immediately | Record only the CLI's validated failure class/code; then inspect the command contract at the exact predecessor commit | The supported predecessor required an explicit `--northbound-origin`; a compatibility assumption omitted it. Pass the origin to both the current release and its unique supported predecessor. Do not infer old CLI behavior from the current source tree. |
| The predecessor installs, but verification stops at `platform-topology-contract` | Compare the exact predecessor and current commits for topology/APISIX inputs, then inspect the database-profile and topology-digest pair in both signed manifests | The supported database predecessor had advanced while its selector still described an older topology. Bind the exact supported predecessor to its actually published topology, origin, secret mounts, and edge contracts; remove the obsolete compatibility branch instead of weakening verification. |
| The install step fails and disk pressure is suspected | Before changing limits, inspect outer free space, DIND `/data`, inner Docker version, Compose version, and the exact release-bundle sizes | In the verified case the gate had sufficient bounded space; the real failure was invalid command input. Measure first. Do not respond with a workstation-wide Docker prune. |

### Verified diagnostic sequence

1. Identify the last completed workflow step. An assembly failure, cleanup
   failure, and inner lifecycle failure have different owners; do not rerun
   the entire gate blindly.
2. Verify every fixed build input before starting DIND:

   ```text
   docker pull <name>@sha256:<manifest-digest>
   docker image tag <name>@sha256:<manifest-digest> <expected-tag>
   docker image inspect <expected-tag> --format '{{.Id}}'
   ```

3. If the gate has entered DIND, capture bounded diagnostics without changing
   the engine:

   ```text
   docker exec <dind> docker version --format '{{.Server.Version}}'
   docker exec <dind> docker compose version --short
   docker exec <dind> df -h /data /var/lib/docker
   ```

4. If the product CLI fails, use only its strict, sanitized error envelope for
   routing. Never print raw stderr because it may contain attacker-controlled
   or secret-bearing content.
5. For `INVALID_COMMAND_INPUT`, inspect the exact fixed source object rather
   than relying on memory or the current checkout. The command used in this
   diagnosis was:

   ```text
   git show 9815916b8bf8ae5505a6bc96681dd92fe92f945c:app/service/installation/internal/cli/command.go
   ```

6. Change only the contract mismatch, run the focused normal/race/vet gates,
   and then require the complete isolated release lifecycle to pass.

### Cleanup

The release workflow owns cleanup through an unconditional final step. It
removes the task-named DIND container, its task-named volumes, the temporary
predecessor worktree, and build-only caches on the ephemeral runner. Cleanup
must be idempotent so that a partially completed earlier step cannot turn the
real failure into a misleading cleanup failure.

Broad commands such as `docker system prune`, deletion of an entire Docker or
WSL data root, or filesystem-wide cleanup are not part of this procedure.

### Owners

- [Release workflow](../../.github/workflows/verification.yml)
- [Safe command runner](../../app/service/installation/test/phase1e2e/command.go)
- [Phase 1 lifecycle gate](../../app/service/installation/test/phase1e2e/gate.go)
- [FEAT-005 acceptance owner](../features/FEAT-005-offline-platform-lifecycle.md)
