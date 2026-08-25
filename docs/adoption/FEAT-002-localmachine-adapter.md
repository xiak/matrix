# FEAT-002 adoption review: LocalMachine adapter

- Status: Complete
- Target: [`FEAT-002 LocalMachine infrastructure adapter`](../features/FEAT-002-localmachine-adapter.md)
- Review date: 2026-08-25
- Direct donor dependency allowed: No

## Fixed baselines

| Donor | Commit | Worktree policy |
| --- | --- | --- |
| `D:\XiaK\project\2026\matrix` | `69336e51f94fa98f6aa278fa4c62382e224dbeaf` | Read only with Git object commands. The current dirty worktree is excluded. |
| `D:\XiaK\project\2026\senatria\matrix` | `f51d5ed19fd60e8c4e43500af5e669d67ae4ef7d` | Read only with Git object commands. The current worktree is excluded. |

The FEAT-002 target design and release gates were written before these source
slices were opened.

## Legacy PaaS comparison

| Slice at fixed commit | Size | Decision | Rationale |
| --- | ---: | --- | --- |
| `providerregistry/domain/provider_binding.go` | 562 lines | `ADAPT` | Preserve credential references instead of bytes, explicit capability policy, canonical sets, binding validation before use, and lifecycle authority. A LocalMachine binding is platform-installation configuration and much smaller; the complete ProviderRegistry aggregate, tenant/provider topology, rotations, quotas, and evidence-reference graph are not copied. |
| `providerregistry/domain/capability_declaration.go` | 368 lines | `REFERENCE` | Immutable, version-qualified capabilities and sensitivity declarations are strong. FEAT-001 already provides a smaller `v1` capability contract; importing the general schema, retry, inverse-effect, permission, and evidence framework would duplicate service policy. |
| `provider/contract/envelope.go` | 32 lines | `ADAPT` | The separation between invocation identity and `CredentialSessionRef` confirms the target's opaque `bindingRef` and internal credential resolution. Its string-only envelope has insufficient validation and does not replace the FEAT-001 command contract. |
| `runtime/domain/records.go` and `values.go` | 1,645 lines | `REFERENCE` | Preserve provider-neutral target health, desired/observed separation, UTC microsecond rules, canonical sets, control-character rejection, and raw-sensitive-material detection. Docker/Compose-shaped public target vocabulary and the donor Project/Environment/Application/Service topology remain rejected. |
| Entire legacy ProviderRegistry and Runtime aggregate closure | Thousands of lines | `REJECT` | There is no LocalMachine host probe or SSH transport at this commit. Pulling the aggregate closure would add policy, persistence, and product hierarchy without implementing FEAT-002. |

## Senatria DevOps comparison

| Slice at fixed commit | Size | Decision | Rationale |
| --- | ---: | --- | --- |
| `devops/infrastructure/remoteexecution/deployment_target.py` | 185 lines | `ADAPT` | Preserve bounded target names, explicit required settings, port validation, safe absolute paths, strict checking by default, and structured configuration errors. Reject raw private keys in environment-backed target objects and reject the option to disable host verification. |
| `devops/infrastructure/remoteexecution/ssh.py` | 217 lines | `ADAPT` | Preserve non-shell local process launch, batch/identity-only behavior, deadlines, per-file permissions, Windows ACL failure handling, argument control-character rejection, and output limits. The new Go transport uses an injected credential resolver and pinned host-key callback; it does not expose arbitrary script/argument execution. Output is bounded while reading, rather than after an unbounded `capture_output` allocation. |
| `test_deployment_target.py` and `test_ssh.py` | 192 lines | `REFERENCE` | Reuse the negative-test categories for missing pins, unsafe ports/paths, control characters, quoting, and injection-shaped values. Add an actual ephemeral SSH server, wrong-pin behavior, deadline, and streaming-size tests absent from the donor. |
| `bootstrap-compose-target-ssh.sh` and `deploy-compose-ssh.sh` | 427 lines | `REJECT` | These are CI deployment scripts, not infrastructure observations. They accept raw keys through environment variables, may disable strict host checking, construct remote shell commands, mutate hosts, upload payloads, and contain Senatria release assumptions. None enter FEAT-002. |
| Compose packaging, release-state, and target-config code | Large DevOps closure | `REJECT` for FEAT-002 | Useful later as FEAT-004 behavior evidence, but it deploys business releases and does not define a safe machine observation boundary. |

## Design comparison result

The target design is narrower and safer for a customer PaaS:

- machine access is a server-side binding reference rather than raw
  environment-backed key material;
- host-key verification is mandatory, not configurable to insecure mode;
- callers choose neither scripts nor SSH arguments;
- machine observations contain no endpoint, username, raw output, or native
  error;
- output limits apply during reads to bound memory;
- Local and SSH observations share one versioned normalized shape.

The donors remain stronger in canonical collection handling, external-text
sanitization, configuration negative tests, and operational SSH edge cases.
Those semantics are adapted. No donor source file is copied and neither donor
is a build or runtime dependency.

## Donor-informed amendments

The review adds two implementation requirements without changing the target
resource model:

1. Every external label, normalized failure message, and safe discovered text
   rejects ASCII control characters and known raw-secret markers before it can
   become Evidence or an observation.
2. Remote stdout/stderr limits are enforced by bounded readers during
   collection. Reading an unlimited response and checking its size afterward
   is not accepted.
