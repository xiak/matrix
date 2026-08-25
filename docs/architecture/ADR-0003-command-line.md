# ADR-0003: Command-line foundation

- Status: Accepted
- Date: 2026-08-25

## Context

Matrix PaaS will need one memorable user-facing CLI and a small number of
internal operational commands. A high-frequency command should not require a
Kubernetes-style `ctl` suffix.
A consistent command tree, flags, help, completion, streams, and exit behavior
should be established before command implementations multiply.

Kubernetes kubectl currently builds its command tree with Cobra and uses
pflag-compatible flags. Kubernetes also provides `k8s.io/cli-runtime` for
generic configuration, I/O, resource builders, and printers.

## Decision

1. The user-facing executable is `mx`, the lowercase short form of Matrix.
   Public examples use command paths such as `mx app deploy`; Go packages,
   API resources, configuration keys, and environment variables keep their
   full Matrix names. Because no pre-v1 consumer exists, compatibility aliases
   are not introduced.
2. Matrix Go CLIs use `github.com/spf13/cobra` and
   `github.com/spf13/pflag` as their command and flag foundation.
3. Library versions are pinned when the first CLI feature is implemented, not
   added to the Runtime contract feature without a consumer.
4. `k8s.io/cli-runtime` is not imported wholesale. We first copy its design
   principles: injected input/output/error streams, options separated from
   execution, deterministic printers, context cancellation, and testable
   command construction. A future ADR may admit selected packages if real
   resource-builder or printer needs justify the dependency closure.
5. Subcommands contain presentation and client orchestration only. Placement,
   authorization, isolation, idempotency, and runtime policy remain server
   responsibilities.
6. Machine-readable output and exit codes are stable contracts. Human table
   output may evolve without becoming an API transport format.
7. Subcommands return errors; only the process entry point maps them to stderr
   and an exit code. Subcommands do not call `os.Exit`.

## Consequences

- The short `mx` command remains easy to type while product and API vocabulary
  stays explicit.
- Future commands share familiar Kubernetes-style command behavior without
  inheriting kubectl's complete dependency graph.
- Command logic remains unit-testable without a terminal or live control
  plane.
- CLI dependencies are introduced only with the first executable FEAT.

## References

- https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/kubectl/pkg/cmd/cmd.go
- https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/kubectl/go.mod
- https://github.com/kubernetes/cli-runtime/blob/master/go.mod
