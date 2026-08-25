# Architecture decisions

| Decision | Status | Summary |
| --- | --- | --- |
| [ADR-0001](ADR-0001-repository-layout.md) | Accepted | Use a minimal `api`/`app`/`deploy` layout while borrowing Kubernetes repository principles. |
| [ADR-0002](ADR-0002-product-boundary.md) | Accepted | Build an independent PaaS product containing IAM and Audit, excluding customer business code. |
| [ADR-0003](ADR-0003-command-line.md) | Accepted | Use Cobra and pflag for Kubernetes-style, testable Go CLIs without importing the full kubectl stack. |

Normative dependency constraints are defined in
[DEPENDENCY-RULES.md](DEPENDENCY-RULES.md).
