# Cross-component tests

This directory will own contract, integration, and end-to-end verification that
crosses service boundaries. Unit tests remain beside their owning packages.

`architecture/` already enforces the dependency direction and service
`internal/` ownership rules defined by
[`docs/architecture/DEPENDENCY-RULES.md`](../docs/architecture/DEPENDENCY-RULES.md).

The first release gates will cover APISIX-to-IAM identity handling, IAM
permission checks, PaaS transactional Audit outbox delivery, and the
LocalMachine-to-Compose runtime loop.
