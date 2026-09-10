# FEAT-008 frontend adoption

- Source repository: this repository, fixed commit `223537ab3bf26c2963a8b739cea3300b0a98d367`.
- Authoritative target baseline: `21507b3f47d6ba3561c408632890ab0629c0ab29`.
- Requirement, implementation status and acceptance owner: [FEAT-008](../features/FEAT-008-product-foundation-shell.md).

| Fixed source slice | Decision | Target |
| --- | --- | --- |
| Brand vectors, semantic theme tokens, public controls | REUSE | The single public UI owner under `app/ui/platform/_frontend`; retain only controls with current consumers or behavioral gates |
| Compact page context, table query/filter, dialog and navigation feedback | ADAPT | Current platform and product routes; local rendering boundaries, keyed messages and safe query continuity |
| Authentication and request orchestration | REFERENCE | Reimplement against current public IAM/session and installed-product authority, preserving current platform response/request guards |
| Static export normalization and CSP hashing | ADAPT | Current `matrix-ui` Go host, preserving readiness, configuration digest and release wiring |
| Fixed product catalogue, fake resources, notifications and CAM workspace | REJECT | Must not become installed-product truth or claim unsupported production authority |
| Old `app/ui/paas`, `matrix-paas-ui`, `/console/*` and backend history | REJECT | No parallel shell, compatibility alias, branch-history merge or superseded backend adoption |
| Old FEAT-007 control-plane documentation | REJECT | Current feature ownership remains FEAT-008 and FEAT-007 repository delivery |

The source is inspected only at the fixed commit. It is not a build or runtime
dependency. Current PaaS/DevOps API behavior comes from the target baseline, not
the source preview implementation.
