# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-04
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/console-theme-session-ux
- Pushed implementation: 578c0540a58c3e7fa4bb879df504464f12ee527d
- Outcome: readable themed buttons and browser login restoration, preserving
  existing IAM authority, revocation and role boundaries; no credentials in Git.

Follow AGENTS.md and repository-local identity `Xiak <Jellal@aliyun.com>`.
Read [FEAT-IAM-010](../../docs/features/iam/FEAT-IAM-010-console.md#浏览器登录持久化),
then the owning source/tests. Shared theme evidence belongs to
[FEAT-007](../../docs/features/FEAT-007-control-plane-console.md#theme-contrast);
installed topology and release boundaries belong to
[FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#local-https-proxy-ingress).

The pushed implementation has native Docker browser evidence, independent
PostgreSQL session regression, affected Go/architecture gates, targeted frontend
regressions, production-export equivalence and reviewed login-page imagery.
The FEAT owns precise limits. Full independent CI and the user's hands-on UI
acceptance remain required. A local source-development environment is not an
accepted sealed Release. The user wants to continue UI review before publishing.

PR #16 was fast-forward merged to main 0afed148437c9241ccd61e62742a7577c7f15176.
That main source passed Verification 41790163222 and Product onboarding
41790180425. It predates this browser-session slice. Do not dispatch a production
release of that older source while the user is accepting this replacement.
After the final UI source is accepted and merged, require all independent gates
on its exact main SHA, then prepare v0.4.0 with successor v0.4.1 only for lifecycle
acceptance, `prepare_release=true` and `https_proxy=true`. Review signatures,
source, complete assets and evidence before publishing. v0.3.0 is immutable;
no formal v0.4.0 release has occurred. Use the existing protected production
signer; never regenerate it or relabel an acceptance-signed candidate.

The dedicated Tencent Debian DEMO still runs accepted source
710d69cdd1882d2561e764cde412cfdb5955e9c6, whose disposable acceptance signer does
not authorize a production Release. This UI/session slice is not deployed there.
The native Docker, Cloudflare Tunnel, controlled accounts, internal-only mail,
first-use and recovery evidence remain owned by FEAT-005 and its linked guides.
Temporary broad passwordless sudo was removed. Token rotation remains an
operator-private handoff. Keep server identifiers, SSH/SMTP/Tunnel/signing
material, browser storage and account handoffs outside Git and public evidence.
Preserve the installed DEMO and the user's original local Matrix data. The
earlier ELK/Redis goal is complete; do not restart it.
