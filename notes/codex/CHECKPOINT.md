# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-03
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/cloudflare-tunnel-entry
- Outcome requested: accept a host-local HTTPS proxy entry and a usable Tencent Debian / Cloudflare Tunnel deployment workflow, using native Docker and keeping all credentials outside GitHub.
- Base main: c609e1078cee3c55442d0164738f03fc28676f15. The published v0.3.0 payload is unchanged and does not include the new HTTPS profile.

Follow AGENTS.md and repository-local identity `Xiak <Jellal@aliyun.com>`.
Read [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#local-https-proxy-ingress), then the owning installation code/tests and [deployment runbook](../../docs/runbooks/platform-installation.md#腾讯云-debian-与-cloudflare-tunnel).

The branch implements external HTTPS origin sealing, loopback-only host ingress,
Host/Origin checks, ignored forwarding metadata, Secure terminal cookies and
local maintenance independent of proxy availability. SourceIP still means the
observed proxy peer. Remote node/runner enrollment is not covered by the Web
Tunnel profile. HTTP release behavior is retained.

Implementation `f6cf6e76fb5f4df028e7e57ad877dbf0e9fcbf60` passed all 20 jobs
in independent Verification 41612656543. Local unit gates and the actual
pinned APISIX gate passed. Native HTTPS acceptance 41612484059 is still running;
do not dispatch a duplicate. Earlier run 41609621167 failed at the browser
logout harness after install and first password change; that selector is
corrected, but the earlier run is not accepted. FEAT-005 owns precise evidence.

The dedicated Tencent Debian 12 host now has a running host-native Cloudflare
connector, enabled at boot, with loopback readiness 200 and root-only token
custody. Its existing Docker engine is preserved. The published hostname has
a Tunnel route, but Matrix is not installed, so public application access is
not accepted. Debian 13 package preparation was separately verified without
a nested daemon. No host reboot or live application recovery is accepted yet.
The current installer still requires SMTP configuration. The user wants to
defer supplying a mailbox; do not request or configure credentials until the
mail-disabled installation scope is resolved. Do not use dummy mail settings
to bypass the existing requirement or silently weaken MFA enrollment.

Next: finish native CI, inspect safe browser evidence, resolve the deferred
mail configuration, then complete live deployment/recovery with an accepted
HTTPS package. Draft PR #16 tracks the change. No release publication or merge
has occurred for this task. The operator configured the Cloudflare route;
never retag the existing release as an HTTPS build. Keep server identifiers,
credentials and local access files outside repository evidence. A temporary
sudo grant must be removed after deployment verification as promised to the
operator. Token rotation remains an operator-private handoff, not a chat input.

Preserve the original local installation and its data. Remove only this task's
disposable Debian preparation container/image after validation. The prior
ELK/Redis release goal is complete and must not be restarted. Dedicated signing
custody already exists; do not generate replacement signing keys. Production
signing inputs, SMTP configuration and Tunnel tokens must never enter Git,
public logs, screenshots or CI artifacts.
