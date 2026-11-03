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

Local unit gates and the actual pinned APISIX gate passed. Debian 13 package
preparation, protected token-file input with synthetic material and service-file
syntax passed without a nested daemon. FEAT-005 owns their precise scope.
Native HTTPS run 41609621167 installed successfully and passed browser first
login/change-password, but failed at the logout harness selector; it is not an
accepted lifecycle run. The selector is corrected and a proxy-interruption
drill is added on this branch. Full native acceptance and current-source
Verification still need successful results before acceptance.

The user is preparing the Tencent server. Live hostname/SSH access and actual
Cloudflare setup are pending; never claim public connectivity or host reboot
has passed based on the local TLS surrogate. Request only a usable SSH alias
and access readiness, not a private key, password or Tunnel Token. Keep the
real domain and deployment credentials out of portable repository evidence.

Next: finish current-source CI, inspect safe browser evidence, update the
owning FEAT, complete live deployment/recovery when access is ready, then offer
the concrete reviewed change. No release publication, merge or DNS mutation
has occurred for this task. Never retag the existing release as an HTTPS build.

Preserve the original local installation and its data. Remove only this task's
disposable Debian preparation container/image after validation. The prior
ELK/Redis release goal is complete and must not be restarted. Dedicated signing
custody already exists; do not generate replacement signing keys. Production
signing inputs, SMTP configuration and Tunnel tokens must never enter Git,
public logs, screenshots or CI artifacts.
